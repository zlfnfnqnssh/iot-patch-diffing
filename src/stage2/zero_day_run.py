"""Zero-Day blind-hunt orchestrator.

Subcommands:
    migrate                               - apply zero_day_migration.sql
    init   ...                            - create new run + load funcs_json
    prefilter <run_id> [--limit N]        - mark dangerous-keyword funcs
    prepare  <run_id> --limit N --out P   - export next batch JSON
    split    <in.json> [--shards 4]       - shard by size
    apply    <run_id> <out_a1..ak.json>   - ingest agent outputs -> verdicts
    status   <run_id>                     - progress summary
    cards-context                         - dump active pattern_cards as card-context JSON (for Agent input)
    list                                  - list runs

Usage:
    python src/stage2/zero_day_run.py migrate
    python src/stage2/zero_day_run.py init --name "sonia_v2.880.0.16_blind" \\
        --binary "output/.../bin/sonia" \\
        --funcs-json tmp/sonia_v2880_016_full/sonia_v2880_016.json \\
        --vendor dahua --model Kant --version 2.880.0.16
    python src/stage2/zero_day_run.py prefilter 1
    python src/stage2/zero_day_run.py prepare 1 --limit 200 --out tmp/zd/in_r1_b1.json
    python src/stage2/zero_day_run.py split tmp/zd/in_r1_b1.json --shards 4
    # -> 4 Drafter Agents run with zero_day_hunter.md prompt, write out_r1_b1_aN.json
    python src/stage2/zero_day_run.py apply 1 tmp/zd/out_r1_b1_a1.json tmp/zd/out_r1_b1_a2.json ...
    python src/stage2/zero_day_run.py status 1
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = PROJECT_ROOT / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
MIGRATION_SQL = PROJECT_ROOT / ".claude" / "skills" / "stage2" / "sql" / "zero_day_migration.sql"

DANGEROUS_KEYWORDS = [
    # Classic libc (when symbols preserved)
    "system(", "popen(", "execl(", "execlp(", "execle(",
    "execv(", "execvp(", "execve(", "posix_spawn(",
    "sprintf(", "strcpy(", "strcat(", "gets(", "vsprintf(",
    "snprintf(", "strncpy(", "strncat(",
    "memcpy(", "memmove(", "bcopy(",
    "printf(", "fprintf(", "dprintf(",
    "chmod(", "chown(", "unlink(", "rename(",
    "symlink(", "mkdir(",
    "recv(", "recvfrom(", "scanf(", "sscanf(", "fscanf(",
    "strtok(", "realpath(",
    # Stripped-binary signals (match in the `strings` JSON field)
    # - HTTP header names + format specifiers strongly suggest header/string building
    '"Host"', '"Content-', '"Cseq"', '"CSeq"', '"Authorization"',
    '"Cookie"', '"Referer"', '"User-Agent"', '"X-',
    # - Risky shell command literals
    "/bin/sh", "/bin/bash", "rm -rf", "chmod +x", "/tmp/",
    # - Format-string sinks
    '"%s"', '"%d"', '"%x"',
    # - printf family format often used unsafely
    "%s %s", "%s/%s", "%s:%s",
]
DANGER_RE = re.compile("|".join(re.escape(k) for k in DANGEROUS_KEYWORDS))


def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


# ── commands ──────────────────────────────────────────────────────────────

def cmd_migrate(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    sql = MIGRATION_SQL.read_text(encoding="utf-8")
    conn.executescript(sql)
    conn.commit()
    c = conn.cursor()
    for t in ("zero_day_runs", "zero_day_functions", "zero_day_verdicts"):
        n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"[migrate] {t}: {n} rows")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    src = Path(args.funcs_json)
    if not src.exists():
        print(f"[init] ERROR: funcs_json not found: {src}", file=sys.stderr)
        return 1
    data = json.loads(src.read_text(encoding="utf-8"))
    funcs = data.get("functions", {})
    print(f"[init] loaded {len(funcs)} functions from {src}")

    conn = open_db(args.db)
    c = conn.cursor()

    c.execute(
        """INSERT INTO zero_day_runs (name, target_binary, target_vendor, target_model,
               target_version, source_json_path, total_functions, status, started_at, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP, ?)""",
        (args.name, args.binary, args.vendor, args.model, args.version,
         str(src), len(funcs), args.notes),
    )
    run_id = c.lastrowid

    rows = 0
    for addr, fn in funcs.items():
        if not isinstance(fn, dict):
            continue
        pseudo = fn.get("pseudocode") or ""
        disasm = fn.get("disasm") or ""
        calls = json.dumps(fn.get("calls") or [], ensure_ascii=False)
        strings = json.dumps(fn.get("strings") or [], ensure_ascii=False)
        c.execute(
            """INSERT OR IGNORE INTO zero_day_functions
               (run_id, addr, name, size, pseudocode, disasm, calls, strings, stage_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
            (run_id, addr, fn.get("name"), fn.get("size") or 0,
             pseudo, disasm, calls, strings),
        )
        rows += c.rowcount if c.rowcount > 0 else 0

    conn.commit()
    print(f"[init] run_id={run_id} functions_loaded={rows}")
    return 0


def cmd_prefilter(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM zero_day_functions WHERE run_id=?", (args.run_id,)).fetchone()[0]
    if total == 0:
        print(f"[prefilter] run {args.run_id} has no functions", file=sys.stderr)
        return 1

    c.execute("SELECT id, pseudocode, disasm, strings FROM zero_day_functions WHERE run_id=?", (args.run_id,))
    pf_yes = []
    pf_no = []
    for r in c.fetchall():
        text = (r["pseudocode"] or "") + "\n" + (r["disasm"] or "") + "\n" + (r["strings"] or "")
        if DANGER_RE.search(text):
            pf_yes.append(r["id"])
        else:
            pf_no.append(r["id"])

    for i in range(0, len(pf_yes), 500):
        chunk = pf_yes[i:i+500]
        conn.execute(f"UPDATE zero_day_functions SET prefiltered=1 WHERE id IN ({','.join('?'*len(chunk))})", chunk)
    for i in range(0, len(pf_no), 500):
        chunk = pf_no[i:i+500]
        conn.execute(f"UPDATE zero_day_functions SET prefiltered=0 WHERE id IN ({','.join('?'*len(chunk))})", chunk)

    conn.execute(
        "UPDATE zero_day_runs SET prefiltered_functions=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (len(pf_yes), args.run_id),
    )
    conn.commit()

    print(f"[prefilter] run {args.run_id}: {len(pf_yes)} prefiltered_in / {len(pf_no)} out / {total} total")
    return 0


def _active_cards_context(
    conn: sqlite3.Connection,
    exclude_pks: set[int] | None = None,
    batch_filter: str | None = None,
) -> list[dict]:
    """Load active pattern_cards as the Agent context list.

    exclude_pks: integer primary keys to hide (for blind validation — hide
      the CVE ground-truth card so the Agent must re-derive it).
    batch_filter: if given, only cards with `created_in_batch=<value>` pass
      (delta hunt — 이번 주 netnew 카드만 쏘고 싶을 때). None = 전체 active.
    """
    exclude_pks = exclude_pks or set()
    out = []
    c = conn.cursor()
    if batch_filter:
        query = """
            SELECT id, card_id, source_type, sink_type, missing_check, summary,
                   severity_hint, cve_similar
            FROM pattern_cards WHERE status='active' AND created_in_batch = ?
            ORDER BY id
        """
        rows_iter = c.execute(query, (batch_filter,))
    else:
        query = """
            SELECT id, card_id, source_type, sink_type, missing_check, summary,
                   severity_hint, cve_similar
            FROM pattern_cards WHERE status='active'
            ORDER BY id
        """
        rows_iter = c.execute(query)
    for r in rows_iter:
        if r["id"] in exclude_pks:
            continue
        out.append({
            "pk": r["id"], "card_id": r["card_id"],
            "formula": [r["source_type"], r["sink_type"], r["missing_check"]],
            "summary": (r["summary"] or "")[:260],
            "severity_hint": r["severity_hint"],
            "cve_similar": r["cve_similar"],
            "tokens": [], "negative_tokens": [],
        })
    # tokens
    tok_by_pk: dict[int, list] = {}
    for r in c.execute("SELECT card_id, token, kind, weight FROM pattern_card_tokens"):
        if r[0] in exclude_pks:
            continue
        tok_by_pk.setdefault(r[0], []).append({"token": r[1], "kind": r[2], "weight": r[3]})
    neg_by_pk: dict[int, list] = {}
    for r in c.execute("SELECT card_id, token, vendor_scope FROM pattern_card_negative_tokens"):
        if r[0] in exclude_pks:
            continue
        neg_by_pk.setdefault(r[0], []).append({"token": r[1], "vendor_scope": r[2]})
    for card in out:
        card["tokens"] = tok_by_pk.get(card["pk"], [])
        card["negative_tokens"] = neg_by_pk.get(card["pk"], [])
    return out


def _parse_exclude_pks(raw: str | None) -> set[int]:
    if not raw:
        return set()
    out: set[int] = set()
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        out.add(int(tok))
    return out


def cmd_cards_context(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    exclude = _parse_exclude_pks(getattr(args, "exclude_card_pk", None))
    cards = _active_cards_context(conn, exclude_pks=exclude)
    args.out = Path(args.out) if args.out else None
    payload = {"count": len(cards), "cards": cards}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        print(f"[cards-context] wrote {len(cards)} cards -> {args.out}")
    else:
        print(json.dumps(payload, ensure_ascii=False))
    return 0


def cmd_prepare(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    c = conn.cursor()

    run = c.execute("SELECT * FROM zero_day_runs WHERE id=?", (args.run_id,)).fetchone()
    if not run:
        print(f"[prepare] run {args.run_id} not found", file=sys.stderr)
        return 1

    order_sql = {
        "id": "id ASC",
        "size_desc": "LENGTH(pseudocode) DESC, size DESC",
        "size_asc": "LENGTH(pseudocode) ASC",
    }.get(getattr(args, "order", "id"), "id ASC")

    pending = c.execute(
        f"""SELECT id, addr, name, size, pseudocode, disasm, calls, strings
            FROM zero_day_functions
            WHERE run_id=? AND stage_status='pending' AND prefiltered=1
            ORDER BY {order_sql} LIMIT ?""",
        (args.run_id, args.limit),
    ).fetchall()

    if not pending:
        print(f"[prepare] no pending prefiltered rows for run {args.run_id}")
        return 0

    # Mark as drafting
    ids = [r["id"] for r in pending]
    for i in range(0, len(ids), 500):
        chunk = ids[i:i+500]
        conn.execute(
            f"UPDATE zero_day_functions SET stage_status='drafting' WHERE id IN ({','.join('?'*len(chunk))})",
            chunk,
        )
    conn.commit()

    exclude = _parse_exclude_pks(getattr(args, "exclude_card_pk", None))
    if exclude:
        print(f"[prepare] excluding {len(exclude)} card pk(s) from context: {sorted(exclude)}")
    batch_filter = getattr(args, "batch_filter", None)
    if batch_filter:
        print(f"[prepare] batch filter: only cards with created_in_batch='{batch_filter}'")
    cards = _active_cards_context(conn, exclude_pks=exclude, batch_filter=batch_filter)
    print(f"[prepare] cards in Agent context: {len(cards)}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run": {
            "run_id": run["id"], "name": run["name"],
            "vendor": run["target_vendor"], "model": run["target_model"],
            "version": run["target_version"], "binary": run["target_binary"],
        },
        "active_pattern_cards": cards,
        "functions": [
            {
                "zdf_id": r["id"], "function_addr": r["addr"],
                "function_name": r["name"], "size": r["size"],
                "pseudocode": r["pseudocode"] or "",
                "disasm": (r["disasm"] or "")[:4000],
                "calls": json.loads(r["calls"] or "[]"),
                "strings": json.loads(r["strings"] or "[]"),
            } for r in pending
        ],
    }
    out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"[prepare] wrote {len(pending)} functions -> {out}")
    print(f"[prepare] marked {len(ids)} rows as stage_status='drafting'")
    return 0


def cmd_split(args: argparse.Namespace) -> int:
    src = Path(args.input)
    payload = json.loads(src.read_text(encoding="utf-8"))
    funcs = payload["functions"]

    # LPT greedy by size
    shards = [[] for _ in range(args.shards)]
    shard_size = [0] * args.shards
    for fn in sorted(funcs, key=lambda x: -len(x.get("pseudocode") or "")):
        idx = shard_size.index(min(shard_size))
        shards[idx].append(fn)
        shard_size[idx] += len(fn.get("pseudocode") or "") + 1

    base = src.with_suffix("")  # strip .json
    for i, shard in enumerate(shards, 1):
        if not shard:
            continue
        out_path = Path(f"{base}_a{i}.json")
        out = {**payload, "functions": shard, "analyst_id": f"A{i}"}
        out_path.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
        print(f"  [A{i}] {out_path.name}: {len(shard)} funcs ({shard_size[i-1]//1024}KB)")

    print("\nexpected Drafter outputs (same prefix + _aN_out.json):")
    for i in range(1, args.shards + 1):
        print(f"  {base}_a{i}_out.json")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    c = conn.cursor()

    run = c.execute("SELECT * FROM zero_day_runs WHERE id=?", (args.run_id,)).fetchone()
    if not run:
        print(f"[apply] run {args.run_id} not found", file=sys.stderr)
        return 1

    total_insert = 0
    vuln_insert = 0

    for path_str in args.output_jsons:
        path = Path(path_str)
        if not path.exists():
            print(f"[apply] skip missing: {path}")
            continue
        items = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(items, dict) and "verdicts" in items:
            items = items["verdicts"]
        if not isinstance(items, list):
            print(f"[apply] {path}: not a list")
            continue

        for v in items:
            zdf_id = v.get("zdf_id")
            fn_addr = v.get("function_addr")
            fn_name = v.get("function_name")

            c.execute("""
                INSERT INTO zero_day_verdicts (
                    run_id, function_id, function_addr, function_name,
                    is_vulnerable, confidence, vuln_type, severity_hint,
                    source_type, sink_type, missing_check,
                    matched_card_pk, matched_score,
                    root_cause, attack_scenario, agent_id,
                    raw_reasoning, needs_human_review, source_batch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                args.run_id,
                zdf_id,
                fn_addr or "",
                fn_name or "",
                1 if v.get("is_vulnerable") else 0,
                float(v.get("confidence") or 0.0),
                v.get("vuln_type"),
                v.get("severity_hint"),
                v.get("source_type"),
                v.get("sink_type"),
                v.get("missing_check"),
                v.get("matched_card_pk"),
                v.get("matched_score"),
                v.get("root_cause"),
                v.get("attack_scenario"),
                v.get("agent_id"),
                v.get("raw_reasoning"),
                1 if v.get("needs_human_review") else 0,
                getattr(args, "batch", None),
            ))
            total_insert += 1
            if v.get("is_vulnerable"):
                vuln_insert += 1

            if zdf_id:
                c.execute(
                    "UPDATE zero_day_functions SET stage_status='done' WHERE id=? AND run_id=?",
                    (zdf_id, args.run_id),
                )

        print(f"[apply] {path.name}: {len(items)} verdicts")

    # Refresh run counters
    c.execute(
        """UPDATE zero_day_runs SET
             processed_functions = (SELECT COUNT(*) FROM zero_day_functions WHERE run_id=? AND stage_status='done'),
             vuln_candidates     = (SELECT COUNT(*) FROM zero_day_verdicts  WHERE run_id=? AND is_vulnerable=1),
             updated_at = CURRENT_TIMESTAMP,
             status     = CASE WHEN status='pending' THEN 'running' ELSE status END
           WHERE id=?""",
        (args.run_id, args.run_id, args.run_id),
    )
    conn.commit()

    print(f"\n[apply] total verdicts inserted: {total_insert} (vuln={vuln_insert})")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    c = conn.cursor()
    run = c.execute("SELECT * FROM zero_day_runs WHERE id=?", (args.run_id,)).fetchone()
    if not run:
        print(f"[status] run {args.run_id} not found", file=sys.stderr)
        return 1

    print(f"=== run {run['id']}: {run['name']} ===")
    print(f"  target:      {run['target_vendor']}/{run['target_model']} v{run['target_version']} ({run['target_binary']})")
    print(f"  source:      {run['source_json_path']}")
    print(f"  status:      {run['status']}")
    print(f"  started_at:  {run['started_at']}")
    print(f"  updated_at:  {run['updated_at']}")
    print()
    print(f"  total functions:       {run['total_functions']}")
    print(f"  prefiltered_in:        {run['prefiltered_functions']}")
    print(f"  processed_functions:   {run['processed_functions']}")
    print(f"  vuln_candidates:       {run['vuln_candidates']}")

    # Drilldown
    rows = c.execute("""
        SELECT stage_status, COUNT(*) FROM zero_day_functions
        WHERE run_id=? GROUP BY stage_status
    """, (args.run_id,)).fetchall()
    print("\n  stage_status:")
    for r in rows:
        print(f"    {r[0]}: {r[1]}")

    # Verdict distribution
    print("\n  verdicts by severity:")
    for r in c.execute("""
        SELECT severity_hint, COUNT(*) FROM zero_day_verdicts
        WHERE run_id=? AND is_vulnerable=1
        GROUP BY severity_hint ORDER BY COUNT(*) DESC
    """, (args.run_id,)):
        print(f"    {r[0] or 'unset'}: {r[1]}")

    # Top vuln verdicts
    print("\n  top 10 vuln verdicts (by confidence):")
    for r in c.execute("""
        SELECT function_addr, function_name, confidence, severity_hint, matched_card_pk, vuln_type
        FROM zero_day_verdicts
        WHERE run_id=? AND is_vulnerable=1
        ORDER BY confidence DESC LIMIT 10
    """, (args.run_id,)):
        pk_str = f"P-#{r[4]}" if r[4] else "novel"
        print(f"    conf={r[2]:.2f} {r[3] or '-':<7} {pk_str:<8} {r[0]:<12} {r[1] or '':<20} :: {(r[5] or '')[:60]}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    conn = open_db(args.db)
    c = conn.cursor()
    rows = c.execute("""
        SELECT id, name, target_vendor, target_model, target_version,
               total_functions, prefiltered_functions, processed_functions,
               vuln_candidates, status, started_at
        FROM zero_day_runs ORDER BY id DESC
    """).fetchall()
    if not rows:
        print("[list] no runs yet")
        return 0
    print(f"{'id':>3} {'status':<10} {'total':>6} {'prefilt':>7} {'done':>6} {'vuln':>5} {'vendor/model':<32} name")
    for r in rows:
        tgt = f"{r['target_vendor']}/{r['target_model']} v{r['target_version']}"
        print(f"{r['id']:>3} {r['status']:<10} {r['total_functions']:>6} {r['prefiltered_functions']:>7} "
              f"{r['processed_functions']:>6} {r['vuln_candidates']:>5} {tgt:<32} {r['name']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("migrate")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("init")
    p.add_argument("--name", required=True)
    p.add_argument("--binary", required=True)
    p.add_argument("--funcs-json", required=True)
    p.add_argument("--vendor", default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--version", default=None)
    p.add_argument("--notes", default=None)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("prefilter")
    p.add_argument("run_id", type=int)
    p.set_defaults(func=cmd_prefilter)

    p = sub.add_parser("prepare")
    p.add_argument("run_id", type=int)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--out", required=True)
    p.add_argument("--exclude-card-pk", default=None,
                   help="comma-separated pattern_cards.id to hide from Agent context (blind validation)")
    p.add_argument("--order", choices=["id", "size_desc", "size_asc"], default="id",
                   help="order of functions picked for this batch")
    p.add_argument("--batch-filter", default=None,
                   help="Agent context 에 올릴 카드를 pattern_cards.created_in_batch=<value> 로 제한. Delta hunt 용 (이번 주 netnew 카드만 쏘기).")
    p.set_defaults(func=cmd_prepare)

    p = sub.add_parser("split")
    p.add_argument("input")
    p.add_argument("--shards", type=int, default=4)
    p.set_defaults(func=cmd_split)

    p = sub.add_parser("apply")
    p.add_argument("run_id", type=int)
    p.add_argument("output_jsons", nargs="+")
    p.add_argument("--batch", default=None, help="zero_day_verdicts.source_batch 에 기록할 태그 (예: 'v2-netnew'). 어떤 카드셋으로 Agent 가 판정했는지 추적용.")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("status")
    p.add_argument("run_id", type=int)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("cards-context")
    p.add_argument("--out", default=None)
    p.add_argument("--exclude-card-pk", default=None)
    p.set_defaults(func=cmd_cards_context)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
