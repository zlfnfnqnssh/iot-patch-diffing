"""Build a custom zero-day batch file from explicit addresses.

Useful for focused validation tests (e.g., include known-CVE target functions
alongside some decoys).

Usage:
    python src/stage2/zero_day_prepare_addrs.py <run_id> \\
        --addrs 0x10e537c,0x417b2c,0x4132dc \\
        --extras 20 \\
        --exclude-card-pk 74 \\
        --out tmp/zd/in_r1_focus.json
"""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = PROJECT_ROOT / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"

# reuse helper from main orchestrator
from zero_day_run import _active_cards_context, _parse_exclude_pks  # type: ignore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id", type=int)
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--addrs", required=True, help="comma-separated addresses (0xHEX)")
    ap.add_argument("--extras", type=int, default=0,
                    help="also grab N random prefiltered_in decoys by size_desc for context")
    ap.add_argument("--exclude-card-pk", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    wanted = {a.strip().lower() for a in args.addrs.split(",") if a.strip()}
    conn = sqlite3.connect(str(args.db))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    run = c.execute("SELECT * FROM zero_day_runs WHERE id=?", (args.run_id,)).fetchone()
    if not run:
        print(f"run {args.run_id} not found"); return 1

    picked: list[dict] = []
    for addr in wanted:
        r = c.execute(
            "SELECT id, addr, name, size, pseudocode, disasm, calls, strings FROM zero_day_functions WHERE run_id=? AND LOWER(addr)=?",
            (args.run_id, addr),
        ).fetchone()
        if not r:
            print(f"  [miss] {addr}")
            continue
        picked.append(dict(r))

    if args.extras > 0:
        existing_ids = {f["id"] for f in picked}
        extras_rows = c.execute(
            """SELECT id, addr, name, size, pseudocode, disasm, calls, strings
               FROM zero_day_functions
               WHERE run_id=? AND prefiltered=1 AND stage_status='pending'
               ORDER BY LENGTH(pseudocode) DESC LIMIT ?""",
            (args.run_id, args.extras + len(existing_ids)),
        ).fetchall()
        for r in extras_rows:
            if r["id"] in existing_ids:
                continue
            picked.append(dict(r))
            if len(picked) >= len(wanted) + args.extras:
                break

    # Mark drafting
    ids = [f["id"] for f in picked]
    for i in range(0, len(ids), 500):
        chunk = ids[i:i+500]
        conn.execute(
            f"UPDATE zero_day_functions SET stage_status='drafting' WHERE id IN ({','.join('?'*len(chunk))})",
            chunk,
        )
    conn.commit()

    exclude = _parse_exclude_pks(args.exclude_card_pk)
    cards = _active_cards_context(conn, exclude_pks=exclude)

    payload = {
        "run": {
            "run_id": run["id"], "name": run["name"],
            "vendor": run["target_vendor"], "model": run["target_model"],
            "version": run["target_version"], "binary": run["target_binary"],
        },
        "active_pattern_cards": cards,
        "functions": [
            {
                "zdf_id": f["id"], "function_addr": f["addr"],
                "function_name": f["name"], "size": f["size"],
                "pseudocode": f["pseudocode"] or "",
                "disasm": (f["disasm"] or "")[:4000],
                "calls": json.loads(f["calls"] or "[]"),
                "strings": json.loads(f["strings"] or "[]"),
            } for f in picked
        ],
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"[prepare-addrs] wrote {len(picked)} funcs -> {out}")
    print(f"[prepare-addrs] cards in context: {len(cards)} (excluded: {sorted(exclude)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
