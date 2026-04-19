"""Export all pattern_cards (with all side tables merged) as a single JSONL.

One line = one pattern_card, fully self-contained:
  - core pattern_cards row
  - tokens[]
  - negative_tokens[]
  - grep_patterns[]
  - stats (pattern_card_stats 1-row merged)
  - members[] (security_patch references + binary/function context)

Usage:
    python src/stage2/export_pattern_cards_jsonl.py
    python src/stage2/export_pattern_cards_jsonl.py --out D:/.../pattern_cards.jsonl
    python src/stage2/export_pattern_cards_jsonl.py --include-inactive
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
DEFAULT_OUT = Path(__file__).resolve().parents[2] / "pattern_cards.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--include-inactive", action="store_true",
                    help="also export status != 'active' cards")
    args = ap.parse_args()

    conn = sqlite3.connect(str(args.db))
    conn.row_factory = sqlite3.Row

    where = "" if args.include_inactive else "WHERE status = 'active'"
    cards = list(conn.execute(f"SELECT * FROM pattern_cards {where} ORDER BY id").fetchall())

    # Bulk fetch side tables
    tokens_by_pk: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT card_id, token, kind, weight FROM pattern_card_tokens"):
        tokens_by_pk.setdefault(r[0], []).append({
            "token": r[1], "kind": r[2], "weight": r[3],
        })

    neg_by_pk: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT card_id, token, vendor_scope, note FROM pattern_card_negative_tokens"):
        neg_by_pk.setdefault(r[0], []).append({
            "token": r[1], "vendor_scope": r[2], "note": r[3],
        })

    grep_by_pk: dict[int, list[dict]] = {}
    try:
        for r in conn.execute("SELECT card_id, pattern, note FROM pattern_card_grep_patterns"):
            grep_by_pk.setdefault(r[0], []).append({
                "pattern": r[1], "note": r[2],
            })
    except sqlite3.OperationalError:
        pass

    stats_by_pk: dict[int, dict] = {}
    try:
        for r in conn.execute("SELECT * FROM pattern_card_stats"):
            stats_by_pk[r["card_id"]] = {k: r[k] for k in r.keys() if k != "card_id"}
    except sqlite3.OperationalError:
        pass

    members_by_pk: dict[int, list[dict]] = {}
    for r in conn.execute("""
        SELECT pcm.card_id, pcm.security_patch_id, pcm.is_representative, pcm.note,
               sp.confidence, sp.vuln_type, sp.severity, sp.known_cve,
               sp.source_desc, sp.sink_desc, sp.missing_check, sp.root_cause,
               cf.binary_name, cf.function_name, cf.old_address, cf.new_address,
               cf.similarity,
               fo.vendor, fo.model, fo.version AS old_version, fn.version AS new_version,
               ds.id AS session_id
        FROM pattern_card_members pcm
        JOIN security_patches sp ON pcm.security_patch_id = sp.id
        JOIN changed_functions cf ON sp.changed_function_id = cf.id
        JOIN bindiff_results br ON cf.bindiff_result_id = br.id
        JOIN changed_files chf ON br.changed_file_id = chf.id
        JOIN diff_sessions ds ON chf.diff_session_id = ds.id
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        JOIN firmware_versions fn ON ds.new_version_id = fn.id
        ORDER BY pcm.card_id, pcm.id
    """):
        members_by_pk.setdefault(r["card_id"], []).append({
            "security_patch_id": r["security_patch_id"],
            "is_representative": bool(r["is_representative"]),
            "note": r["note"],
            "confidence": r["confidence"],
            "vuln_type": r["vuln_type"],
            "severity": r["severity"],
            "known_cve": r["known_cve"],
            "source_desc": r["source_desc"],
            "sink_desc": r["sink_desc"],
            "missing_check": r["missing_check"],
            "root_cause": r["root_cause"],
            "session_id": r["session_id"],
            "vendor": r["vendor"],
            "model": r["model"],
            "old_version": r["old_version"],
            "new_version": r["new_version"],
            "binary_name": r["binary_name"],
            "function_name": r["function_name"],
            "old_address": r["old_address"],
            "new_address": r["new_address"],
            "similarity": r["similarity"],
        })

    args.out.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with args.out.open("w", encoding="utf-8", newline="\n") as f:
        for card in cards:
            pk = card["id"]
            d = {k: card[k] for k in card.keys()}
            d["tokens"] = tokens_by_pk.get(pk, [])
            d["negative_tokens"] = neg_by_pk.get(pk, [])
            d["grep_patterns"] = grep_by_pk.get(pk, [])
            d["stats"] = stats_by_pk.get(pk)
            d["members"] = members_by_pk.get(pk, [])
            d["member_count"] = len(d["members"])
            f.write(json.dumps(d, ensure_ascii=False, default=str) + "\n")
            written += 1

    print(f"[export] wrote {written} cards -> {args.out}")
    # Summary by severity
    from collections import Counter
    sev = Counter(c["severity_hint"] or "unset" for c in cards)
    print(f"[export] severity breakdown: {dict(sev)}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
