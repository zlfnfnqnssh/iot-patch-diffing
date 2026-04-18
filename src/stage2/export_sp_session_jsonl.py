"""Export security_patches joined with session + pattern_card_members as JSONL.

Used by the team leader to wire pattern_card_members across collaborators.

Each line = one security_patch row with:
  - session/firmware context
  - binary/function context
  - Drafter verdict fields
  - pattern_card_members[] that link this patch to one or more pattern_cards

Output: data/handoff/security_patches_session.jsonl

Usage:
    python src/stage2/export_sp_session_jsonl.py
    python src/stage2/export_sp_session_jsonl.py --out path.jsonl --only-security
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
DEFAULT_OUT = Path(__file__).resolve().parents[2] / "data" / "handoff" / "security_patches_session.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--only-security", action="store_true",
                    help="export only rows where is_security_patch=1")
    ap.add_argument("--include-analysis-raw", action="store_true",
                    help="include large analysis_raw column (default off for size)")
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(args.db))
    conn.row_factory = sqlite3.Row

    where = "WHERE sp.is_security_patch = 1" if args.only_security else ""

    rows = conn.execute(f"""
        SELECT
            ds.id                 AS session_id,
            fo.vendor, fo.model,
            fo.version            AS old_version,
            fn.version            AS new_version,
            cf.id                 AS changed_function_id,
            cf.binary_name,
            cf.function_name,
            cf.old_address, cf.new_address,
            cf.similarity, cf.instructions, cf.basic_blocks,
            sp.id                 AS security_patch_id,
            sp.is_security_patch, sp.confidence,
            sp.vuln_type, sp.cwe, sp.severity,
            sp.fix_category, sp.fix_description,
            sp.attack_vector, sp.requires_auth, sp.attack_surface,
            sp.source_desc, sp.sink_desc, sp.missing_check,
            sp.root_cause,
            sp.huntable, sp.hunt_strategy,
            sp.known_cve, sp.advisory,
            sp.llm_model, sp.llm_prompt_ver,
            sp.analyst_id, sp.pattern_card_id, sp.needs_human_review,
            sp.analysis_raw,
            sp.created_at AS sp_created_at
        FROM security_patches sp
        JOIN changed_functions cf ON sp.changed_function_id = cf.id
        JOIN bindiff_results br   ON cf.bindiff_result_id = br.id
        JOIN changed_files chf    ON br.changed_file_id = chf.id
        JOIN diff_sessions ds     ON chf.diff_session_id = ds.id
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        JOIN firmware_versions fn ON ds.new_version_id = fn.id
        {where}
        ORDER BY ds.id, sp.id
    """).fetchall()

    # Bulk fetch card_members
    members_by_sp: dict[int, list[dict]] = {}
    for r in conn.execute("""
        SELECT pcm.security_patch_id, pcm.is_representative, pcm.note,
               pc.id AS card_pk, pc.card_id, pc.source_type, pc.sink_type,
               pc.missing_check, pc.severity_hint, pc.cve_similar, pc.summary
        FROM pattern_card_members pcm
        JOIN pattern_cards pc ON pcm.card_id = pc.id
        WHERE pc.status = 'active'
    """):
        members_by_sp.setdefault(r[0], []).append({
            "card_pk": r[3],
            "card_id": r[4],
            "formula": [r[5], r[6], r[7]],
            "severity_hint": r[8],
            "cve_similar": r[9],
            "is_representative": bool(r[1]),
            "note": r[2],
            "summary": (r[10] or "")[:240],
        })

    written = 0
    with args.out.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            d = dict(r)
            if not args.include_analysis_raw:
                d.pop("analysis_raw", None)
            sp_id = d["security_patch_id"]
            d["pattern_card_memberships"] = members_by_sp.get(sp_id, [])
            # Also surface direct pattern_card_id if present (Drafter-assigned) resolved
            if d.get("pattern_card_id"):
                direct = conn.execute(
                    "SELECT card_id, source_type, sink_type, missing_check, severity_hint FROM pattern_cards WHERE id = ?",
                    (d["pattern_card_id"],),
                ).fetchone()
                if direct:
                    d["direct_card"] = {
                        "card_pk": d["pattern_card_id"],
                        "card_id": direct[0],
                        "formula": [direct[1], direct[2], direct[3]],
                        "severity_hint": direct[4],
                    }
            f.write(json.dumps(d, ensure_ascii=False, default=str) + "\n")
            written += 1

    print(f"[export] wrote {written} rows -> {args.out}")

    # Quick breakdown
    sec = sum(1 for r in rows if r["is_security_patch"])
    print(f"[export] is_security_patch=1: {sec} / total: {len(rows)}")
    print(f"[export] sessions covered: {len({r['session_id'] for r in rows})}")

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
