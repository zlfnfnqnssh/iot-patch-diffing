"""Register sonia BinDiff result into patch_learner.db

Steps:
1. Insert changed_files row (bin/sonia) under diff_session 74 (Kant v2.860.0.31 -> v2.860.0.34)
2. Insert bindiff_results row
3. Insert changed_functions rows (one per sim<1.0 pair) with decompiled_old/new filled from selected JSON
4. Set stage2_status=pending so prefilter can pick up

Usage:
    python src/stage2/register_sonia.py
"""
from __future__ import annotations
import json
import sqlite3
import sys
from pathlib import Path

DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
SESSION_ID = 74   # Kant v2.860.0.31 -> v2.860.0.34
BINARY_REL_PATH = "bin/sonia"
BINDIFF_FILE = Path("output/dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN/v2.860.0.31_vs_v2.860.0.34/bindiff/sonia/sonia_old_vs_sonia_new.BinDiff")
OLD_DECOMP_JSON = Path("tmp/sonia_test/funcs_out/sonia_old_selected.json")
NEW_DECOMP_JSON = Path("tmp/sonia_test/funcs_out/sonia_new_selected.json")


def norm_hex(a):
    if isinstance(a, int):
        return hex(a)
    if isinstance(a, str):
        return hex(int(a, 16)) if a.startswith("0x") else a
    return str(a)


def main():
    conn = sqlite3.connect(str(DB))
    c = conn.cursor()

    # ── Ensure session exists
    r = c.execute("SELECT id FROM diff_sessions WHERE id=?", (SESSION_ID,)).fetchone()
    if not r:
        print(f"[error] diff_sessions id={SESSION_ID} not found", file=sys.stderr)
        return 1

    # ── Upsert changed_files bin/sonia
    r = c.execute(
        "SELECT id FROM changed_files WHERE diff_session_id=? AND file_path=?",
        (SESSION_ID, BINARY_REL_PATH),
    ).fetchone()
    if r:
        cf_id = r[0]
        print(f"[reuse] changed_files id={cf_id}")
    else:
        c.execute(
            "INSERT INTO changed_files (diff_session_id, file_path, file_type, change_type) VALUES (?,?,?,?)",
            (SESSION_ID, BINARY_REL_PATH, "binary", "modified"),
        )
        cf_id = c.lastrowid
        print(f"[ins] changed_files id={cf_id}")

    # ── Read BinDiff result
    bd = sqlite3.connect(str(BINDIFF_FILE))
    bdc = bd.cursor()
    pairs = bdc.execute(
        "SELECT name1, address1, name2, address2, similarity, confidence, basicblocks, instructions FROM function WHERE similarity < 1.0 AND instructions >= 10 ORDER BY address1"
    ).fetchall()
    total_funcs = bdc.execute("SELECT COUNT(*) FROM function").fetchone()[0]
    identical = bdc.execute("SELECT COUNT(*) FROM function WHERE similarity=1.0").fetchone()[0]
    bd.close()

    overall_sim = identical / total_funcs if total_funcs else 0.0

    # ── Upsert bindiff_results
    r = c.execute("SELECT id FROM bindiff_results WHERE changed_file_id=?", (cf_id,)).fetchone()
    if r:
        br_id = r[0]
        print(f"[reuse] bindiff_results id={br_id}")
    else:
        c.execute(
            """INSERT INTO bindiff_results (changed_file_id, bindiff_path, total_functions, matched_functions, changed_functions, added_functions, removed_functions, overall_similarity) VALUES (?,?,?,?,?,?,?,?)""",
            (cf_id, str(BINDIFF_FILE), total_funcs, total_funcs - identical, len(pairs), 0, 0, overall_sim),
        )
        br_id = c.lastrowid
        print(f"[ins] bindiff_results id={br_id}")

    # ── Load decompiled JSONs
    old_j = json.loads(Path(OLD_DECOMP_JSON).read_text(encoding="utf-8"))
    new_j = json.loads(Path(NEW_DECOMP_JSON).read_text(encoding="utf-8"))
    old_funcs = old_j.get("functions", {})
    new_funcs = new_j.get("functions", {})
    print(f"[load] old funcs={len(old_funcs)} new funcs={len(new_funcs)}")

    # ── Insert changed_functions
    existed = c.execute("SELECT COUNT(*) FROM changed_functions WHERE bindiff_result_id=?", (br_id,)).fetchone()[0]
    if existed:
        print(f"[skip-ins] changed_functions already has {existed} rows for br_id={br_id}")
    else:
        ins = 0
        for name1, a1, name2, a2, sim, conf, bb, ins_count in pairs:
            k_old = norm_hex(a1)
            k_new = norm_hex(a2)
            o = old_funcs.get(k_old, {})
            n = new_funcs.get(k_new, {})
            decompiled_old = o.get("pseudocode", "") or o.get("disasm", "")
            decompiled_new = n.get("pseudocode", "") or n.get("disasm", "")

            c.execute(
                """INSERT INTO changed_functions (bindiff_result_id, binary_name, function_name, old_address, new_address, similarity, confidence, basic_blocks, instructions, decompiled_old, decompiled_new, stage2_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    br_id,
                    "sonia",
                    name2 or name1 or f"sub_{a2:X}",
                    k_old,
                    k_new,
                    float(sim),
                    float(conf),
                    int(bb),
                    int(ins_count),
                    decompiled_old,
                    decompiled_new,
                    "pending",
                ),
            )
            ins += 1
        print(f"[ins] changed_functions: {ins}")

    conn.commit()

    # Report
    n = c.execute("SELECT COUNT(*) FROM changed_functions WHERE bindiff_result_id=?", (br_id,)).fetchone()[0]
    pen = c.execute("SELECT COUNT(*) FROM changed_functions WHERE bindiff_result_id=? AND stage2_status='pending'", (br_id,)).fetchone()[0]
    print(f"[done] sonia: changed_functions={n}, pending={pen}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
