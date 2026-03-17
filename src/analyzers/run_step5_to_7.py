"""
Step 5~7 테스트 스크립트.

이미 생성된 함수 JSON + BinExport 파일을 사용하여
BinDiff → Pseudocode Diff → 요약 리포트를 실행한다.

Usage:
    python src/analyzers/run_step5_to_7.py
"""

import json
import sqlite3
import subprocess
import sys
import difflib
from pathlib import Path

# ── 경로 설정 ─────────────────────────────────────────────────────
BINDIFF_PATH = Path(r"C:\Program Files\BinDiff\bin\bindiff.exe")
BASE = Path(r"c:/Users/deser/Desktop/project/Patch-Learner-main/firmware/ubiquiti_s2/diffs/UVC_vs_uvc")

FUNCTIONS_DIR = BASE / "functions"
BINEXPORT_DIR = BASE / "binexport"
BINDIFF_DIR = BASE / "bindiff"
FUNC_DIFF_DIR = BASE / "function_diffs"


# =====================================================================
#  Step 5: BinDiff
# =====================================================================

def run_bindiff(old_be: Path, new_be: Path, output_dir: Path) -> Path | None:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(BINDIFF_PATH),
        "--primary", str(old_be),
        "--secondary", str(new_be),
        "--output_dir", str(output_dir),
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"    [TIMEOUT] BinDiff")
        return None

    for f in output_dir.iterdir():
        if f.suffix == ".BinDiff" and f.stat().st_size > 0:
            return f
    return None


def parse_bindiff_results(bindiff_db: Path) -> dict:
    conn = sqlite3.connect(str(bindiff_db))
    cur = conn.cursor()

    cur.execute("""SELECT name1, address1, name2, address2,
                          similarity, confidence, basicblocks, instructions, edges
                   FROM function WHERE similarity < 1.0
                   ORDER BY similarity ASC""")
    changed = []
    for r in cur.fetchall():
        changed.append({
            "name_old": r[0], "addr_old": hex(r[1]),
            "name_new": r[2], "addr_new": hex(r[3]),
            "similarity": round(r[4], 4), "confidence": round(r[5], 4),
            "basicblocks": r[6], "instructions": r[7], "edges": r[8],
        })

    cur.execute("SELECT COUNT(*) FROM function")
    total_matched = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM function WHERE similarity = 1.0")
    identical = cur.fetchone()[0]
    cur.execute("SELECT similarity, confidence FROM metadata")
    meta = cur.fetchone()
    conn.close()

    return {
        "changed_functions": changed,
        "total_matched": total_matched,
        "identical": identical,
        "changed_count": len(changed),
        "overall_similarity": round(meta[0], 4) if meta else 0,
        "overall_confidence": round(meta[1], 4) if meta else 0,
    }


# =====================================================================
#  Step 6: Pseudocode Diff
# =====================================================================

def _safe_filename(name: str) -> str:
    for ch in r'<>:"/\|?* ':
        name = name.replace(ch, "_")
    return name[:200]


def generate_function_diffs(binary_name, old_fj, new_fj, bindiff_result, output_dir):
    with open(old_fj, "r", encoding="utf-8") as f:
        old_data = json.load(f)
    with open(new_fj, "r", encoding="utf-8") as f:
        new_data = json.load(f)

    old_funcs = old_data.get("functions", {})
    new_funcs = new_data.get("functions", {})
    has_pseudo = old_data.get("has_pseudocode", False) and new_data.get("has_pseudocode", False)

    diff_dir = output_dir / binary_name
    diff_dir.mkdir(parents=True, exist_ok=True)

    changed_functions = bindiff_result.get("changed_functions", [])
    diff_results = []
    skipped_plt = 0

    for fn in changed_functions:
        name_old = fn["name_old"]
        name_new = fn["name_new"]
        similarity = fn["similarity"]
        insn_count = fn.get("instructions", 0)

        if insn_count <= 3:
            skipped_plt += 1
            continue

        old_func = old_funcs.get(name_old)
        new_func = new_funcs.get(name_new)
        if not old_func or not new_func:
            continue

        if has_pseudo and old_func.get("pseudocode") and new_func.get("pseudocode"):
            old_code = old_func["pseudocode"]
            new_code = new_func["pseudocode"]
            code_type = "pseudocode"
        else:
            old_code = old_func.get("disasm", "")
            new_code = new_func.get("disasm", "")
            code_type = "disasm"

        if not old_code or not new_code:
            continue

        diff_lines = list(difflib.unified_diff(
            old_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True),
            fromfile=f"old/{name_old}", tofile=f"new/{name_new}",
        ))
        if not diff_lines:
            continue

        safe_name = _safe_filename(name_old)
        ext = ".c.diff" if code_type == "pseudocode" else ".asm.diff"
        (diff_dir / f"{safe_name}{ext}").write_text("".join(diff_lines), encoding="utf-8")

        code_ext = ".c" if code_type == "pseudocode" else ".asm"
        (diff_dir / f"{safe_name}_old{code_ext}").write_text(old_code, encoding="utf-8")
        (diff_dir / f"{safe_name}_new{code_ext}").write_text(new_code, encoding="utf-8")

        added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))

        diff_results.append({
            "name_old": name_old, "name_new": name_new,
            "similarity": similarity, "code_type": code_type,
            "lines_added": added, "lines_removed": removed,
            "diff_file": f"{safe_name}{ext}",
        })

    return {
        "binary": binary_name,
        "total_changed": len(changed_functions),
        "diffs_generated": len(diff_results),
        "skipped_plt": skipped_plt,
        "has_pseudocode": has_pseudo,
        "functions": diff_results,
    }


# =====================================================================
#  Step 7: Summary
# =====================================================================

def write_summary(all_results, all_diff_stats):
    md = BASE / "summary_step5to7.md"
    lines = ["# Step 5~7 결과 요약\n"]

    lines.append(f"\n## BinDiff 함수 비교 결과 ({len(all_results)}개 바이너리)")
    for name, result in sorted(all_results.items(), key=lambda x: -x[1]["changed_count"]):
        funcs = result["changed_functions"]
        sim = result["overall_similarity"]
        lines.append(f"\n### {name} — {sim*100:.1f}% similar ({len(funcs)} changed)")
        if funcs:
            lines.append("| Function (old) | Function (new) | Similarity | Instrs |")
            lines.append("|----------------|----------------|-----------|--------|")
            for fn in funcs[:20]:
                lines.append(f"| {fn['name_old']} | {fn['name_new']} | {fn['similarity']:.4f} | {fn['instructions']} |")
            if len(funcs) > 20:
                lines.append(f"| ... | ... | {len(funcs)-20} more | |")

    lines.append(f"\n## Pseudocode Diff 결과")
    total_diffs = 0
    for name, ds in sorted(all_diff_stats.items(), key=lambda x: -x[1]["diffs_generated"]):
        n = ds["diffs_generated"]
        total_diffs += n
        code_type = "pseudocode" if ds["has_pseudocode"] else "disasm"
        lines.append(f"- **{name}** ({code_type}): {n}개 diff, PLT 스킵 {ds['skipped_plt']}개")

    lines.append(f"\n**총 {total_diffs}개 함수 diff 생성 완료**")

    md.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[DONE] {md}")


# =====================================================================
#  Main
# =====================================================================

def find_ready_binaries():
    """old+new JSON과 BinExport가 모두 있는 바이너리 찾기."""
    ready = []
    for f in sorted(FUNCTIONS_DIR.glob("*_old.json")):
        name = f.name.replace("_old.json", "")
        new_json = FUNCTIONS_DIR / f"{name}_new.json"
        old_be = BINEXPORT_DIR / f"{name}_old.BinExport"
        new_be = BINEXPORT_DIR / f"{name}_new.BinExport"
        if new_json.exists() and old_be.exists() and new_be.exists():
            ready.append(name)
    return ready


def main():
    if not BINDIFF_PATH.exists():
        print(f"[ERROR] BinDiff not found: {BINDIFF_PATH}")
        sys.exit(1)

    binaries = find_ready_binaries()
    print(f"준비된 바이너리: {len(binaries)}개\n")

    # 이전 결과 정리
    import shutil
    for d in [BINDIFF_DIR, FUNC_DIFF_DIR]:
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    # ── Step 5: BinDiff ──────────────────────────────────────────
    print("=" * 60)
    print("[Step 5] BinDiff 함수 매칭")
    print("=" * 60)

    all_results = {}
    for i, name in enumerate(binaries, 1):
        old_be = BINEXPORT_DIR / f"{name}_old.BinExport"
        new_be = BINEXPORT_DIR / f"{name}_new.BinExport"
        bd_out = BINDIFF_DIR / name

        bd_file = run_bindiff(old_be, new_be, bd_out)
        if bd_file:
            result = parse_bindiff_results(bd_file)
            all_results[name] = result
            print(f"  [{i}/{len(binaries)}] {name}: "
                  f"{result['overall_similarity']*100:.1f}% sim, "
                  f"{result['changed_count']} changed")
        else:
            print(f"  [{i}/{len(binaries)}] {name}: BinDiff 실패")

    results_json = BASE / "diff_results.json"
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\n  → {results_json}")

    # ── Step 6: Pseudocode Diff ──────────────────────────────────
    print("\n" + "=" * 60)
    print("[Step 6] Pseudocode Diff 생성")
    print("=" * 60)

    all_diff_stats = {}
    for i, name in enumerate(binaries, 1):
        if name not in all_results:
            continue
        old_fj = FUNCTIONS_DIR / f"{name}_old.json"
        new_fj = FUNCTIONS_DIR / f"{name}_new.json"

        ds = generate_function_diffs(name, old_fj, new_fj, all_results[name], FUNC_DIFF_DIR)
        all_diff_stats[name] = ds
        if ds["diffs_generated"] > 0:
            print(f"  [{i}/{len(binaries)}] {name}: "
                  f"{ds['diffs_generated']}개 diff (PLT 스킵: {ds['skipped_plt']})")

    diff_stats_json = BASE / "function_diff_stats.json"
    with open(diff_stats_json, "w", encoding="utf-8") as f:
        json.dump(all_diff_stats, f, indent=2, ensure_ascii=False)

    # ── Step 7: 요약 ────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("[Step 7] 요약 리포트")
    print("=" * 60)

    write_summary(all_results, all_diff_stats)

    # 최종 통계
    total_changed = sum(r["changed_count"] for r in all_results.values())
    total_diffs = sum(ds["diffs_generated"] for ds in all_diff_stats.values())
    binaries_with_changes = sum(1 for r in all_results.values() if r["changed_count"] > 0)

    print(f"\n{'='*60}")
    print(f"  분석 바이너리: {len(all_results)}개")
    print(f"  변경 있는 바이너리: {binaries_with_changes}개")
    print(f"  총 변경 함수: {total_changed}개")
    print(f"  생성된 diff: {total_diffs}개")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
