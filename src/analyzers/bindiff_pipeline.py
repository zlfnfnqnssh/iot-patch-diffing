"""
Patch-Learner Diff Pipeline — 통합 자동화 스크립트.

펌웨어 추출 → 해시 비교 → 텍스트 diff → 함수 추출(디컴파일+BinExport)
→ BinDiff → pseudocode diff → 분석 리포트

Usage:
    python bindiff_pipeline.py --old <file_or_dir> --new <file_or_dir>

    --output은 자동 결정:
      파일이 firmware/<vendor>/raw/ 안에 있으면 → firmware/<vendor>/diffs/<old>_vs_<new>/
      디렉토리이면 → <old의 부모>/diffs/<old>_vs_<new>/
      수동 지정도 가능: --output <dir>

Example:
    python bindiff_pipeline.py \
        --old firmware/ubiquiti_s2/raw/UVC.S2LM_4.30.0.bin \
        --new firmware/ubiquiti_s2/raw/uvc.s2lm.v4.51.4.67.bin
"""

import argparse
import difflib
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── 절대 경로 ────────────────────────────────────────────────────
IDA_PATH = Path(r"C:\Program Files\IDA Professional 9.0\idat64.exe")
BINDIFF_PATH = Path(r"C:\Program Files\BinDiff\bin\bindiff.exe")

# ── IDAPython 통합 추출 스크립트 ──────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
EXTRACT_SCRIPT = PROJECT_ROOT / "ida_user" / "extract_with_decompile.py"

# ── IDA 임시 파일 확장자 (해시 비교에서 제외) ─────────────────────
IDA_TEMP_EXTS = {".id0", ".id1", ".id2", ".id3", ".nam", ".til", ".idb", ".i64"}

# ── 노이즈 필터링: 타임존 경로 패턴 ──────────────────────────────
TIMEZONE_PATH_FRAGMENTS = {"zoneinfo/", "zoneinfo\\", "/posix/", "/right/"}


# =====================================================================
#  1. Synology .sa.bin 추출
# =====================================================================

def is_synology_firmware(path: Path) -> bool:
    """파일이 Synology .sa.bin 펌웨어인지 판별."""
    if not path.is_file():
        return False
    if not path.name.lower().endswith(".sa.bin"):
        return False
    try:
        with open(path, "rb") as f:
            f.seek(0x18)
            model = f.read(16).split(b"\x00")[0].decode("ascii", errors="ignore")
        return len(model) > 2 and model.isascii() and model[0].isalpha()
    except Exception:
        return False


def extract_synology(sa_bin: Path, out_dir: Path) -> Path:
    """Synology .sa.bin → rootfs 파일시스템 추출. 추출된 루트 경로 반환."""
    cache_marker = out_dir / ".extracted_ok"
    if cache_marker.exists():
        print(f"    [CACHE] {out_dir.name} 이미 추출됨, 스킵")
        return out_dir

    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"    [EXTRACT] {sa_bin.name} → {out_dir.name}")

    with open(sa_bin, "rb") as f:
        f.seek(0x08)
        fw_version = f.read(16).split(b"\x00")[0].decode("ascii", errors="ignore")
        f.seek(0x18)
        model = f.read(16).split(b"\x00")[0].decode("ascii", errors="ignore")
        print(f"      Model: {model}, Version: {fw_version}")

        f.seek(0x7C)
        num_partitions = struct.unpack("<H", f.read(2))[0]
        f.seek(0x80)
        prescript_len = struct.unpack("<I", f.read(4))[0]
        f.seek(prescript_len, 1)

        postscript_len = struct.unpack("<I", f.read(4))[0]
        f.seek(postscript_len, 1)

        partitions = []
        for i in range(num_partitions):
            part_header = f.read(0x40)
            name = part_header[:0x40].split(b"\x00")[0].decode("ascii", errors="ignore")
            sub_len = struct.unpack("<I", f.read(4))[0]
            img_len = struct.unpack("<I", f.read(4))[0]
            compressed_data = f.read(img_len)

            try:
                raw_data = zlib.decompress(compressed_data)
            except zlib.error:
                raw_data = compressed_data

            partitions.append({"name": name, "data": raw_data, "size": len(raw_data)})
            print(f"      Partition {i}: {name} ({len(raw_data):,} bytes)")

        rootfs = None
        for p in partitions:
            if "rootfs" in p["name"].lower() or "root" in p["name"].lower():
                rootfs = p
                break
        if rootfs is None:
            rootfs = max(partitions, key=lambda p: p["size"])

        rootfs_data = rootfs["data"]

        if rootfs_data[:4] == b"hsqs":
            _extract_squashfs(rootfs_data, out_dir)
        elif rootfs_data[:4] == b"UBI#":
            sqfs_data = _extract_ubi_to_squashfs(rootfs_data, out_dir)
            if sqfs_data:
                _extract_squashfs(sqfs_data, out_dir)
            else:
                print("      [FAIL] UBI에서 squashfs를 찾지 못함")
                return out_dir
        else:
            raw_path = out_dir / f"{rootfs['name']}.bin"
            raw_path.write_bytes(rootfs_data)
            print(f"      [WARN] 알 수 없는 rootfs 형식, 원본 저장: {raw_path}")
            return out_dir

    cache_marker.touch()
    file_count = sum(1 for _ in out_dir.rglob("*") if _.is_file() and _.name != ".extracted_ok")
    print(f"      [OK] {file_count}개 파일 추출 완료")
    return out_dir


def _extract_ubi_to_squashfs(ubi_data: bytes, work_dir: Path) -> bytes | None:
    """UBI 이미지에서 squashfs 데이터 추출."""
    offset = 0
    while True:
        pos = ubi_data.find(b"hsqs", offset)
        if pos == -1:
            break
        if pos + 44 <= len(ubi_data):
            sqfs_size = struct.unpack("<Q", ubi_data[pos + 40:pos + 48])[0]
            if 1024 < sqfs_size < len(ubi_data):
                return ubi_data[pos:pos + sqfs_size]
        offset = pos + 4

    ubi_path = work_dir / "_temp_rootfs.ubi"
    ubi_path.write_bytes(ubi_data)
    try:
        subprocess.run(
            [sys.executable, "-m", "ubireader.scripts.ubireader_extract_images", str(ubi_path)],
            capture_output=True, text=True, timeout=120, cwd=str(work_dir)
        )
        for f in work_dir.rglob("*"):
            if f.is_file() and f.stat().st_size > 1024:
                header = f.read_bytes()[:4]
                if header == b"hsqs":
                    sqfs_data = f.read_bytes()
                    ubi_path.unlink(missing_ok=True)
                    return sqfs_data
    except Exception as e:
        print(f"      [WARN] ubireader 실패: {e}")

    ubi_path.unlink(missing_ok=True)
    return None


def _extract_squashfs(sqfs_data: bytes, out_dir: Path):
    """squashfs 데이터를 out_dir에 추출."""
    try:
        from PySquashfsImage import SquashFsImage
    except ImportError:
        print("      [ERROR] PySquashfsImage 미설치: pip install PySquashfsImage")
        return

    import io
    img = SquashFsImage.from_fd(io.BytesIO(sqfs_data))
    for entry in img.root.walk():
        rel = entry.path.lstrip("/")
        if not rel:
            continue
        target = out_dir / rel
        if entry.is_dir:
            target.mkdir(parents=True, exist_ok=True)
        elif entry.is_file:
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(entry.read_bytes())
            except Exception:
                pass
        elif entry.is_symlink:
            pass
    img.close()


def _find_rootfs(out_dir: Path) -> Path:
    """추출된 디렉토리에서 rootfs (bin, usr, etc, lib 포함) 찾기."""
    def _has_rootfs_dirs(d: Path) -> bool:
        try:
            return any(x.name in ("bin", "usr", "etc", "lib")
                       for x in d.iterdir() if x.is_dir())
        except OSError:
            return False

    def _safe_is_dir(p: Path) -> bool:
        try:
            return p.is_dir()
        except OSError:
            return False

    def _count_files(d: Path) -> int:
        count = 0
        try:
            for f in d.rglob("*"):
                try:
                    if f.is_file():
                        count += 1
                except OSError:
                    pass
        except OSError:
            pass
        return count

    candidates = [d for d in out_dir.rglob("*")
                  if _safe_is_dir(d) and _has_rootfs_dirs(d)]
    if candidates:
        return max(candidates, key=_count_files)
    return out_dir


def extract_binwalk(fw_path: Path, out_dir: Path) -> Path:
    """binwalk -e로 펌웨어 추출 (WSL Ubuntu). 추출된 루트 경로 반환."""
    cache_marker = out_dir / ".extracted_ok"
    if cache_marker.exists():
        print(f"    [CACHE] {out_dir.name} 이미 추출됨, 스킵")
        rootfs = _find_rootfs(out_dir)
        print(f"      rootfs: {rootfs.relative_to(out_dir)}")
        return rootfs

    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"    [EXTRACT] binwalk -e {fw_path.name}...")

    def to_wsl_path(p: Path) -> str:
        s = str(p.resolve()).replace("\\", "/")
        if len(s) >= 2 and s[1] == ":":
            return f"/mnt/{s[0].lower()}/{s[2:].lstrip('/')}"
        return s

    wsl_fw = to_wsl_path(fw_path)
    wsl_cwd = to_wsl_path(fw_path.parent)

    try:
        env = {k: v for k, v in os.environ.items()}
        env["WSLENV"] = ""
        subprocess.run(
            ["wsl", "-d", "Ubuntu", "--", "bash", "-lc",
             f"cd '{wsl_cwd}' && binwalk -e '{wsl_fw}'"],
            capture_output=True, text=True, timeout=600, env=env
        )
    except Exception as e:
        print(f"    [ERROR] binwalk(WSL) 실행 실패: {e}")
        sys.exit(1)

    extracted_name = f"_{fw_path.name}.extracted"
    extracted_dir = fw_path.parent / extracted_name

    if not extracted_dir.exists():
        print(f"    [FAIL] binwalk 추출 결과 없음: {extracted_name}")
        return out_dir

    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.move(str(extracted_dir), str(out_dir))

    rootfs = _find_rootfs(out_dir)
    cache_marker = out_dir / ".extracted_ok"
    cache_marker.touch()
    print(f"      [OK] rootfs: {rootfs.relative_to(out_dir)}")
    return rootfs


def resolve_input_dir(path: Path, extracted_base: Path) -> Path:
    """입력이 펌웨어 파일이면 추출, 디렉토리면 그대로 반환."""
    if path.is_dir():
        return path
    if path.is_file() and is_synology_firmware(path):
        extract_dir = extracted_base / path.stem
        return extract_synology(path, extract_dir)
    if path.is_file():
        extract_dir = extracted_base / path.stem
        return extract_binwalk(path, extract_dir)
    print(f"[ERROR] 경로를 찾을 수 없음: {path}")
    sys.exit(1)


# =====================================================================
#  2. 해시 비교
# =====================================================================

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_hashes(root: Path) -> dict[str, str]:
    """디렉토리 내 모든 파일의 상대경로 → SHA256 딕셔너리."""
    result = {}
    for f in sorted(root.rglob("*")):
        try:
            if not f.is_file():
                continue
        except OSError:
            continue
        if f.suffix.lower() in IDA_TEMP_EXTS:
            continue
        if f.name == ".extracted_ok":
            continue
        rel = f.relative_to(root).as_posix()
        try:
            result[rel] = sha256(f)
        except OSError:
            continue
    return result


def compare_dirs(old_dir: Path, new_dir: Path, cache_path: Path | None = None) -> dict:
    """두 디렉토리 해시 비교 → changed/added/removed. cache_path가 있으면 캐시 사용."""
    if cache_path and cache_path.exists():
        print(f"\n[1/7] 해시 비교 [CACHE] {cache_path.name} 재사용")
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    print("\n[1/7] 해시 비교 중...")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_old = pool.submit(scan_hashes, old_dir)
        f_new = pool.submit(scan_hashes, new_dir)
        old_hashes = f_old.result()
        new_hashes = f_new.result()

    changed, added, removed = [], [], []
    for rel, h in new_hashes.items():
        if rel in old_hashes:
            if old_hashes[rel] != h:
                changed.append(rel)
        else:
            added.append(rel)
    for rel in old_hashes:
        if rel not in new_hashes:
            removed.append(rel)

    print(f"      파일 수: old={len(old_hashes)}, new={len(new_hashes)}")
    print(f"      changed={len(changed)}, added={len(added)}, removed={len(removed)}")
    return {"changed": changed, "added": added, "removed": removed}


# =====================================================================
#  3. 텍스트/바이너리 분류 + 텍스트 diff
# =====================================================================

def is_binary(path: Path) -> bool:
    """ELF 매직 또는 NULL 바이트 존재 → 바이너리."""
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if header[:4] == b"\x7fELF":
                return True
            f.seek(0)
            chunk = f.read(8192)
            return b"\x00" in chunk
    except Exception:
        return True


def diff_text_files(old_dir: Path, new_dir: Path, text_files: list[str], output_dir: Path) -> int:
    """텍스트 파일 unified diff → .patch 파일 저장. 처리 개수 반환."""
    text_diff_dir = output_dir / "text_diffs"
    text_diff_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for rel in text_files:
        old_file = old_dir / rel
        new_file = new_dir / rel
        if not old_file.exists() or not new_file.exists():
            continue
        try:
            old_lines = old_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            new_lines = new_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            diff = list(difflib.unified_diff(old_lines, new_lines, fromfile=f"old/{rel}", tofile=f"new/{rel}"))
            if diff:
                patch_name = rel.replace("/", "_") + ".patch"
                (text_diff_dir / patch_name).write_text("".join(diff), encoding="utf-8")
                count += 1
        except Exception:
            pass
    return count


# =====================================================================
#  4. 통합 추출: 함수(디컴파일) + BinExport (IDA 1회 실행)
# =====================================================================

def is_timezone_file(rel_path: str) -> bool:
    """타임존 데이터 파일인지 판별 (노이즈 필터링)."""
    for frag in TIMEZONE_PATH_FRAGMENTS:
        if frag in rel_path:
            return True
    return False


def run_combined_extract(binary: Path, functions_dir: Path,
                         binexport_dir: Path, tag: str = "") -> tuple[Path | None, Path | None]:
    """IDA 한 번 실행 → 함수 JSON(pseudocode 포함) + BinExport 파일 생성.

    Returns:
        (functions_json_path, binexport_path) — 실패 시 None
    """
    suffix = f"_{tag}" if tag else ""
    functions_json = functions_dir / f"{binary.name}{suffix}.json"
    binexport_path = binexport_dir / f"{binary.name}{suffix}.BinExport"

    # 캐시 확인: 함수 JSON이 이미 있으면 스킵
    if functions_json.exists() and functions_json.stat().st_size > 100:
        print(f"    [CACHE] {functions_json.name}")
        be = binexport_path if binexport_path.exists() else None
        return functions_json, be

    functions_dir.mkdir(parents=True, exist_ok=True)
    binexport_dir.mkdir(parents=True, exist_ok=True)

    log_path = binexport_dir / f"{binary.name}{suffix}_extract.log"

    env = os.environ.copy()
    env["IDA_EXPORT_DIR"] = str(functions_dir)
    env["IDA_BINARY_TAG"] = tag

    cmd = [
        str(IDA_PATH), "-A",
        f"-OBinExportModule:{binexport_path}",
        f"-S{EXTRACT_SCRIPT}",
        f"-L{log_path}",
        str(binary),
    ]

    print(f"    [EXTRACT] {binary.name} ({tag})...")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
    except subprocess.TimeoutExpired:
        print(f"    [TIMEOUT] {binary.name} ({tag})")
        return None, None

    # IDA 임시 파일 정리
    for ext in IDA_TEMP_EXTS:
        temp = binary.with_suffix(ext)
        if temp.exists():
            try:
                temp.unlink()
            except OSError:
                pass

    fj = functions_json if functions_json.exists() and functions_json.stat().st_size > 100 else None
    be = binexport_path if binexport_path.exists() and binexport_path.stat().st_size > 100 else None

    if fj:
        print(f"    [OK] {functions_json.name}")
    else:
        print(f"    [FAIL] functions: {binary.name} ({tag})")

    if be:
        print(f"    [OK] {binexport_path.name}")
    elif fj:
        # BinExport가 스크립트에서 트리거 안 됐으면 별도 실행 (IDB 재사용으로 빠름)
        print(f"    [BINEXPORT] fallback: {binary.name} ({tag})...")
        be = _run_binexport_only(binary, binexport_path)

    return fj, be


def _run_binexport_only(binary: Path, binexport_path: Path) -> Path | None:
    """BinExport만 생성 (함수 추출 후 .i64가 있으면 재사용)."""
    i64 = binary.with_suffix(".i64")
    target = str(i64) if i64.exists() else str(binary)

    cmd = [
        str(IDA_PATH), "-A",
        f"-OBinExportModule:{binexport_path}",
        "-OBinExportAutoAction:BinExportBinary",
        target,
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return None

    # IDA 임시 파일 정리
    for ext in IDA_TEMP_EXTS:
        temp = binary.with_suffix(ext)
        if temp.exists():
            try:
                temp.unlink()
            except OSError:
                pass

    if binexport_path.exists() and binexport_path.stat().st_size > 100:
        print(f"    [OK] {binexport_path.name}")
        return binexport_path
    return None


# =====================================================================
#  5. BinDiff (CLI)
# =====================================================================

def run_bindiff(old_binexport: Path, new_binexport: Path, output_dir: Path) -> Path | None:
    """BinDiff CLI로 두 .BinExport 파일을 비교. .BinDiff SQLite 파일 반환."""
    # 캐시 확인: .BinDiff 파일이 이미 있으면 스킵
    if output_dir.exists():
        for f in output_dir.iterdir():
            if f.suffix == ".BinDiff" and f.stat().st_size > 0:
                print(f"    [CACHE] {f.name}")
                return f

    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(BINDIFF_PATH),
        "--primary", str(old_binexport),
        "--secondary", str(new_binexport),
        "--output_dir", str(output_dir),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"    [TIMEOUT] BinDiff")
        return None

    # .BinDiff 파일 찾기
    for f in output_dir.iterdir():
        if f.suffix == ".BinDiff" and f.stat().st_size > 0:
            return f

    return None


def parse_bindiff_results(bindiff_db: Path) -> dict:
    """BinDiff SQLite DB를 파싱하여 변경된 함수 목록 반환."""
    conn = sqlite3.connect(str(bindiff_db))
    cur = conn.cursor()

    # 변경된 함수 (similarity < 1.0)
    cur.execute("""SELECT name1, address1, name2, address2,
                          similarity, confidence, basicblocks, instructions, edges
                   FROM function WHERE similarity < 1.0
                   ORDER BY similarity ASC""")
    changed = []
    for r in cur.fetchall():
        changed.append({
            "name_old": r[0],
            "addr_old": hex(r[1]),
            "name_new": r[2],
            "addr_new": hex(r[3]),
            "similarity": round(r[4], 4),
            "confidence": round(r[5], 4),
            "basicblocks": r[6],
            "instructions": r[7],
            "edges": r[8],
        })

    # 전체 통계
    cur.execute("SELECT COUNT(*) FROM function")
    total_matched = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM function WHERE similarity = 1.0")
    identical = cur.fetchone()[0]

    # metadata에서 전체 유사도
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
#  6. 함수 diff 생성 (pseudocode / disasm)
# =====================================================================

def _safe_filename(name: str) -> str:
    """함수명 → 안전한 파일명으로 변환."""
    for ch in r'<>:"/\|?* ':
        name = name.replace(ch, "_")
    if len(name) > 200:
        name = name[:200]
    return name


def generate_function_diffs(
    binary_name: str,
    old_funcs_json: Path,
    new_funcs_json: Path,
    bindiff_result: dict,
    output_dir: Path,
) -> dict:
    """변경된 함수의 pseudocode diff를 생성.

    Args:
        binary_name: 바이너리 파일명
        old_funcs_json: old 버전 함수 JSON 경로
        new_funcs_json: new 버전 함수 JSON 경로
        bindiff_result: parse_bindiff_results() 결과 dict
        output_dir: diff 출력 디렉토리

    Returns:
        dict with diff statistics and per-function diff info
    """
    # 함수 JSON 로드
    with open(old_funcs_json, "r", encoding="utf-8") as f:
        old_data = json.load(f)
    with open(new_funcs_json, "r", encoding="utf-8") as f:
        new_data = json.load(f)

    old_funcs = old_data.get("functions", {})
    new_funcs = new_data.get("functions", {})
    has_pseudo = old_data.get("has_pseudocode", False) and new_data.get("has_pseudocode", False)

    diff_dir = output_dir / binary_name

    # 캐시 확인: diff 디렉토리에 이미 파일이 있으면 스킵
    if diff_dir.exists() and any(diff_dir.glob("*.diff")):
        existing = list(diff_dir.glob("*.diff"))
        print(f"    [CACHE] {binary_name}: {len(existing)}개 diff 이미 존재, 스킵")
        # 기존 통계 집계
        skipped_plt = 0
        diff_results = []
        for df in existing:
            diff_text = df.read_text(encoding="utf-8", errors="replace")
            added = sum(1 for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++"))
            removed = sum(1 for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---"))
            diff_results.append({
                "name_old": df.stem.replace("_old", "").replace(".c", ""),
                "name_new": df.stem.replace("_old", "").replace(".c", ""),
                "similarity": 0,
                "code_type": "pseudocode" if ".c.diff" in df.name else "disasm",
                "lines_added": added,
                "lines_removed": removed,
                "diff_file": df.name,
            })
        has_pseudo = old_data.get("has_pseudocode", False) and new_data.get("has_pseudocode", False)
        return {
            "binary": binary_name,
            "total_changed": len(bindiff_result.get("changed_functions", [])),
            "diffs_generated": len(diff_results),
            "skipped_plt": skipped_plt,
            "has_pseudocode": has_pseudo,
            "functions": diff_results,
            "from_cache": True,
        }

    diff_dir.mkdir(parents=True, exist_ok=True)

    changed_functions = bindiff_result.get("changed_functions", [])
    diff_results = []
    skipped_plt = 0

    for fn in changed_functions:
        name_old = fn["name_old"]
        name_new = fn["name_new"]
        similarity = fn["similarity"]
        insn_count = fn.get("instructions", 0)

        # PLT stub 필터링 (≤ 3 instructions, 노이즈)
        if insn_count <= 3:
            skipped_plt += 1
            continue

        old_func = old_funcs.get(name_old)
        new_func = new_funcs.get(name_new)

        if not old_func or not new_func:
            continue

        # pseudocode 우선, 없으면 disasm 사용
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

        # unified diff 생성
        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)

        diff_lines = list(difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"old/{name_old}",
            tofile=f"new/{name_new}",
        ))

        if not diff_lines:
            continue

        # diff 파일 저장
        safe_name = _safe_filename(name_old)
        ext = ".c.diff" if code_type == "pseudocode" else ".asm.diff"
        diff_path = diff_dir / f"{safe_name}{ext}"
        diff_path.write_text("".join(diff_lines), encoding="utf-8")

        # before/after 코드도 개별 저장
        code_ext = ".c" if code_type == "pseudocode" else ".asm"
        (diff_dir / f"{safe_name}_old{code_ext}").write_text(old_code, encoding="utf-8")
        (diff_dir / f"{safe_name}_new{code_ext}").write_text(new_code, encoding="utf-8")

        added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))

        diff_results.append({
            "name_old": name_old,
            "name_new": name_new,
            "similarity": similarity,
            "code_type": code_type,
            "lines_added": added,
            "lines_removed": removed,
            "diff_file": str(diff_path.name),
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
#  7. 요약 생성
# =====================================================================

def write_summary(output_dir: Path, compare_result: dict,
                  text_count: int, binary_results: dict,
                  diff_stats: dict | None = None):
    """summary.md 생성."""
    md = output_dir / "summary.md"
    lines = ["# Patch Diff Summary\n"]

    lines.append(f"\n## 해시 비교")
    lines.append(f"- Changed: {len(compare_result['changed'])}")
    lines.append(f"- Added: {len(compare_result['added'])}")
    lines.append(f"- Removed: {len(compare_result['removed'])}")

    lines.append(f"\n## 텍스트 Diff")
    lines.append(f"- {text_count}개 패치 파일 생성 → `text_diffs/`")

    lines.append(f"\n## BinDiff 함수 비교 결과")
    for binary_name, result in binary_results.items():
        funcs = result["changed_functions"]
        sim = result["overall_similarity"]
        lines.append(f"\n### {binary_name} — {sim*100:.1f}% similar ({len(funcs)} changed functions)")
        if funcs:
            lines.append(f"| Function (old) | Function (new) | Similarity | Confidence | BBs | Instrs |")
            lines.append(f"|----------------|----------------|-----------|-----------|-----|--------|")
            for fn in funcs[:30]:
                lines.append(f"| {fn['name_old']} | {fn['name_new']} | {fn['similarity']:.4f} | {fn['confidence']:.4f} | {fn['basicblocks']} | {fn['instructions']} |")
            if len(funcs) > 30:
                lines.append(f"| ... | ... | {len(funcs) - 30} more | | | |")

    # ── Pseudocode Diff 요약 ──────────────────────────────────────
    if diff_stats:
        lines.append(f"\n## 함수 Pseudocode Diff")
        lines.append(f"- 결과 디렉토리: `function_diffs/`")
        total_diffs = 0
        for binary_name, ds in diff_stats.items():
            n = ds["diffs_generated"]
            total_diffs += n
            code_type = "pseudocode" if ds["has_pseudocode"] else "disasm"
            lines.append(f"\n### {binary_name} ({code_type}) — {n}개 diff 생성")
            if ds.get("skipped_plt", 0) > 0:
                lines.append(f"- PLT stub 필터링: {ds['skipped_plt']}개 스킵")
            # 상위 10개 변경 함수 (추가/삭제 라인이 많은 순)
            top_funcs = sorted(ds.get("functions", []),
                               key=lambda x: x["lines_added"] + x["lines_removed"],
                               reverse=True)[:10]
            if top_funcs:
                lines.append(f"| Function | Similarity | +Added | -Removed | Type |")
                lines.append(f"|----------|-----------|--------|----------|------|")
                for tf in top_funcs:
                    lines.append(f"| {tf['name_old']} | {tf['similarity']:.4f} | "
                                 f"+{tf['lines_added']} | -{tf['lines_removed']} | {tf['code_type']} |")
        lines.append(f"\n**총 {total_diffs}개 함수 diff 생성 완료**")

    md.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[DONE] {md}")


# =====================================================================
#  main
# =====================================================================

def auto_output_dir(old_input: Path, new_input: Path) -> Path:
    """입력 경로에서 출력 디렉토리 자동 결정."""
    old_stem = old_input.stem.split(".")[0] if old_input.is_file() else old_input.name
    new_stem = new_input.stem.split(".")[0] if new_input.is_file() else new_input.name
    diff_name = f"{old_stem}_vs_{new_stem}"

    ref = old_input if old_input.is_file() else old_input
    if ref.parent.name == "raw":
        return ref.parent.parent / "diffs" / diff_name
    return ref.parent / "diffs" / diff_name


def main():
    parser = argparse.ArgumentParser(description="Patch-Learner Diff Pipeline")
    parser.add_argument("--old", required=True, help="이전 버전 (디렉토리 또는 펌웨어 파일)")
    parser.add_argument("--new", required=True, help="이후 버전 (디렉토리 또는 펌웨어 파일)")
    parser.add_argument("--output", default=None, help="결과 출력 디렉토리 (생략 시 자동)")
    args = parser.parse_args()

    old_input = Path(args.old)
    new_input = Path(args.new)

    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = auto_output_dir(old_input, new_input)
        print(f"[OUTPUT] {output_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # 환경 확인
    if not IDA_PATH.exists():
        print(f"[ERROR] IDA not found: {IDA_PATH}")
        sys.exit(1)
    if not BINDIFF_PATH.exists():
        print(f"[ERROR] BinDiff not found: {BINDIFF_PATH}")
        sys.exit(1)
    if not EXTRACT_SCRIPT.exists():
        print(f"[ERROR] Extract script not found: {EXTRACT_SCRIPT}")
        sys.exit(1)

    # ── Step 0: 펌웨어 추출 (필요 시) ────────────────────────────
    extracted_base = output_dir / "extracted"
    old_dir = resolve_input_dir(old_input, extracted_base)
    new_dir = resolve_input_dir(new_input, extracted_base)

    # ── Step 1: 해시 비교 (캐시 사용) ───────────────────────────
    hash_json = output_dir / "hash_compare.json"
    compare_result = compare_dirs(old_dir, new_dir, cache_path=hash_json)
    with open(hash_json, "w", encoding="utf-8") as f:
        json.dump(compare_result, f, indent=2, ensure_ascii=False)

    if not compare_result["changed"]:
        print("변경된 파일 없음. 종료.")
        sys.exit(0)

    # ── Step 2: 텍스트/바이너리 분류 + 노이즈 필터링 ─────────────
    print("\n[2/7] 파일 분류 중...")
    text_files, binary_files = [], []
    timezone_skipped = 0
    for rel in compare_result["changed"]:
        if is_timezone_file(rel):
            timezone_skipped += 1
            continue
        path = new_dir / rel
        if is_binary(path):
            binary_files.append(rel)
        else:
            text_files.append(rel)
    print(f"      text={len(text_files)}, binary={len(binary_files)}, "
          f"timezone_skipped={timezone_skipped}")

    # ── Step 3: 텍스트 diff ──────────────────────────────────────
    print(f"\n[3/7] 텍스트 diff ({len(text_files)}개)...")
    text_count = diff_text_files(old_dir, new_dir, text_files, output_dir)
    print(f"      {text_count}개 패치 파일 생성")

    # ── Step 4: 통합 추출 (함수 디컴파일 + BinExport, 병렬 4개) ──
    functions_dir = output_dir / "functions"
    binexport_dir = output_dir / "binexport"

    # 캐시 상태 사전 확인
    cached, todo = [], []
    for rel in binary_files:
        binary_name = Path(rel).name
        old_fj = functions_dir / f"{binary_name}_old.json"
        new_fj = functions_dir / f"{binary_name}_new.json"
        if (old_fj.exists() and old_fj.stat().st_size > 100 and
                new_fj.exists() and new_fj.stat().st_size > 100):
            cached.append(rel)
        else:
            todo.append(rel)

    print(f"\n[4/7] 함수 추출 + BinExport — 전체 {len(binary_files)}개 "
          f"(캐시 {len(cached)}개 스킵, 신규 {len(todo)}개 처리)")

    extract_results = {}  # rel -> (old_fj, new_fj, old_be, new_be)

    # 캐시 항목 바로 로드
    for rel in cached:
        binary_name = Path(rel).name
        old_fj = functions_dir / f"{binary_name}_old.json"
        new_fj = functions_dir / f"{binary_name}_new.json"
        old_be = binexport_dir / f"{binary_name}_old.BinExport"
        new_be = binexport_dir / f"{binary_name}_new.BinExport"
        extract_results[rel] = (
            old_fj,
            new_fj,
            old_be if old_be.exists() else None,
            new_be if new_be.exists() else None,
        )

    # 신규 항목 병렬 처리
    if todo:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {}
            done_count = 0
            for rel in todo:
                old_bin = old_dir / rel
                new_bin = new_dir / rel
                if not old_bin.exists() or not new_bin.exists():
                    continue
                f_old = pool.submit(run_combined_extract, old_bin,
                                    functions_dir, binexport_dir, tag="old")
                f_new = pool.submit(run_combined_extract, new_bin,
                                    functions_dir, binexport_dir, tag="new")
                futures[rel] = (f_old, f_new)

            for rel, (f_old, f_new) in futures.items():
                old_fj, old_be = f_old.result()
                new_fj, new_be = f_new.result()
                extract_results[rel] = (old_fj, new_fj, old_be, new_be)
                done_count += 1
                print(f"      진행: {done_count}/{len(todo)} (전체 {len(cached)+done_count}/{len(binary_files)})")

    success = sum(1 for v in extract_results.values() if v[0] and v[1])
    print(f"      함수 추출 성공: {success}/{len(binary_files)} (캐시 포함)")

    # ── Step 5: BinDiff (함수 매칭) ──────────────────────────────
    export_pairs = [(rel, v[2], v[3]) for rel, v in extract_results.items()
                    if v[2] and v[3]]
    print(f"\n[5/7] BinDiff ({len(export_pairs)}개)...")
    bindiff_dir = output_dir / "bindiff"
    bindiff_dir.mkdir(parents=True, exist_ok=True)

    all_results = {}
    for rel, old_be, new_be in export_pairs:
        binary_name = Path(rel).name
        bd_out = bindiff_dir / binary_name
        bd_out.mkdir(parents=True, exist_ok=True)

        bd_file = run_bindiff(old_be, new_be, bd_out)
        if bd_file:
            result = parse_bindiff_results(bd_file)
            all_results[binary_name] = result
            changed_count = result["changed_count"]
            sim = result["overall_similarity"]
            print(f"      {binary_name}: {sim*100:.1f}% similar, "
                  f"{changed_count} changed functions")
        else:
            print(f"      {binary_name}: BinDiff 실패")

    results_json = output_dir / "diff_results.json"
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    # ── Step 6: 함수 Pseudocode Diff ─────────────────────────────
    print(f"\n[6/7] 함수 diff 생성...")
    func_diff_dir = output_dir / "function_diffs"
    func_diff_dir.mkdir(parents=True, exist_ok=True)

    all_diff_stats = {}
    for rel, (old_fj, new_fj, _, _) in extract_results.items():
        binary_name = Path(rel).name
        if not old_fj or not new_fj:
            continue
        if binary_name not in all_results:
            continue

        ds = generate_function_diffs(
            binary_name, old_fj, new_fj,
            all_results[binary_name], func_diff_dir,
        )
        all_diff_stats[binary_name] = ds
        print(f"      {binary_name}: {ds['diffs_generated']}개 diff "
              f"(PLT 스킵: {ds['skipped_plt']})")

    diff_stats_json = output_dir / "function_diff_stats.json"
    with open(diff_stats_json, "w", encoding="utf-8") as f:
        json.dump(all_diff_stats, f, indent=2, ensure_ascii=False)

    # ── Step 7: 요약 ─────────────────────────────────────────────
    write_summary(output_dir, compare_result, text_count,
                  all_results, all_diff_stats)

    # 터미널 출력
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    total_diffs = sum(ds["diffs_generated"] for ds in all_diff_stats.values())
    print(f"\n바이너리: {len(all_results)}개 분석, "
          f"함수 diff: {total_diffs}개 생성")

    for binary_name, result in sorted(all_results.items(),
                                       key=lambda x: -x[1]["changed_count"]):
        funcs = result["changed_functions"]
        sim = result["overall_similarity"]
        ds = all_diff_stats.get(binary_name, {})
        n_diffs = ds.get("diffs_generated", 0)
        print(f"\n{binary_name}: {sim*100:.1f}% sim, "
              f"{len(funcs)} changed, {n_diffs} diffs")
        for fn in funcs[:5]:
            name = fn["name_old"] or fn["name_new"]
            print(f"  {name:<40} sim={fn['similarity']:.4f}")
        if len(funcs) > 5:
            print(f"  ... +{len(funcs) - 5} more")

    print(f"\nResults: {output_dir}")
    print(f"Function diffs: {func_diff_dir}")


if __name__ == "__main__":
    main()
