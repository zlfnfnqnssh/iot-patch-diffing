"""
Run bindiff_pipeline.py sequentially across firmware version pairs.

If --firmware-dir points to a directory that directly contains versioned .bin
files, that directory is processed as a single model.

If --firmware-dir points to a parent folder, child firmware directories are
discovered automatically and each model is processed independently.
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PIPELINE_SCRIPT = Path(__file__).resolve().parent / "bindiff_pipeline.py"
DEFAULT_FIRMWARE_ROOT = PROJECT_ROOT / "data" / "firmware" / "tapo_C200"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "output"

VERSION_PATTERNS = [
    re.compile(r"_en_(\d+)\.(\d+)\.(\d+)_"),
    re.compile(r"(?:^|[_-])v(\d+)\.(\d+)\.(\d+)(?:[_-]|$)", re.IGNORECASE),
]


def parse_version(filename: str) -> tuple[int, int, int] | None:
    """Extract (major, minor, patch) from a firmware filename."""
    for pattern in VERSION_PATTERNS:
        match = pattern.search(filename)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None


def version_str(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def collect_firmware_files(firmware_dir: Path) -> list[tuple[tuple[int, int, int], Path]]:
    """Return versioned .bin files in a directory, sorted by version."""
    files: list[tuple[tuple[int, int, int], Path]] = []
    for file_path in sorted(firmware_dir.glob("*.bin")):
        version = parse_version(file_path.name)
        if version is None:
            print(f"  [SKIP] version parse failed: {file_path.name}")
            continue
        files.append((version, file_path))
    files.sort(key=lambda item: item[0])
    return files


def discover_firmware_dirs(root: Path) -> list[Path]:
    """
    Discover firmware directories.

    - If root itself directly contains versioned .bin files, treat it as a
      single target.
    - Otherwise scan descendants and collect directories that directly contain
      at least two versioned .bin files.
    """
    if len(collect_firmware_files(root)) >= 2:
        return [root]

    discovered: list[Path] = []
    for dirpath, _, filenames in os.walk(root, onerror=lambda _exc: None):
        directory = Path(dirpath)
        if directory == root:
            continue
        if not any(name.lower().endswith(".bin") for name in filenames):
            continue
        if len(collect_firmware_files(directory)) >= 2:
            discovered.append(directory)
    return sorted(discovered)


def filter_pairs(
    files: list[tuple[tuple[int, int, int], Path]],
    from_version: tuple[int, int, int] | None,
) -> list[tuple[tuple[tuple[int, int, int], Path], tuple[tuple[int, int, int], Path]]]:
    """Build sequential version pairs, optionally starting from from_version."""
    pairs = [(files[index], files[index + 1]) for index in range(len(files) - 1)]
    if from_version is None:
        return pairs
    return [pair for pair in pairs if pair[0][0] >= from_version]


def run_pipeline(old_path: Path, new_path: Path, output_dir: Path, dry_run: bool) -> bool:
    """Invoke bindiff_pipeline.py. Returns True on success."""
    command = [
        sys.executable,
        str(PIPELINE_SCRIPT),
        "--old",
        str(old_path),
        "--new",
        str(new_path),
        "--output",
        str(output_dir),
    ]

    if dry_run:
        print(f"  [DRY-RUN] {' '.join(command)}")
        return True

    print("\n  running: python bindiff_pipeline.py")
    print(f"    --old    {old_path.name}")
    print(f"    --new    {new_path.name}")
    print(f"    --output {output_dir}")

    start = time.time()
    result = subprocess.run(command, cwd=str(PROJECT_ROOT))
    elapsed = time.time() - start

    if result.returncode == 0:
        print(f"  [OK] finished ({elapsed:.0f}s)")
        return True

    print(f"  [FAIL] exit code={result.returncode} ({elapsed:.0f}s)")
    return False


def resolve_output_base(
    firmware_dir: Path,
    output_root: Path,
    explicit_output_base: bool,
    multi_target_mode: bool,
) -> Path:
    """
    Resolve the output base directory for one firmware directory.

    Multi-target mode always gets a per-model subdirectory.
    Single-target mode keeps an explicit --output-base as-is, otherwise defaults
    to output/<model_name>.
    """
    if multi_target_mode:
        return output_root / firmware_dir.name
    if explicit_output_base:
        return output_root
    return output_root / firmware_dir.name


def parse_from_version(raw: str | None) -> tuple[int, int, int] | None:
    if raw is None:
        return None
    try:
        parts = tuple(int(part) for part in raw.split("."))
    except ValueError as exc:
        raise ValueError(f"invalid version format: {raw}") from exc
    if len(parts) != 3:
        raise ValueError(f"invalid version format: {raw}")
    return parts


def process_firmware_dir(
    firmware_dir: Path,
    output_base: Path,
    from_version: tuple[int, int, int] | None,
    dry_run: bool,
) -> tuple[int, int, int]:
    """Run sequential diffs for one firmware directory."""
    files = collect_firmware_files(firmware_dir)
    if len(files) < 2:
        print(f"[SKIP] {firmware_dir.name}: fewer than 2 versioned .bin files")
        return (0, 0, 0)

    pairs = filter_pairs(files, from_version)
    if not pairs:
        print(f"[SKIP] {firmware_dir.name}: no pairs after --from-version filter")
        return (0, 0, 0)

    print("\n" + "=" * 60)
    print(f"{firmware_dir.name} sequential diff - total {len(pairs)} pairs")
    print(f"firmware dir: {firmware_dir}")
    print(f"output base:  {output_base}")
    print("=" * 60)

    for index, ((old_ver, _), (new_ver, _)) in enumerate(pairs, 1):
        pair_output = output_base / f"v{version_str(old_ver)}_vs_v{version_str(new_ver)}"
        status = ""
        if (pair_output / "function_diff_stats.json").exists():
            status = " [already done]"
        print(f"  [{index:2d}] v{version_str(old_ver)} -> v{version_str(new_ver)}{status}")

    if dry_run:
        print("\n[DRY-RUN] commands are printed only.")

    print()
    output_base.mkdir(parents=True, exist_ok=True)

    success_count = 0
    fail_count = 0
    skip_count = 0

    for index, ((old_ver, old_file), (new_ver, new_file)) in enumerate(pairs, 1):
        old_label = version_str(old_ver)
        new_label = version_str(new_ver)
        pair_output = output_base / f"v{old_label}_vs_v{new_label}"

        print(f"\n[{index}/{len(pairs)}] v{old_label} -> v{new_label}")

        if (pair_output / "function_diff_stats.json").exists() and not dry_run:
            print(f"  [SKIP] existing result: {pair_output.name}")
            skip_count += 1
            continue

        if run_pipeline(old_file, new_file, pair_output, dry_run):
            success_count += 1
        else:
            fail_count += 1
            print("  [WARNING] failed, continuing with next pair")

    print("\n" + "-" * 60)
    print(f"{firmware_dir.name} summary")
    print("-" * 60)
    print(f"  success: {success_count}")
    print(f"  failed:  {fail_count}")
    print(f"  skipped: {skip_count}")
    print(f"  output:  {output_base}")

    return (success_count, fail_count, skip_count)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run sequential firmware diffs for one model or an entire firmware root."
    )
    parser.add_argument(
        "--firmware-dir",
        default=str(DEFAULT_FIRMWARE_ROOT),
        help="single firmware directory or parent folder to scan recursively",
    )
    parser.add_argument(
        "--output-base",
        default=None,
        help="output root. multi-target mode writes to <output-base>/<model>/",
    )
    parser.add_argument(
        "--from-version",
        default=None,
        help="start from a specific version, for example 1.0.5",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print commands without running bindiff_pipeline.py",
    )
    args = parser.parse_args()

    firmware_root = Path(args.firmware_dir)
    output_root = Path(args.output_base) if args.output_base else DEFAULT_OUTPUT_ROOT
    explicit_output_base = args.output_base is not None

    if not firmware_root.exists():
        print(f"[ERROR] firmware directory not found: {firmware_root}")
        sys.exit(1)

    if not PIPELINE_SCRIPT.exists():
        print(f"[ERROR] pipeline script not found: {PIPELINE_SCRIPT}")
        sys.exit(1)

    try:
        from_version = parse_from_version(args.from_version)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    firmware_dirs = discover_firmware_dirs(firmware_root)
    if not firmware_dirs:
        print(f"[ERROR] no firmware directories with at least 2 versioned .bin files under: {firmware_root}")
        sys.exit(1)

    multi_target_mode = len(firmware_dirs) > 1 or firmware_dirs[0].resolve() != firmware_root.resolve()

    print("=" * 60)
    print(f"discovered firmware directories: {len(firmware_dirs)}")
    print(f"scan root: {firmware_root}")
    print(f"output root: {output_root}")
    print("=" * 60)
    for directory in firmware_dirs:
        print(f"  - {directory}")

    total_success = 0
    total_fail = 0
    total_skip = 0

    for directory in firmware_dirs:
        model_output = resolve_output_base(
            directory,
            output_root,
            explicit_output_base=explicit_output_base,
            multi_target_mode=multi_target_mode,
        )
        success_count, fail_count, skip_count = process_firmware_dir(
            directory,
            model_output,
            from_version=from_version,
            dry_run=args.dry_run,
        )
        total_success += success_count
        total_fail += fail_count
        total_skip += skip_count

    print("\n" + "=" * 60)
    print("overall summary")
    print("=" * 60)
    print(f"  success: {total_success}")
    print(f"  failed:  {total_fail}")
    print(f"  skipped: {total_skip}")
    print(f"  output root: {output_root}")

    if total_fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
