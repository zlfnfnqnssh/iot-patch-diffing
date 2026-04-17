"""Phase 0 Python 키워드 필터.

prefilter.sql 실행 후 `pending` 상태로 남은 changed_functions를 대상으로
decompiled_old/decompiled_new에 위험 키워드가 있는 것만 `prefiltered_in`로 표시.
나머지는 `prefiltered_out`.

실행:
    python src/stage2/prefilter.py

DB 경로 override:
    python src/stage2/prefilter.py --db path/to/patch_learner.db
"""
from __future__ import annotations

import argparse
import re
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"

# 위험 키워드 -- decompiled_new 또는 decompiled_old에 이 중 하나 이상 등장해야 prefiltered_in.
# 단순 substring 매칭으로 충분 (regex 컴파일 비용 없이 fast path).
DANGEROUS_KEYWORDS = [
    # Shell / exec
    "system(", "popen(", "execl(", "execlp(", "execle(",
    "execv(", "execvp(", "execve(", "posix_spawn(",
    # Unsafe string copy / format
    "sprintf(", "strcpy(", "strcat(", "gets(", "vsprintf(",
    # Bounded but often misused
    "snprintf(", "strncpy(", "strncat(",
    # Memory copy (length 검사 필요)
    "memcpy(", "memmove(", "bcopy(",
    # Format string
    "printf(", "fprintf(", "dprintf(",
    # File system primitives (경로 주입)
    "chmod(", "chown(", "unlink(", "rename(",
    "symlink(", "mkdir(",
    # Network / parsing
    "recv(", "recvfrom(", "scanf(", "sscanf(", "fscanf(",
    # Dangerous APIs
    "strtok(", "realpath(",
    # Synology/Dahua/Ubiquiti 고유 (Hard Rules 매칭 증거용)
    "sub_6CEE0", "sub_1E5E4", "sub_D7E0", "sub_E170",
    "SynoPopen", "syno_popen",
]


def compile_keyword_pattern() -> re.Pattern[str]:
    """모든 키워드를 하나의 regex로 합쳐 단일 스캔."""
    escaped = [re.escape(k) for k in DANGEROUS_KEYWORDS]
    return re.compile("|".join(escaped))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    ap.add_argument("--batch-size", type=int, default=5000, help="한 번에 처리할 행 수")
    ap.add_argument("--dry-run", action="store_true", help="UPDATE 없이 통계만")
    args = ap.parse_args()

    pattern = compile_keyword_pattern()
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    total = c.execute(
        "SELECT COUNT(*) FROM changed_functions WHERE stage2_status = 'pending'"
    ).fetchone()[0]
    print(f"[prefilter.py] target pending rows: {total:,}")
    if total == 0:
        print("[prefilter.py] nothing to do.")
        return 0

    in_ids: list[int] = []
    out_ids: list[int] = []
    processed = 0

    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, decompiled_old, decompiled_new
        FROM changed_functions
        WHERE stage2_status = 'pending'
        """
    )
    while True:
        rows = cur.fetchmany(args.batch_size)
        if not rows:
            break
        for row in rows:
            old = row["decompiled_old"] or ""
            new = row["decompiled_new"] or ""
            hit = pattern.search(old) or pattern.search(new)
            if hit:
                in_ids.append(row["id"])
            else:
                out_ids.append(row["id"])
        processed += len(rows)
        if processed % (args.batch_size * 4) == 0:
            print(f"  scanned {processed:,} / {total:,}")

    print(f"[prefilter.py] scanned {processed:,}")
    print(f"  prefiltered_in : {len(in_ids):,}")
    print(f"  prefiltered_out: {len(out_ids):,}")

    if args.dry_run:
        print("[prefilter.py] dry-run -- no UPDATE executed.")
        conn.close()
        return 0

    # UPDATE batching
    def batch_update(ids: list[int], status: str) -> None:
        for i in range(0, len(ids), 500):
            chunk = ids[i : i + 500]
            placeholders = ",".join("?" * len(chunk))
            conn.execute(
                f"UPDATE changed_functions SET stage2_status = ? WHERE id IN ({placeholders})",
                [status, *chunk],
            )

    batch_update(in_ids, "prefiltered_in")
    batch_update(out_ids, "prefiltered_out")
    conn.commit()

    print("[prefilter.py] final distribution:")
    for s, n in conn.execute(
        "SELECT stage2_status, COUNT(*) FROM changed_functions GROUP BY stage2_status ORDER BY COUNT(*) DESC"
    ):
        print(f"  - {s}: {n:,}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
