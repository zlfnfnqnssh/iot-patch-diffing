"""
Patch-Learner SQLite DB 초기화 스크립트.

Usage:
    python init_db.py [--db-path <path>]

기본 DB 경로: src/db/patch_learner.db
"""

import sqlite3
import sys
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).parent / "patch_learner.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_db(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """DB 생성 및 스키마 적용."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema_sql)
    conn.commit()

    print(f"DB initialized: {db_path}")
    return conn


if __name__ == "__main__":
    path = Path(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--db-path" else DEFAULT_DB_PATH
    conn = init_db(path)

    # 테이블 목록 출력
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    print(f"\nTables ({len(tables)}):")
    for t in tables:
        count = conn.execute(f"SELECT COUNT(*) FROM [{t['name']}]").fetchone()[0]
        print(f"  {t['name']}: {count} rows")

    conn.close()
