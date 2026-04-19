"""Read-only SQLite access helpers."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from contextlib import contextmanager

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"


@contextmanager
def get_conn(readonly: bool = True):
    """Yield a SQLite connection. Read-only by default (safer for a dashboard)."""
    uri = f"file:{DB_PATH.as_posix()}" + ("?mode=ro" if readonly else "")
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=5)
    conn.row_factory = sqlite3.Row
    if readonly:
        conn.execute("PRAGMA query_only = 1")
    try:
        yield conn
    finally:
        conn.close()


def rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]
