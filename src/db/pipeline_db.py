"""
파이프라인 ↔ DB 연동 모듈.

bindiff_pipeline.py의 각 단계 결과를 SQLite DB에 자동 저장한다.
팀원(서동민)의 DB 중심 설계 + 팀장(강지혁)의 IDA 1-pass 방식 통합.

Usage:
    from db.pipeline_db import PipelineDB

    db = PipelineDB()  # 기본 경로: src/db/patch_learner.db
    session_id = db.create_session("synology", "BC500", "1.0.5", "1.0.6")
    db.save_changed_files(session_id, compare_result, old_dir, new_dir)
    db.save_bindiff_results(session_id, binary_name, bindiff_result)
    db.save_changed_functions(session_id, binary_name, bindiff_result, old_funcs, new_funcs)
"""

import json
import sqlite3
from pathlib import Path

try:
    from .init_db import init_db, DEFAULT_DB_PATH
except ImportError:
    from init_db import init_db, DEFAULT_DB_PATH


class PipelineDB:
    """파이프라인 결과를 DB에 저장하는 래퍼 클래스."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.conn = init_db(db_path)

    def close(self):
        self.conn.close()

    # ── firmware_versions ─────────────────────────────────────────

    def _get_or_create_version(self, vendor: str, model: str, version: str,
                               filename: str = None, sha256: str = None,
                               extracted_path: str = None) -> int:
        """firmware_versions 레코드 조회 또는 생성. ID 반환."""
        row = self.conn.execute(
            "SELECT id FROM firmware_versions WHERE vendor=? AND model=? AND version=?",
            (vendor, model, version)
        ).fetchone()
        if row:
            return row["id"]

        cur = self.conn.execute(
            """INSERT INTO firmware_versions (vendor, model, version, filename, sha256, extracted_path)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (vendor, model, version, filename, sha256, extracted_path)
        )
        self.conn.commit()
        return cur.lastrowid

    # ── diff_sessions ─────────────────────────────────────────────

    def create_session(self, vendor: str, model: str,
                       old_version: str, new_version: str,
                       advisory: str = None) -> int:
        """디핑 세션 생성. session_id 반환."""
        old_id = self._get_or_create_version(vendor, model, old_version)
        new_id = self._get_or_create_version(vendor, model, new_version)

        # 기존 세션 있으면 재사용
        row = self.conn.execute(
            "SELECT id FROM diff_sessions WHERE old_version_id=? AND new_version_id=?",
            (old_id, new_id)
        ).fetchone()
        if row:
            print(f"[DB] 기존 세션 재사용: session_id={row['id']}")
            return row["id"]

        cur = self.conn.execute(
            """INSERT INTO diff_sessions (old_version_id, new_version_id, advisory, status)
               VALUES (?, ?, ?, 'pending')""",
            (old_id, new_id, advisory)
        )
        self.conn.commit()
        session_id = cur.lastrowid
        print(f"[DB] 새 세션 생성: session_id={session_id}")
        return session_id

    def update_session_status(self, session_id: int, status: str,
                              total_changed_binaries: int = None,
                              total_changed_texts: int = None):
        """세션 상태 업데이트."""
        updates = ["status=?"]
        params = [status]
        if total_changed_binaries is not None:
            updates.append("total_changed_binaries=?")
            params.append(total_changed_binaries)
        if total_changed_texts is not None:
            updates.append("total_changed_texts=?")
            params.append(total_changed_texts)
        params.append(session_id)
        self.conn.execute(
            f"UPDATE diff_sessions SET {', '.join(updates)} WHERE id=?", params
        )
        self.conn.commit()

    # ── changed_files ─────────────────────────────────────────────

    def save_changed_files(self, session_id: int, compare_result: dict,
                           old_dir: Path, new_dir: Path,
                           binary_files: list[str], text_files: list[str]) -> int:
        """해시 비교 결과를 changed_files 테이블에 저장. 저장 건수 반환."""
        # 이미 저장된 게 있으면 스킵
        existing = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM changed_files WHERE diff_session_id=?",
            (session_id,)
        ).fetchone()["cnt"]
        if existing > 0:
            print(f"[DB] changed_files 이미 {existing}건 존재, 스킵")
            return existing

        count = 0
        binary_set = set(binary_files)
        text_set = set(text_files)

        for rel in compare_result.get("changed", []):
            if rel in binary_set:
                file_type = "binary"
            elif rel in text_set:
                file_type = "text"
            else:
                file_type = "unknown"

            old_path = old_dir / rel
            new_path = new_dir / rel
            old_size = old_path.stat().st_size if old_path.exists() else None
            new_size = new_path.stat().st_size if new_path.exists() else None

            self.conn.execute(
                """INSERT INTO changed_files
                   (diff_session_id, file_path, file_type, change_type,
                    old_size, new_size)
                   VALUES (?, ?, ?, 'modified', ?, ?)""",
                (session_id, rel, file_type, old_size, new_size)
            )
            count += 1

        for rel in compare_result.get("added", []):
            new_path = new_dir / rel
            new_size = new_path.stat().st_size if new_path.exists() else None
            self.conn.execute(
                """INSERT INTO changed_files
                   (diff_session_id, file_path, file_type, change_type, new_size)
                   VALUES (?, ?, 'unknown', 'added', ?)""",
                (session_id, rel, new_size)
            )
            count += 1

        for rel in compare_result.get("removed", []):
            self.conn.execute(
                """INSERT INTO changed_files
                   (diff_session_id, file_path, file_type, change_type)
                   VALUES (?, ?, 'unknown', 'removed')""",
                (session_id, rel)
            )
            count += 1

        self.conn.commit()
        print(f"[DB] changed_files: {count}건 저장")
        return count

    # ── bindiff_results ───────────────────────────────────────────

    def _get_changed_file_id(self, session_id: int, file_path: str) -> int | None:
        """changed_files에서 file_path로 id 조회."""
        row = self.conn.execute(
            "SELECT id FROM changed_files WHERE diff_session_id=? AND file_path=?",
            (session_id, file_path)
        ).fetchone()
        return row["id"] if row else None

    def save_bindiff_result(self, session_id: int, rel_path: str,
                            bindiff_result: dict,
                            bindiff_file_path: str = None) -> int | None:
        """단일 바이너리의 BinDiff 결과를 저장. bindiff_result_id 반환."""
        changed_file_id = self._get_changed_file_id(session_id, rel_path)
        if not changed_file_id:
            return None

        # 이미 있으면 스킵
        row = self.conn.execute(
            "SELECT id FROM bindiff_results WHERE changed_file_id=?",
            (changed_file_id,)
        ).fetchone()
        if row:
            return row["id"]

        cur = self.conn.execute(
            """INSERT INTO bindiff_results
               (changed_file_id, bindiff_path,
                total_functions, matched_functions, changed_functions,
                overall_similarity)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (changed_file_id,
             bindiff_file_path,
             bindiff_result.get("total_matched", 0),
             bindiff_result.get("identical", 0) + bindiff_result.get("changed_count", 0),
             bindiff_result.get("changed_count", 0),
             bindiff_result.get("overall_similarity", 0))
        )
        self.conn.commit()
        return cur.lastrowid

    # ── changed_functions ─────────────────────────────────────────

    def save_changed_functions(self, bindiff_result_id: int,
                               binary_name: str,
                               bindiff_result: dict,
                               old_funcs: dict = None,
                               new_funcs: dict = None) -> int:
        """변경된 함수 목록을 DB에 저장. old/new pseudocode 포함. 저장 건수 반환."""
        # 이미 있으면 스킵
        existing = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM changed_functions WHERE bindiff_result_id=?",
            (bindiff_result_id,)
        ).fetchone()["cnt"]
        if existing > 0:
            return existing

        count = 0
        for fn in bindiff_result.get("changed_functions", []):
            name_old = fn.get("name_old", "")
            name_new = fn.get("name_new", "")

            # pseudocode 가져오기 (JSON 캐시에서)
            decompiled_old = None
            decompiled_new = None
            if old_funcs and name_old in old_funcs:
                decompiled_old = old_funcs[name_old].get("pseudocode", "")
            if new_funcs and name_new in new_funcs:
                decompiled_new = new_funcs[name_new].get("pseudocode", "")

            self.conn.execute(
                """INSERT INTO changed_functions
                   (bindiff_result_id, binary_name, function_name,
                    old_address, new_address, similarity, confidence,
                    basic_blocks, instructions,
                    decompiled_old, decompiled_new)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (bindiff_result_id, binary_name,
                 name_old or name_new,
                 fn.get("addr_old"), fn.get("addr_new"),
                 fn.get("similarity", 0), fn.get("confidence", 0),
                 fn.get("basicblocks", 0), fn.get("instructions", 0),
                 decompiled_old, decompiled_new)
            )
            count += 1

        self.conn.commit()
        return count

    # ── 통계 ──────────────────────────────────────────────────────

    def print_session_stats(self, session_id: int):
        """세션의 DB 저장 현황 출력."""
        cf = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM changed_files WHERE diff_session_id=?",
            (session_id,)
        ).fetchone()["cnt"]

        # bindiff_results는 changed_files를 통해 연결
        br = self.conn.execute(
            """SELECT COUNT(*) as cnt FROM bindiff_results br
               JOIN changed_files cf ON br.changed_file_id = cf.id
               WHERE cf.diff_session_id=?""",
            (session_id,)
        ).fetchone()["cnt"]

        # changed_functions도 같은 경로
        fn = self.conn.execute(
            """SELECT COUNT(*) as cnt FROM changed_functions cfn
               JOIN bindiff_results br ON cfn.bindiff_result_id = br.id
               JOIN changed_files cf ON br.changed_file_id = cf.id
               WHERE cf.diff_session_id=?""",
            (session_id,)
        ).fetchone()["cnt"]

        sp = self.conn.execute(
            """SELECT COUNT(*) as cnt FROM security_patches sp
               JOIN changed_functions cfn ON sp.changed_function_id = cfn.id
               JOIN bindiff_results br ON cfn.bindiff_result_id = br.id
               JOIN changed_files cf ON br.changed_file_id = cf.id
               WHERE cf.diff_session_id=?""",
            (session_id,)
        ).fetchone()["cnt"]

        print(f"\n[DB 현황] session_id={session_id}")
        print(f"  changed_files:     {cf}")
        print(f"  bindiff_results:   {br}")
        print(f"  changed_functions: {fn}")
        print(f"  security_patches:  {sp}")
