"""Diff sessions + findings API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from .db import get_conn, rows_to_dicts

router = APIRouter(prefix="/api", tags=["sessions"])


@router.get("/sessions")
def list_sessions(limit: int = 200):
    with get_conn() as conn:
        c = conn.cursor()
        # One-shot aggregate: session_id -> {funcs, queued, drafted}
        agg_sql = """
          SELECT chf.diff_session_id AS sid,
                 COUNT(cf.id) AS funcs,
                 SUM(CASE WHEN cf.stage2_status='prefiltered_in' THEN 1 ELSE 0 END) AS queued,
                 SUM(CASE WHEN cf.stage2_status LIKE 'drafted_%' THEN 1 ELSE 0 END) AS drafted
          FROM changed_files chf
          JOIN bindiff_results br ON br.changed_file_id=chf.id
          JOIN changed_functions cf ON cf.bindiff_result_id=br.id
          GROUP BY chf.diff_session_id
        """
        agg: dict[int, dict] = {r[0]: {"funcs": r[1], "queued": r[2], "drafted": r[3]} for r in c.execute(agg_sql)}

        files_sql = "SELECT diff_session_id, COUNT(*) FROM changed_files GROUP BY diff_session_id"
        files: dict[int, int] = {r[0]: r[1] for r in c.execute(files_sql)}

        sess_sql = """
          SELECT ds.id AS session_id, fo.vendor, fo.model,
                 fo.version AS old_version, fn.version AS new_version,
                 ds.advisory, ds.status, ds.created_at
          FROM diff_sessions ds
          JOIN firmware_versions fo ON ds.old_version_id = fo.id
          JOIN firmware_versions fn ON ds.new_version_id = fn.id
          ORDER BY ds.id DESC LIMIT ?
        """
        sessions = []
        for r in c.execute(sess_sql, (limit,)):
            d = dict(r)
            a = agg.get(d["session_id"], {})
            d["funcs"] = a.get("funcs", 0) or 0
            d["queued"] = a.get("queued", 0) or 0
            d["drafted"] = a.get("drafted", 0) or 0
            d["files"] = files.get(d["session_id"], 0)
            sessions.append(d)
        return {"count": len(sessions), "sessions": sessions}


@router.get("/sessions/{sid}")
def session_detail(sid: int):
    with get_conn() as conn:
        c = conn.cursor()
        row = c.execute("""
          SELECT ds.id, fo.vendor, fo.model,
                 fo.version AS old_version, fn.version AS new_version,
                 ds.advisory, ds.status, ds.created_at, ds.notes
          FROM diff_sessions ds
          JOIN firmware_versions fo ON ds.old_version_id = fo.id
          JOIN firmware_versions fn ON ds.new_version_id = fn.id
          WHERE ds.id = ?
        """, (sid,)).fetchone()
        if not row:
            raise HTTPException(404, f"session {sid} not found")
        out = dict(row)

        out["binaries"] = rows_to_dicts(c.execute("""
          SELECT cf.binary_name, COUNT(*) AS funcs,
                 SUM(CASE WHEN cf.stage2_status LIKE 'drafted_%' THEN 1 ELSE 0 END) AS drafted,
                 SUM(CASE WHEN cf.stage2_status='prefiltered_in' THEN 1 ELSE 0 END) AS queued
          FROM changed_functions cf
          JOIN bindiff_results br ON cf.bindiff_result_id=br.id
          JOIN changed_files chf ON br.changed_file_id=chf.id
          WHERE chf.diff_session_id=?
          GROUP BY cf.binary_name ORDER BY funcs DESC
        """, (sid,)).fetchall())

        out["recent_sec_patches"] = rows_to_dicts(c.execute("""
          SELECT sp.id, cf.binary_name, cf.function_name, cf.old_address, cf.new_address,
                 sp.confidence, sp.vuln_type, sp.severity, sp.known_cve
          FROM security_patches sp
          JOIN changed_functions cf ON sp.changed_function_id=cf.id
          JOIN bindiff_results br ON cf.bindiff_result_id=br.id
          JOIN changed_files chf ON br.changed_file_id=chf.id
          WHERE chf.diff_session_id=? AND sp.is_security_patch=1
          ORDER BY sp.confidence DESC LIMIT 50
        """, (sid,)).fetchall())
        return out


@router.get("/findings")
def list_findings(
    card_pk: int | None = None,
    card_id: str | None = None,
    target_binary: str | None = None,
    min_score: float | None = None,
    limit: int = 200,
):
    where = ["1=1"]
    params: list = []
    if card_pk:
        where.append("hf.pattern_card_id = ?")
        params.append(card_pk)
    if card_id:
        where.append("pc.card_id = ?")
        params.append(card_id)
    if target_binary:
        where.append("hf.target_binary = ?")
        params.append(target_binary)
    if min_score is not None:
        where.append("hf.match_confidence >= ?")
        params.append(min_score)

    sql = f"""
      SELECT hf.id, hf.pattern_card_id, pc.card_id,
             hf.target_binary, hf.target_version,
             hf.match_confidence, hf.matched_formula, hf.notes,
             cf.function_name, cf.old_address, cf.new_address,
             hf.created_at, hf.is_true_positive
      FROM hunt_findings hf
      LEFT JOIN pattern_cards pc ON hf.pattern_card_id = pc.id
      LEFT JOIN changed_functions cf ON hf.target_function_id = cf.id
      WHERE {' AND '.join(where)}
      ORDER BY hf.match_confidence DESC, hf.id DESC
      LIMIT ?
    """
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return {"count": len(rows), "findings": rows_to_dicts(rows)}
