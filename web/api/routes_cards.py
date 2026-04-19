"""Pattern cards API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from .db import get_conn, rows_to_dicts

router = APIRouter(prefix="/api/cards", tags=["cards"])


@router.get("")
def list_cards(
    severity: str | None = None,
    status: str = "active",
    source_type: str | None = None,
    sink_type: str | None = None,
    has_cve: bool = False,
    q: str | None = None,
    limit: int = 200,
):
    where = ["1=1"]
    params: list = []
    if status and status != "all":
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("severity_hint = ?")
        params.append(severity)
    if source_type:
        where.append("source_type = ?")
        params.append(source_type)
    if sink_type:
        where.append("sink_type = ?")
        params.append(sink_type)
    if has_cve:
        where.append("cve_similar IS NOT NULL AND cve_similar != ''")
    if q:
        where.append("(summary LIKE ? OR long_description LIKE ? OR snippet_origin LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]

    sql = f"""
        SELECT pc.id AS pk, pc.card_id, pc.source_type, pc.sink_type, pc.missing_check,
               pc.severity_hint, pc.cve_similar, pc.status,
               pc.summary, pc.snippet_origin,
               (SELECT COUNT(*) FROM pattern_card_members m WHERE m.card_id = pc.id) AS member_count,
               (SELECT COUNT(*) FROM pattern_card_tokens t WHERE t.card_id = pc.id) AS token_count,
               pc.created_at, pc.updated_at
        FROM pattern_cards pc
        WHERE {' AND '.join(where)}
        ORDER BY pc.id
        LIMIT ?
    """
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return {"count": len(rows), "cards": rows_to_dicts(rows)}


@router.get("/{pk}")
def card_detail(pk: int):
    with get_conn() as conn:
        c = conn.cursor()
        card = c.execute("SELECT * FROM pattern_cards WHERE id = ?", (pk,)).fetchone()
        if not card:
            raise HTTPException(404, f"card pk={pk} not found")
        out = dict(card)
        out["tokens"] = rows_to_dicts(c.execute(
            "SELECT token, kind, weight FROM pattern_card_tokens WHERE card_id = ?", (pk,)
        ).fetchall())
        out["negative_tokens"] = rows_to_dicts(c.execute(
            "SELECT token, vendor_scope, note FROM pattern_card_negative_tokens WHERE card_id = ?", (pk,)
        ).fetchall())
        try:
            out["grep_patterns"] = rows_to_dicts(c.execute(
                "SELECT pattern, note FROM pattern_card_grep_patterns WHERE card_id = ?", (pk,)
            ).fetchall())
        except Exception:
            out["grep_patterns"] = []
        out["members"] = rows_to_dicts(c.execute("""
            SELECT pcm.security_patch_id, pcm.is_representative, pcm.note,
                   sp.confidence, sp.vuln_type, sp.severity, sp.known_cve,
                   cf.binary_name, cf.function_name, cf.old_address, cf.new_address,
                   fo.vendor, fo.model, fo.version AS old_version, fn.version AS new_version,
                   ds.id AS session_id
            FROM pattern_card_members pcm
            LEFT JOIN security_patches sp ON pcm.security_patch_id = sp.id
            LEFT JOIN changed_functions cf ON sp.changed_function_id = cf.id
            LEFT JOIN bindiff_results br ON cf.bindiff_result_id = br.id
            LEFT JOIN changed_files chf ON br.changed_file_id = chf.id
            LEFT JOIN diff_sessions ds ON chf.diff_session_id = ds.id
            LEFT JOIN firmware_versions fo ON ds.old_version_id = fo.id
            LEFT JOIN firmware_versions fn ON ds.new_version_id = fn.id
            WHERE pcm.card_id = ?
        """, (pk,)).fetchall())
        out["hunt_findings_count"] = c.execute(
            "SELECT COUNT(*) FROM hunt_findings WHERE pattern_card_id = ?", (pk,)
        ).fetchone()[0]
        out["zero_day_verdicts_count"] = c.execute(
            "SELECT COUNT(*) FROM zero_day_verdicts WHERE matched_card_pk = ?", (pk,)
        ).fetchone()[0]
        return out
