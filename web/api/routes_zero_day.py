"""Zero-day runs + verdicts API."""
from __future__ import annotations

import asyncio
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from .db import get_conn, rows_to_dicts, DB_PATH
import sqlite3

router = APIRouter(prefix="/api/zero-day", tags=["zero_day"])


@router.get("/runs")
def list_runs():
    with get_conn() as conn:
        rows = conn.execute("""
          SELECT id, name, target_vendor, target_model, target_version,
                 target_binary, source_json_path,
                 total_functions, prefiltered_functions, processed_functions,
                 vuln_candidates, status,
                 started_at, updated_at, completed_at, notes
          FROM zero_day_runs ORDER BY id DESC
        """).fetchall()
        return {"count": len(rows), "runs": rows_to_dicts(rows)}


@router.get("/runs/{run_id}")
def run_detail(run_id: int):
    with get_conn() as conn:
        c = conn.cursor()
        run = c.execute("SELECT * FROM zero_day_runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            raise HTTPException(404, f"run {run_id} not found")
        out = dict(run)
        out["stage_status"] = rows_to_dicts(c.execute("""
          SELECT stage_status, COUNT(*) AS n
          FROM zero_day_functions WHERE run_id=? GROUP BY stage_status
        """, (run_id,)).fetchall())
        out["severity_dist"] = rows_to_dicts(c.execute("""
          SELECT COALESCE(severity_hint,'unset') AS severity, COUNT(*) AS n
          FROM zero_day_verdicts WHERE run_id=? AND is_vulnerable=1
          GROUP BY severity_hint ORDER BY n DESC
        """, (run_id,)).fetchall())
        out["top_verdicts"] = rows_to_dicts(c.execute("""
          SELECT id, function_addr, function_name, confidence,
                 severity_hint, vuln_type, source_type, sink_type, missing_check,
                 matched_card_pk, matched_score, needs_human_review, reviewed
          FROM zero_day_verdicts
          WHERE run_id=? AND is_vulnerable=1
          ORDER BY confidence DESC LIMIT 20
        """, (run_id,)).fetchall())
        return out


@router.get("/runs/{run_id}/verdicts")
def list_verdicts(
    run_id: int,
    vuln: int | None = None,          # 0 / 1
    min_conf: float | None = None,
    matched_card_pk: int | None = None,
    reviewed: int | None = None,
    limit: int = 200,
):
    where = ["run_id=?"]
    params: list = [run_id]
    if vuln is not None:
        where.append("is_vulnerable=?")
        params.append(vuln)
    if min_conf is not None:
        where.append("confidence >= ?")
        params.append(min_conf)
    if matched_card_pk is not None:
        where.append("matched_card_pk=?")
        params.append(matched_card_pk)
    if reviewed is not None:
        where.append("reviewed=?")
        params.append(reviewed)

    sql = f"""
      SELECT v.*, pc.card_id AS matched_card_text
      FROM zero_day_verdicts v
      LEFT JOIN pattern_cards pc ON v.matched_card_pk = pc.id
      WHERE {' AND '.join(where)}
      ORDER BY v.confidence DESC, v.id DESC
      LIMIT ?
    """
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return {"count": len(rows), "verdicts": rows_to_dicts(rows)}


@router.get("/verdicts/{vid}")
def verdict_detail(vid: int):
    with get_conn() as conn:
        c = conn.cursor()
        v = c.execute("""
          SELECT v.*, pc.card_id AS matched_card_text,
                 pc.source_type AS card_source_type, pc.sink_type AS card_sink_type,
                 pc.missing_check AS card_missing_check, pc.summary AS card_summary,
                 f.pseudocode, f.disasm, f.calls, f.strings, f.size
          FROM zero_day_verdicts v
          LEFT JOIN pattern_cards pc ON v.matched_card_pk = pc.id
          LEFT JOIN zero_day_functions f ON v.function_id = f.id
          WHERE v.id = ?
        """, (vid,)).fetchone()
        if not v:
            raise HTTPException(404, f"verdict {vid} not found")
        return dict(v)


class ReviewUpdate(BaseModel):
    reviewed: bool = True
    human_verdict: str | None = None   # confirmed_vuln / false_positive / needs_more_info
    human_note: str | None = None


@router.post("/verdicts/{vid}/review")
def update_review(vid: int, body: ReviewUpdate):
    # Separate write-enabled connection
    conn = sqlite3.connect(str(DB_PATH), timeout=5)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE zero_day_verdicts SET reviewed=?, human_verdict=?, human_note=? WHERE id=?",
            (1 if body.reviewed else 0, body.human_verdict, body.human_note, vid),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, f"verdict {vid} not found")
        conn.commit()
        return {"ok": True, "vid": vid, "reviewed": body.reviewed}
    finally:
        conn.close()


@router.get("/runs/{run_id}/stream")
async def run_stream(run_id: int):
    """Server-Sent Events stream of run progress (updates every 2s)."""
    async def gen():
        while True:
            try:
                with get_conn() as conn:
                    r = conn.execute(
                        "SELECT total_functions, prefiltered_functions, processed_functions, vuln_candidates, status FROM zero_day_runs WHERE id=?",
                        (run_id,),
                    ).fetchone()
                if r is None:
                    yield f"event: error\ndata: {json.dumps({'error': 'run not found'})}\n\n"
                    return
                payload = dict(r)
                yield f"data: {json.dumps(payload)}\n\n"
                if payload["status"] in ("done", "error"):
                    return
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                return
            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream")
