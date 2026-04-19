"""Dashboard / home page API."""
from __future__ import annotations

from fastapi import APIRouter
from .db import get_conn, rows_to_dicts

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
def dashboard_snapshot():
    with get_conn() as conn:
        c = conn.cursor()
        out = {}

        # stage2 distribution
        dist = c.execute("""
            SELECT stage2_status, COUNT(*) AS n
            FROM changed_functions GROUP BY stage2_status ORDER BY n DESC
        """).fetchall()
        out["stage2_status"] = rows_to_dicts(dist)

        # table totals
        out["totals"] = {}
        for t in (
            "firmware_versions", "diff_sessions", "changed_files", "bindiff_results",
            "changed_functions", "security_patches", "pattern_cards",
            "pattern_card_members", "hunt_findings",
            "zero_day_runs", "zero_day_functions", "zero_day_verdicts",
        ):
            try:
                out["totals"][t] = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except Exception:
                out["totals"][t] = None

        out["totals"]["pattern_cards_active"] = c.execute(
            "SELECT COUNT(*) FROM pattern_cards WHERE status='active'"
        ).fetchone()[0]
        out["totals"]["security_patches_positive"] = c.execute(
            "SELECT COUNT(*) FROM security_patches WHERE is_security_patch=1"
        ).fetchone()[0]

        # card severity breakdown (active only)
        out["cards_severity"] = rows_to_dicts(c.execute("""
            SELECT COALESCE(severity_hint,'unset') AS severity, COUNT(*) AS n
            FROM pattern_cards WHERE status='active'
            GROUP BY severity_hint ORDER BY n DESC
        """).fetchall())

        # top 10 sessions with pending workload
        out["top_pending_sessions"] = rows_to_dicts(c.execute("""
            SELECT ds.id AS session_id, fo.vendor, fo.model,
                   fo.version AS old_version, fn.version AS new_version,
                   COUNT(cf.id) AS remaining
            FROM diff_sessions ds
            JOIN firmware_versions fo ON ds.old_version_id = fo.id
            JOIN firmware_versions fn ON ds.new_version_id = fn.id
            JOIN changed_files chf ON chf.diff_session_id = ds.id
            JOIN bindiff_results br ON br.changed_file_id = chf.id
            JOIN changed_functions cf ON cf.bindiff_result_id = br.id
            WHERE cf.stage2_status='prefiltered_in'
            GROUP BY ds.id ORDER BY remaining DESC LIMIT 10
        """).fetchall())

        # recent zero_day_runs
        out["recent_runs"] = rows_to_dicts(c.execute("""
            SELECT id, name, target_vendor, target_model, target_version,
                   status, total_functions, prefiltered_functions,
                   processed_functions, vuln_candidates, updated_at
            FROM zero_day_runs ORDER BY id DESC LIMIT 10
        """).fetchall())

        return out
