"""Phase 2 Hunter — 공격대상 함수에서 패턴카드 매칭.

MVP 설계 (LLM 없이 토큰 기반 prefilter):
1. 모든 active pattern_cards 로드 (tokens + negative_tokens 포함)
2. 타겟 함수의 decompiled_new에서 카드별 토큰 서브스트링 매칭
3. negative_tokens (safe wrapper) 히트 있으면 제외 (이미 패치됨)
4. 정규화 점수 (hit_weight_sum / total_weight) >= min_score 면 hunt_findings INSERT
5. hunt_findings.is_true_positive=NULL (사람 검토 대기)

LLM 단계는 별도 (hunter-llm 명령, 미구현 — 필요 시 Agent로 확장).

실행:
  python src/stage2/hunter_run.py prefilter --limit 500 --min-score 0.3
  python src/stage2/hunter_run.py report
  python src/stage2/hunter_run.py reset
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
HANDOFF_DIR = Path(__file__).resolve().parents[2] / "data" / "handoff"


def _load_cards(conn: sqlite3.Connection) -> dict[int, dict]:
    c = conn.cursor()
    cards: dict[int, dict] = {}
    for pk, cid, st, sk, mc, summary, sev in c.execute(
        "SELECT id, card_id, source_type, sink_type, missing_check, summary, severity_hint "
        "FROM pattern_cards WHERE status='active'"
    ):
        cards[pk] = {
            "pk": pk, "card_id": cid, "formula": (st, sk, mc),
            "summary": summary or "", "severity": sev,
            "tokens": [], "neg_tokens": [],
        }
    for card_id, token, kind, weight in c.execute(
        "SELECT card_id, token, kind, weight FROM pattern_card_tokens"
    ):
        if card_id in cards:
            cards[card_id]["tokens"].append({"token": token, "kind": kind, "weight": weight or 1.0})
    for card_id, token, vendor_scope in c.execute(
        "SELECT card_id, token, vendor_scope FROM pattern_card_negative_tokens"
    ):
        if card_id in cards:
            cards[card_id]["neg_tokens"].append({"token": token, "vendor_scope": vendor_scope})
    return cards


def cmd_prefilter(args: argparse.Namespace) -> int:
    conn = sqlite3.connect(args.db)
    c = conn.cursor()

    cards = _load_cards(conn)
    print(f"[hunt] loaded {len(cards)} active cards")
    if not cards:
        print("[hunt] no active cards — nothing to hunt.", file=sys.stderr)
        return 1

    # 타겟 함수 조회
    query = """
        SELECT cf.id, cf.binary_name, cf.function_name, cf.decompiled_new,
               cf.similarity,
               fo.vendor, fo.model, fo.version AS old_ver, fn.version AS new_ver,
               ds.id AS session_id
        FROM changed_functions cf
        JOIN bindiff_results br ON cf.bindiff_result_id = br.id
        JOIN changed_files chf ON br.changed_file_id = chf.id
        JOIN diff_sessions ds ON chf.diff_session_id = ds.id
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        JOIN firmware_versions fn ON ds.new_version_id = fn.id
        WHERE cf.decompiled_new IS NOT NULL
          AND LENGTH(cf.decompiled_new) >= 80
    """
    params: list = []
    if args.status:
        query += " AND cf.stage2_status = ?"
        params.append(args.status)
    if args.session:
        query += " AND ds.id = ?"
        params.append(args.session)
    if args.exclude_session:
        query += " AND ds.id != ?"
        params.append(args.exclude_session)
    query += " ORDER BY cf.id LIMIT ?"
    params.append(args.limit)

    targets = c.execute(query, params).fetchall()
    print(f"[hunt] targets: {len(targets)}")
    if not targets:
        print("[hunt] no targets — check --status/--session filters.")
        return 0

    # 중복 방지: 이미 hunt_findings에 (card, function) 있으면 스킵
    existing_pairs = set()
    for r in c.execute("SELECT pattern_card_id, target_function_id FROM hunt_findings"):
        if r[0] is not None and r[1] is not None:
            existing_pairs.add((r[0], r[1]))

    findings = 0
    skipped_existing = 0
    scanned = 0
    for t in targets:
        cf_id, bname, fname, decomp, sim, vendor, model, oldv, newv, sess_id = t
        scanned += 1

        for card in cards.values():
            if (card["pk"], cf_id) in existing_pairs:
                skipped_existing += 1
                continue

            total_w = sum(tok["weight"] for tok in card["tokens"]) or 1.0
            pos_hits = [tok for tok in card["tokens"] if tok["token"] in decomp]
            if not pos_hits:
                continue

            # Negative token 검사 — 벤더 scope 고려
            neg_hits = []
            for n in card["neg_tokens"]:
                if n["token"] not in decomp:
                    continue
                if n["vendor_scope"] is None or n["vendor_scope"].lower() in (vendor or "").lower():
                    neg_hits.append(n)
            if neg_hits:
                continue  # 이미 패치된 패턴

            score = sum(tok["weight"] for tok in pos_hits) / total_w
            if score < args.min_score:
                continue

            target_version = f"{vendor}/{model} v{oldv}->v{newv}"
            match_lines = [f"{tok['token']} [{tok['kind']}]" for tok in pos_hits]
            notes = (
                f"token prefilter {len(pos_hits)}/{len(card['tokens'])} hits "
                f"(w={sum(tok['weight'] for tok in pos_hits):.2f}/{total_w:.2f}, session={sess_id})"
            )
            matched_formula = " + ".join(card["formula"])

            c.execute(
                """
                INSERT INTO hunt_findings (
                    pattern_card_id, target_function_id, target_binary, target_version,
                    match_confidence, match_lines, matched_formula, is_true_positive, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    card["pk"], cf_id, bname, target_version, score,
                    json.dumps(match_lines, ensure_ascii=False),
                    matched_formula, notes,
                ),
            )
            findings += 1

        if scanned % 500 == 0:
            print(f"  scanned {scanned}/{len(targets)}, findings so far: {findings}")

    conn.commit()
    conn.close()
    print(f"[hunt] scanned {scanned} targets")
    print(f"[hunt] inserted {findings} hunt_findings")
    print(f"[hunt] skipped {skipped_existing} (already existed)")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """hunt_findings → data/handoff/hunt_report.md + hunt_findings.jsonl"""
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    HANDOFF_DIR.mkdir(parents=True, exist_ok=True)

    total = c.execute("SELECT COUNT(*) FROM hunt_findings").fetchone()[0]
    tp = c.execute("SELECT COUNT(*) FROM hunt_findings WHERE is_true_positive=1").fetchone()[0]
    fp = c.execute("SELECT COUNT(*) FROM hunt_findings WHERE is_true_positive=0").fetchone()[0]
    pend = c.execute("SELECT COUNT(*) FROM hunt_findings WHERE is_true_positive IS NULL").fetchone()[0]

    lines: list[str] = ["# Hunter 결과 보고서", ""]
    lines.append(f"_생성: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_")
    lines.append("")
    lines.append(f"- 전체 발견: **{total}**")
    lines.append(f"- 사람 검토 대기 (NULL): {pend}")
    lines.append(f"- True Positive: {tp}")
    lines.append(f"- False Positive: {fp}")
    lines.append("")

    # 카드별 매칭 수 Top 20
    lines.append("## 카드별 매칭 수 (Top 20)")
    lines.append("| card_id | severity | matches | TP | FP | precision | formula |")
    lines.append("|---|---|---|---|---|---|---|")
    card_rows = c.execute(
        """
        SELECT pc.card_id, pc.severity_hint,
               COUNT(hf.id) AS matches,
               SUM(CASE WHEN hf.is_true_positive=1 THEN 1 ELSE 0 END) AS tp,
               SUM(CASE WHEN hf.is_true_positive=0 THEN 1 ELSE 0 END) AS fp,
               pc.source_type || ' + ' || pc.missing_check || ' + ' || pc.sink_type AS formula
        FROM pattern_cards pc
        LEFT JOIN hunt_findings hf ON hf.pattern_card_id = pc.id
        WHERE pc.status = 'active'
        GROUP BY pc.id
        HAVING matches > 0
        ORDER BY matches DESC
        LIMIT 20
        """
    ).fetchall()
    for cid, sev, m, tp_, fp_, formula in card_rows:
        total_judged = (tp_ or 0) + (fp_ or 0)
        prec = f"{(tp_ or 0) / total_judged:.2f}" if total_judged else "-"
        lines.append(f"| {cid} | {sev or '-'} | {m} | {tp_ or 0} | {fp_ or 0} | {prec} | `{formula}` |")
    lines.append("")

    # 높은 confidence 샘플 (검토 대상)
    lines.append("## 높은 match_confidence 상위 30 (검토 우선)")
    lines.append("| card_id | target (vendor/binary) | target func | conf | formula |")
    lines.append("|---|---|---|---|---|")
    top_rows = c.execute(
        """
        SELECT pc.card_id, hf.target_version, hf.target_binary, cf.function_name,
               hf.match_confidence, hf.matched_formula
        FROM hunt_findings hf
        JOIN pattern_cards pc ON hf.pattern_card_id = pc.id
        JOIN changed_functions cf ON hf.target_function_id = cf.id
        WHERE hf.is_true_positive IS NULL AND pc.status='active'
        ORDER BY hf.match_confidence DESC
        LIMIT 30
        """
    ).fetchall()
    for cid, tver, tbin, tfn, conf, formula in top_rows:
        vendor_model = (tver or "").split(" v")[0]
        ver_pair = (tver or "")[len(vendor_model):]
        lines.append(
            f"| [{cid}](cards/{cid}.md) | {vendor_model} `{tbin}` {ver_pair} | `{tfn or ''}` | {conf:.2f} | `{formula}` |"
        )
    lines.append("")

    # 크로스벤더 매칭 (카드가 원래 벤더와 다른 벤더에서 매칭된 건 — 가장 흥미로운 케이스)
    lines.append("## 크로스벤더 매칭 (가장 흥미로운 후보)")
    lines.append("| card_id | 원 벤더 | 매칭 벤더/모델 | 매칭 함수 | conf |")
    lines.append("|---|---|---|---|---|")
    cross_rows = c.execute(
        """
        WITH card_origin AS (
            SELECT pc.id AS pc_id, pc.card_id,
                   MIN(fo.vendor) AS orig_vendor
            FROM pattern_cards pc
            JOIN pattern_card_members pcm ON pcm.card_id = pc.id
            JOIN security_patches sp ON pcm.security_patch_id = sp.id
            JOIN changed_functions cf ON sp.changed_function_id = cf.id
            JOIN bindiff_results br ON cf.bindiff_result_id = br.id
            JOIN changed_files chf ON br.changed_file_id = chf.id
            JOIN diff_sessions ds ON chf.diff_session_id = ds.id
            JOIN firmware_versions fo ON ds.old_version_id = fo.id
            WHERE pcm.is_representative=1 AND pc.status='active'
            GROUP BY pc.id
        )
        SELECT co.card_id, co.orig_vendor, hf.target_version, hf.target_binary,
               cf2.function_name, hf.match_confidence
        FROM hunt_findings hf
        JOIN card_origin co ON hf.pattern_card_id = co.pc_id
        JOIN changed_functions cf2 ON hf.target_function_id = cf2.id
        JOIN bindiff_results br2 ON cf2.bindiff_result_id = br2.id
        JOIN changed_files chf2 ON br2.changed_file_id = chf2.id
        JOIN diff_sessions ds2 ON chf2.diff_session_id = ds2.id
        JOIN firmware_versions fo2 ON ds2.old_version_id = fo2.id
        WHERE fo2.vendor != co.orig_vendor
          AND hf.is_true_positive IS NULL
        ORDER BY hf.match_confidence DESC
        LIMIT 20
        """
    ).fetchall()
    if cross_rows:
        for cid, orig, tver, tbin, tfn, conf in cross_rows:
            lines.append(f"| [{cid}](cards/{cid}.md) | {orig} | {tver} `{tbin}` | `{tfn or ''}` | {conf:.2f} |")
    else:
        lines.append("| _(아직 없음)_ | | | | |")
    lines.append("")

    # 벤더별 매칭 분포
    lines.append("## 타겟 벤더별 매칭")
    lines.append("| vendor | findings |")
    lines.append("|---|---|")
    for r in c.execute("""
        SELECT
            SUBSTR(hf.target_version, 1, INSTR(hf.target_version, '/')-1) AS vendor,
            COUNT(*) AS n
        FROM hunt_findings hf
        WHERE hf.is_true_positive IS NULL
        GROUP BY vendor ORDER BY n DESC
    """):
        lines.append(f"| {r[0] or '(unknown)'} | {r[1]} |")
    lines.append("")

    report_md = "\n".join(lines)
    (HANDOFF_DIR / "hunt_report.md").write_text(report_md, encoding="utf-8")
    print(f"[hunt] report -> {HANDOFF_DIR / 'hunt_report.md'}")

    # JSONL export (기계 읽기용)
    jsonl_path = HANDOFF_DIR / "hunt_findings.jsonl"
    n = 0
    with jsonl_path.open("w", encoding="utf-8") as f:
        for row in c.execute(
            """
            SELECT pc.card_id, pc.source_type, pc.sink_type, pc.missing_check,
                   pc.severity_hint, hf.target_version, hf.target_binary,
                   cf.function_name, cf.old_address, cf.new_address,
                   hf.match_confidence, hf.matched_formula, hf.match_lines, hf.notes
            FROM hunt_findings hf
            JOIN pattern_cards pc ON hf.pattern_card_id = pc.id
            JOIN changed_functions cf ON hf.target_function_id = cf.id
            WHERE pc.status = 'active'
            ORDER BY hf.match_confidence DESC
            """
        ):
            obj = {
                "card_id": row[0],
                "formula": {"source_type": row[1], "sink_type": row[2], "missing_check": row[3]},
                "severity_hint": row[4],
                "target_version": row[5],
                "target_binary": row[6],
                "target_function": row[7],
                "addresses": {"old": row[8], "new": row[9]},
                "match_confidence": row[10],
                "matched_formula": row[11],
                "match_lines": json.loads(row[12]) if row[12] else [],
                "notes": row[13],
            }
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            n += 1
    print(f"[hunt] {n} rows -> {jsonl_path}")
    conn.close()
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    if not args.yes:
        print("[hunt] --yes 필요 (안전장치).", file=sys.stderr)
        return 1
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    n = c.execute("SELECT COUNT(*) FROM hunt_findings").fetchone()[0]
    c.execute("DELETE FROM hunt_findings")
    conn.commit()
    conn.close()
    print(f"[hunt] deleted {n} hunt_findings rows.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("prefilter", help="토큰 기반 prefilter로 hunt_findings 생성")
    p1.add_argument("--limit", type=int, default=500, help="스캔할 타겟 함수 수")
    p1.add_argument("--min-score", type=float, default=0.30,
                    help="정규화 토큰 점수 임계 (기본 0.30)")
    p1.add_argument("--status", type=str, default=None,
                    help="changed_functions.stage2_status 필터 (기본: 제한 없음)")
    p1.add_argument("--session", type=int, default=None, help="특정 diff_session_id")
    p1.add_argument("--exclude-session", type=int, default=None,
                    help="특정 diff_session_id 제외")

    p2 = sub.add_parser("report", help="data/handoff/hunt_report.md + JSONL 생성")

    p3 = sub.add_parser("reset", help="hunt_findings 전체 삭제")
    p3.add_argument("--yes", action="store_true")

    args = ap.parse_args()
    if args.cmd == "prefilter":
        return cmd_prefilter(args)
    elif args.cmd == "report":
        return cmd_report(args)
    elif args.cmd == "reset":
        return cmd_reset(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
