"""배치 종료 후 DB의 pattern_cards를 사람이 읽을 수 있는 MD 파일로 export.

DB는 gitignore 되어 있으므로 팀 공유는 이 MD 파일들을 git에 올려서 진행.

실행:
    python src/stage2/export_batch.py

생성:
    data/handoff/cards/P-001.md        (카드 1장 = MD 1개)
    data/handoff/cards/P-002.md
    ...
    data/handoff/progress.md           (전체 진행 요약, 배치 로그)
    data/handoff/cards/index.md        (카드 목록 인덱스)

대상: status='active' 카드만. retired/superseded는 제외.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "Patch-Learner-main" / "src" / "db" / "patch_learner.db"
HANDOFF_DIR = Path(__file__).resolve().parents[2] / "data" / "handoff"
CARDS_DIR = HANDOFF_DIR / "cards"


def fmt_snippet(s: str | None) -> str:
    if not s:
        return "_(없음)_"
    # 코드 블록 안전 처리
    fence = "```"
    return f"{fence}c\n{s}\n{fence}"


def render_card_md(conn: sqlite3.Connection, card: dict) -> str:
    c = conn.cursor()
    card_id = card["card_id"]
    pc_id = card["id"]

    # tokens
    tokens = c.execute(
        "SELECT token, kind, weight FROM pattern_card_tokens WHERE card_id = ? ORDER BY weight DESC, kind",
        (pc_id,),
    ).fetchall()
    # negative tokens
    neg = c.execute(
        "SELECT token, vendor_scope, note FROM pattern_card_negative_tokens WHERE card_id = ?",
        (pc_id,),
    ).fetchall()
    # grep patterns
    greps = c.execute(
        "SELECT pattern, pattern_flavor FROM pattern_card_grep_patterns WHERE card_id = ?",
        (pc_id,),
    ).fetchall()
    # members
    members = c.execute(
        """
        SELECT pcm.is_representative, cf.binary_name, cf.function_name,
               fo.vendor, fo.model, fo.version AS old_ver, fn.version AS new_ver,
               sp.confidence, sp.severity, sp.needs_human_review
        FROM pattern_card_members pcm
        JOIN security_patches sp ON pcm.security_patch_id = sp.id
        JOIN changed_functions cf ON sp.changed_function_id = cf.id
        JOIN bindiff_results br ON cf.bindiff_result_id = br.id
        JOIN changed_files chf ON br.changed_file_id = chf.id
        JOIN diff_sessions ds ON chf.diff_session_id = ds.id
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        JOIN firmware_versions fn ON ds.new_version_id = fn.id
        WHERE pcm.card_id = ?
        ORDER BY pcm.is_representative DESC, pcm.id ASC
        """,
        (pc_id,),
    ).fetchall()
    # stats
    stats = c.execute(
        "SELECT matches_total, true_positives, false_positives FROM pattern_card_stats WHERE card_id = ?",
        (pc_id,),
    ).fetchone()

    lines: list[str] = []
    lines.append(f"# {card_id}")
    lines.append("")
    lines.append(f"- **status**: {card['status']} (v{card['version']})")
    lines.append(f"- **공식**: `{card['source_type']}` → `{card['missing_check']}` 부재 → `{card['sink_type']}`")
    if card.get("source_detail") or card.get("sink_detail"):
        detail_parts = []
        if card.get("source_detail"):
            detail_parts.append(f"source_detail=`{card['source_detail']}`")
        if card.get("sink_detail"):
            detail_parts.append(f"sink_detail=`{card['sink_detail']}`")
        lines.append(f"  - " + ", ".join(detail_parts))
    lines.append(f"- **severity_hint**: {card.get('severity_hint') or '(없음)'}")
    if card.get("cve_similar"):
        lines.append(f"- **cve_similar**: {card['cve_similar']}")
    if card.get("advisory"):
        lines.append(f"- **advisory**: {card['advisory']}")
    lines.append(f"- **origin**: `{card.get('snippet_origin') or '(없음)'}`  (언어: {card.get('snippet_language', 'decompiled_c')})")
    lines.append("")

    lines.append("## 요약")
    lines.append("")
    lines.append(card["summary"] or "_(없음)_")
    lines.append("")

    if card.get("long_description"):
        lines.append("## 상세 설명")
        lines.append("")
        lines.append(card["long_description"])
        lines.append("")

    lines.append("## 취약 코드 (OLD)")
    lines.append("")
    lines.append(fmt_snippet(card.get("vulnerable_snippet")))
    lines.append("")

    lines.append("## 수정된 코드 (NEW)")
    lines.append("")
    lines.append(fmt_snippet(card.get("fixed_snippet")))
    lines.append("")

    if card.get("attack_scenario"):
        lines.append("## 공격 시나리오")
        lines.append("")
        lines.append(card["attack_scenario"])
        lines.append("")

    if card.get("fix_detail"):
        lines.append("## 수정 설명")
        lines.append("")
        lines.append(card["fix_detail"])
        lines.append("")

    # tokens
    lines.append(f"## 탐지 토큰 ({len(tokens)}개)")
    lines.append("")
    if tokens:
        lines.append("| token | kind | weight |")
        lines.append("|---|---|---|")
        for tok, kind, w in tokens:
            lines.append(f"| `{tok}` | {kind} | {w} |")
    else:
        lines.append("_(없음)_")
    lines.append("")

    # negative tokens
    if neg:
        lines.append(f"## 배제 토큰 (safe wrapper 등, {len(neg)}개)")
        lines.append("")
        lines.append("| token | vendor_scope | 메모 |")
        lines.append("|---|---|---|")
        for tok, scope, note in neg:
            lines.append(f"| `{tok}` | {scope or '(universal)'} | {note or ''} |")
        lines.append("")

    # grep patterns
    if greps:
        lines.append(f"## Grep 패턴 ({len(greps)}개)")
        lines.append("")
        for pat, flavor in greps:
            lines.append(f"- `{pat}`  _(flavor: {flavor})_")
        lines.append("")

    # members
    lines.append(f"## 발견 위치 (멤버 {len(members)}건)")
    lines.append("")
    lines.append("| 대표 | 벤더/모델 | 버전 | 바이너리 / 함수 | conf | sev | 검토필요 |")
    lines.append("|---|---|---|---|---|---|---|")
    for is_rep, bname, fname, vendor, model, oldv, newv, conf, sev, nhr in members:
        rep = "⭐" if is_rep else ""
        lines.append(
            f"| {rep} | {vendor}/{model} | v{oldv}→v{newv} | `{bname}` / `{fname or ''}` | {conf:.2f} | {sev or '-'} | {'✓' if nhr else ''} |"
        )
    lines.append("")

    # stats
    if stats:
        m, tp, fp = stats
        lines.append("## Hunt 통계")
        lines.append(f"- matches: {m}, TP: {tp}, FP: {fp}")
        if (tp + fp) > 0:
            lines.append(f"- precision: {tp / (tp + fp):.2f}")
        lines.append("")

    lines.append(f"---")
    lines.append(f"_생성: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_")
    lines.append("")
    return "\n".join(lines)


def render_index_md(cards: list[dict]) -> str:
    lines = ["# 패턴카드 인덱스", ""]
    lines.append(f"- 총 active 카드: **{len(cards)}**")
    lines.append(f"- 업데이트: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("| card_id | severity | 공식 | summary |")
    lines.append("|---|---|---|---|")
    for c in cards:
        formula = f"`{c['source_type']}` + `{c['missing_check']}` + `{c['sink_type']}`"
        summary_short = (c["summary"] or "").replace("|", "\\|")[:80]
        lines.append(f"| [{c['card_id']}]({c['card_id']}.md) | {c.get('severity_hint','-')} | {formula} | {summary_short} |")
    lines.append("")
    return "\n".join(lines)


def render_progress_md(conn: sqlite3.Connection) -> str:
    c = conn.cursor()
    lines = ["# Stage 2 진행 상황", ""]
    lines.append(f"_업데이트: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_")
    lines.append("")

    # 카드 요약
    ac = c.execute("SELECT COUNT(*) FROM pattern_cards WHERE status='active'").fetchone()[0]
    rt = c.execute("SELECT COUNT(*) FROM pattern_cards WHERE status='retired'").fetchone()[0]
    sp = c.execute("SELECT COUNT(*) FROM pattern_cards WHERE status='superseded'").fetchone()[0]
    lines.append(f"## 패턴카드")
    lines.append(f"- active: **{ac}** / retired: {rt} / superseded: {sp}")
    lines.append("")

    # 판정 요약
    tot = c.execute("SELECT COUNT(*) FROM security_patches").fetchone()[0]
    sec = c.execute("SELECT COUNT(*) FROM security_patches WHERE is_security_patch=1").fetchone()[0]
    # needs_human_review 컬럼 있는지 확인
    cols = {r[1] for r in c.execute("PRAGMA table_info(security_patches)")}
    if "needs_human_review" in cols:
        nhr = c.execute("SELECT COUNT(*) FROM security_patches WHERE needs_human_review=1").fetchone()[0]
    else:
        nhr = 0
    lines.append(f"## 판정 누적")
    lines.append(f"- 전체 판정: **{tot}**")
    lines.append(f"- 보안 패치로 분류: {sec} ({100*sec/tot:.1f}%)" if tot else "- 보안 패치: 0")
    lines.append(f"- 사람 검토 대기: {nhr}")
    lines.append("")

    # stage2 큐
    lines.append(f"## Stage 2 큐 상태")
    lines.append("| status | count |")
    lines.append("|---|---|")
    for s, n in c.execute("SELECT stage2_status, COUNT(*) AS cnt FROM changed_functions GROUP BY stage2_status ORDER BY cnt DESC"):
        lines.append(f"| {s} | {n:,} |")
    lines.append("")

    # 공식별 분포
    lines.append(f"## 공식(taint formula) 분포 (active)")
    lines.append("| source_type | missing_check | sink_type | 카드수 | 멤버수 |")
    lines.append("|---|---|---|---|---|")
    rows = c.execute("""
        SELECT pc.source_type, pc.missing_check, pc.sink_type,
               COUNT(DISTINCT pc.id) AS cards,
               COUNT(pcm.id) AS members
        FROM pattern_cards pc
        LEFT JOIN pattern_card_members pcm ON pc.id = pcm.card_id
        WHERE pc.status='active'
        GROUP BY pc.source_type, pc.missing_check, pc.sink_type
        ORDER BY cards DESC, members DESC
    """).fetchall()
    if rows:
        for r in rows:
            lines.append(f"| `{r[0]}` | `{r[1]}` | `{r[2]}` | {r[3]} | {r[4]} |")
    else:
        lines.append("| _(아직 없음)_ | | | | |")
    lines.append("")

    # 벤더별 멤버 수
    lines.append(f"## 벤더별 멤버 누적")
    lines.append("| vendor | 카드 멤버 수 |")
    lines.append("|---|---|")
    vendor_rows = c.execute("""
        SELECT fo.vendor, COUNT(pcm.id) AS n
        FROM pattern_card_members pcm
        JOIN security_patches sp ON pcm.security_patch_id = sp.id
        JOIN changed_functions cf ON sp.changed_function_id = cf.id
        JOIN bindiff_results br ON cf.bindiff_result_id = br.id
        JOIN changed_files chf ON br.changed_file_id = chf.id
        JOIN diff_sessions ds ON chf.diff_session_id = ds.id
        JOIN firmware_versions fo ON ds.old_version_id = fo.id
        GROUP BY fo.vendor ORDER BY n DESC
    """).fetchall()
    if vendor_rows:
        for v, n in vendor_rows:
            lines.append(f"| {v} | {n} |")
    else:
        lines.append("| _(아직 없음)_ | |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=DEFAULT_DB)
    args = ap.parse_args()

    CARDS_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    cards = [dict(r) for r in c.execute(
        "SELECT * FROM pattern_cards WHERE status='active' ORDER BY card_id"
    ).fetchall()]

    # 각 카드 MD
    written = 0
    for card in cards:
        md = render_card_md(conn, card)
        p = CARDS_DIR / f"{card['card_id']}.md"
        p.write_text(md, encoding="utf-8")
        written += 1

    # 인덱스
    (CARDS_DIR / "index.md").write_text(render_index_md(cards), encoding="utf-8")

    # 진행 상황
    (HANDOFF_DIR / "progress.md").write_text(render_progress_md(conn), encoding="utf-8")

    conn.close()
    print(f"[export_batch] wrote {written} card(s) to {CARDS_DIR}")
    print(f"[export_batch] wrote index.md + progress.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
