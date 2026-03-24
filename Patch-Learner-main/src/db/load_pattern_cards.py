"""
패턴 카드 JSON → SQLite DB 저장 스크립트.

Usage:
    python load_pattern_cards.py <json_file> [--db-path <path>] [--show]

Examples:
    python load_pattern_cards.py ../../firmware/ubiquiti_s2/diffs/UVC_vs_uvc/llm_cards_iot_merged.json --show
"""

import json
import sqlite3
import sys
from pathlib import Path

from init_db import init_db, DEFAULT_DB_PATH


def load_cards(json_path: Path, db_path: Path = DEFAULT_DB_PATH,
               source_label: str | None = None) -> int:
    """JSON 파일의 패턴 카드를 DB에 저장. 저장된 카드 수 반환."""
    conn = init_db(db_path)

    with open(json_path, encoding="utf-8") as f:
        cards = json.load(f)

    source = source_label or str(json_path.name)
    inserted = 0

    for card in cards:
        keywords = json.dumps(card.get("detection_keywords", []), ensure_ascii=False)

        try:
            conn.execute("""
                INSERT OR REPLACE INTO pattern_cards
                    (card_id, binary_name, function_name,
                     vulnerability_type, cwe, severity, confidence,
                     is_security_relevant, summary, vulnerability_detail,
                     fix_detail, attack_scenario, detection_keywords,
                     cve_similar, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                card["id"],
                card["binary"],
                card["function"],
                card["vulnerability_type"],
                card.get("cwe"),
                card["severity"],
                card.get("confidence", "MEDIUM"),
                1 if card.get("is_security_relevant", True) else 0,
                card["summary"],
                card.get("vulnerability_detail"),
                card.get("fix_detail"),
                card.get("attack_scenario"),
                keywords,
                card.get("cve_similar"),
                source,
            ))
            inserted += 1
        except Exception as e:
            print(f"  SKIP {card['id']}: {e}")

    conn.commit()
    conn.close()
    return inserted


def show_cards(db_path: Path = DEFAULT_DB_PATH):
    """DB에 저장된 패턴 카드를 테이블 형태로 출력."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # 전체 통계
    total = conn.execute("SELECT COUNT(*) FROM pattern_cards").fetchone()[0]
    print(f"\n{'='*90}")
    print(f" Pattern Cards DB: {total} cards  |  {db_path}")
    print(f"{'='*90}")

    # 심각도별 통계
    print("\n[Severity Distribution]")
    rows = conn.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM pattern_cards GROUP BY severity
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END
    """).fetchall()
    for r in rows:
        bar = "#" * (r["cnt"] * 2)
        print(f"  {r['severity']:>8}: {r['cnt']:>3}  {bar}")

    # 바이너리별 통계
    print("\n[By Binary]")
    rows = conn.execute("""
        SELECT binary_name, COUNT(*) as cnt,
               SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) as high_cnt
        FROM pattern_cards GROUP BY binary_name ORDER BY cnt DESC
    """).fetchall()
    for r in rows:
        print(f"  {r['binary_name']:<20} {r['cnt']:>3} cards  (CRITICAL/HIGH: {r['high_cnt']})")

    # 취약점 유형별
    print("\n[By Vulnerability Type]")
    rows = conn.execute("""
        SELECT vulnerability_type, COUNT(*) as cnt
        FROM pattern_cards GROUP BY vulnerability_type ORDER BY cnt DESC
    """).fetchall()
    for r in rows:
        print(f"  {r['vulnerability_type']:<35} {r['cnt']:>3}")

    # CVE 매칭 목록
    print("\n[CVE Matches]")
    rows = conn.execute("""
        SELECT card_id, binary_name, function_name, severity,
               vulnerability_type, cve_similar
        FROM pattern_cards WHERE cve_similar IS NOT NULL
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END
    """).fetchall()
    print(f"  {'ID':<14} {'Binary':<18} {'Function':<14} {'Sev':<9} {'Type':<25} {'CVE'}")
    print(f"  {'-'*13} {'-'*17} {'-'*13} {'-'*8} {'-'*24} {'-'*20}")
    for r in rows:
        print(f"  {r['card_id']:<14} {r['binary_name']:<18} {r['function_name']:<14} "
              f"{r['severity']:<9} {r['vulnerability_type']:<25} {r['cve_similar']}")

    # 전체 카드 상세
    print(f"\n{'='*90}")
    print(" ALL PATTERN CARDS (sorted by severity)")
    print(f"{'='*90}")
    rows = conn.execute("""
        SELECT * FROM pattern_cards
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END,
        binary_name, card_id
    """).fetchall()

    for r in rows:
        sev_icon = {"CRITICAL": "[!!!]", "HIGH": "[!! ]",
                     "MEDIUM": "[ ! ]", "LOW": "[   ]"}.get(r["severity"], "[   ]")
        print(f"\n{sev_icon} {r['card_id']} | {r['binary_name']}:{r['function_name']} "
              f"| {r['severity']} | {r['vulnerability_type']} | {r['cwe'] or '-'}")
        print(f"      Summary: {r['summary']}")
        if r["cve_similar"]:
            print(f"      CVE:     {r['cve_similar']}")
        if r["attack_scenario"]:
            scenario = r["attack_scenario"]
            if len(scenario) > 120:
                scenario = scenario[:117] + "..."
            print(f"      Attack:  {scenario}")

    conn.close()


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return

    json_path = Path(args[0])
    db_path = DEFAULT_DB_PATH
    do_show = "--show" in args

    for i, a in enumerate(args):
        if a == "--db-path" and i + 1 < len(args):
            db_path = Path(args[i + 1])

    print(f"Loading: {json_path}")
    count = load_cards(json_path, db_path)
    print(f"Inserted/Updated: {count} cards")

    if do_show:
        show_cards(db_path)


if __name__ == "__main__":
    main()
