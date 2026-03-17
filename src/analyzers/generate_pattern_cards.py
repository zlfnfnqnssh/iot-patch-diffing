"""
패턴 카드 자동 생성 스크립트.

function_diffs/의 before/after pseudocode를 분석하여
보안 관련 패턴 카드를 JSON으로 생성한다.

키워드 기반 휴리스틱 + 코드 패턴 매칭으로 자동 분류.
"""

import json
import re
from pathlib import Path

BASE = Path(r"c:/Users/deser/Desktop/project/Patch-Learner-main/firmware/ubiquiti_s2/diffs/UVC_vs_uvc")
DIFF_DIR = BASE / "function_diffs"
OUTPUT = BASE / "pattern_cards.json"

# ── 취약점 패턴 정의 ─────────────────────────────────────────────
VULN_PATTERNS = [
    {
        "type": "Authentication Bypass",
        "cwe": "CWE-287",
        "severity": "CRITICAL",
        "detect_in_old": [r"strlen\s*\(.*\)\s*>\s*0", r"return\s+1", r"token", r"auth"],
        "detect_in_new": [r"verify", r"hmac", r"validate", r"check.*token"],
        "description": "인증 로직이 단순 길이 확인에서 암호학적 검증으로 강화됨",
    },
    {
        "type": "Buffer Overflow",
        "cwe": "CWE-120",
        "severity": "HIGH",
        "detect_in_diff_added": [r"sizeof", r"strnlen", r"strncpy", r"snprintf", r"_chk\b",
                                  r"bounds", r">=\s*\d+", r"<=\s*\d+", r"MAX_", r"min\("],
        "detect_in_diff_removed": [r"strcpy", r"strcat", r"sprintf", r"gets\b", r"scanf\b"],
        "description": "버퍼 크기 미검증 → 크기 제한 추가 (strcpy→strncpy 등)",
    },
    {
        "type": "Command Injection",
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "detect_in_old": [r"system\s*\(", r"popen\s*\(", r"exec[lv]?\s*\("],
        "detect_in_new": [r"sanitize", r"escape", r"whitelist", r"allowed"],
        "detect_in_diff_removed": [r"system\s*\(", r"popen\s*\("],
        "description": "사용자 입력이 시스템 명령어에 직접 삽입되는 취약점 수정",
    },
    {
        "type": "Format String",
        "cwe": "CWE-134",
        "severity": "HIGH",
        "detect_in_diff_removed": [r'printf\s*\(\s*[^"]\w', r'syslog\s*\([^,]*,\s*[^"]'],
        "detect_in_diff_added": [r'printf\s*\(\s*"%', r'syslog\s*\([^,]*,\s*"%'],
        "description": "포맷 스트링이 사용자 입력에서 직접 전달되는 취약점 수정",
    },
    {
        "type": "Input Validation Missing",
        "cwe": "CWE-20",
        "severity": "MEDIUM",
        "detect_in_diff_added": [r"if\s*\(.*[<>=!]=.*\)", r"validate", r"check",
                                  r"NULL\b", r"nullptr", r"!.*\w+\s*\)"],
        "detect_code_pattern": "new_longer",  # new 코드가 old보다 조건문이 많으면
        "description": "입력값 검증 로직 추가 (NULL 체크, 범위 검사 등)",
    },
    {
        "type": "Integer Overflow",
        "cwe": "CWE-190",
        "severity": "HIGH",
        "detect_in_diff_added": [r"overflow", r"UINT_MAX", r"INT_MAX", r"__builtin_add_overflow",
                                  r"> 0x[0-9a-fA-F]+", r"unsigned"],
        "description": "정수 오버플로우 체크 추가",
    },
    {
        "type": "Use After Free",
        "cwe": "CWE-416",
        "severity": "HIGH",
        "detect_in_diff_added": [r"= NULL", r"= 0;.*free", r"= nullptr"],
        "detect_in_diff_removed": [r"free\s*\("],
        "description": "메모리 해제 후 포인터 초기화 또는 사용 순서 변경",
    },
    {
        "type": "Path Traversal",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "detect_in_old": [r"fopen", r"open\s*\(", r"file", r"path"],
        "detect_in_diff_added": [r"\.\.", r"realpath", r"canonical", r"sanitize.*path"],
        "description": "파일 경로에 '../' 등 상위 디렉토리 접근 방지 로직 추가",
    },
    {
        "type": "Cryptographic Improvement",
        "cwe": "CWE-327",
        "severity": "MEDIUM",
        "detect_in_old": [r"MD5", r"SHA1\b", r"DES\b", r"RC4"],
        "detect_in_new": [r"SHA256", r"SHA384", r"SHA512", r"AES", r"AEAD", r"GCM"],
        "description": "약한 암호 알고리즘에서 강한 알고리즘으로 변경",
    },
    {
        "type": "NULL Pointer Dereference",
        "cwe": "CWE-476",
        "severity": "MEDIUM",
        "detect_in_diff_added": [r"if\s*\(\s*!\s*\w+\s*\)", r"if\s*\(\s*\w+\s*==\s*NULL",
                                  r"if\s*\(\s*\w+\s*!=\s*NULL", r"if\s*\(\s*\w+\s*\)"],
        "detect_code_pattern": "null_check_added",
        "description": "NULL 포인터 검사 추가로 크래시 방지",
    },
    {
        "type": "Access Control",
        "cwe": "CWE-284",
        "severity": "HIGH",
        "detect_in_diff_added": [r"permission", r"role", r"admin", r"authorized",
                                  r"isAdmin", r"checkAuth", r"ACL"],
        "description": "접근 제어/권한 검사 로직 추가",
    },
    {
        "type": "Information Disclosure",
        "cwe": "CWE-200",
        "severity": "MEDIUM",
        "detect_in_diff_removed": [r"printf.*password", r"log.*key", r"print.*secret",
                                    r"debug.*token"],
        "description": "민감 정보(비밀번호, 키 등)가 로그에 노출되는 문제 수정",
    },
]


def match_patterns(old_code, new_code, diff_text):
    """코드에서 취약점 패턴을 매칭하고 해당하는 패턴 목록 반환."""
    matches = []

    diff_lines = diff_text.splitlines()
    added_lines = "\n".join(l[1:] for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
    removed_lines = "\n".join(l[1:] for l in diff_lines if l.startswith("-") and not l.startswith("---"))

    for pattern in VULN_PATTERNS:
        score = 0
        matched_evidence = []

        # old 코드에서 취약 패턴 탐지
        for regex in pattern.get("detect_in_old", []):
            found = re.findall(regex, old_code, re.IGNORECASE)
            if found:
                score += 2
                matched_evidence.append(f"old: {regex} → {found[:3]}")

        # new 코드에서 수정 패턴 탐지
        for regex in pattern.get("detect_in_new", []):
            found = re.findall(regex, new_code, re.IGNORECASE)
            if found:
                score += 2
                matched_evidence.append(f"new: {regex} → {found[:3]}")

        # diff에서 추가된 라인 패턴
        for regex in pattern.get("detect_in_diff_added", []):
            found = re.findall(regex, added_lines, re.IGNORECASE)
            if found:
                score += 3
                matched_evidence.append(f"added: {regex} → {found[:3]}")

        # diff에서 삭제된 라인 패턴
        for regex in pattern.get("detect_in_diff_removed", []):
            found = re.findall(regex, removed_lines, re.IGNORECASE)
            if found:
                score += 3
                matched_evidence.append(f"removed: {regex} → {found[:3]}")

        # 코드 패턴: new가 더 길면 (검증 로직 추가)
        if pattern.get("detect_code_pattern") == "new_longer":
            old_ifs = len(re.findall(r"\bif\s*\(", old_code))
            new_ifs = len(re.findall(r"\bif\s*\(", new_code))
            if new_ifs > old_ifs + 2:
                score += 2
                matched_evidence.append(f"if문 증가: {old_ifs} → {new_ifs}")

        if pattern.get("detect_code_pattern") == "null_check_added":
            old_nulls = len(re.findall(r"if\s*\(\s*!?\s*\w+\s*\)", old_code))
            new_nulls = len(re.findall(r"if\s*\(\s*!?\s*\w+\s*\)", new_code))
            if new_nulls > old_nulls:
                score += 2
                matched_evidence.append(f"NULL체크 증가: {old_nulls} → {new_nulls}")

        if score >= 4:
            matches.append({
                "type": pattern["type"],
                "cwe": pattern["cwe"],
                "severity": pattern["severity"],
                "score": score,
                "evidence": matched_evidence,
                "pattern_description": pattern["description"],
            })

    matches.sort(key=lambda x: -x["score"])
    return matches


def extract_key_changes(diff_text, max_lines=20):
    """diff에서 핵심 변경 부분만 추출."""
    lines = diff_text.splitlines()
    key_changes = []
    for i, line in enumerate(lines):
        if line.startswith("@@"):
            chunk = lines[i:i+max_lines]
            key_changes.extend(chunk)
            if len(key_changes) > 50:
                break
    return "\n".join(key_changes[:50])


def main():
    print("패턴 카드 생성 시작...\n")

    pattern_cards = []
    card_id = 0

    # 보안 우선순위 바이너리
    priority_order = [
        "ubnt_cgi", "dropbear", "libcrypto.so.1.1", "libssl.so.1.1",
        "hostapd", "wpa_supplicant", "ubnt_networkd", "ubnt_system_cfg",
        "ubnt_ctlserver", "openssl", "logrotate", "ubnt_nvr",
    ]

    # 나머지 바이너리도 포함
    all_bins = sorted(d.name for d in DIFF_DIR.iterdir() if d.is_dir())
    ordered_bins = priority_order + [b for b in all_bins if b not in priority_order]

    for bin_name in ordered_bins:
        bin_dir = DIFF_DIR / bin_name
        if not bin_dir.is_dir():
            continue

        diff_files = list(bin_dir.glob("*.c.diff"))
        if not diff_files:
            continue

        for diff_file in diff_files:
            func_name = diff_file.stem.replace(".c", "")
            old_file = bin_dir / f"{func_name}_old.c"
            new_file = bin_dir / f"{func_name}_new.c"

            if not old_file.exists() or not new_file.exists():
                continue

            old_code = old_file.read_text(encoding="utf-8", errors="replace")
            new_code = new_file.read_text(encoding="utf-8", errors="replace")
            diff_text = diff_file.read_text(encoding="utf-8", errors="replace")

            # 패턴 매칭
            matches = match_patterns(old_code, new_code, diff_text)

            if not matches:
                continue

            top_match = matches[0]
            card_id += 1

            # 코드 크기 제한 (너무 크면 요약만)
            old_preview = old_code[:2000] + ("..." if len(old_code) > 2000 else "")
            new_preview = new_code[:2000] + ("..." if len(new_code) > 2000 else "")

            card = {
                "id": f"PC-{card_id:03d}",
                "binary": bin_name,
                "function_old": func_name,
                "function_new": diff_file.stem.replace(".c", ""),
                "vulnerability_type": top_match["type"],
                "cwe": top_match["cwe"],
                "severity": top_match["severity"],
                "confidence_score": top_match["score"],
                "description": top_match["pattern_description"],
                "evidence": top_match["evidence"],
                "all_matches": [{"type": m["type"], "cwe": m["cwe"], "score": m["score"]}
                                for m in matches],
                "key_changes": extract_key_changes(diff_text),
                "lines_added": sum(1 for l in diff_text.splitlines()
                                   if l.startswith("+") and not l.startswith("+++")),
                "lines_removed": sum(1 for l in diff_text.splitlines()
                                     if l.startswith("-") and not l.startswith("---")),
                "detection_pattern": {
                    "keywords": list(set(
                        re.findall(r"(\w+)", " ".join(top_match["evidence"]))
                    ))[:20],
                },
                "before_code_preview": old_preview,
                "after_code_preview": new_preview,
            }

            pattern_cards.append(card)

    # 점수순 정렬
    pattern_cards.sort(key=lambda x: (-{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                                        .get(x["severity"], 0),
                                       -x["confidence_score"]))

    # 저장
    with open(str(OUTPUT), "w", encoding="utf-8") as f:
        json.dump(pattern_cards, f, indent=2, ensure_ascii=False)

    # 통계
    print(f"총 패턴 카드: {len(pattern_cards)}개\n")

    by_type = {}
    by_severity = {}
    by_binary = {}
    for c in pattern_cards:
        by_type[c["vulnerability_type"]] = by_type.get(c["vulnerability_type"], 0) + 1
        by_severity[c["severity"]] = by_severity.get(c["severity"], 0) + 1
        by_binary[c["binary"]] = by_binary.get(c["binary"], 0) + 1

    print("=== 취약점 유형별 ===")
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t}: {n}개")

    print("\n=== 심각도별 ===")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if s in by_severity:
            print(f"  {s}: {by_severity[s]}개")

    print("\n=== 바이너리별 (상위 15) ===")
    for b, n in sorted(by_binary.items(), key=lambda x: -x[1])[:15]:
        print(f"  {b}: {n}개")

    print(f"\n저장: {OUTPUT}")


if __name__ == "__main__":
    main()
