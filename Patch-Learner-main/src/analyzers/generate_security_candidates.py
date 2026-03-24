"""
보안 후보 함수 선별 스크립트.

function_diffs/ 내 모든 변경 함수에 대해 보안 관련 점수를 산정하고
상위 후보를 security_candidates.json으로 출력한다.

선별 기준:
  1. 함수명/바이너리명 키워드 매칭
  2. diff 내용 키워드 매칭 (위험 함수, 보안 패턴)
  3. 코드 변경량 (lines_added + lines_removed)
  4. 바이너리 우선순위 (IoT 자체코드 > 보안 라이브러리 > 기타)

사용법:
  python generate_security_candidates.py [base_dir] [--min-ratio 0.2]
"""

import json
import re
import sys
from pathlib import Path

DEFAULT_BASE = Path(r"c:/Users/deser/Desktop/project/Patch-Learner-main/firmware/ubiquiti_s2/diffs/UVC_vs_uvc")

# ── 키워드 및 가중치 ─────────────────────────────────────────────

# 함수명에 포함되면 점수 부여
FUNC_NAME_KEYWORDS = {
    # 인증/인가
    "auth": 30, "login": 30, "password": 30, "passwd": 30, "credential": 30,
    "token": 25, "session": 25, "cookie": 20, "permission": 20, "privilege": 20,
    "admin": 25, "root": 15, "sudo": 20, "access": 15,
    # 암호화
    "crypt": 25, "cipher": 25, "encrypt": 25, "decrypt": 25, "hash": 20,
    "hmac": 25, "sign": 20, "verify": 25, "cert": 20, "ssl": 25, "tls": 25,
    "rsa": 25, "aes": 20, "sha": 15, "md5": 15, "key": 15, "nonce": 20,
    "ecdsa": 25, "x509": 20, "pem": 15, "pkcs": 20,
    # 입력 처리
    "parse": 15, "input": 15, "request": 15, "param": 10, "query": 10,
    "header": 10, "url": 15, "uri": 15, "path": 10, "file": 10,
    "upload": 20, "download": 15, "read": 5, "write": 5, "recv": 10, "send": 5,
    # 명령/실행
    "exec": 25, "system": 25, "command": 25, "cmd": 25, "shell": 25,
    "popen": 25, "spawn": 20, "run": 10, "eval": 20,
    # 메모리
    "buffer": 15, "overflow": 20, "malloc": 10, "free": 10, "memcpy": 15,
    "strcpy": 20, "strcat": 15, "sprintf": 15, "format": 10,
    # 네트워크
    "socket": 15, "connect": 10, "bind": 10, "listen": 10, "accept": 10,
    "http": 20, "cgi": 25, "api": 15, "handler": 10, "server": 10, "client": 10,
    # IoT 특화
    "firmware": 25, "update": 15, "upgrade": 15, "flash": 20, "boot": 15,
    "config": 15, "setting": 10, "network": 10, "wifi": 15, "wireless": 15,
    "camera": 15, "stream": 10, "video": 5, "nvr": 15, "motion": 5,
    "device": 10, "sensor": 10, "gpio": 10, "uart": 10, "serial": 10,
    # 검증/보안
    "check": 10, "valid": 15, "sanitize": 20, "escape": 15, "filter": 10,
    "safe": 10, "secure": 15, "protect": 10, "guard": 10,
}

# diff 내용에서 매칭할 위험 패턴 (정규식)
DANGEROUS_PATTERNS = [
    # 위험 함수 호출
    (r"\bstrcpy\s*\(", 20, "strcpy"),
    (r"\bstrcat\s*\(", 15, "strcat"),
    (r"\bsprintf\s*\(", 15, "sprintf"),
    (r"\bgets\s*\(", 25, "gets"),
    (r"\bsystem\s*\(", 30, "system()"),
    (r"\bpopen\s*\(", 25, "popen()"),
    (r"\bexecve?\s*\(", 25, "exec()"),
    (r"\bmemcpy\s*\(", 10, "memcpy"),
    (r"\bfree\s*\(", 10, "free"),
    # 보안 관련 패턴 (추가된 경우 = 수정)
    (r"\bif\s*\(\s*!\s*\w+\s*\)", 5, "null_check"),
    (r"\bsizeof\s*\(", 5, "sizeof"),
    (r"\bstrncpy\s*\(", 5, "strncpy"),
    (r"\bsnprintf\s*\(", 5, "snprintf"),
    # 네트워크/HTTP
    (r"\brecv\s*\(", 15, "recv()"),
    (r"\bsend\s*\(", 10, "send()"),
    (r"Content-Type|HTTP/|GET |POST |PUT |DELETE ", 15, "http_pattern"),
    (r"/cgi-bin/|/api/|/admin", 20, "web_path"),
    # 인증
    (r"password|passwd|credential|token|cookie|session_id", 20, "auth_data"),
    (r"strcmp\s*\(.*passw", 25, "password_compare"),
    # 설정/명령
    (r"/etc/|/tmp/|/var/|/proc/", 10, "fs_path"),
    (r"ioctl\s*\(", 10, "ioctl"),
]

# 바이너리별 우선순위 가중치
BINARY_PRIORITY = {
    # IoT 자체코드 — 최우선
    "ubnt_cgi": 50,           # 웹 인터페이스 (공격 표면 최대)
    "ubnt_ctlserver": 40,     # 제어 서버
    "ubnt_networkd": 40,      # 네트워크 관리
    "ubnt_system_cfg": 35,    # 시스템 설정
    "ubnt_nvr": 30,           # NVR 녹화
    "ubnt_avclient": 25,      # AV 클라이언트
    "ubnt_streamer": 25,      # 스트리밍
    "ubnt_analytics": 20,     # 분석
    "ubnt_reportd": 20,       # 리포트
    "ubnt_talkback": 20,      # 양방향 오디오
    "ubnt_smart_motion": 15,  # 모션 감지
    "ubnt_audio_events": 15,  # 오디오 이벤트
    "ubnt_osd": 10,           # OSD
    "ubnt_sounds_leds": 5,    # 소리/LED
    "ubnt_ipc_cli": 15,       # IPC
    "ubnt_ispserver": 15,     # ISP 서버
    # Ubiquiti 라이브러리
    "libubnt.so": 20,
    "libubnt_ipc.so": 15,
    "libubnt_network_utils_cxx.so": 15,
    "libubnt_network_utils_wireless.so": 15,
    "libubnt_utils.so": 10,
    # 보안 라이브러리
    "libcrypto.so.1.1": 25,
    "libssl.so.1.1": 25,
    "dropbear": 25,
    "openssl": 20,
    "hostapd": 20,
    "wpa_supplicant": 20,
    # 시스템 도구
    "busybox": 10,
    "logrotate": 5,
    "ubntbox": 10,
}


def score_function(binary: str, func_name: str, diff_text: str,
                   lines_added: int, lines_removed: int) -> tuple[int, list[str]]:
    """함수의 보안 관련 점수를 산정. (score, matched_keywords) 반환."""
    score = 0
    keywords = []

    # 1. 바이너리 우선순위
    bin_score = BINARY_PRIORITY.get(binary, 0)
    # 매칭 안 되면 prefix로 시도
    if bin_score == 0:
        for prefix in ["ubnt_", "libubnt"]:
            if binary.startswith(prefix):
                bin_score = 15
                break
    score += bin_score
    if bin_score > 0:
        keywords.append(f"bin:{binary}")

    # 2. 함수명 키워드
    func_lower = func_name.lower()
    for kw, weight in FUNC_NAME_KEYWORDS.items():
        if kw in func_lower:
            score += weight
            keywords.append(kw)

    # 3. diff 내용 위험 패턴
    for pattern, weight, label in DANGEROUS_PATTERNS:
        matches = re.findall(pattern, diff_text, re.IGNORECASE)
        if matches:
            score += weight
            keywords.append(label)

    # 4. 코드 변경량 보너스 (변경이 클수록 중요할 가능성)
    change_size = lines_added + lines_removed
    if change_size >= 100:
        score += 20
    elif change_size >= 50:
        score += 15
    elif change_size >= 20:
        score += 10
    elif change_size >= 5:
        score += 5

    # 5. sub_ 함수 (심볼 없음)는 약간 감점 — 분석 난이도 높음
    if func_name.startswith("sub_"):
        score -= 5

    return score, keywords


def generate_candidates(base_dir: Path, min_ratio: float = 0.2) -> Path:
    """전체 function_diffs를 스캔하여 security_candidates.json 생성."""
    diff_dir = base_dir / "function_diffs"
    all_candidates = []

    for bin_dir in sorted(diff_dir.iterdir()):
        if not bin_dir.is_dir():
            continue

        binary = bin_dir.name
        diff_files = list(bin_dir.glob("*.c.diff"))

        for diff_file in diff_files:
            func_name = diff_file.stem.replace(".c", "")
            diff_text = diff_file.read_text(encoding="utf-8", errors="replace")

            lines_added = sum(1 for l in diff_text.splitlines()
                              if l.startswith("+") and not l.startswith("+++"))
            lines_removed = sum(1 for l in diff_text.splitlines()
                                if l.startswith("-") and not l.startswith("---"))

            score, keywords = score_function(binary, func_name, diff_text,
                                             lines_added, lines_removed)

            all_candidates.append({
                "binary": binary,
                "function": func_name,
                "score": score,
                "keywords": keywords,
                "lines_added": lines_added,
                "lines_removed": lines_removed,
                "diff_file": str(diff_file.relative_to(base_dir.parent.parent.parent)),
                "priority_bin": binary in BINARY_PRIORITY,
            })

    # 점수순 정렬
    all_candidates.sort(key=lambda x: -x["score"])

    # 최소 비율 적용
    total = len(all_candidates)
    min_count = max(int(total * min_ratio), 50)
    selected = all_candidates[:min_count]

    # 저장
    output_path = base_dir / "security_candidates.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(selected, f, indent=2, ensure_ascii=False)

    # 통계
    print(f"=== 보안 후보 선별 완료 ===")
    print(f"전체 변경 함수: {total}개")
    print(f"선별 기준: 상위 {min_ratio*100:.0f}% (최소 50개)")
    print(f"선별된 후보: {len(selected)}개")
    print(f"점수 범위: {selected[0]['score']} ~ {selected[-1]['score']}")
    print()

    # 바이너리별 통계
    by_bin = {}
    for c in selected:
        b = c["binary"]
        by_bin[b] = by_bin.get(b, 0) + 1

    iot_count = sum(n for b, n in by_bin.items() if b.startswith("ubnt_") or b.startswith("libubnt"))
    lib_count = sum(n for b, n in by_bin.items() if not b.startswith("ubnt_") and not b.startswith("libubnt"))

    print(f"IoT 자체코드: {iot_count}개 ({100*iot_count//len(selected)}%)")
    print(f"라이브러리: {lib_count}개 ({100*lib_count//len(selected)}%)")
    print()

    print("=== 바이너리별 선별 수 (상위 20) ===")
    for b, n in sorted(by_bin.items(), key=lambda x: -x[1])[:20]:
        tag = "IoT" if b.startswith("ubnt_") or b.startswith("libubnt") else "LIB"
        print(f"  [{tag}] {b}: {n}개")

    print(f"\n저장: {output_path}")
    return output_path


def main():
    base_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BASE
    min_ratio = 0.2

    for arg in sys.argv[1:]:
        if arg.startswith("--min-ratio"):
            min_ratio = float(arg.split("=")[1])

    generate_candidates(base_dir, min_ratio)


if __name__ == "__main__":
    main()
