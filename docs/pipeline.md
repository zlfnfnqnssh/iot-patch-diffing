# 파이프라인 개발 과정

## 전체 구조

```
펌웨어 A (old) ─┐
                ├─ Step 0: 추출 → Step 1: 해시 비교 → Step 2: 분류
펌웨어 B (new) ─┘
                        ↓
                Step 3: 텍스트 diff
                        ↓
                Step 4: IDA 통합 추출
                (함수 디컴파일 + BinExport 동시 처리 — IDA 1회 실행)
                        ↓
                Step 5: BinDiff 함수 매칭
                        ↓
                Step 6: Pseudocode Diff 생성
                        ↓
                Step 7: 요약 리포트
                        ↓
                Step 8: IoT 보안 후보 선별 (키워드/위험함수/바이너리 가중치)
                        ↓
                Step 9: Discovery → Analysis 2단계 LLM 분석 (병렬 에이전트)
                        ↓
                Step 10: Pydantic 검증 + SQLite DB 저장
```

---

## Step 0: 펌웨어 추출

- **도구**: binwalk (WSL Ubuntu)
- **방식**: `wsl -d Ubuntu -- bash -lc "binwalk -e ..."` (WSLENV="" 로 Windows PATH 차단)
- **캐싱**: `.extracted_ok` 마커 파일로 재추출 방지
- **rootfs 탐색**: `_find_rootfs()` — bin/usr/etc/lib 포함 디렉토리 자동 탐색
- **지원 포맷**: UBIFS (Ubiquiti), SquashFS (Synology)

## Step 1: 해시 비교

- SHA256으로 old/new rootfs 전체 파일 해시
- `ThreadPoolExecutor`로 병렬 해싱
- IDA 임시파일 (.id0, .id1, .nam, .til) 자동 제외
- 결과: `hash_compare.json` (changed / added / removed)

## Step 2: 파일 분류 + 노이즈 필터링

**바이너리 판별 기준:**
1. ELF 매직 바이트 (`\x7fELF`) 확인
2. 첫 8KB에서 NULL 바이트 존재 여부

**노이즈 필터링:**
- `/usr/share/zoneinfo/` 경로 → 타임존 데이터, 분석 제외
- 위 필터로 241개 변경 파일 중 116개 타임존 제거 → 실제 분석 대상 ~125개

## Step 3: 텍스트 Diff

- Python `difflib.unified_diff` 사용
- 결과: `text_diffs/*.patch`

## Step 4: IDA 통합 추출 (핵심)

**핵심 설계: IDA 1회 실행으로 두 가지 동시 처리**

```
idat64.exe -A \
  -OBinExportModule:{output}.BinExport \   ← BinExport 생성
  -S"extract_with_decompile.py" \           ← 함수 디컴파일
  -L{log} binary
```

**추출 데이터 (함수별):**

| 필드 | 설명 | 용도 |
|------|------|------|
| pseudocode | Hex-Rays C 의사코드 | 변경 함수 diff 비교 |
| disasm | 어셈블리 | pseudocode 실패 시 fallback |
| mnem_hash | mnemonic 시퀀스 MD5 | 주소 무관 동일성 판별 |
| calls | 호출 함수 목록 | 호출 관계 분석 |
| strings | 참조 문자열 | 기능 파악 |
| constants | 사용 상수값 | 매직넘버 분석 |
| bb_count | 기본 블록 수 | 함수 복잡도 |

**Import Thunk 처리:**
- `__imp_printf` 같은 PLT stub (4바이트, instruction 1개)
- Hex-Rays가 디컴파일 안 함 (pseudocode = null) → 정상 동작
- ubnt_system_cfg 기준: 245개 함수 중 82개가 import thunk

**병렬 처리:** `ThreadPoolExecutor(max_workers=4)`

**BinExport fallback:**
- IDAPython 스크립트 내에서 BinExport 트리거 안 될 경우
- `.i64` 파일 재사용하여 별도 BinExport 실행

## Step 5: BinDiff 함수 매칭

```
bindiff.exe --primary old.BinExport --secondary new.BinExport --output_dir dir
```

**매칭 알고리즘 (12가지 이상):**
- 이름 매칭 (함수명 해시)
- CFG 매칭 (제어 흐름 그래프 구조 비교)
- Call Graph 전파
- Prime Signature (기본 블록의 소수 곱)
- MD Index (그래프 위상 정보)

**결과: `.BinDiff` SQLite DB**

`function` 테이블 주요 컬럼:

| 컬럼 | 설명 |
|------|------|
| name1, name2 | old/new 함수명 |
| address1, address2 | 각 버전 함수 주소 |
| similarity | 유사도 (0.0~1.0) |
| confidence | 매칭 신뢰도 |
| basicblocks, instructions, edges | CFG 구조 정보 |

## Step 6: Pseudocode Diff 생성

**필터링:**
- PLT stub 제거: instruction 수 ≤ 3인 함수 스킵
- pseudocode 우선, 없으면 disasm fallback

**출력 (함수별 3개 파일):**
```
function_diffs/ubnt_cgi/
├── authenticateToken_old.c     ← 패치 전 C 의사코드
├── authenticateToken_new.c     ← 패치 후 C 의사코드
└── authenticateToken.c.diff    ← unified diff
```

## Step 7: 요약 리포트

- `summary_step5to7.md` — 바이너리별 변경 통계, 주요 함수 목록
- `diff_results.json` — 구조화된 분석 결과
- `function_diff_stats.json` — 함수별 diff 통계

## Step 8: IoT 보안 후보 선별 (Security Candidate Scoring)

> `src/analyzers/generate_security_candidates.py`

**기존 문제:** 키워드 스코어링이 crypto/auth 위주 → OpenSSL/Dropbear만 선별, IoT 바이너리(ubnt_*) 0개

**개선된 스코어링 시스템:**

| 카테고리 | 항목 | 예시 |
|----------|------|------|
| 함수명 키워드 (80+개) | auth:30, cgi:25, system:25, firmware:25, exec:25 | `authenticateToken` → 30점 |
| 위험 함수 패턴 (14개) | system(), exec(), sprintf(), strcpy(), memcpy() | diff에서 직접 탐지 |
| 바이너리 우선순위 | ubnt_cgi:50, ubnt_ctlserver:40, ubnt_networkd:40 | IoT 바이너리 가중치 |

**결과:**
- 전체 5,497개 변경 함수 → 1,099개 선별 (20%)
- IoT 바이너리: 177개 (16%) — ubnt_cgi 91, ubnt_ctlserver 24, ubnt_networkd 22

## Step 9: Discovery → Analysis 2단계 LLM 분석

> `src/analyzers/multi_agent_pipeline.py`

토스 보안팀 블로그에서 영감을 받은 2단계 에이전트 파이프라인:

```
Supervisor (Opus)
    |
    +-- Discovery: 1,099개 후보 → 보안 관련성 필터 (Yes/No + 이유)
    |
    +-- Analysis: 필터된 함수 → 배치 분할 → 병렬 Sonnet 에이전트
    |       Agent 1: ubnt_cgi (12함수) → 패턴 카드 JSON
    |       Agent 2: ubnt_ctlserver (10함수) → 패턴 카드 JSON
    |       Agent 3: ubnt_networkd (12함수) → 패턴 카드 JSON
    |
    +-- Review + Merge: Pydantic 검증 → 심각도 정렬 → ID 재할당
```

**패턴 카드 필드:**
```json
{
  "id": "LPC-IoT-004",
  "binary": "ubnt_cgi",
  "function": "sub_30A68",
  "vulnerability_type": "Command Injection",
  "cwe": "CWE-78",
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "is_security_relevant": true,
  "summary": "WiFi SSID/passphrase passed unsanitized to sysExecSimple",
  "vulnerability_detail": "...",
  "fix_detail": "...",
  "attack_scenario": "...",
  "detection_keywords": ["sysExecSimple", "WiFi", "passphrase"],
  "cve_similar": "CVE-2021-22909"
}
```

## Step 10: Pydantic 검증 + SQLite DB 저장

> `src/analyzers/pattern_card_schema.py` + `src/db/load_pattern_cards.py`

**Pydantic 검증:**
- VulnerabilityType enum (17개 유형) + 비정형 입력 자동 정규화
- CWE 형식 자동 보정 (`CWE120` → `CWE-120`)
- severity/confidence 대소문자 정규화
- 짧은 텍스트 필드 자동 패딩 (비보안 카드)

**SQLite 저장:**
- `schema.sql`에 `pattern_cards` 테이블 추가 (19개 컬럼)
- `load_pattern_cards.py`: JSON → DB INSERT OR REPLACE
- 인덱스: binary_name, severity, vulnerability_type, cve_similar

**최종 결과:**
- 34개 IoT 패턴 카드 (CRITICAL:1, HIGH:13, MEDIUM:17, LOW:3)
- CVE 매칭: 15/34 (44%)
- 분석 바이너리: ubnt_cgi(12), ubnt_ctlserver(10), ubnt_networkd(12)

---

## 출력 디렉토리 구조

```
UVC_vs_uvc/
├── extracted/              ← rootfs (old, new)
├── functions/              ← 함수 JSON (pseudocode + 메타데이터)
│   ├── ubnt_cgi_old.json
│   └── ubnt_cgi_new.json
├── binexport/              ← .BinExport 파일
├── bindiff/                ← 바이너리별 .BinDiff SQLite
├── text_diffs/             ← 텍스트 파일 .patch
├── function_diffs/         ← 변경 함수별 pseudocode diff
│   └── ubnt_cgi/
│       ├── sub_XXX_old.c
│       ├── sub_XXX_new.c
│       └── sub_XXX.c.diff
├── hash_compare.json
├── diff_results.json
├── security_candidates.json ← IoT 포함 보안 후보 1,099개
├── llm_cards_iot_cgi.json   ← ubnt_cgi 패턴 카드 12개
├── llm_cards_iot_ctlserver.json ← ubnt_ctlserver 패턴 카드 10개
├── llm_cards_iot_merged.json ← 전체 IoT 패턴 카드 34개
├── function_diff_stats.json
└── summary_step5to7.md
```

## SQLite DB 구조

```
src/db/patch_learner.db
├── firmware_versions      ← 펌웨어 버전 관리
├── diff_sessions          ← 디핑 세션 (old vs new)
├── changed_files          ← 해시 디핑 결과
├── bindiff_results        ← BinDiff 바이너리 단위
├── changed_functions      ← 변경 함수 개별 정보
├── security_patches       ← LLM 보안 패치 분석 (상세)
├── pattern_cards          ← 패턴 카드 요약 (34개)
└── hunt_findings          ← 0-day 헌팅 결과
```
