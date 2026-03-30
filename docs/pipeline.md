# 파이프라인 개발 과정

> 아키텍처 확정안은 [architecture-decisions.md](architecture-decisions.md) 참고

## 전체 구조 (확정 — 2026-03-25)

```
펌웨어 A (old) ─┐
                ├─ Stage 0: 펌웨어 추출 + 해시 디핑
펌웨어 B (new) ─┘       ↓ changed_files
                   Stage 1: BinDiff + 전체 디컴파일 → DB
                        ↓ changed_functions (전수)
                   Stage 2: LLM 1-pass 전수 분석
                        ↓ security_patches (전수, is_security_patch 0/1)
                   Stage 3: 0-day 헌팅
                        ↓ hunt_findings
```

**이전 Step 0~10 → Stage 0~3으로 통합:**

| 이전 | 이후 | 변경점 |
|------|------|--------|
| Step 0~3 (추출, 해시, 분류, 텍스트diff) | Stage 0 | 통합 |
| Step 4~7 (IDA, BinDiff, pseudocode diff, 리포트) | Stage 1 | 전체 디컴파일 → DB 저장 |
| Step 8~10 (스코어링, LLM 분석, DB 저장) | Stage 2 | 분류 단계 스킵, 1-pass 전수 분석 |
| (신규) | Stage 3 | 0-day 헌팅 추가 |

---

## Stage 0: 펌웨어 추출 + 해시 디핑

### 0-1. 펌웨어 추출

- **도구**: binwalk (WSL Ubuntu) 또는 직접 파싱
- **방식**: `wsl -d Ubuntu -- bash -lc "binwalk -e ..."` (WSLENV="" 로 Windows PATH 차단)
- **캐싱**: `.extracted_ok` 마커 파일로 재추출 방지
- **rootfs 탐색**: `_find_rootfs()` — bin/usr/etc/lib 포함 디렉토리 자동 탐색
- **지원 포맷**: UBIFS (Ubiquiti), SquashFS (Synology .sa.bin 직접 파싱)

### 0-2. 해시 비교

- SHA256으로 old/new rootfs 전체 파일 해시
- `ThreadPoolExecutor`로 병렬 해싱
- IDA 임시파일 (.id0, .id1, .nam, .til) 자동 제외
- 결과: `changed_files` 테이블 + `hash_compare.json`

### 0-3. 파일 분류 + 노이즈 필터링

**바이너리 판별 기준:**
1. ELF 매직 바이트 (`\x7fELF`) 확인
2. 첫 8KB에서 NULL 바이트 존재 여부

**노이즈 필터링:**
- `/usr/share/zoneinfo/` 경로 → 타임존 데이터, 분석 제외

### 0-4. 텍스트 Diff

- Python `difflib.unified_diff` 사용
- 결과: `text_diffs/*.patch`

---

## Stage 1: BinDiff + 전체 디컴파일 → DB

### 1-1. IDA 통합 추출 (핵심)

**핵심 설계: IDA 1회 실행으로 두 가지 동시 처리**

```
idat64.exe -A \
  -OBinExportModule:{output}.BinExport \   <- BinExport 생성
  -S"extract_with_decompile.py" \           <- 함수 디컴파일
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

**캐싱:** `functions/{name}_old.json` + `_new.json` 존재 시 스킵. 재분석 시 IDA 재실행 불필요.

**병렬 처리:** `ThreadPoolExecutor(max_workers=4)`

### 1-2. BinDiff 함수 매칭

```
bindiff.exe --primary old.BinExport --secondary new.BinExport --output_dir dir
```

**매칭 알고리즘 (12가지 이상):**
- 이름 매칭 (함수명 해시)
- CFG 매칭 (제어 흐름 그래프 구조 비교)
- Call Graph 전파
- Prime Signature (기본 블록의 소수 곱)
- MD Index (그래프 위상 정보)

### 1-3. Pseudocode Diff 생성

**필터링:**
- PLT stub 제거: instruction 수 <= 3인 함수 스킵
- pseudocode 우선, 없으면 disasm fallback

**출력 (함수별 3개 파일):**
```
function_diffs/ubnt_cgi/
├── authenticateToken_old.c     <- 패치 전 C 의사코드
├── authenticateToken_new.c     <- 패치 후 C 의사코드
└── authenticateToken.c.diff    <- unified diff
```

### 1-4. DB 저장

**변경 함수 전수 저장**: 바뀐 함수가 30개면 30개 전부 old/new pseudocode DB INSERT.

```
changed_functions 테이블:
  binary_name, function_name,
  old_address, new_address,
  decompiled_old, decompiled_new,   <- pseudocode 쌍
  similarity, instructions
```

---

## Stage 2: LLM 1-pass 전수 분석

### 분류 단계 스킵 (확정)

BinDiff가 이미 "바뀐 함수"만 뽑아줌 = 토스의 Discovery 역할.
우리 규모(30~200개)에서 별도 필터링은 오탐/미탐만 늘린다.

### LLM 분석 프로세스

```
changed_functions에서 old/new pseudocode 쌍 가져오기
         ↓
LLM에게 질문: "old -> new에서 뭐가 바뀌었어? 보안패치야?"
         ↓
LLM 응답 (구조화 출력):
  is_security_patch: true/false
  severity: CRITICAL/HIGH/MEDIUM/LOW   <- LLM 직접 판단 (가중치 공식 없음)
  confidence: 0.85                     <- LLM 직접 판단
  vuln_type, cwe, root_cause, fix_description,
  source_desc, sink_desc, missing_check, hunt_strategy
         ↓
security_patches 테이블에 전수 저장 (is_security_patch=0도 포함)
```

### 출력 포맷 강제

LLM 응답이 매번 달라지면 파싱 깨짐 방지:
- Claude API 직접 호출 시: `tool_use` (function calling)로 스키마 강제
- Claude Code가 분석 시: 프롬프트에서 JSON 출력 명시 + Pydantic 검증

### 원칙

- **과탐 > 미탐**: 애매하면 is_security_patch=1 판정
- **전수 저장**: is_security_patch=0도 DB에 저장 (논문 precision/recall 계산에 필요)
- **가중치 공식 금지**: severity/confidence는 LLM이 코드를 보고 직접 판단

### 평가 지표

- Synology SA advisory에 명시된 CVE와 탐지 결과 대조 → ground truth
- precision: LLM이 보안패치라고 한 것 중 실제 보안패치 비율
- recall: 실제 보안패치 중 LLM이 잡아낸 비율

---

## Stage 3: 0-day 헌팅

### Phase 1: 패턴 매칭 (자동)
- DB의 각 security_patch에서 sink 함수 추출 (system, popen, sprintf 등)
- 타깃 펌웨어에서 해당 함수의 xref 전수 검색
- IDA MCP의 xrefs_to, find_regex 활용

### Phase 2: 컨텍스트 분석 (LLM)
- Phase 1 후보만 디컴파일
- DB의 패치 패턴과 비교: "이것도 같은 취약점 패턴인가?"
- hunt_findings 테이블에 저장 (status: candidate)

### Phase 3: 수동 검증 (사람)
- candidate 중 confidence 높은 것부터 IDA로 직접 확인
- status: verified / false_positive / exploitable

---

## 출력 디렉토리 구조

```
{old}_vs_{new}/
├── extracted/              <- rootfs (old, new)
├── functions/              <- 함수 JSON (pseudocode + 메타데이터, 캐시)
│   ├── ubnt_cgi_old.json
│   └── ubnt_cgi_new.json
├── binexport/              <- .BinExport 파일
├── bindiff/                <- 바이너리별 .BinDiff SQLite
├── text_diffs/             <- 텍스트 파일 .patch
├── function_diffs/         <- 변경 함수별 pseudocode diff
│   └── ubnt_cgi/
│       ├── sub_XXX_old.c
│       ├── sub_XXX_new.c
│       └── sub_XXX.c.diff
├── hash_compare.json
├── diff_results.json
└── function_diff_stats.json
```

## SQLite DB 구조

```
src/db/patch_learner.db
├── firmware_versions      <- 펌웨어 버전 관리
├── diff_sessions          <- 디핑 세션 (old vs new)
├── changed_files          <- Stage 0: 해시 디핑 결과
├── bindiff_results        <- Stage 1: BinDiff 바이너리 단위
├── changed_functions      <- Stage 1: 변경 함수 + old/new pseudocode
├── security_patches       <- Stage 2: LLM 전수 분석 결과
└── hunt_findings          <- Stage 3: 0-day 헌팅 결과
```

---

## 개발 이력 (Step 기반 → Stage 기반 전환 전)

아래는 Step 0~10 체계로 개발했던 시기의 기록이다. 현재는 Stage 0~3으로 통합.

### 과거 Step 8: IoT 보안 후보 선별

> 현재 Stage 2에서 LLM 전수 분석으로 대체. 키워드 스코어링 단계 제거.

- 기존: 키워드/위험함수/바이너리 가중치로 스코어링 → 상위 후보 선별
- 문제: 임의 가중치에 근거 없음, IoT 바이너리 누락 발생
- 변경: BinDiff가 Discovery 역할 → LLM이 전수 분석

### 과거 Step 9: Discovery -> Analysis 2단계

> 현재 Stage 2의 1-pass로 통합. 분류 단계 스킵.

- 기존: 토스 방식 Discovery(필터) → Analysis(심층) 2단계
- 변경 이유: 우리 규모(30~200개)에서 2단계는 오탐/미탐만 증가

### 과거 Step 10: Pydantic 검증 + DB 저장

> Stage 2 내부 프로세스로 흡수.

- Pydantic 검증은 유지 (출력 포맷 강제)
- DB 저장은 Stage 2 마지막에 자동 수행
