# 파이프라인 설계

> 설계 원칙은 [architecture-decisions.md](architecture-decisions.md) 참고

## 전체 구조 (확정 2026-03-25, DB 통합 2026-04-02, Zero-Day 경로 추가 2026-04-21)

```
[A] Diff 기반 학습 경로 (Stage 0~2)
펌웨어 A (old) ─┐
                ├─ Stage 0: 펌웨어 추출 + 해시 디핑
펌웨어 B (new) ─┘       ↓ changed_files (DB)
                   Stage 1: BinDiff + 변경 함수 디컴파일
                        ↓ changed_functions (DB + JSON 캐시)
                   Stage 2: Drafter Agent 전수 분석
                        ↓ security_patches + pattern_cards (DB)
                   Stage 3 Hunter: 카드 토큰 매칭
                        ↓ hunt_findings (DB)

[B] Zero-Day 블라인드 헌트 경로 (2026-04-21 추가)
학습된 pattern_cards ─┐
                      ├─ Zero-Day Phase A: 대상 바이너리 전체 함수 디컴파일
새 바이너리 ───────────┘       ↓ zero_day_functions (DB)
                        Zero-Day Phase B: 위험 키워드 prefilter
                             ↓ prefiltered=1
                        Zero-Day Phase C: 블라인드 Agent 판정
                             (학습 카드 일부 은닉 가능 = validation)
                             ↓ zero_day_verdicts (DB)
                        Zero-Day Phase D: 사람 리뷰 + 승격
                             ↓ 새 pattern_card 로 promote
```

두 경로 모두 같은 `pattern_cards` 라이브러리를 공유. [A]에서 학습된 카드를 [B]에서 판정 기준으로 사용. [B]에서 novel로 판정된 것이 사람 리뷰 거쳐 [A]의 pattern_cards 에 추가되는 피드백 루프 구조.

Stage 0~1은 여러 벤더를 상대로 반복 실행하고, Stage 2는 충분한 코퍼스가 모인 뒤 일괄 수행한다.
`bindiff_pipeline.py`에 `--vendor`, `--model`, `--old-ver`, `--new-ver`를 전달하면 JSON 출력과 동시에 DB에 자동 저장된다.
`sequential_diff.py`는 firmware 디렉토리명에서 vendor/model을 자동 감지해 pipeline에 전달한다.
Zero-Day 헌트는 `src/stage2/zero_day_run.py` 로 별도 오케스트레이션 — 자세한 절차는 [zero-day-runbook.md](zero-day-runbook.md) 참고.

## Stage 0: 펌웨어 추출 + 해시 디핑

### 0-1. 추출 경로

- **Synology**: `.sa.bin` 포맷을 직접 파싱해 루트 파일시스템을 복원한다.
- **일반 펌웨어**: WSL Ubuntu에서 `binwalk -e`를 실행한다.
- **Tapo v3/v4 계열**: 헤더를 검사해 `signed/encrypted` 형식이면 `tp-link-decrypt`를 먼저 수행한 뒤 `binwalk`를 실행한다.

현재 구현에서 `binwalk` 전에는 `wsl --shutdown`을 먼저 호출한다.
이 단계는 WSL 인스턴스가 열린 상태에서 `binwalk`가 실패하던 문제를 줄이기 위한 운영 보강이다.

### 0-2. rootfs 탐색과 캐시

- 추출 결과에서 `bin`, `usr`, `etc`, `lib`가 함께 있는 디렉터리를 rootfs 후보로 본다.
- `.extracted_ok` 마커 파일을 두어 재실행 시 재추출을 피한다.
- Tapo 복호화 결과는 출력 폴더 하위 `_decrypt_cache/`에 둔다.

### 0-3. 해시 비교

- SHA256으로 old/new rootfs 전체 파일을 비교한다.
- `ThreadPoolExecutor`로 병렬 해싱한다.
- IDA 임시파일과 분석 노이즈는 제외한다.
- 결과는 `hash_compare.json`과 `changed_files` 테이블에 저장한다.

### 0-4. 파일 분류

- ELF 매직 바이트와 NULL 바이트 유무로 바이너리 여부를 판별한다.
- `/usr/share/zoneinfo/` 계열 파일은 노이즈로 보고 제외한다.
- 텍스트 파일은 `difflib.unified_diff`로 `.patch`를 생성한다.

## Stage 1: BinDiff + 전체 디컴파일 → DB

### 1-1. 함수 추출

IDA는 바이너리별로 old/new 각각 1회 실행한다.
우선 `extract_with_decompile.py`로 함수 JSON을 만들고, 같은 실행에서 `.BinExport` 생성을 시도한다.
만약 `.BinExport`가 누락되면 `-OBinExportAutoAction:BinExportBinary` 기반 fallback export를 추가로 수행한다.

추출 데이터는 다음을 포함한다.

- `pseudocode`
- `disasm`
- `mnem_hash`
- `calls`
- `strings`
- `constants`
- `bb_count`

함수 JSON 캐시는 `functions/{binary}_old.json`, `functions/{binary}_new.json`에 저장한다.

### 1-2. BinDiff 함수 매칭

```
bindiff.exe --primary old.BinExport --secondary new.BinExport --output_dir dir
```

BinDiff는 이름, CFG, Call Graph, Prime Signature 등 여러 기준으로 함수를 매칭한다.
매칭 결과는 바이너리별 `.BinDiff`와 `bindiff_results` 테이블에 저장한다.

### 1-3. 함수 단위 diff 생성

- `pseudocode`가 있으면 이를 우선 사용한다.
- 없으면 `disasm`을 fallback으로 사용한다.
- instruction 수가 매우 작은 PLT stub 함수는 제외한다.

출력 예시는 다음과 같다.

```
function_diffs/ubnt_cgi/
├── authenticateToken_old.c
├── authenticateToken_new.c
└── authenticateToken.c.diff
```

### 1-4. DB 저장

변경 함수는 old/new pseudocode 쌍과 함께 `changed_functions` 테이블에 저장한다.
비보안 함수도 저장해 분모 데이터와 재분석 기반으로 활용한다.

## Stage 2: LLM 3-Phase 분석 (2026-04-17 v3 확정, 오케스트레이션은 `.claude/skills/stage2/`)

Stage 2는 Drafter 단일 Phase로 판정과 카드 작성을 한 번에 수행한다. 오케스트레이션 스킬(`/stage2`)이 프롬프트, 스키마, SQL을 제공한다.

```
Phase 0. 사전 필터 (Python)    : OSS 바이너리/similarity/키워드로 27K→~1.5K
Phase 1. Drafter (A1·A2 병렬)  : 보안 판정 + 패턴카드 작성 동시 수행
                                 → security_patches + pattern_cards(+ 부속) 동시 INSERT
                                 같은 공식 카드는 Auto-merge로 pattern_card_members에 흡수
Phase 2. Hunter H (Opus)       : 타겟 펌웨어 함수 × 카드 1:N 매칭
```

2026-04-17 이전 초안은 Analyst / Reviewer / Designer를 분리한 5-Phase 구조였다. 팀 논의에서 토큰/쿼터 부담과 맥락 중복을 이유로 단일 Drafter로 통합했다. 상세 근거는 [architecture-decisions.md §13](architecture-decisions.md) 참고.

Drafter 출력은 다음 두 섹션을 함께 포함한다.

- `patch_record` (security_patches 용): `is_security_patch`, `confidence`, `vuln_type`, `cwe`, `severity`, `root_cause`, `fix_description`, `fix_category`, `source_desc`, `sink_desc`, `missing_check`, `attack_vector`, `attack_surface`, `requires_auth`, `known_cve`
- `card_draft` (보안 패치일 때만, pattern_cards + 부속 용): `source_type`, `source_detail`, `sink_type`, `sink_detail`, `missing_check`, `summary`, `vulnerable_snippet`, `fixed_snippet`, `snippet_origin`, `long_description`, `attack_scenario`, `fix_detail`, `severity_hint`, `cve_similar`, `tokens[]`, `grep_patterns[]`, `negative_tokens[]`

운영 순서:

1. 여러 벤더에 대해 Stage 0~1 결과를 먼저 축적한다.
2. 누적된 `changed_functions`에 대해 `sql/prefilter.sql` + Python 키워드 필터를 돌려 입력 큐를 줄인다.
3. Drafter A1(vendor 바이너리) / A2(그 외)를 Agent 서브에이전트로 병렬 실행한다.
4. 오케스트레이터가 Drafter 출력을 DB에 저장하면서 같은 공식 active 카드 존재 시 Auto-merge로 `pattern_card_members` 추가, 없으면 신규 카드 INSERT.
5. Hunter가 타겟 펌웨어의 함수 F에 대해 후보 카드와 1:N 매칭 → `hunt_findings`.
6. 사람이 `is_true_positive` 확정 → `pattern_card_stats.precision` 갱신 → 필요 시 retire.

### 패턴카드 설계 (2026-04-17 확정, v2 포맷 / v3 워크플로우)

패턴카드는 벤더·CWE 라벨이 아니라 **구조적 taint 공식 + 핵심 코드 스니펫**으로 저장한다. 상세 설계는 [architecture-decisions.md §12](architecture-decisions.md) 참고.

카드 본체 필드:

- 공식 3원소: `source_type`, `missing_check`, `sink_type` (+ 각 detail)
- LLM 직접 입력: `summary` (200자), `vulnerable_snippet` (OLD 5~15줄), `fixed_snippet` (NEW 5~15줄), `snippet_origin`
- 인간 전용: `long_description`, `attack_scenario`, `fix_detail`
- 참고 라벨: `severity_hint`, `cve_similar`, `advisory`
- 수명주기: `status`, `version`, `superseded_by`
- 공유: `shared_with_team`, `shared_batch_id`

부속 테이블:

- `pattern_card_tokens` — grep 인덱스 (api/literal/error_msg/const/struct_field)
- `pattern_card_negative_tokens` — safe wrapper 배제 (`vendor_scope`로 벤더 범위 지정)
- `pattern_card_grep_patterns` — regex (선택)
- `pattern_card_members` — 파생 `security_patches` 추적
- `pattern_card_stats` — TP/FP 집계, precision 관리

Phase 5 전처리가 함수 F에서 토큰/enum을 추출해 공식 3원소 + 토큰 인덱스로 후보 카드 1~5장을 컷하며, LLM 호출 전에 99% 축소한다. Hunter는 후보 카드의 `vulnerable_snippet`과 F의 모양을 비교해 1차 매칭하고, `fixed_snippet`과 동형이면 이미 패치됐다고 보고 FP로 내린다.

## Stage 3: 0-day 헌팅 (diff-based)

### Phase 1: 패턴 매칭

- `security_patches`에서 sink 함수와 검증 누락 패턴을 추출한다.
- 타깃 펌웨어에서 해당 호출과 xref를 전수 검색한다.

### Phase 2: 컨텍스트 분석

- Phase 1 후보만 다시 디컴파일한다.
- DB에 저장된 패치 패턴과 유사한지 LLM으로 판별한다.

### Phase 3: 수동 검증

- 신뢰도가 높은 후보부터 IDA에서 직접 검토한다.
- `candidate`, `verified`, `false_positive`, `exploitable` 상태로 관리한다.

## Zero-Day 블라인드 헌트 (2026-04-21 신규 — 비-diff 경로)

Stage 3의 diff 기반 경로와 달리 **대상 바이너리 1개의 전체 함수를 pattern_cards 라이브러리 vs 블라인드 Agent 판정으로 감사**하는 독립 경로. Bitdefender 식 제로데이 연구에 직접 적용 가능.

### Phase A: 전체 함수 디컴파일 (`ida_user/extract_all_funcs.py`)

- 대상 바이너리 하나를 IDA로 자동 분석 + Hex-Rays 전수 디컴파일
- 체크포인트 (`*.partial`) + resume 지원 (IDA 크래시 복구)
- 출력 스키마 = `extract_with_decompile.py` 와 동일하지만 `changed` 필터 없음
- 규모: sonia (33MB) = 121,900 함수 / 116,589 decompile (약 30~45분)

### Phase B: DB 적재 + 위험 키워드 Prefilter

- `zero_day_runs` 에 run 생성, `zero_day_functions` 로 121K 함수 전부 적재
- Prefilter: pseudocode/disasm/strings 에 위험 키워드(`strncpy(`, `sprintf(`, `"Host"`, `"Cseq"`, `/bin/sh` 등) 포함 여부로 `prefiltered=1` 마킹. Stripped binary 대응을 위해 HTTP 헤더 문자열 · 셸 명령 literal 도 포함.
- sonia 예: 121,900 → 1,468 (1.2%) 통과

### Phase C: 블라인드 Drafter Agent (4 병렬 shard)

- `prepare --limit 200 --order size_desc --exclude-card-pk <pk>` 로 배치 JSON 생성
  - `--exclude-card-pk` 는 validation 용. 알려진 CVE 카드를 Agent context 에서 제거해 독자 재도출 가능한지 테스트.
- `split --shards 4` 로 LPT greedy 분배
- Agent 프롬프트: `.claude/skills/stage2/prompts/zero_day_hunter.md`
  - **STRICT CONSTRAINTS**: 외부 지식 / CVE 번호 / advisory 파일 / WebSearch 전면 금지
  - **v3 추가 규칙 (2026-04-21)**: size/length argument 가 literal 이어도 bounded 결론 금지. size 의 origin (strlen/pointer arithmetic/strchr 결과) 을 따져야 함.
- `apply` 로 `zero_day_verdicts` INSERT

### Phase D: 사람 리뷰 + 승격

- 웹 `/zero-day/<run_id>` 에서 취약 판정을 인라인 LLM reasoning 카드로 열람
- 사람이 `confirmed_vuln / false_positive / needs_more_info` 판단 + 메모
- confirmed 는 `pattern_cards` 로 승격 (카드 수동 편집 / CLI promote 경로 예정)

### Validation 사례 (2026-04-21)

같은 48개 함수 (CVE 타겟 8 + 디코이 40) 에 3회 재실행:

| 프롬프트 | 총 vuln | CVE-31700 | CVE-31701 | CVE 번호 누출 |
|---|---|---|---|---|
| v1 (카드 인용 X) | 3 | 적중 but 공식 틀림 | ❌ | 0 |
| v2 (카드 인용 강제) | 3 | benign 오판 | novel | 0 |
| **v3 (+size-literal 금지)** | **7** | **✅ 3축 재도출** | **✅** | 0 |

결론: v3 프롬프트로 running. 카드 은닉 상태에서도 CVE 공식 (`http_header → stack_buffer_copy + length_bound`) 재도출 가능. 자세한 절차는 [zero-day-runbook.md](zero-day-runbook.md).

## 운영 자동화 스크립트

### `src/analyzers/sequential_diff.py`

- 단일 모델 폴더 또는 상위 펌웨어 폴더를 입력으로 받는다.
- 상위 폴더를 주면 하위 모델 디렉터리를 재귀 탐색한다.
- 결과는 `output/<모델>/v<old>_vs_v<new>/`에 저장한다.
- `function_diff_stats.json`이 있으면 해당 pair를 건너뛴다.
- `--vendor`, `--model`을 지정하거나, 경로에서 자동 감지한다.
- DB 저장은 기본 활성화이며, `--no-db`로 끌 수 있다.

### `src/tools/import_existing_output.py`

- 기존 output 디렉토리의 JSON 결과를 PipelineDB로 일괄 import한다.
- `--output-root`, `--vendor`, `--model-filter`, `--db-path`, `--dry-run` 옵션을 지원한다.
- hash_compare.json, diff_results.json, functions/*.json을 파싱해 DB에 저장한다.

### `src/analyzers/rebuild_bindiff_from_exports.py`

- 이미 `functions/`와 `binexport/`가 있는 output pair 디렉터리에서 BinDiff만 다시 수행한다.
- 기본 스캔 경로는 `output/dahua/<model>/v<old>_vs_v<new>/` 형태를 가정한다.
- `bindiff/`, `function_diffs/`, `diff_results.json`, `function_diff_stats.json`, `summary.md`를 다시 생성한다.
- old/new JSON 또는 `.BinExport`가 없는 바이너리는 건너뛴다.
- 이 스크립트는 output 재생성 전용이며, DB는 갱신하지 않는다. DB 반영이 필요하면 `import_existing_output.py`를 별도로 실행한다.
- 기존 export 자체가 함수 0개로 저장된 pair는 재실행해도 `changed_functions = 0` 결과가 유지된다.

### `src/analyzers/download_iptime_firmware.py`

- ipTIME 공지글에서 모델 목록을 읽는다.
- 다운로드 게시판의 과거 공지까지 탐색해 모델별 펌웨어를 수집한다.
- 저장 경로는 `data/firmware/iptime/<MODEL>/`이며, 모델별 manifest를 남긴다.

## 출력 디렉터리 구조

```
{model}/v{old}_vs_v{new}/
├── extracted/
├── functions/
├── binexport/
├── bindiff/
├── text_diffs/
├── function_diffs/
├── _decrypt_cache/         <- Tapo 복호화 입력/출력 캐시
├── hash_compare.json
├── diff_results.json
├── function_diff_stats.json
└── summary.md
```

## SQLite DB 구조

DB 파일: `Patch-Learner-main/src/db/patch_learner.db`

```
firmware_versions          제조사/모델/버전 레지스트리
    ↓
diff_sessions              버전 쌍 비교 단위 (status: pending→hash_diffed→bindiffed→analyzed)
    ↓
changed_files              파일 레벨 변경 (binary/text, 크기)
    ↓
bindiff_results            바이너리별 BinDiff 통계 (유사도 %)
    ↓
changed_functions          함수별 old/new pseudocode 포함
    ↓
security_patches           LLM 보안 판단 (Stage 2에서 채워짐)
    ↓
hunt_findings              0-day 후보 관리 (Stage 3)

pattern_cards              재사용 가능한 취약점 패턴 (v2: 공식 + 스니펫 중심)
  ├─ pattern_card_tokens             grep/prefilter 인덱스
  ├─ pattern_card_negative_tokens    safe wrapper 배제 (vendor_scope)
  ├─ pattern_card_grep_patterns      regex (선택)
  ├─ pattern_card_members            security_patches 파생 추적
  └─ pattern_card_stats              TP/FP 집계 + precision

[Zero-Day 경로 (2026-04-21 추가)]
zero_day_runs              블라인드 감사 실행 단위
  ↓
zero_day_functions         대상 바이너리 전체 함수 (pseudocode + prefiltered)
  ↓
zero_day_verdicts          Agent 판정 (matched_card_pk + 사람 리뷰)
```

### Stage 2 상태 컬럼 (2026-04-17 migration 적용 시)

- `changed_functions.stage2_status` : pending/skipped_oss/prefiltered_in/analyzing_aN/analyzed_aN/error
- `security_patches.analyst_id, review_status, reopen_count, reviewer_note, reopen_reason`
- `security_patches.pattern_group_id, is_group_representative, phase4_status`
- `hunt_findings.pattern_card_id, target_function_id, match_confidence, match_lines, matched_formula, is_true_positive, notes`

### DB 현황 (2026-04-21)

| 테이블 | 건수 | 비고 |
|--------|------|------|
| firmware_versions | 899 | |
| diff_sessions | 833 | |
| changed_files | 60,691 | |
| bindiff_results | 49,112 | |
| changed_functions | 414,879 | |
| security_patches | 2,016 | is_security_patch=1 : 572 |
| pattern_cards | 106 | active 99 / superseded 7 (팀 32 + 우리 74 병합) |
| pattern_card_members | 123 | |
| hunt_findings | 11,193 | |
| zero_day_runs | 1 | sonia v2.880.0.16_blind_noP106 |
| zero_day_functions | 121,900 | prefilter 통과 1,468 |
| zero_day_verdicts | 48 | vuln 판정 7 |

### 벤더별 security_patches 누적 (2026-04-21)

| vendor | sec=1 / total |
|---|---|
| dahua | 493 / 1,050 |
| tp-link | 61 / 600 |
| ipTIME | 18 / 165 |

### 카드 번호 규칙 (2026-04-21 팀 병합 이후)

- P-001..P-032 : 팀장 원본 카드 (25 active, 7 status=`superseded_by_ours`)
- P-033..P-106 : 우리 Drafter 생성 카드 (원래 P-001..P-074 에서 shift)
- P-106 (pk=74) : `http_header → stack_buffer_copy + length_bound`, cve_similar=CVE-2025-31700

## CLI 사용법

### 단일 실행 (DB 저장 포함)
```bash
python src/analyzers/bindiff_pipeline.py \
    --old data/firmware/tapo_C200/C200v1/old.bin \
    --new data/firmware/tapo_C200/C200v1/new.bin \
    --vendor tp-link --model Tapo_C200v1 --old-ver 1.0.2 --new-ver 1.0.3
```

### 순차 자동 실행 (vendor/model 자동 감지)
```bash
python src/analyzers/sequential_diff.py \
    --firmware-dir data/firmware/tapo_C200
```

### 기존 결과 일괄 DB import
```bash
python src/tools/import_existing_output.py \
    --output-root output/ --dry-run
```

### 기존 Dahua export 기준 BinDiff 재생성
```bash
python src/analyzers/rebuild_bindiff_from_exports.py \
    --output-root output/dahua
```

## 현재 제약사항

- IDA와 BinDiff는 Windows 상용 도구에 의존한다.
- Tapo v3/v4처럼 벤더별 전처리가 필요한 포맷은 계속 추가 보완이 필요하다.
- 대형 바이너리는 IDA 처리 시간이 길고, 장시간 실행 중 파일 잠금 이슈가 생길 수 있다.
- Stage 2와 Stage 3의 평가 자동화는 다중 벤더 코퍼스가 더 쌓인 뒤 확장할 예정이다.
