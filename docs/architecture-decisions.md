# Patch-Learner 파이프라인 아키텍처 확정안

> 초안 확정: 2026-03-25
> 운영 보완 반영: 2026-04-02

## 1. 구조를 Step이 아닌 Stage로 통합한다

결론은 4단계 구조다.

```
Stage 0: 펌웨어 추출 + 해시 디핑
Stage 1: BinDiff + 전체 디컴파일 → DB
Stage 2: LLM 1-pass 전수 분석
Stage 3: 0-day 헌팅
```

이 구조를 쓰는 이유는 중간 산출물의 책임 경계를 분명히 하고, Stage 0~1 결과를 여러 번 재사용하기 쉽기 때문이다.

## 2. 변경 함수는 전부 저장한다

BinDiff가 찾아낸 변경 함수가 30개면 30개 전부 old/new pseudocode와 함께 저장한다.

이 결정을 유지하는 이유는 다음과 같다.

- 비보안 변경도 다음 버전 비교의 기준점이 된다.
- LLM 판단이 바뀌더라도 IDA를 다시 돌리지 않고 재분석할 수 있다.
- 논문과 보고서에서 "전체 변경 함수 중 몇 개가 보안 패치였는가"를 계산하려면 분모 데이터가 필요하다.

## 3. 별도 분류기는 두지 않는다

토스 방식처럼 Discovery와 Analysis를 분리할 수도 있지만, 현재 프로젝트에서는 분리하지 않는다.

이유는 다음과 같다.

- 우리의 입력은 이미 BinDiff가 좁힌 "변경 함수" 집합이다.
- 한 번 더 필터링하면 false negative가 생겨 분석 기회 자체를 잃을 수 있다.
- 현재 규모(버전 페어당 수십~수백 함수)는 LLM이 전수 분석 가능한 범위다.

따라서 Stage 2는 **분류 + 분석을 한 번에 수행하는 1-pass 구조**를 유지한다.

## 4. severity와 confidence는 LLM이 직접 판단한다

임의 가중치 공식은 사용하지 않는다.

- `severity`: CRITICAL / HIGH / MEDIUM / LOW
- `confidence`: 0.0 ~ 1.0

평가 기준은 수치 공식이 아니라, 최종 결과의 precision / recall과 근거 설명의 일관성이다.

## 5. Stage 0~1 코퍼스를 먼저 넓힌 뒤 Stage 2를 일괄 수행한다

2026-04-02 기준 운영 순서는 다음과 같이 정리했다.

1. Synology, Tapo, 이후 ipTIME/Ubiquiti까지 Stage 0~1 산출물을 먼저 확보한다.
2. 여러 벤더에서 누적된 `changed_functions`를 기준으로 Stage 2를 배치 실행한다.
3. Stage 2 결과를 기반으로 Stage 3 헌팅 패턴을 추출한다.

즉, Stage 2는 파이프라인에서 빠진 것이 아니라 **실행 순서가 뒤로 조정된 것**이다.

## 6. 펌웨어 추출은 포맷별로 분기한다

### Synology

- `.sa.bin`은 직접 파싱한다.
- 필요 시 UBI에서 SquashFS를 복원한다.

### 일반 펌웨어

- WSL Ubuntu에서 `binwalk -e`를 실행한다.
- `binwalk` 전에는 `wsl --shutdown`을 호출해 추출 충돌을 줄인다.

### Tapo v3/v4 계열

- `signed/encrypted` 헤더를 검사한다.
- 해당 패턴이면 `tp-link-decrypt`를 먼저 수행하고, 복호화된 결과에 대해 `binwalk`를 실행한다.

이 결정을 통해 평문형 Tapo(v1/v2)와 복호화 선행형 Tapo(v3/v4)를 같은 Stage 0 흐름 안에서 처리한다.

## 7. 모델 폴더 단위 자동 실행을 기본으로 한다

`sequential_diff.py`는 다음 두 모드를 모두 지원한다.

- 단일 모델 폴더 실행
- 상위 펌웨어 루트를 주고 하위 모델 폴더를 재귀 탐색

출력은 항상 모델 기준으로 정리한다.

```
output/<모델>/v<old>_vs_v<new>/
```

이 방식으로 벤더나 모델이 늘어나도 같은 실행 인터페이스를 유지할 수 있다.

## 8. 저장 방식은 JSON 캐시 + SQLite DB를 병행한다

- 함수 단위 원본 데이터: JSON 캐시
- diff 세션과 분석 결과: SQLite DB

이 조합을 유지하는 이유는 다음과 같다.

- JSON은 대용량 pseudocode를 파일 단위로 재사용하기 좋다.
- SQLite는 누적 비교, 재분석, 통계 질의에 적합하다.

## 9. 0-day 헌팅은 3단계로 진행한다

1. **패턴 매칭**: sink 함수와 검증 누락 패턴을 빠르게 검색
2. **컨텍스트 분석**: 후보만 다시 디컴파일해 LLM으로 비교
3. **수동 검증**: 높은 신뢰도 후보를 사람이 확인

이 3단계 구조는 자동화 범위와 사람 검증 범위를 분리해, 규모가 커져도 운영 가능한 형태를 유지하기 위한 결정이다.

## 10. DB 저장은 파이프라인에 통합한다

2026-04-02에 다음 사항을 확정했다.

- `bindiff_pipeline.py`에 `--vendor`, `--model`, `--old-ver`, `--new-ver`, `--db-path` 인자를 추가해 JSON 출력과 DB 저장을 동시에 수행한다.
- `sequential_diff.py`는 firmware 디렉토리명에서 vendor/model을 자동 감지해 pipeline에 전달한다.
- DB는 `Patch-Learner-main/src/db/patch_learner.db` 단일 파일을 사용한다.
- `src/tools/import_existing_output.py`로 기존 output JSON 결과를 DB에 일괄 import할 수 있다.
- `--no-db` 플래그로 DB 저장을 선택적으로 끌 수 있다.

이 결정으로 Stage 0~1 실행 시 별도 수동 저장 스크립트 없이 자동으로 DB에 축적된다.

## 11. 기존 export 재활용 재실행은 output-only로 분리한다

2026-04-06에 다음 사항을 추가로 정리했다.

- `src/analyzers/rebuild_bindiff_from_exports.py`는 기존 `functions/` + `binexport/` 산출물을 재사용해 BinDiff 결과만 다시 생성한다.
- 이 스크립트는 `bindiff/`, `function_diffs/`, `diff_results.json`, `function_diff_stats.json`, `summary.md`를 다시 만드는 복구 경로다.
- DB 갱신은 이 스크립트의 책임이 아니다. DB 동기화가 필요하면 `bindiff_pipeline.py`의 자동 저장 경로를 쓰거나 `src/tools/import_existing_output.py`를 별도로 실행한다.
- 입력 export가 비어 있는 pair는 재생성해도 `changed_functions = 0`으로 남을 수 있다.

이렇게 분리해 두면 output 복구와 DB 적재의 책임 경계가 명확해지고, 기존 결과를 다시 돌릴 때 provenance를 추적하기 쉽다.

## 12. 패턴카드는 벤더·CWE 라벨이 아닌 구조적 taint 공식 + 핵심 스니펫으로 저장한다

2026-04-17에 Stage 2 Phase 4 패턴카드 스키마를 재설계했다.

기존 스키마는 `vendor`, `cwe`, `vulnerability_type` 같은 라벨 필드를 카드 본체에 두고 있었다. 이 설계는 두 가지 문제가 있었다.

- **재사용성**: 같은 취약점(예: HTTP Host 헤더 길이 미검증)이 Dahua(CVE-2025-31700), ipTIME(KVE-2023-5458) 등 여러 벤더에서 동일한 형식으로 반복되지만, `vendor='dahua'`로 고정하면 크로스 벤더 헌팅이 불가능하다.
- **토큰 폭발**: 카드가 수백~수천 장 쌓이면 Phase 5 Hunter LLM에 전부 넣을 수 없다. 라벨 기반 카드는 서사 설명이 길어져 카드당 토큰이 수백 단위로 커진다.

확정 설계는 다음과 같다.

### 카드 본체 = 구조적 공식 3원소

- `source_type` — 외부 데이터 출처 (`http_header`, `http_body`, `rpc_arg`, `onvif_field` 등)
- `missing_check` — 빠진 검증 (`length_bound`, `metachar_filter`, `auth_check` 등)
- `sink_type` — 위험 연산 (`stack_buffer_copy`, `shell_exec`, `format_string` 등)

동일 source + missing_check여도 sink가 다르면 별개 카드로 분리한다.

### 핵심 앵커 = OLD/NEW 코드 스니펫

`vulnerable_snippet`(취약 라인 5~15줄)과 `fixed_snippet`(수정 라인 5~15줄)을 카드에 함께 저장한다. Hunter는 공식 3요소로 후보를 거른 뒤 `vulnerable_snippet`과 대상 함수의 모양을 비교해 1차 매칭하고, `fixed_snippet`과 동형이면 이미 패치됐다고 보고 FP로 배제한다.

### 토큰/배제 힌트는 부속 테이블로 분리

- `pattern_card_tokens`: grep/Python 전처리용 리터럴 토큰 (인덱싱 필수)
- `pattern_card_negative_tokens`: safe wrapper 배제 (`vendor_scope` 필드로 벤더별 범위 지정)
- `pattern_card_grep_patterns`: regex (선택)
- `pattern_card_members`: 어느 `security_patches`에서 파생됐는지
- `pattern_card_stats`: TP/FP 집계로 precision 관리, `< 0.3` 카드는 retire

### 라벨 필드는 참고용 메타로만 유지

`severity_hint`, `cve_similar`, `advisory`는 검색 편의를 위해 카드에 남기되, 매칭 로직의 1차 키로는 쓰지 않는다.

### Hunter LLM 입력 직렬화 표준

카드 1장 = `~200 토큰` (summary 50 + vuln snippet 60 + fixed snippet 60 + 메타 10). Phase 5 전처리가 후보를 1~5장으로 컷하므로 함수당 LLM 입력 총량은 ~1,000 토큰 이내로 유지된다. `long_description`, `attack_scenario`, `fix_detail` 같은 서사는 DB에는 저장하되 Hunter 프롬프트에는 주입하지 않는다.

이 설계로 벤더 라벨 종속성을 제거하고, 같은 공식을 가진 취약점이 다른 벤더에서 재발견되면 자연스럽게 한 카드로 수렴한다. 카드 수가 늘어도 Hunter 토큰 예산은 선형 증가하지 않는다.

## 13. Stage 2 워크플로우를 Drafter 단일 Phase로 통합한다 (Reviewer 제거)

2026-04-17에 팀 논의로 확정한 구조다. 초기 설계는 5-Phase(사전필터 / Analyst / Reviewer / Dedupe / Designer / Hunter)였으나 다음 이유로 단순화했다.

- **토큰/쿼터 부담**: 한 함수를 Analyst·Reviewer·Designer가 각각 읽어 LLM 호출이 3회 발생. Claude Max 5시간 쿼터 내 처리량이 제약됨.
- **맥락 손실**: 같은 함수를 여러 에이전트가 다시 해석하며 중복 비용.
- **Echo chamber**: 같은 Opus 모델이 Analyst와 Reviewer를 동시에 맡으면 자기 판정을 승인하는 위험을 프롬프트로만 억제해야 함.
- **카드 포맷으로 쌓아 훑는 게 더 효율적**이라는 팀 의견이 설득력 있었다.

확정 구조는 다음과 같다.

```
Phase 0. 사전 필터 (Python)    : OSS 바이너리/similarity/키워드 컷
Phase 1. Drafter (A1·A2 병렬)  : 판정 + 카드 작성 동시 수행
Phase 2. Hunter (Opus)         : 타겟 펌웨어 × 카드 1:N 매칭
```

### Drafter의 역할 통합

Drafter는 한 턴에:
1. 함수 diff를 읽고 `is_security_patch` 판정 + `security_patches` 필드 채움.
2. 보안 패치면 동시에 `card_draft` 섹션을 출력 — 공식 3원소, OLD/NEW 스니펫, 토큰, negative_tokens까지.
3. 오케스트레이터가 DB에 저장할 때 같은 공식의 active 카드가 있으면 `pattern_card_members`에 행 추가 (Auto-merge), 없으면 신규 INSERT.

### Reviewer 부재 시 FP 가드

Reviewer를 없앤 대신 FP는 세 층에서 거른다.
1. Drafter 프롬프트 자체에 False Positive 가드 7종 + Synology Hard Rules + confidence 기준표 하드코딩. confidence 0.70 미만은 기본 `is_security_patch=false`.
2. Auto-merge로 같은 공식 카드 수렴. 드문 오류는 카드 폭발로 이어지지 않음.
3. Hunter 결과의 `hunt_findings.is_true_positive`를 사람이 확정 → `pattern_card_stats.precision` 하락 시 retire 게이트 진입.

### DB 레벨 중복 차단

`pattern_cards`에 부분 UNIQUE INDEX (`idx_pc_formula_active`)로 `status='active'`인 같은 `(source_type, sink_type, missing_check)` 조합은 1건만 존재. 오케스트레이터의 Auto-merge 로직이 실패해도 DB가 최종 방어한다.

### 유지된 Phase 2 (Hunter)

Hunter는 구조 변경 없음. 단 카드 입력 포맷이 공식 + 스니펫 shortform으로 확정됐고, `fixed_snippet`과 대상 함수가 동형이면 이미 패치된 것으로 보고 match=false로 내리는 규칙이 프롬프트에 내장됐다.

## 14. Zero-Day 블라인드 헌트를 Stage 2 와 별도 경로로 둔다 (2026-04-21)

Stage 2 Drafter는 diff (OLD/NEW) 기반 판정이라 패치가 있는 버전에만 동작. 실제 제로데이 헌팅은 **단일 바이너리의 모든 함수를 학습 카드 vs 블라인드 Agent 로 감사**하는 비-diff 경로가 필요. Stage 3 Hunter 는 토큰 기반 prefilter 만 하므로 부족.

### 블라인드 헌터의 범위

- 입력: **단일 바이너리** 1개 (IDA 전체 함수 디컴파일 JSON) + 학습된 `pattern_cards`
- 출력: `zero_day_verdicts` — 함수당 취약/정상 판정 + matched_card_pk (없으면 novel) + root_cause
- 별도 테이블: `zero_day_runs` / `zero_day_functions` / `zero_day_verdicts` — Stage 2 테이블과 분리
- 재사용: `prefilter.py` 의 DANGEROUS_KEYWORDS, `pattern_card_tokens/negative_tokens`

### 블라인드 제약 (하드 규칙, 프롬프트 내장)

실제 제로데이 연구를 시뮬레이션하려면 Agent 가 외부 CVE 지식을 사용하면 안 된다.

- 외부 지식 완전 차단 (CVE DB / 벤더 advisory / 연구자 블로그 사전 기억 없는 척)
- 파일 읽기 allow-list: `zero_day_hunter.md` / `hard-rules.md` / `pattern-card-spec.md` / 입력 JSON
- 차단 파일: `cve-*.md`, `kve*.md`, `advisory*`, `changelog*`
- WebSearch/WebFetch 절대 금지
- 출력 field 전체에 `CVE-\d{4}-\d+` / `KVE-\d{4}-\d+` 정규식 매치 0건 (사후 검증)

카드의 `cve_similar` 필드가 있어도 **opaque label 로만** 취급 — Agent 가 그 CVE 가 무엇인지 안다고 가정 금지.

### Validation 기법: "알려진 CVE 카드 은닉" 검증

`zero_day_run.py prepare --exclude-card-pk <pk>` 로 특정 카드를 Agent context 에서 제거. 이미 해당 CVE 의 공식을 학습한 카드를 숨긴 채 Agent 가 같은 함수·같은 공식을 **독자적으로 재도출** 하는지 측정.

sonia v2.880.0.16 에서 **P-106 (CVE-2025-31700) 은닉** 후 48개 함수 (CVE 타겟 8 + 디코이 40) 블라인드 실행 → **v3 프롬프트로 CVE-31700/31701 타겟 둘 다 3축 재도출 + 같은 함수 addr 포착 + CVE 번호 누출 0**.

### size-literal anchoring 금지 규칙 (v3 프롬프트)

v2 실패 사례에서 도출:

- v2 Agent가 `sub_10B0FBC(..., v97, 0x7FFu)` 같은 literal size 인자 보고 "bounded → benign" 로 short-circuit.
- 실제 CVE-31700 본질은 size 가 `(bracket_ptr - dest)` 같은 attacker-controlled 산술 결과 — literal 이 아니라 **"size 의 origin"** 이 중요.

v3 규칙: size 가 literal 이어도 bounded 결론 금지. 반드시 출처 (`strlen(user)` / pointer 산술 / strchr 결과) 를 따져야 함. 출처 불분명 시 conf 0.5~0.65 + needs_human_review.

### 피드백 루프 (승격)

블라인드 Agent 가 novel 로 판정한 verdict 는 자동으로 `pattern_cards` 에 승격하지 않는다. 사람 리뷰 → `confirmed_vuln` 확정 후 명시적 promote. 자동 승격은 false positive 로 라이브러리를 오염시킬 수 있음.

---

## 15. 팀 카드 card_id 병합 시 우리 카드를 shift 한다 (2026-04-21)

팀장 원본 `pattern_cards.jsonl` 32장과 내 DB 74장이 **같은 card_id (P-001..P-032) 를 서로 다른 공식으로 사용**. 병합 시 충돌.

### 결정

팀 기준 번호 보존, **우리 카드를 뒤로 shift** (P-001..P-074 → P-033..P-106). TMP-N 중간 상태로 UNIQUE 충돌 회피. `idx_pc_formula_active` 충돌하면 팀 카드를 `status='superseded_by_ours' + superseded_by=<our_id>` 로 보존.

`card_id` 문자열은 표시 라벨, 모든 FK 는 `pattern_cards.id` (INT pk) 로 유지되므로 외부 참조는 깨지지 않음.

---

## 16. 웹 대시보드는 읽기 전용 + 리뷰만 쓰기로 분리한다 (2026-04-21)

CLI SQL 로 상태 확인하던 것을 localhost 웹 UI 로 전환. DB 연결 기본 `file:...?mode=ro` + `PRAGMA query_only=1`. 예외는 사람 리뷰 저장 (`POST /api/zero-day/verdicts/{vid}/review`) 만 별도 write-enabled connection. Agent 실행/배치 트리거는 웹 불가, CLI만 — 단일 오케스트레이터 단순화.

SSE 2초 간격 진행률 push, 취약 판정은 **모달이 아닌 인라인 카드** (LLM root_cause + attack_scenario + raw_reasoning 전문 + 리뷰 폼) 로 표시.

---

## 17. 현재 문서화 기준

2026-04-21 기준으로 다음 항목이 추가 반영됐다.

- Zero-Day 블라인드 헌트 경로: `.claude/skills/stage2/sql/zero_day_migration.sql`, `prompts/zero_day_hunter.md`, `src/stage2/zero_day_run.py`, `ida_user/extract_all_funcs.py`
- 웹 대시보드: `web/` (FastAPI + Jinja2 + SSE, 한국어화 완료, localhost:8787)
- 팀 카드 병합: `src/stage2/merge_team_cards.py`, DB 총 106장 (99 active + 7 superseded)
- CVE ground truth: `data/cve/ground_truth.jsonl` (3건 — CVE-2025-31700/31701, KVE-2023-5458)
- pattern_cards 전체 export: `src/stage2/export_pattern_cards_jsonl.py` → `pattern_cards.jsonl` (106장)
- security_patches 세션 export: `src/stage2/export_sp_session_jsonl.py` → `data/handoff/security_patches_session.jsonl` (572건)
- 운영 런북 추가: `docs/zero-day-runbook.md`
- size-literal anchoring 금지 규칙 (zero_day_hunter.md v3)

2026-04-17 기준으로 다음 항목이 추가 반영됐다.

- Stage 2 워크플로우 v3: `.claude/skills/stage2/` 를 3-Phase(사전필터 / Drafter / Hunter)로 재구성
- Drafter / Hunter 시스템 프롬프트 확정. Analyst/Reviewer/Designer 프롬프트 파일은 삭제
- 패턴카드 스키마 v2: 공식 기반 재생성 + 부속 6개 테이블 + `idx_pc_formula_active` 부분 UNIQUE INDEX
- 팀원 공유용 스펙 문서 `docs/pattern-card-spec.md` 작성 (컬럼별 설명, 체크리스트, FAQ 10건)

2026-04-06 기준으로 다음 항목이 구현 또는 반영됐다.

- `bindiff_pipeline.py`의 DB 자동 저장 통합
- `bindiff_pipeline.py`의 Tapo 복호화 분기
- `bindiff_pipeline.py`의 `wsl --shutdown` 선행 처리
- `sequential_diff.py`의 상위 폴더 재귀 실행 + vendor/model 자동 감지
- `import_existing_output.py`의 기존 output 일괄 DB import
- `rebuild_bindiff_from_exports.py`의 기존 export 기반 BinDiff 재생성
- `download_iptime_firmware.py`의 모델별 다운로드 수집 경로

이후 문서 업데이트는 위 구현을 기준으로 맞춘다.
