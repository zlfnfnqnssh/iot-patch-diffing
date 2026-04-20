# Patch-Learner — Claude 작업 가이드

## 프로젝트 한 줄 요약
IoT 펌웨어 두 버전을 비교해 변경된 함수를 자동 추출하고, C 의사코드(pseudocode) 수준에서 보안 취약점을 분석하는 파이프라인.

## GitHub 저장소

| 구분 | URL | 브랜치 |
|------|-----|--------|
| 개인 (기본) | https://github.com/zlfnfnqnssh/iot-patch-diffing | `main` |
| 팀 | https://github.com/seosamuel02/Patch-Learner | `riri` (로컬: `Patch-Learner-collab/`) |

**push 규칙:** 기본=개인 저장소. "팀쪽으로" / "team에" 언급 시 팀 저장소 `riri` 브랜치.

## 핵심 경로

| 항목 | 경로 |
|------|------|
| 메인 파이프라인 (Stage 0~1) | `src/analyzers/bindiff_pipeline.py` |
| 순차 디핑 | `src/analyzers/sequential_diff.py` |
| Stage 2 Drafter | `src/stage2/drafter_run.py` |
| Stage 2 prefilter | `src/stage2/prefilter.py` |
| Stage 2 Hunter | `src/stage2/hunter_run.py` |
| **Zero-Day 오케스트레이터** | `src/stage2/zero_day_run.py` |
| 주소 지정 focus batch | `src/stage2/zero_day_prepare_addrs.py` |
| 팀 카드 병합 | `src/stage2/merge_team_cards.py` |
| IDAPython (변경 함수만) | `ida_user/extract_with_decompile.py` |
| IDAPython (전체 함수) | `ida_user/extract_all_funcs.py` |
| IDAPython (주소 지정) | `ida_user/decompile_selected.py` |
| 웹 대시보드 | `web/app.py` (→ http://127.0.0.1:8787) |
| DB 모듈 | `src/db/pipeline_db.py` |
| DB 파일 (유일 진실원) | `Patch-Learner-main/src/db/patch_learner.db` |
| 블라인드 헌터 프롬프트 | `.claude/skills/stage2/prompts/zero_day_hunter.md` |
| Zero-Day 마이그레이션 | `.claude/skills/stage2/sql/zero_day_migration.sql` |
| Ground truth (CVE 레이블) | `data/cve/ground_truth.jsonl` |
| IDA Pro | `C:\Program Files\IDA Professional 9.0\idat64.exe` |
| BinDiff | `C:\Program Files\BinDiff\bin\bindiff.exe` |

## 코드 구조

```
src/
  analyzers/
    bindiff_pipeline.py       # Stage 0~1 메인 파이프라인 (DB 자동 저장)
    sequential_diff.py        # 연속 버전 쌍 자동 실행 (vendor/model 자동 감지)
    generate_pattern_cards.py # 레거시 카드 생성
    rebuild_bindiff_from_exports.py
  stage2/
    prefilter.py              # Phase 0: 위험 키워드 필터
    drafter_run.py            # Phase 1: Drafter Agent 오케스트레이터 (diff-based)
    hunter_run.py             # Phase 2: 카드 토큰 매칭 hunt_findings
    zero_day_run.py           # Phase 3 (신규): 블라인드 제로데이 헌트 오케스트레이터
    zero_day_prepare_addrs.py # Zero-Day focus batch (주소 지정)
    merge_team_cards.py       # 팀 카드 병합 (shift + upsert)
    export_pattern_cards_jsonl.py
    export_sp_session_jsonl.py
    register_sonia.py         # Stage 0~1 우회 DB 등록 (특정 바이너리)
  db/
    pipeline_db.py
    init_db.py
    schema.sql
  tools/
    import_existing_output.py
ida_user/
  extract_with_decompile.py   # 변경 함수만 (Stage 0~1 용)
  extract_all_funcs.py        # 전체 함수 (Zero-Day 용, checkpoint + resume)
  decompile_selected.py       # 주소 리스트 지정 디컴파일
  find_xrefs_and_dump.py      # 문자열 xref 기반 함수 찾기
  find_named_funcs.py         # 함수명 패턴 매칭
.claude/skills/stage2/
  sql/
    migration.sql             # Stage 2 v3/v4 스키마
    zero_day_migration.sql    # Zero-Day 3테이블 (runs/functions/verdicts)
  prompts/
    drafter.md                # Stage 2 Drafter (diff-based)
    hunter.md                 # Stage 2 Hunter
    zero_day_hunter.md        # Zero-Day 블라인드 프롬프트 (v3 size-anchoring 금지)
  rules/hard-rules.md
web/
  app.py                      # FastAPI localhost:8787
  api/                        # dashboard / cards / sessions / zero_day routes
  templates/                  # Jinja2 (한국어화 완료)
  static/                     # style.css + labels.js
  run.ps1 + run.sh
data/
  cve/ground_truth.jsonl      # CVE 정답 레이블 (3건: CVE-31700/31701/KVE-2023-5458)
  handoff/
    security_patches_session.jsonl  # 572건, 카드 연결 포함
pattern_cards.jsonl           # 106장 전체 export (project root)
Patch-Learner-main/
  src/db/patch_learner.db     # 유일 DB 파일 (모든 데이터 여기)
```

## DB 파이프라인 흐름

```
[Stage 0~1 diff 경로]
  firmware_versions → diff_sessions → changed_files → bindiff_results
    → changed_functions → security_patches → hunt_findings
                                          → pattern_cards (+ tokens/members/stats)

[Zero-Day 경로 — 신규]
  pattern_cards(학습된 카드 라이브러리)
       ↓ (Agent context, 특정 카드 은닉 가능)
  zero_day_runs → zero_day_functions (전체 함수 디컴파일 결과)
              → zero_day_verdicts (블라인드 Agent 판정)
```

`bindiff_pipeline.py`에 `--vendor`, `--model`, `--old-ver`, `--new-ver` 전달 시 Stage 0~1 자동 저장.
Zero-Day는 `src/stage2/zero_day_run.py` 커맨드 (`migrate/init/prefilter/prepare/split/apply/status`).

## 현재 DB 현황 (2026-04-21)

| 테이블 | 건수 | 비고 |
|--------|------|------|
| firmware_versions | 899 | |
| diff_sessions | 833 | |
| changed_files | 60,691 | |
| bindiff_results | 49,112 | |
| changed_functions | 414,879 | |
| security_patches | 2,016 | is_security_patch=1 : **572** |
| pattern_cards | **106** | active **99** / superseded 7 |
| pattern_card_members | 123 | |
| hunt_findings | 11,193 | |
| zero_day_runs | 1 | sonia v2.880.0.16_blind_noP106 |
| zero_day_functions | 121,900 | prefiltered_in: 1,468 |
| zero_day_verdicts | 48 | vuln 판정: 7 (CVE-31700/31701 포함) |

**카드 번호 규칙 (2026-04-21 변경):**
- P-001..P-032 = 팀장 원본 카드 (status `active` 25 + `superseded_by_ours` 7)
- **P-033..P-106** = 내 Drafter 생성 카드 (기존 P-001..P-074 에서 shift)
- **P-106 (pk=74)** = `http_header → stack_buffer_copy + length_bound`, cve_similar=CVE-2025-31700 (진짜 CVE 타겟용)

## 분석 대상별 상태

### Ubiquiti UniFi Camera (ARM, v4.30.0 vs v4.51.4)
- Stage 0~2 완료, 34개 패턴 카드
- 주요 발견: Command Injection (CVE-2021-22909), Auth Bypass, Hardcoded AES Key

### Synology BC500

| 비교 | Stage | 결과 |
|------|-------|------|
| v1.0.4→v1.0.5 | 0~2 완료 | 4 패턴 카드 (CRITICAL: Format String CWE-134) |
| v1.0.5→v1.0.6 | 0~2 완료 | 16 보안 패치 (CRITICAL 2, HIGH 7, MEDIUM 5, LOW 2) |

### TP-Link Tapo C200 (MIPS)

| 모델 | 세션 수 | 변경 파일 | 변경 함수 | Stage |
|------|---------|-----------|-----------|-------|
| C200v1 | 20 | 1,020 | 10,371 | 0~1 완료, DB 저장 완료 |
| C200v2 | 8 | 334 | 999 | 0~1 완료, DB 저장 완료 |
| C200v3 | 10 | 326 | 477 | 0~1 완료, DB 저장 완료 |
| C200v4 | 1 | 92 | 208 | 0~1 완료, DB 저장 완료 |

## Zero-Day 블라인드 헌트 (2026-04-21 신규 파이프라인)

**목표:** 기존 pattern_cards (학습된 취약 공식 카탈로그) 만으로 새 바이너리 전체 함수를 블라인드 감사 → CVE 사전 지식 없이 제로데이 후보 도출. 실제 CVE-2025-31700/31701 은닉 테스트로 3-axis 공식 재도출 검증됨.

### 실행 흐름
```
python src/stage2/zero_day_run.py migrate                    # 테이블 생성
ida_user/extract_all_funcs.py                                # 전체 함수 디컴파일 (~45분)
python src/stage2/zero_day_run.py init ...                   # run 생성
python src/stage2/zero_day_run.py prefilter <run_id>         # 위험 키워드 필터
python src/stage2/zero_day_run.py prepare <run_id> \
    --limit 200 --order size_desc --exclude-card-pk <pk>     # 배치 JSON (특정 카드 은닉 가능)
python src/stage2/zero_day_run.py split <in.json> --shards 4
# → 4 Agent 병렬 spawn with .claude/skills/stage2/prompts/zero_day_hunter.md
python src/stage2/zero_day_run.py apply <run_id> <out_a*.json>
```

### 블라인드 제약 (프롬프트 내장)
- 외부 지식 금지 (CVE 번호 인지 X)
- `cve-*.md/kve*.md/advisory*/changelog*` 파일 읽기 금지
- WebSearch/WebFetch 금지
- 출력에 `CVE-\d{4}-\d+` / `KVE-\d{4}-\d+` 정규식 매치 금지
- **size-literal anchoring 금지** (v3): `0x7FFu` 같은 literal 인자 있어도 bounded 판단 금지. size 의 **출처 (strlen/포인터 산술/strchr)**를 따져야 함.

### 웹 대시보드
```
cd web && .\run.ps1  (또는 bash run.sh)
# → http://127.0.0.1:8787
```
- `/` 대시보드 / `/cards` 106장 / `/sessions` 833 / `/findings` 11K / `/zero-day` runs
- `/zero-day/<run_id>` — SSE 실시간 진행률 + 취약 판정 인라인 LLM reasoning 카드 + 사람 리뷰 폼

## 다음에 할 일

- [x] **Zero-Day 인프라 구축** (2026-04-21 완료)
- [x] sonia v2.880.0.16 전체 디컴파일 + run 1 init
- [x] 블라인드 v3 프롬프트 검증 (CVE-31700/31701 둘 다 3축 재도출 성공)
- [ ] sonia run 1 남은 1,420 함수 v3 프롬프트로 batch 순차 실행
- [ ] Novel 판정 5건 사람 리뷰 → confirmed_vuln 은 pattern_card 로 promote
- [ ] `web` 에 "Promote verdict → pattern_card" 버튼 추가
- [ ] TP-Link Tapo C200 12,055개 변경 함수 Drafter 배치 계속 (diff-based)
- [ ] Detection Rules 자동 생성 (패턴 카드 기반)
- [ ] ipTIME 펌웨어 수집 + Stage 0~1 코퍼스 확대

## 자동 문서화 규칙
코드 수정, 기능 추가, 에러 해결, 설계 변경, 분석 결과 발견 시:
1. `docs/dev-notes.md`에 `### YYYY-MM-DD | 제목` 형식으로 기록
2. GitHub push: `bash scripts/push_team_artifacts.sh "설명"` (origin/main) + 팀 공유 시 `git push team HEAD:riri`

## 관련 문서
- [프로젝트 개요](docs/project-overview.md) — 기획 동기, 목표, 검증 대상
- [파이프라인 설계](docs/pipeline.md) — Stage 0~3 + Zero-Day 블라인드 아키텍처
- [개발 일지](docs/dev-notes.md) — 날짜별 트러블슈팅, 분석 결과
- [아키텍처 결정](docs/architecture-decisions.md) — 팀 논의 확정안
- [패턴카드 작성 스펙 v2](docs/pattern-card-spec.md) — 스키마·컬럼·체크리스트
- [Stage 2 런북](docs/stage2-runbook.md) — Stage 2 CLI 운영 절차
- [**Zero-Day 런북**](docs/zero-day-runbook.md) — **블라인드 헌트 전용 절차 + 웹 사용법**
- [Stage 2 스킬](.claude/skills/stage2/SKILL.md) — 3-Phase (사전필터 / Drafter / Hunter)
