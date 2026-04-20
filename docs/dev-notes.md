# 개발 특이사항 및 트러블슈팅

## 날짜별 개발 일지

---

### 2026-04-21 | 팀 카드 병합 + Zero-Day 인프라 구축 + CVE-31700/31701 블라인드 재탐지 (3회차 프롬프트 튜닝)

**배경:**

4-19 에 만든 P-074(CVE-2025-31700) 카드를 토대로 실제 제로데이 시뮬레이션 전면 실행. 동시에 팀장 요청으로 ground_truth.jsonl + pattern_cards.jsonl 병합 handoff 진행. 웹 대시보드 (FastAPI) 구축해서 CLI SQL 의존 제거.

---

#### A. 팀 카드 병합 (team P-001..P-032 + 우리 P-001..P-074)

**문제:** 팀장이 보낸 `pattern_cards.jsonl` 32장과 내 DB 74장이 같은 card_id P-001..P-032 를 서로 다른 공식으로 사용. 겹치는 32개 card_id 의 formula 가 0/32 일치.

**해결 (`src/stage2/merge_team_cards.py`):**
1. DB 백업 (`.bak.premerge-team-*`)
2. 우리 P-001..P-074 → **P-033..P-106** 로 shift (TMP-N 경유 2-phase update)
3. 팀 32장을 P-001..P-032 로 insert + tokens / negative_tokens / grep_patterns 복제
4. `idx_pc_formula_active` UNIQUE 충돌시 → `status='superseded_by_ours'` + `superseded_by=<our_id>` 로 마킹
5. 팀 카드의 `members[].security_patch_id` 는 상대 DB 기준이라 skip

**결과:** 74 → **106 카드** (99 active + 7 superseded). 팀 기준 번호 보존. CVE-2025-31700 카드: P-074 → **P-106** 으로 이동 (내부 pk=74 유지).

---

#### B. 팀장 handoff (`data/cve/ground_truth.jsonl` + `data/handoff/security_patches_session.jsonl`)

팀장 요청 스키마대로 출력:

- `data/cve/ground_truth.jsonl` (3 entries) — CVE-2025-31700, CVE-2025-31701 (cve-2025-31700.md 기반), KVE-2023-5458 (kve.md 기반). 필드: cve_id, vendor, model, vuln/patched_version, target_binary/function/address, cvss/cwe, source_type/sink_type/missing_check 등 enum 매핑, root_cause_summary, references_url, source.

- `data/handoff/security_patches_session.jsonl` (572 rows) — `is_security_patch=1` 전체. 세션/펌웨어/함수/Drafter 판정 + `pattern_card_memberships[]` 연결 정보 포함. 123건 카드 연결, Dahua 493 / TP-Link 61 / ipTIME 18.

- `pattern_cards.jsonl` 도 같은 방식으로 export (`src/stage2/export_pattern_cards_jsonl.py`) — 카드 + tokens + negative_tokens + grep_patterns + stats + members 전부 merge, 106장 단일 파일.

- `.gitignore` + `scripts/push_team_artifacts.sh` — `data/cve/` 경로 화이트리스트 추가.

- `origin/main` + `team/riri` 양쪽 push 완료 (commit `0ed30cd`).

---

#### C. Zero-Day 블라인드 헌트 인프라 (플랜 승인 후 구현)

**신규 파일:**

1. **DB 스키마** (`.claude/skills/stage2/sql/zero_day_migration.sql`)
   - `zero_day_runs` — run 메타 + 진행률 카운터
   - `zero_day_functions` — run 별 함수 pseudocode + prefiltered 플래그
   - `zero_day_verdicts` — Agent 판정 레코드 (matched_card_pk 포함) + 사람 리뷰 필드

2. **블라인드 프롬프트** (`.claude/skills/stage2/prompts/zero_day_hunter.md`)
   - STRICT CONSTRAINTS: 외부 지식 금지, `cve-*.md/kve*.md/advisory*` 파일 읽기 금지, WebSearch/WebFetch 금지, 출력에 `CVE-\d{4}-\d+` / `KVE-\d{4}-\d+` 정규식 매치 금지
   - 3-way decision: (a) existing card match / (b) novel formula / (c) benign
   - confidence ≥0.85 = 3축 모두 visible, 0.70~0.84 = 2/3축, <0.50 = 자동 benign

3. **오케스트레이터** (`src/stage2/zero_day_run.py`)
   - `migrate / init / prefilter / prepare / split / apply / status / list / cards-context` 커맨드
   - `prepare --exclude-card-pk N` 옵션 — 특정 카드를 Agent context에서 은닉 (validation 용)
   - `prepare --order size_desc|size_asc|id` — 함수 선택 순서
   - 프리필터 키워드 확장: 기존 libc 계열 + stripped binary 대응 (HTTP 헤더명 literal `"Host"`, `"Content-"`, `"Cseq"`, 셸 명령 literal `/bin/sh`, `/tmp/`, 포맷 문자열 `"%s"` 등)

4. **주소 지정 prepare** (`src/stage2/zero_day_prepare_addrs.py`) — 특정 함수 주소 + 디코이 N개로 focus batch 구성. CVE 타겟 함수 8개 + 40 random 큰 함수 조합.

5. **전체 함수 디컴파일** (`ida_user/extract_all_funcs.py`) — 체크포인트 + resume 지원. sonia v2.880.0.16 (33MB 바이너리) → **121,900 함수** (116,589 decompiled, 5,311 decompile failed, 22,495 skip_small). IDA exit code 4로 종료됐으나 `.partial` 에 전체 checkpoint 저장됨 → 그대로 사용.

**Run 1 초기화 결과:**
```
run_id=1  name="sonia_v2.880.0.16_blind_noP106"  vendor=dahua/Kant
  total_functions       = 121,900
  prefiltered_functions = 1,468  (1.2%)
  P-106 (CVE-2025-31700) 카드 Agent context 에서 은닉
```

---

#### D. 프롬프트 튜닝 3회차 (동일 48 함수: CVE 타겟 8 + 디코이 40)

같은 focus batch 를 3번 재실행해 프롬프트 표현이 판정에 미치는 영향 측정.

| 버전 | 프롬프트 특이점 | 총 vuln | CVE-31700 타겟 | CVE-31701 타겟 |
|---|---|---|---|---|
| v1 | 카드 인용 요구 없음 | 3 | ✅ 적중 (conf 0.55) — **sink/missing 2축 틀림** (heap/auth_check) | ❌ benign+review |
| v2 | "근거 카드 인용 + 축 일치 명시" 강제 | 3 | ❌ **benign 판정** (literal size 0x7FFu 보고 bounded 결론) | ✅ novel (P-100 2축 일치) |
| **v3** | v2 + **"size-literal anchoring 금지" 문단** 추가 | **7** | ✅ **공식 3축 완벽** (http_header → stack_buffer_copy + length_bound, conf 0.6) | ✅ stack_buffer_copy + length_bound, conf 0.6 |

**v2 실패 원인:** Agent 가 `sub_10B0FBC(..., v97, 0x7FFu)` 같은 literal size argument 를 보면 "bounded → benign" 으로 short-circuit. 실제 CVE-31700 은 size 가 `(bracket_ptr - dest)` 같은 attacker-controlled 산술 결과로 넘어가는 게 본질 — Agent 가 해당 함수 내부에서는 literal 만 보고 외부 helper 내부로 데이터 흐름을 따라가지 못함.

**v3 핵심 추가 문단 (프롬프트):**
```
A size/length argument being present or a const literal does NOT prove safety.
Before concluding "bounded → benign", trace where the size comes from:
- 0x7FF, 256, sizeof(buf) → literal, bounded
- strlen(user_input) → attacker-controlled, unbounded
- (p2 - p1) where p1/p2 from strchr/strstr on attacker input → HIGH RISK
When size provenance unclear → conf 0.5~0.65 + needs_human_review
```

**v3 reasoning 예시 (sub_10E537C, CVE-31700 target):**
> size-literal-anchoring 규칙 적용: 0x7FFu는 literal 상수이므로 이 함수 경계 안에서는 bounded. 그러나 중요한 점은 `sub_10B0FBC` 내부에서 Host 문자열과 v51(request 객체)을 실제 복사하는 경계는 함수 외부, size provenance 는 본 함수 안에서 literal이지만 **외부에서 `strchr/strstr/getHeader` 기반 포인터 산술로 재계산될 가능성 검토 필요** → confidence 0.6, needs_human_review=true

**v3 총 7 vuln 판정 (48 중):**
1. `sub_10E537C` (OnvifHandler::handleRequest) — **CVE-2025-31700** 타겟 ✅
2. `sub_417B2C` (RPC2_UploadFileWithName handler) — **CVE-2025-31701** 타겟 ✅
3. `sub_C7588` (PTP handleManagement) — novel
4. `sub_16811CC` (mDNSCoreReceive) — novel
5. `sub_104CCD8` (CUpgrader::appendData) — novel (uint32 wrap)
6. `sub_17792C` (DVRIP F4 proxy hook) — novel (auth_check bypass)
7. `sub_3EF224` (setLocalityConfig) — novel (silent truncation)

**블라인드 제약:** 3회차 전부 `raw_reasoning` + `root_cause` + `attack_scenario` 필드에 CVE/KVE 번호 정규식 매치 0건 유지. 모든 Agent가 `cve-*.md/kve.md` 파일 존재 확인 후 "resisted" 명시.

---

#### E. 웹 대시보드 (`web/` 신규 디렉토리)

FastAPI + Jinja2 + SSE, localhost:8787. venv + requirements.txt + `run.ps1/run.sh`.

**API 엔드포인트 (routes_dashboard / routes_cards / routes_sessions / routes_zero_day):**
- `/api/dashboard` — 테이블 totals + severity 분포 + stage2 큐 + top pending sessions + recent runs
- `/api/cards?severity=&status=&q=` + `/api/cards/{pk}` 상세
- `/api/sessions` (one-shot aggregate로 최적화 — 최초 구현은 833 sessions × 3 subquery 로 30s+ timeout 발생, GROUP BY 한 번으로 0.86s 로 단축)
- `/api/findings?card_id=&min_score=`
- `/api/zero-day/runs` + `/api/zero-day/runs/{id}` + `/verdicts?vuln=1&min_conf=0.5`
- `POST /api/zero-day/verdicts/{vid}/review` — 사람 리뷰 저장 (write enabled 별도 connection)
- `/api/zero-day/runs/{id}/stream` — SSE 2초 간격 진행률 push

**페이지:**
- `/` 대시보드
- `/cards` 목록 + `/cards/{pk}` 상세
- `/sessions`
- `/findings`
- `/zero-day` 리스트
- `/zero-day/{run_id}` — **취약 판정 인라인 카드 뷰** (LLM root_cause + attack_scenario + raw_reasoning 펼쳐서 바로 읽힘, pseudocode lazy load, 사람 리뷰 폼)

**한국어화** (`static/labels.js`):
- 네비: 대시보드 / 패턴 카드 / Diff 세션 / 헌터 결과 / 제로데이
- 테이블명: `firmware_versions` → "펌웨어 버전" (한글 라벨 + 원문 키 병기)
- 심각도: high → "높음 (high)", medium → "중간", low → "낮음"
- stage2_status: prefiltered_in → "Drafter 큐에 들어감" 등
- run_status: running → "진행 중"

**CSS 이슈 해결:**
- `pre.prose-block` 이 기본 `white-space: pre` 로 가로 스크롤 발생 → `!important` 로 `white-space: pre-wrap + word-break: break-word + overflow-x: hidden` 강제 + `/static/style.css?v=3` 캐시 버스터

---

#### F. 구조적 한계 & 다음 단계

**한계:**
- `matched_card_pk` 를 Agent 가 None(novel) 으로 판정하면 `pattern_cards` 에 자동 승격되지 않음. 사람 리뷰 → 명시적 promote 경로가 아직 없음. 후보: web 에 "Promote to pattern_card" 버튼 + `zero_day_run.py promote <vid>` CLI.
- v3 프롬프트가 7 vuln 을 냈지만 그 중 5개가 사람 리뷰 대기 (novel). 진짜 제로데이 vs FP vs 이미 다른 곳에서 고쳐진 것 구분은 수동.
- IDA full-decompile 이 exit code 4 로 종료 (145K 함수 중 144K 처리 후). `.partial` checkpoint 로 복구.

**후속:**
- sonia 남은 1,468 − 48 = 1,420 함수 v3 프롬프트로 batch 계속
- 2-Pass 구조 (Pass1=free-form bug-shape description, Pass2=card matching) 실험 여부 결정
- 웹 Promote 버튼 추가

**신규/수정 파일 (이번 세션):**

신규:
- `.claude/skills/stage2/sql/zero_day_migration.sql`
- `.claude/skills/stage2/prompts/zero_day_hunter.md`
- `src/stage2/zero_day_run.py`
- `src/stage2/zero_day_prepare_addrs.py`
- `src/stage2/merge_team_cards.py`
- `src/stage2/export_pattern_cards_jsonl.py`
- `src/stage2/export_sp_session_jsonl.py`
- `ida_user/extract_all_funcs.py`
- `ida_user/decompile_selected.py`
- `ida_user/find_xrefs_and_dump.py`
- `ida_user/find_named_funcs.py`
- `web/app.py` + `api/{db,routes_dashboard,routes_cards,routes_sessions,routes_zero_day}.py`
- `web/templates/{base,dashboard,cards,card_detail,sessions,findings,zero_day_list,zero_day_detail}.html`
- `web/static/{style.css,app.js,labels.js}` + `requirements.txt` + `run.ps1/run.sh`
- `docs/zero-day-runbook.md`
- `data/cve/ground_truth.jsonl`
- `pattern_cards.jsonl` (project root, 106장)

수정:
- `.gitignore` — `data/cve/` 추적 허용
- `scripts/push_team_artifacts.sh` — `data/cve/` 경로 추가

**Git 동기화:**
- `origin/main` + `team/riri` 양쪽 push 완료
- Backup: `Patch-Learner-main/src/db/patch_learner.db.bak.premerge-team-1776613673`

---

### 2026-04-19 | Stage 2 Drafter 배치 4건 + CVE-2025-31700 블라인드 탐지 성공 + 팀장 handoff + Zero-Day 플랜 승인

**배경:**

오늘 세션 세 축으로 진행.
1. Stage 2 Drafter 배치 계속 돌려 pattern_cards / security_patches 누적.
2. cve-2025-31700.md 의 Dahua CVE를 "외부 지식 없이 우리 파이프라인이 찾을 수 있는가" 실제 테스트.
3. 팀장이 `data/cve/ground_truth.jsonl` + `security_patches_session.jsonl` 요청 → 핸드오프.
4. 실패한 부분을 보완하기 위해 **Zero-Day 블라인드 헌트 + 웹 대시보드** 플랜 확정.

**Stage 2 배치 결과 (4건, 565 funcs 처리):**

| 배치 | 세션 | 타겟 | 처리 | sec | 카드 신규 | auto-merge |
|---|---|---|---|---|---|---|
| 1 | s11 | tp-link Tapo_C200v1 v1.0.7→v1.0.10 | 200 | 0 | 0 | 0 |
| 2 (A4만) | s105 | dahua Molec v2.800.0.16→v2.840.0.5 | 50 | 5 | 2 | 3 |
| 3 | s536 | ipTIME a6004mx v68→v70 | 165 | 12 | 10 | 2 |
| 4 (sonia 1차) | s74 | dahua Kant v2.860.0.31→v2.860.0.34 | 200 | 1 | 1 (P-074) | 0 |

DB 상태 변화: `pattern_cards` 73 → **74**, `security_patches` 1,815 → **2,016**, `hunt_findings` 1,746 → **7,412** (Hunter 재실행 포함).

**CVE-2025-31700 블라인드 탐지 테스트:**

Dahua Kant v2.860.0.31 vs v2.860.0.34 `sonia` 바이너리(ONVIF/HTTP/RPC 통합 데몬). 심볼 stripped. 변경 함수 7,442개 중 ins≥10인 2,681개 디컴파일 → DB 등록 → 프리필터 381개 → Drafter 200개 배치.

Drafter가 `sub_38F9F4` (HTTP 헤더 파서)를 CVE 문서 비열람 상태에서 다음과 같이 식별:
- source = `Host:` HTTP 헤더 (attacker-controlled)
- sink = 256B 스택 버퍼 `strncpy`
- missing_check = length_bound
- `hard-rules.md §5` 패밀리 매칭 → **cve_similar="CVE-2025-31700"** 자동 기입, confidence 0.78, severity=high
- 카드 P-074 생성: `http_header → stack_buffer_copy + length_bound`

Hunter P-074 카드로 전체 코퍼스 재스캔 → 다른 바이너리에서 0 hit. 원인: negative_token `sub_383C98`(Dahua 안전 헬퍼)이 패치된 NEW에 존재해 "이미 패치됨"으로 정확히 제외.

**한계 (실제 CVE 함수는 못 잡음):**

진짜 CVE-2025-31700 위치는 sonia 내부 `ONVIF_HandleRequest`(소스 `Src/OnvifHandler.cpp`)인데, 우리 비교쌍 v2.860.0.31↔.34는 패치 기준일(2025-04-16)을 **하루 차로 스치기만 해서** 해당 함수가 unchanged 집합에 들어가 Drafter가 건드리지 못함. P-074는 같은 파일의 헤더 파서 `sub_38F9F4`를 본 결과. Bitdefender 원문상 정확한 `strchr(']')` + 잘못된 길이 계산 코드는 이 함수가 아님.

추가 확인:
- sonia 바이너리 문자열 스캔 → `Src/OnvifHandler.cpp`, `Src/RPCSessionManager.cpp`, `/RPC2_UploadFileWithName/*` 존재.
- `v2.880.0.17` 에만 추가된 `DisableWebAppFileImport` ← CVE-31701 방어 플래그로 추정.
- v2.880.0.16 ↔ .17 sonia BinExport 2개 완료. BinDiff 직전에 사용자 중단 (Zero-Day 플랜으로 전환 요청).

**팀장 handoff:**

- `data/cve/ground_truth.jsonl` — 3 entries (CVE-2025-31700/31701/KVE-2023-5458). 스키마: cve_id, vendor, model, vuln/patched_version, target_binary/function/address, cvss, cwe, source_kind/sink_kind/missing_check, root_cause_summary, references_url, source.
- `data/handoff/security_patches_session.jsonl` — 572 rows (10 sessions, 123건 pattern_card_members 연결, Dahua 493 / TP-Link 61 / ipTIME 18). 재생성 스크립트 `src/stage2/export_sp_session_jsonl.py`.
- `scripts/push_team_artifacts.sh` + `.gitignore` — `data/cve/` 경로 화이트리스트 추가.
- `origin/main` + `team/riri` 둘 다 push 완료.

**Zero-Day 플랜 승인 (`C:\Users\zlfnf\.claude\plans\shimmying-dreaming-snowflake.md`):**

목표: v2.880.0.16 sonia **전체 함수**에 Drafter Agent를 한 번씩 태워 CVE-2025-31700이 블라인드로 잡히는지 검증 + 향후 실제 제로데이 헌팅에도 쓸 FastAPI 로컬 대시보드.

스코프:
- `src/stage2/zero_day_run.py` — migrate/init/prefilter/prepare/split/apply/status 오케스트레이터
- `.claude/skills/stage2/prompts/zero_day_hunter.md` — 블라인드 프롬프트 (CVE 번호 출력 금지, `cve-*.md`/`kve*.md` 파일 읽기 금지, WebSearch/WebFetch 금지)
- `.claude/skills/stage2/sql/zero_day_migration.sql` — `zero_day_runs` / `zero_day_functions` / `zero_day_verdicts` 3 테이블
- `ida_user/extract_all_funcs.py` — 전체 바이너리 디컴파일 (changed 아닌 것도)
- `web/` 신규 (FastAPI + Jinja2 + SSE, localhost:8787) — DB 대시보드 + 카드/세션/findings/zero-day 페이지 + 실시간 진행률

**오늘 생성된 주요 파일:**
- `data/cve/ground_truth.jsonl`, `data/handoff/security_patches_session.jsonl`
- `src/stage2/export_sp_session_jsonl.py`, `src/stage2/register_sonia.py`
- `ida_user/decompile_selected.py`, `ida_user/find_xrefs_and_dump.py`, `ida_user/find_named_funcs.py`
- `.claude/skills/stage2/sql/zero_day_migration.sql`
- `.claude/skills/stage2/prompts/zero_day_hunter.md`
- `output/.../binexport/sonia_*.BinExport` (4개), v2.860 쌍 BinDiff 결과

**Git:**
```
4830fd0 handoff: add data/cve/ground_truth.jsonl (3 entries)
3c77c0e handoff: push script whitelist
4267429 handoff: CVE ground_truth + security_patches session JSONL
6cc9344 stage2: session 11 batch #1 done (200 funcs, 0 sec)
```
origin/main + team/riri 동기화.

**다음 액션:**
1. Zero-Day 오케스트레이터 구현 (`src/stage2/zero_day_run.py`).
2. sonia v2.880.0.16 전체 함수 디컴파일 (~45분 백그라운드).
3. FastAPI `web/` 스캐폴딩 5페이지 + SSE.
4. Zero-Day run 1회 실행 → P-074 매칭 또는 ONVIF_HandleRequest 블라인드 검출 검증.
5. `docs/zero-day-runbook.md` 작성.

---

### 2026-04-17 (오후) | Stage 2 워크플로우 Drafter 단일 Phase로 통합 (Reviewer 제거)

**배경:**

- 오전에 확정한 5-Phase 구조(사전필터/Analyst/Reviewer/Dedupe/Designer/Hunter)를 팀원이 재검토.
- 팀원 의견: "검증 단계를 두지 말고 패턴카드 포맷으로 쌓으면서 훑는 식이 더 효율 좋을 듯. 토큰이랑 품질 둘 다 챙길 수 있을 듯."
- 합의: Reviewer 제거 + Analyst/Designer를 Drafter 단일 Phase로 통합.

**결정 이유:**

1. **토큰/쿼터 60% 절감** — 한 함수당 LLM 호출 3회 → 1회. Claude Max 5시간 쿼터 내 처리량 ~3배.
2. **맥락 손실 제거** — 같은 함수를 Analyst·Reviewer·Designer가 각각 다시 읽던 중복 제거.
3. **Echo chamber 자연 해소** — Reviewer 없으므로 같은 Opus가 자기 답 승인하는 구조 자체가 사라짐.
4. **security_patches 스키마에 이미 공식 필드 존재** — `source_desc`/`sink_desc`/`missing_check`. 판정과 카드 작성을 분리할 이유가 없었음.

**변경된 파일:**

- `.claude/skills/stage2/prompts/drafter.md` (신규) — analyst.md + designer.md 통합. 판정 + 카드 draft 동시 출력.
- `.claude/skills/stage2/prompts/analyst.md`, `reviewer.md`, `designer.md` 삭제.
- `.claude/skills/stage2/prompts/hunter.md` 갱신 — Phase 5 → Phase 2로 위치 이동, v3 구조 언급.
- `.claude/skills/stage2/SKILL.md` — 3-Phase(사전필터 / Drafter / Hunter)로 재구성.
- `.claude/skills/stage2/sql/migration.sql`:
  - `review_status` / `reopen_count` / `reviewer_note` / `reopen_reason` 컬럼 제거.
  - `stage2_status` enum: `drafting_a1/a2 → drafted_sec / drafted_nonsec`.
  - `pattern_cards`에 부분 UNIQUE INDEX `idx_pc_formula_active` 추가 — 같은 공식의 active 카드 중복 DB 레벨 차단.
  - `security_patches.pattern_card_id` FK 컬럼 추가.
- `.claude/skills/stage2/sql/dedupe.sql` — Phase 3 수동 Dedupe 쿼리 → Auto-merge 사후 점검 쿼리로 전환.
- `.claude/skills/stage2/sql/dashboard.sql` — Reviewer 지표 제거, Drafter confidence 분포 + Auto-merge 효과 + precision 품질 대시보드로 재구성.
- `docs/architecture-decisions.md` §13 추가 (Drafter 통합 결정 근거).
- `docs/pipeline.md` Stage 2 섹션 3-Phase로 갱신.
- `docs/pattern-card-spec.md` — status 전이 v3 반영 (생성 시 바로 active, draft 단계 없음), Auto-merge 설명, FAQ Q9/Q10 추가.

**FP 가드 3층 구조 (Reviewer 부재 보상):**

1. Drafter 프롬프트에 False Positive 가드 7종 + Synology Hard Rules + confidence 기준표 하드코딩. confidence 0.70 미만은 기본 `is_security_patch=false`.
2. Auto-merge로 같은 공식 카드 수렴 — 드문 오류가 카드 폭발로 이어지지 않음.
3. Hunter 결과 사람 검토 → `pattern_card_stats.precision` 하락 시 retire 게이트 자동 진입.

**다음 액션:**

- DB 백업 후 `migration.sql` 적용 (pattern_cards 0건이라 안전).
- Phase 0 Python 사전 필터 스크립트 작성 (`src/stage2/prefilter.py`).
- 오케스트레이터 스크립트 작성 (`src/stage2/drafter_run.py`) — Drafter Agent 호출 + Auto-merge SQL 실행.
- BC500 v1.0.5→v1.0.6 16건으로 Drafter 파일럿 실행. confidence 분포와 카드 품질 확인 후 프롬프트 튜닝.
- TP-Link Tapo C200v1 (12,055 함수) Phase 0~1 착수.

---

### 2026-04-17 (오전) | Stage 2 오케스트레이션 스킬 추가 + 패턴카드 v2 재설계

**배경:**

- 팀 회의(2026-04-16)에서 Stage 2를 5-Phase 워크플로우(사전필터/Analyst/Reviewer/Dedupe/Designer/Hunter)로 확정.
- 첫 시도로 벤더·CWE 라벨 중심 패턴카드 스키마를 만들었으나 두 가지 문제 노출:
  1. 같은 공식(예: HTTP Host 헤더 길이 미검증)이 Dahua/ipTIME 등 여러 벤더에서 반복되는데 벤더 라벨이 매칭을 가두는 부작용.
  2. 카드가 늘어나면 Hunter LLM에 넣을 토큰이 폭발 (카드당 서사 설명이 커서).

**결정:**

- 패턴카드 본체를 **구조적 taint 공식 3원소**(`source_type` / `missing_check` / `sink_type`) + **OLD/NEW 핵심 스니펫**으로 재설계.
- 벤더/CWE 라벨 필드 제거. `severity_hint`, `cve_similar`는 검색 편의용 메타로만 유지.
- 부속 테이블 분리: `pattern_card_tokens` (grep 인덱스), `pattern_card_negative_tokens` (safe wrapper 배제, `vendor_scope`), `pattern_card_grep_patterns`, `pattern_card_members`, `pattern_card_stats` (TP/FP precision).
- Hunter는 카드 shortform(~200 토큰)을 받아 `vulnerable_snippet` 동형 매칭 + `fixed_snippet` 동형 시 배제.
- 전처리가 공식 3원소 + 토큰 인덱스로 후보 카드를 99% 컷 → 함수당 LLM 입력 ~1,000 토큰 유지.

**결과물:**

- `.claude/skills/stage2/` — SKILL.md, `prompts/` (analyst/reviewer/designer/hunter), `rules/hard-rules.md`, `sql/` (migration/prefilter/dedupe/dashboard).
- `sql/migration.sql`: 기존 `pattern_cards` DROP + 재생성 (0건 상태라 안전). 부속 6개 테이블 신규.
- 문서 갱신: `docs/architecture-decisions.md` §12, `docs/pipeline.md` Stage 2 섹션.

**DB 현황 (마이그레이션 이전):**

- `pattern_cards` 0건, `security_patches` 0건, `hunt_findings` 0건 — 재설계 적용에 데이터 이동 부담 없음.

**다음 액션:**

- 마이그레이션 적용 전 DB 스냅샷 백업 (`patch_learner.db.bak.pre-stage2-v2`).
- Phase 0 Python 사전 필터 스크립트 작성 (`src/stage2/prefilter.py`).
- BC500 v1.0.5→v1.0.6 16건으로 Analyst + Reviewer 파일럿 실행해 프롬프트 튜닝.
- 프롬프트 확정 후 TP-Link Tapo C200v1 (12,055 함수) Phase 1 착수.

---

### 2026-03-09 ~ 03-12 | 초기 설계 및 IDAPython 방식 시도

**진행 내용:**
- 프로젝트 초기 설계: 펌웨어 추출 → 해시 비교 → IDA 분석 흐름 확정
- IDAPython으로 함수별 mnemonic 추출 후 직접 비교하는 방식 구현
- `ida_user/export_for_diff.py` 작성 (3단계 매칭: 이름 매칭 → mnem_hash → fuzzy SequenceMatcher)

**문제점:**
- PLT stub 노이즈: `printf`, `getppid` 등 3개 instruction 함수가 유사도 0.4로 잘못 분류됨 (linker 주소 재배치 때문)
- 함수 위치가 바뀌면 매칭 불가 (`sub_XXXXX` 형식 함수는 주소가 버전마다 다름)
- 5,653개 변경 함수 검출했으나 노이즈 포함 많음

---

### 2026-03-13 ~ 03-14 | BinExport 플러그인 문제 + 방식 전환 논의

**문제:**
- IDA Pro 9.0 크랙 버전에서 `binexport12_ida64.dll` 로드 실패
- 오류: `binexport12_ida64.dll: can't load file - 지정된 프로시저를 찾을 수 없습니다`
- DLL 버전 호환성 문제 (크랙 IDA 9.0과 BinExport 버전 불일치)

**임시 대응:**
- IDAPython mnemonic 비교 방식으로 중간 구현 유지
- BinDiff 위치 탐색: `C:\Program Files\BinDiff\bin\bindiff.exe` 확인

**해결:**
- 사용자가 플러그인 파일 교체 후 BinExport 연결 성공
- `C:\Users\deser\AppData\Roaming\Hex-Rays\IDA Pro\plugins` 경로에 호환 버전 설치

---

### 2026-03-15 | BinExport+BinDiff 방식으로 전면 전환

**변경 사항:**
- `bindiff_pipeline.py` 전면 재작성
- `run_ida_export()` → `run_binexport()` 교체
- `compare_function_exports()` 삭제
- `run_bindiff()` + `parse_bindiff_results()` 추가
- `import sqlite3` 추가

**핵심 변경 코드:**

```python
# BinExport 생성
cmd = [
    str(IDA_PATH), "-A",
    f"-OBinExportModule:{binexport_path}",
    "-OBinExportAutoAction:BinExportBinary",
    f"-L{log_path}",
    str(binary),
]

# BinDiff 실행
cmd = [
    str(BINDIFF_PATH),
    "--primary", str(old_binexport),
    "--secondary", str(new_binexport),
    "--output_dir", str(output_dir),
]
```

**결과 비교:**
- IDAPython 방식: 5,653개 변경 함수 (노이즈 많음)
- BinDiff 방식: 12,408개 변경 함수, 더 정확한 CFG 기반 매칭

---

### 2026-03-15 | 추출 캐시 버그 수정

**문제:**
- 파이프라인 재실행 시 펌웨어 재추출 반복 (캐시 무시)
- 원인: `.extracted_ok` 마커가 rootfs 하위 폴더에 있었음
  - 실제 위치: `extracted/UVC.S2LM_4.30.0/ubifs-root/880278559/rootfs/.extracted_ok`
  - 코드가 확인하는 위치: `extracted/UVC.S2LM_4.30.0/.extracted_ok`

**해결:**
1. 올바른 위치에 `.extracted_ok` 마커 수동 생성 (`touch`)
2. `_find_rootfs()` 헬퍼 함수 추가 — 캐시 히트 시에도 rootfs 경로 정확히 반환

```python
def _find_rootfs(out_dir: Path) -> Path:
    """추출된 디렉토리에서 rootfs (bin, usr, etc, lib 포함) 찾기."""
    candidates = [d for d in out_dir.rglob("*")
                  if _safe_is_dir(d) and _has_rootfs_dirs(d)]
    if candidates:
        return max(candidates, key=_count_files)
    return out_dir
```

---

### 2026-03-15 | 타임존 파일 노이즈 발견

**현상:**
- `/usr/share/zoneinfo/` 하위 파일 (Accra, Brisbane, Budapest 등)이 바이너리로 분류
- 이유: TZif 형식 파일에 NULL 바이트 포함 → `is_binary()` 판정
- IDA 분석 결과: 함수 0~2개, BinDiff 유사도 0%
- 184개 bindiff 디렉토리 중 112개가 타임존 노이즈

**해결:**
- `zoneinfo` 경로 포함 파일 자동 필터링 추가

---

### 2026-03-16 | IDA 통합 추출 방식으로 전환

**배경:**
- 기존: BinExport만 생성 → BinDiff로 변경 함수 찾기 → 다시 IDA 돌려서 디컴파일
- 문제: IDA를 두 번 돌려야 함 (시간 낭비)

**새 방식:**
- IDA 1회 실행으로 **BinExport 생성 + 함수 pseudocode 추출 동시 처리**
- `ida_user/extract_with_decompile.py` 작성
- 환경변수로 출력 경로 전달: `IDA_EXPORT_DIR`, `IDA_BINARY_TAG`

**테스트 결과 (ubnt_system_cfg, 32KB 바이너리):**
- 전체 245개 함수
- 디컴파일 성공: 163개
- Import thunk (스킵): 82개 (`__imp_xxx`, instruction 1개, pseudocode=null)
- BinDiff: 184개 매칭, 8개 변경, 유사도 99.3%

---

### 2026-03-18 | 파이프라인 재실행 시 캐시(이어하기) 기능 추가

**배경:**
- Step 4(IDA 통합 추출)는 바이너리 수가 많아 중간에 중단되는 경우가 많음
- 재실행 시 이미 완료된 파일까지 다시 처리해서 시간 낭비 발생

**추가된 캐시 동작:**

| 단계 | 캐시 기준 | 동작 |
|------|----------|------|
| Step 1 (해시 비교) | `hash_compare.json` 존재 여부 | 파일 있으면 재해싱 없이 로드 |
| Step 4 (IDA 추출) | `functions/{name}_old.json` + `_new.json` 둘 다 존재 | 해당 바이너리 스킵 |
| Step 5 (BinDiff) | `bindiff/{name}/*.BinDiff` 존재 여부 | 해당 바이너리 스킵 |
| Step 6 (diff 생성) | `function_diffs/{name}/*.diff` 존재 여부 | 해당 바이너리 스킵 |

**Step 4 진행률 표시 개선:**
```
[4/7] 함수 추출 + BinExport — 전체 125개 (캐시 60개 스킵, 신규 65개 처리)
      진행: 1/65 (전체 61/125)
      진행: 2/65 (전체 62/125)
      ...
```

**핵심 변경 내용:**
- `compare_dirs()`: `cache_path` 파라미터 추가, `hash_compare.json` 있으면 재사용
- `run_bindiff()`: 실행 전 `.BinDiff` 파일 존재 여부 확인 후 캐시 반환
- `generate_function_diffs()`: `*.diff` 파일 존재 시 기존 파일 기반으로 통계 반환
- `main()` Step 4: 캐시/신규 바이너리 사전 분류 후 신규만 병렬 처리

### 2026-03-17 | 보안 함수 우선순위 분류

**작업:**
- 4,676개 diff 중 보안 관련 상위 50개 선별
- `security_candidates.json` 생성

**선별 기준:**
- 보안 관련 바이너리 가중치 +50: ubnt_cgi, dropbear, libcrypto, libssl, hostapd, wpa_supplicant 등
- 보안 키워드 매칭 가중치 +20/개: auth, valid, verify, crypt, parse, token, exec, system, password 등
- 변경 규모 가중치 +1/라인 (최대 100)

**상위 결과 예시:**
- `libcrypto.so.1.1/RSA_padding_check_SSLv23` — score 192 (ssl, rsa, check)
- `libcrypto.so.1.1/X509_verify_cert` — score 190 (verify, cert)
- `libssl.so.1.1/d2i_SSL_SESSION` — score 190 (session, ssl)

---

### 2026-03-23 | 팀 GitHub 연결 + IoT 카메라 CVE 리서치 + 멀티 에이전트 패턴 카드 설계

**진행 내용:**

1. **팀 GitHub 연결**
   - `https://github.com/seosamuel02/Patch-Learner` 클론 → `Patch-Learner-collab/`
   - 작업 브랜치 `riri` 생성 및 push 완료
   - CLAUDE.md에 개인/팀 저장소 구분 규칙 추가

2. **IoT 카메라 CVE 리서치 문서 작성** (`docs/iot_camera_cve_research.md`)
   - 10개 제조사 / 6개국 조사
   - 구버전 펌웨어 아카이브 실제 접근 검증 (curl)
   - 펌웨어 암호화 여부 정리
   - Synology 전 버전 공개 아카이브 확인 (패치 디핑 최적)

3. **멀티 에이전트 패턴 카드 생성 시스템 설계**

   ```
   [Opus 4.6 — 매니저/리뷰어]
           │
           ├── 작업 분배 (top 50 → 25 + 25)
           │
           ├── Agent 1 (Sonnet) ── 후보 1~25 분석 → 패턴 카드 JSON
           ├── Agent 2 (Sonnet) ── 후보 26~50 분석 → 패턴 카드 JSON
           │   (병렬 실행)
           │
           └── 매니저 리뷰
                 ├── 카드 품질 검토, 피드백
                 └── 최종 llm_pattern_cards.json 확정
   ```

   **각 에이전트 역할:**
   - 매니저 (Opus): 작업 분배, 결과 리뷰, 보안 정확성 검토
   - Analyst Agent (Sonnet × 2): old.c/new.c 읽고 보안 분석, 패턴 카드 작성
   - API 미사용 — Claude Code Agent 툴로 서브에이전트 spawn

   **패턴 카드 필드:**
   - vulnerability_type, cwe, severity, confidence
   - summary, vulnerability_detail, fix_detail, attack_scenario
   - detection_keywords, cve_similar, is_security_relevant

4. **멀티 에이전트 패턴 카드 실행 완료**
   - Opus 4.6(매니저) + Sonnet×2(분석) 구조로 50개 함수 분석
   - Agent 1: libcrypto(15) + libssl(3) + dropbear(7) = 25개
   - Agent 2: dropbear 25개
   - 결과: `llm_pattern_cards.json` — 50카드 (33 보안관련, 17 비보안)
   - 주요 발견: RSA timing side-channel(LPC-001), EVP integer overflow(LPC-018), ECDSA nonce reuse(LPC-048)

5. **토스 보안팀 취약점 분석 자동화 분석 및 적용**
   - [toss.tech 블로그](https://toss.tech/article/vulnerability-analysis-automation-1) 2편 분석
   - 핵심 아이디어: SAST(Semgrep) + Multi-Agent + Pydantic 검증 + 오픈모델
   - 우리 프로젝트에 적용 가능한 2가지 선별:
     - Discovery → Analysis 2단계 에이전트 (토큰 50% 절감)
     - Pydantic 구조화 출력 검증 (파싱 실패 0)

6. **파이프라인 개선 구현**

   **새 파일:**
   - `src/analyzers/pattern_card_schema.py` — Pydantic 검증 스키마
     - PatternCard, DiscoveryResult 모델
     - VulnerabilityType 비정형 입력 정규화 (bof→Buffer Overflow 등)
     - CWE 형식 자동 보정 (CWE120→CWE-120)
     - CLI: `python pattern_card_schema.py cards.json`

   - `src/analyzers/multi_agent_pipeline.py` — 2단계 오케스트레이터
     - Discovery → Analysis 분리 (토스 방식 적용)
     - 4단계: discovery → process → analysis → merge
     - 프롬프트 템플릿 내장 (Discovery, Analysis, Review)
     - Pydantic 검증 + 자동 보정 통합

   **개선된 워크플로우:**
   ```
   이전:  Manager → [Analyst1(25개), Analyst2(25개)] → Review
   이후:  Manager → Discovery(50개→필터) → [Analyst1, Analyst2] → Review + Pydantic 검증
   ```

   **검증 결과:**
   - 기존 50개 패턴 카드 → 50/50 유효 (5개 자동 보정)
   - 자동 보정: `attack_scenario` "해당 없음" → "해당 없음 (상세 분석 불필요)"

---

### 2026-03-24 | IoT 바이너리 보안 분석 + Pydantic 검증 + SQLite DB 저장

**진행 내용:**

1. **IoT 보안 후보 선별 시스템 구현** (`generate_security_candidates.py`)
   - 기존: crypto/auth 키워드만 → OpenSSL/Dropbear만 50개 선별 (IoT 0개)
   - 개선: IoT 키워드 80+개 + 위험함수 14패턴 + 바이너리 우선순위
   - 결과: 5,497개 → 1,099개 선별 (20%), IoT 177개 (16%)

2. **3개 IoT 바이너리 병렬 LLM 분석**
   - ubnt_cgi (12카드): CRITICAL Command Injection 발견 (CVE-2021-22909)
   - ubnt_ctlserver (10카드): /etc/passwd 인젝션, 인증 우회 등
   - ubnt_networkd (12카드): 하드코딩 AES 키, TLV OOB 읽기, null deref 등
   - 총 34개 IoT 패턴 카드 생성

3. **Pydantic 검증 스키마** (`pattern_card_schema.py`)
   - VulnerabilityType 17개 enum + 비정형 입력 자동 정규화
   - 34/34 카드 검증 통과

4. **SQLite DB 저장** (`schema.sql` + `load_pattern_cards.py`)
   - `pattern_cards` 테이블 추가 (19개 컬럼)
   - 34개 카드 INSERT 완료
   - 인덱스: binary_name, severity, vulnerability_type, cve_similar

**주요 발견:**
- CRITICAL: WiFi SSID/passphrase → sysExecSimple 명령 주입 (CVE-2021-22909)
- HIGH: /etc/passwd 직접 쓰기로 백도어 계정 생성 가능 (CVE-2020-8515)
- HIGH: GetRequest 인증 없이 카메라 스냅샷 반환 (CVE-2022-23134)
- HIGH: 펌웨어 덤프로 AES 페어링 키 추출 가능 (CWE-321)
- 체계적 패턴: sign-extension `v|(v>>31)` 정수 언더플로우 — 코드베이스 전체에 반복

---

### 2026-03-25 | Synology BC500 .sa.bin 파서 구현 + 크로스 디바이스 분석 시작

**진행 내용:**

1. **Synology .sa.bin 포맷 분석 및 파서 구현** (`bindiff_pipeline.py`)
   - `.sa.bin` 구조: 0x80-byte 헤더 → 0x82에서 raw zlib prescript → u32-prefixed zlib postscript → 파티션 배열
   - 파티션 구조: `0x40-byte 이름` + `u32 sub_len` + `u32 img_len` + sub_data + img_data
   - `_extract_ubi_to_squashfs()`: UBI PEB(128KB) EC/VID 헤더 파싱 → LEB 수집 → 헤더 제거 → squashfs 재조립
   - `_extract_squashfs()`: PySquashfsImage `from_bytes()` + 재귀 `iterdir()`로 전체 파일시스템 추출

2. **버그 수정 3건:**
   - **prescript 길이 오류**: 0x80에서 u32 직접 읽으면 2.6B length 반환 → `zlib.decompressobj()`로 스트림 경계 탐지로 교체
   - **인덴테이션 버그**: rootfs 탐색 코드가 파티션 for-loop 안에 있어 partition 0 처리 후 조기 반환 → 루프 밖으로 이동
   - **PySquashfsImage API**: `from_fd()` → `from_bytes()`, `walk()` → 재귀 `iterdir()` 교체

3. **subprocess 인코딩 수정:**
   - IDA 서브프로세스 출력 cp949 오류 → `encoding="utf-8", errors="replace"` 3개 호출 모두 추가
   - print 문의 em-dash(`—`) → 하이픈(`-`) 교체

4. **Synology BC500 v1.0.4 vs v1.0.5 전체 파이프라인 완료**
   - Step 0~10 완료: 107개 바이너리, 5,497개 변경 함수 분석
   - LPC-SYN-001: **CRITICAL** Format String (CWE-134) — synocam_param.cgi `sub_40FD4`에서 `printf(user_input)` 패턴
   - LPC-SYN-002: MEDIUM Memory Leak (CWE-401) — webd `sub_5DBD0` malloc 후 에러 경로 미해제
   - LPC-SYN-003: MEDIUM Memory Leak (CWE-401) — synocam_param.cgi `sub_DD28` 동일 패턴
   - LPC-SYN-004: LOW Feature Addition — nvtd `sub_69328` 기능 추가
   - DB: Ubiquiti 34 + Synology 4 = **총 38개** 패턴 카드

5. **Synology BC500 v1.0.5 vs v1.0.6 파이프라인 완료**
   - 196개 파일 추가, 107개 바이너리 변경
   - 주요 변경: webd 315 diffs (66.5% sim), nvtd 418 diffs (46.3% sim), central_server 257 diffs (87.9% sim)
   - libssl.so / libcrypto.so 대규모 교체 (OpenSSL 업그레이드 추정)
   - 보안 분석 진행 중

---

### 2026-03-25 | 파이프라인 아키텍처 확정 (팀 논의)

**진행 내용:**

1. **Step 0~10 체계 → Stage 0~3 체계로 통합 확정**
   - Stage 0: 펌웨어 추출 + 해시 디핑 (기존 Step 0~3 통합)
   - Stage 1: BinDiff + 전체 디컴파일 → DB (기존 Step 4~7 통합)
   - Stage 2: LLM 1-pass 전수 분석 (기존 Step 8~10 통합, 분류 단계 제거)
   - Stage 3: 0-day 헌팅 (신규)

2. **핵심 설계 결정**
   - Discovery 분류 단계 스킵: BinDiff가 Discovery 역할, 우리 규모(30~200개)에서 별도 필터링 불필요
   - severity/confidence: LLM 직접 판단, 임의 가중치 공식 사용 금지 (논문 신뢰성)
   - 비보안 함수 포함 전수 DB 저장 (precision/recall 계산용 분모)
   - 과탐 > 미탐 원칙 (토스 방식 채택)

3. **팀 코드 비교 (collab vs main)**
   - 팀: 모듈형 (6개 파일), DB 중심 데이터 흐름, IDA 2-pass (BinDiff 먼저 → 변경 주소만 디컴파일)
   - 내 것: 통합형 (1개 파일 1,086줄), JSON 중심, IDA 1-pass (전체 추출 + 캐시)
   - 확정: 내 IDA 방식(전체 추출 + 캐시) 채택, DB 저장은 팀 방식 참고

4. **문서 정리**
   - `docs/architecture-decisions.md` 신규 작성 (아키텍처 확정안)
   - `docs/pipeline.md` 전면 개편 (Stage 0~3 구조)
   - `docs/project-overview.md` 현재 상태 반영

**참고:**
- 토스 보고서: https://toss.tech/article/vulnerability-analysis-automation-1 (1편), 2편
- 아키텍처 확정안: `docs/architecture-decisions.md`

---

### 2026-03-25 | DB 중심 설계 통합 (팀원 방식 반영)

**진행 내용:**

1. **`src/db/pipeline_db.py` 신규 작성** — 파이프라인 ↔ DB 연동 모듈
   - `PipelineDB` 클래스: 세션 생성, 해시 비교 결과 저장, BinDiff 결과 저장, 변경 함수+pseudocode 저장
   - 팀원의 DB 중심 데이터 흐름 설계를 팀장의 IDA 1-pass 파이프라인에 통합
   - 중복 저장 방지 (기존 데이터 있으면 스킵)

2. **`bindiff_pipeline.py` 수정** — DB 자동 저장 옵션 추가
   - 새 CLI 인자: `--vendor`, `--model`, `--old-ver`, `--new-ver`, `--no-db`
   - Step 1(해시 비교) 후 → `changed_files` 테이블 저장
   - Step 5(BinDiff) 후 → `bindiff_results` + `changed_functions`(pseudocode 포함) 저장
   - 파이프라인 완료 시 DB 현황 출력

3. **`multi_agent_pipeline.py` 수정** — merge_and_validate()에 DB 자동 저장
   - Pydantic 검증 통과 → JSON 저장 + DB `pattern_cards` 테이블 자동 저장
   - `_save_cards_to_db()` 함수 추가

**사용법 변경:**
```bash
# 이전 (JSON만 저장)
python bindiff_pipeline.py --old fw_old/ --new fw_new/

# 이후 (JSON + DB 동시 저장)
python bindiff_pipeline.py --old fw_old/ --new fw_new/ \
    --vendor synology --model BC500 --old-ver 1.0.5 --new-ver 1.0.6
```

---

### 2026-03-26 | BC500 v1.0.5 vs v1.0.6 Stage 2 LLM 보안 분석 완료

**진행 내용:**

1. **MCP SQLite 서버 구성** (`.claude/settings.json`)
   - `@modelcontextprotocol/server-sqlite` npx로 DB 연결
   - 분석 세션 동안 Python sqlite3로 대체 사용

2. **Stage 2 분석 전략 확정**
   - 26,545개 함수 중 BinDiff mismatch(sim<0.01 & 크기비>3x) 제외
   - Phase 1: Synology 특화 바이너리 우선 (synocam_param.cgi, central_server, nvtd, synoaid)
   - Phase 2: curl, dhcpcd (라이브러리 버전 업그레이드로 판명 → 패치 없음)
   - Phase 3: libcrypto/libssl/FFmpeg 등 → 전부 라이브러리 버전 업그레이드 → 스킵

3. **핵심 발견: `system()/popen()` → `sub_6CEE0()` 전사 마이그레이션**
   - `sub_6CEE0`은 Synology의 안전한 execve 래퍼 (argv[] 배열, 쉘 없음)
   - central_server에서 총 9개 함수에서 system() 제거

4. **보안 패치 DB 저장 완료 (security_patches 테이블)**
   - `save_central_patches.py`, `save_central_patches2.py`, `save_nvtd_patches.py` 작성

**분석 결과 (session_id=2, 총 16개):**

| severity  | count | 대표 취약점 |
|-----------|-------|------------|
| CRITICAL  | 2     | `/etc/passwd` 외부파라미터 삽입, `chpasswd` 명령 인젝션 |
| HIGH      | 7     | SynoPopen→execve, rm/cp/openssl 경로 인젝션, Format String |
| MEDIUM    | 5     | killall/https cert system() 교체, ONVIF sprintf→snprintf |
| LOW       | 2     | UTC timezone sprintf→snprintf |

**바이너리별 패치 수:**
- `central_server`: 11개 (CRITICAL 2, HIGH 5, MEDIUM 3, LOW 1)
- `synocam_param.cgi`: 2개 (HIGH 2)
- `nvtd`: 3개 (MEDIUM 2, LOW 1)
- `synoaid` / `webd` / `librtsp_syno.so`: 0개

**CRITICAL 패치 상세:**
- `sub_E508`: `snprintf(s, ..., "echo \"%s:x:0:1101::/root:/bin/sh\" >> /etc/passwd", a1)` → hardcoded "synodebug" 교체. 외부 파라미터로 임의 root 계정 생성 가능했던 취약점 제거.
- `sub_E47C`: `echo "user:pass" | chpasswd` 패턴에서 사용자명/비밀번호가 쉘 명령에 직접 삽입 → 큰따옴표 삽입으로 RCE 가능. BinDiff mismatch로 NEW 함수는 제거됨.

**에러 및 해결:**
- Windows CP949 터미널에서 em-dash(`—`) 출력 시 `UnicodeEncodeError` → `sys.stdout.reconfigure(encoding='utf-8')` 패턴으로 해결
- Python heredoc 내 single-quote 충돌 → 스크립트 파일로 분리 후 실행

---

## 주요 노이즈 유형 정리

| 유형 | 설명 | 처리 방법 |
|------|------|----------|
| 타임존 파일 | `/usr/share/zoneinfo/` TZif 파일, 함수 0개 | 경로 필터링으로 제외 |
| PLT stub | `__imp_xxx`, instruction ≤ 3, 주소만 바뀜 | diff 생성 스킵 |
| 주소 재배치 | similarity 12.4%짜리 1-instruction 함수 | instruction 수 임계치로 필터 |
| 링커 아티팩트 | `.init_proc`, `JUMPOUT(0)` 형태 | 함수 크기로 필터 가능 |

---

### 2026-03-31 | Tapo C200v1 순차 디핑 자동화 + 파이프라인 버그 수정 4건

**진행 내용:**

1. **`src/analyzers/sequential_diff.py` 신규 작성** — 폴더 내 .bin 파일 순차 자동 비교
   - 파일명에서 버전 추출: `_en_(\d+)\.(\d+)\.(\d+)_` 정규식
   - 버전 튜플로 정렬 후 연속 쌍 구성 (1.0.2→1.0.3, 1.0.3→1.0.4, ...)
   - `bindiff_pipeline.py`를 subprocess로 호출 (pair당 1회)
   - `function_diff_stats.json` 존재 시 스킵 (이어하기 지원)
   - CLI: `--firmware-dir`, `--output-base`, `--from-version`, `--dry-run`
   - `PROJECT_ROOT`: `Path(__file__).resolve().parent.parent.parent` — 드라이브 변경 시 자동 적응

2. **binwalk WSL 설치**
   - `wsl -d Ubuntu -u root -- apt-get install -y binwalk` 로 설치
   - 버전: `binwalk 2.3.4+dfsg1-5` (dpkg -l 확인)

3. **파이프라인 버그 수정 4건:**

   **Bug 1: WSL binwalk PATH 문제 (binwalk 실행 결과 없음)**
   - 원인: `-lc` (login shell) 사용 시 Windows PATH 먼저 적재 → Windows Python에 설치된 binwalk 스크립트 실행
   - 해결: `-c` + 명시적 `PATH=/usr/local/bin:/usr/bin:/bin` 지정
   ```python
   # 변경 전
   ["wsl", "-d", "Ubuntu", "--", "bash", "-lc", f"binwalk -e '{wsl_fw}'"]
   # 변경 후
   ["wsl", "-d", "Ubuntu", "--", "bash", "-c",
    f"PATH=/usr/local/bin:/usr/bin:/bin && cd '{wsl_cwd}' && binwalk -e '{wsl_fw}'"]
   ```

   **Bug 2: UnicodeDecodeError cp949 (subprocess 출력 디코딩 실패)**
   - 원인: `text=True`만 설정 시 Windows 기본 코드페이지(cp949) 사용, WSL는 UTF-8 출력
   - 해결: binwalk, IDA, BinDiff(×2) 총 4개 `subprocess.run()` 호출에 `encoding='utf-8', errors='replace'` 추가

   **Bug 3: UnicodeEncodeError em-dash (print 출력 실패)**
   - 원인: f-string 내 em-dash(`—`) → Windows 터미널 cp949 인코딩 불가
   - 해결: `—` → `-` 교체 (sequential_diff.py, bindiff_pipeline.py)

   **Bug 4: PermissionError shutil.rmtree (IDA 파일 잠금)**
   - 원인: IDA Pro가 .id0/.id1/.nam/.til 파일을 열어둔 채 종료 → rmtree 실패
   - 해결: try/except 추가, 실패 시 IDA 임시 파일 개별 삭제 후 `ignore_errors=True`로 재시도

4. **sqlite-mcp 설치 및 설정**
   - `npm install -g mcp-sqlite` → `C:/home/riri/.npm-global/node_modules/mcp-sqlite/`
   - `~/.claude/settings.json`에 MCP 서버 설정 추가 (patch_learner.db 연결)

5. **첫 테스트: v1.0.2 → v1.0.3 성공**
   - 출력물: extracted/, functions/, bindiff/, binexport/, function_diffs/, hash_compare.json, diff_results.json, function_diff_stats.json, summary.md

6. **디스크 공간 부족 → 프로젝트 D 드라이브 이동**
   - pair 6/20(v1.0.7→v1.0.8) 처리 중 C 드라이브 100% 점유 → WinError 112
   - 전체 프로젝트 `D:\과제모음\4학년\project`로 이동
   - sequential_diff.py는 `__file__` 기반 경로 계산 → 코드 변경 불필요
   - 재실행 명령: `cd D:/과제모음/4학년/project && python src/analyzers/sequential_diff.py --from-version 1.0.7`

**대상 펌웨어:**
- TP-Link Tapo C200v1, v2는 일반 `binwalk` 경로로 처리 가능
- Tapo C200v3, v4는 당시 기준으로 `signed/encrypted` 계열 여부를 추가 확인해야 했음
- `sequential_diff.py`로 모델별 순차 자동화의 기본 틀을 확보

| 모델 | 상태 |
|------|------|
| C200v1 | ✅ 완료 (1.0.2 ~ 1.3.6, 19쌍) |
| C200v2 | ✅ 완료 |
| C200v3 | 보류 (복호화/추출 경로 점검 필요) |
| C200v4 | 보류 (복호화/추출 경로 점검 필요) |

---

### 2026-04-02 | Tapo v3/v4 복호화 경로 추가 + 상위 폴더 자동 실행 정리

**진행 내용:**

1. **`bindiff_pipeline.py`에 Tapo 복호화 분기 추가**
   - `signed/encrypted` 헤더를 감지하면 `tp-link-decrypt`를 먼저 수행
   - 복호화된 `.dec` 파일을 `binwalk` 입력으로 사용
   - 복호화 산출물은 출력 폴더 하위 `_decrypt_cache/`에 저장

2. **WSL 충돌 완화**
   - `binwalk` 실행 전에 `wsl --shutdown`을 선행하도록 수정
   - WSL이 열린 상태에서 `binwalk`가 실패하던 운영 이슈를 줄이도록 보강

3. **`sequential_diff.py` 상위 폴더 실행 정리**
   - `data/firmware/tapo_C200`처럼 상위 폴더를 주면 `Tapo_C200v1`~`v4`를 재귀 탐색
   - 출력은 `output/<모델>/v<old>_vs_v<new>/` 구조로 고정

4. **ipTIME 수집 자동화 초안 추가**
   - `download_iptime_firmware.py` 작성
   - 모델별 폴더를 만들고 과거 버전까지 수집하는 구조를 설계
   - 사이트 타임아웃이 있어 실제 수집은 네트워크 상태를 보며 재시도 필요

5. **문서/저장소 정리**
   - 코드와 도구 소스만 GitHub에 올리고, 분석 산출물은 ignore 유지
   - `data/`, `output/`는 빈 디렉터리 형태로만 저장소에 유지하도록 정리

**상태 정리:**
- Tapo C200v1, v2: Stage 0~1 산출물 확보
- Tapo C200v3, v4: 복호화 선행 경로 구현, 공식 출력 경로 기준 재실행 진행
- Stage 2: 다중 벤더 Stage 0~1 결과를 더 모은 뒤 일괄 수행 예정

---

## 알려진 제약사항

- IDA Pro 9.0 크랙 버전 사용 — 일부 플러그인 호환성 이슈 있음
- ARM 바이너리 전용 (x86 펌웨어는 추가 테스트 필요)
- `ThreadPoolExecutor(max_workers=4)` — PC 성능에 따라 조정 필요
- evostreamms (15,013개 함수), libcrypto (5,858개 함수) 등 대형 바이너리는 IDA 처리 시간 길어짐
- BinDiff는 함수가 완전히 삭제/추가된 경우 `function` 테이블에 기록 안 됨 (unmatched 함수는 별도 처리 필요)

---

### 2026-03-30 | TP-Link Tapo C200v1 디핑 준비 + 펌웨어 복호화 검증

**진행 내용:**

1. **Reolink 취약점 조사 → 탈락**
   - CVE 50+개 (Talos 연구) 있으나 대부분 미패치/EoL → 디핑 불가
   - cgiserver.cgi, netserver 바이너리에 집중

2. **TP-Link Tapo C200v1 선정**
   - 선정 이유: CVE 활발 (2023~2025), 펌웨어 추출 가능, MIPS 아키텍처 (크로스 아키텍처 검증)
   - 펌웨어 아카이브: https://github.com/tapo-firmware/Tapo_C200 (V1 20개 버전)

3. **펌웨어 암호화 검증 (핵심)**
   - `tp-link-decrypt` 빌드 완료 (WSL Ubuntu, `tapo_tools/tp-link-decrypt/`)
     - `extract_keys.sh`에서 binwalk UBI 추출 실패 → 수동으로 `ubireader_extract_files`로 UBI 풀어서 `nvrammanager`, `slpupgrade`에서 RSA 키 추출
     - SHA256 검증 통과, `make` 빌드 성공
   - **C200v1 실제 테스트 결과: 암호화 없음!**
     - v1.0.2, v1.0.3, v1.3.6 전부 `binwalk`가 SquashFS를 바로 감지
     - tp-link-decrypt은 C200v1에는 불필요 (C210 등 신형 모델용)
   - 기존 파이프라인의 `binwalk -e` (WSL) 경로가 그대로 동작

4. **tp-link-decrypt 빌드 과정 (참고용)**
   ```
   # WSL Ubuntu에서:
   cd tapo_tools/
   git clone https://github.com/robbins/tp-link-decrypt.git
   cd tp-link-decrypt

   # 의존성
   sudo apt-get install -y libssl-dev
   pip install ubi_reader  # ubireader_extract_files 필요

   # 키 추출 (extract_keys.sh가 자동화하지만, UBI 추출에서 실패할 수 있음)
   # 수동 키 추출 절차:
   #   1. extract_keys.sh 실행 → AX6000 펌웨어 다운 + binwalk 추출
   #   2. binwalk가 UBI만 풀고 squashfs 못 풀면:
   #      ubireader_extract_files -o ubi_out 3C1233.ubi
   #   3. ubi_out에서 nvrammanager 찾아 strings | grep BgIAAAwk → RSA_1
   #   4. C210 펌웨어도 binwalk 추출 → slpupgrade에서 → RSA_0
   #   5. include/RSA_0.h, RSA_1.h 생성 (const char RSA_0[] = "...";)
   #   6. make

   # 사용법 (암호화된 펌웨어일 때만):
   bin/tp-link-decrypt encrypted_firmware.bin > decrypted.bin
   binwalk -Me decrypted.bin
   ```

5. **파이프라인 실행 명령어**
   ```
   python Patch-Learner-main/src/analyzers/bindiff_pipeline.py --old "Patch-Learner-main/firmware/Tapo_C200-main/Tapo_C200v1/Tapo_C200v1_en_1.0.2_Build_190821_Rel.40297n__1569812112373.bin" --new "Patch-Learner-main/firmware/Tapo_C200-main/Tapo_C200v1/Tapo_C200v1_en_1.0.3_Build_190911_Rel.61583n__1574130335308.bin" --vendor tp-link --model "Tapo C200v1" --old-ver 1.0.2 --new-ver 1.0.3
   ```

**암호화 판별법:**
- `binwalk firmware.bin` → SquashFS 보이면 → 암호화 없음 → 바로 파이프라인 실행
- 아무것도 안 보이면 → `tp-link-decrypt`로 복호화 후 진행

**디핑 순서 (20개 버전):**
```
1.0.2 → 1.0.3 → 1.0.4 → 1.0.5 → 1.0.6 → 1.0.7 → 1.0.10 → 1.0.14 →
1.0.16 → 1.0.17 → 1.0.18 → 1.1.1 → 1.1.11 → 1.1.15 → 1.1.16 → 1.1.18 →
1.3.2 → 1.3.4 → 1.3.5 → 1.3.6
```

**파일명 참고:** 같은 버전에 타임스탬프만 다른 파일이 여러 개 있음 (예: `_1569812112373.bin` vs `_1572226147854.bin`). 버전 번호가 같으면 내용 동일 — 아무거나 하나만 사용.

---

### 2026-04-09 | Dahua 코퍼스 DB 적재 + DB 현황 정리

**진행 내용:**

1. **Dahua 198개 version pair 일괄 DB import**
   - `src/tools/import_existing_output.py`의 버전 정규식을 4-part(`v2.860.0.13` 형식)까지 매칭하도록 수정 (`^v([\d.]+)_vs_v([\d.]+)$`)
   - VENDOR_MAP에 `dh_ipc`, `dahua`, `ezip` 키워드 추가
   - 기존 import 로직이 Stage 0에서 저장된 파티션 레벨 `changed_files`(`zip_contents/romfs-x.squashfs.img`)와 BinDiff 결과의 rootfs 레벨 basename(`aewDebug`)이 매칭 안 돼 `changed_functions`가 0건으로 남던 문제 수정
   - `ensure_changed_file()` / `ensure_bindiff_result()` 헬퍼 추가: `_get_changed_file_id`로 매칭 실패 시 `diff_results.json`의 basename 기준으로 직접 INSERT

2. **DB 현황 (2026-04-09 기준)**
   ```
   firmware_versions      271
   diff_sessions          237
   changed_files        5,578
   bindiff_results      2,825
   changed_functions   67,104
   security_patches         0
   pattern_cards            0
   hunt_findings            0
   ```
   - dahua: 198 세션 / 3,806 changed_files / 2,020 bindiff_results / **55,049 changed_functions**
   - tp-link: 39 세션 / 1,772 changed_files / 805 bindiff_results / **12,055 changed_functions**

3. **Dahua 펌웨어 32개 모델 분류 (DH-ZIP 추출 결과)**
   - 추출 가능: 15개 모델 (구형, SquashFS/CramFS 직접 노출)
   - 암호화: 17개 모델 / 약 155개 .bin (내부 .img 첫 4KB 엔트로피 256/256)
     - HX18XX-Molec, HX1XXX-Edison2, HX1XXX-Hertz×2, HX1XXX-Kant, HX1XXX-Molec, HX2(1)XXX-Edison, HX25(8)XX-Molec, HX2XXX-Kant, HX2XXX-Molec, HX3XXX-Dalton, HX3XXX-Leo, HX3XXX-Taurus, HX4XXX-Volt, HX5(4)(3)XXX-Leo, HX5XXX-Volt, EZIP-Leto

4. **Dahua 복호화 도구 조사**
   - 공개 end-to-end 복호화 도구는 없음. 외곽 DH-ZIP 컨테이너만 처리하는 도구가 전부
   - 정리:
     - `BotoX/Dahua-Firmware-Mod-Kit` — DH→PK 헤더 패치 + uImage strip + SquashFS unpack. 구형 펌웨어 한정. AES 페이로드는 못 푼다.
     - `mcw0/Tools` (`DahuaConfigBackupDecEnc.py`) — 기기 config backup 전용 (펌웨어 .img 아님)
     - `mcw0/DahuaConsole` — DHIP 기반 디버그 콘솔 접근
     - Nozomi Networks / Tarlogic — 부트로더에서 키 추출 후 에뮬레이션, 코드 미공개
     - CDDC Finals 2025 CTF writeup — Unicorn으로 `SecUnit_*` 함수 에뮬레이트해 AES-CBC-512 페이로드 복호화 (`ssc325` SoC 기준), 스크립트 미공개
   - 결론: 신형(암호화) 17개 모델은 모델별 부트로더/커널 리버싱이 필요. 일반화 불가.

---

### 2026-04-09 | ipTIME 펌웨어 코퍼스 확보 + 추출 방식 검증

**진행 내용:**

1. **ipTIME 카메라 펌웨어 다운로드 완료**
   - 약 1,800개 .bin 확보 (ipTIME 카메라 라인 전체)
   - `data/firmware/iptime/` 적재 작업은 별도 진행 예정

2. **암호화 여부 조사 결론: 복호화 불필요**
   - ipTIME 라우터 펌웨어는 평문 SquashFS (LZMA) 구조로 잘 알려져 있음
   - OpenWrt 포팅(예: `stypr/openwrt-iptime` AX3000M), Pierre Kim의 9.52 PoC, 다수 RCE 연구가 모두 binwalk 직접 추출 전제로 작성됨
   - 카메라/NVR도 EFM Networks가 같은 빌드 시스템을 재사용하므로 동일 패턴으로 추정 (별도 헤더/AES 래퍼 보고 사례 없음)
   - 결론: **`binwalk -Me firmware.bin` 한 번으로 추출 가능 → tp-link-decrypt 같은 전처리 스텝 불필요**

3. **권장 추출 절차**
   ```bash
   # 1차: 엔트로피 확인 (평탄한 0.95면 암호화 의심)
   binwalk -E firmware.bin

   # 2차: 헤더가 낮고 SquashFS 구간만 높으면 평문이므로 바로 추출
   binwalk -Me firmware.bin
   ```
   - 기존 `bindiff_pipeline.py`의 `binwalk -e` (WSL) 경로가 그대로 동작할 것으로 예상
   - 카메라/NVR `.bin`만 별도로 첫 추출 한 번 돌려 확인 후 본격 디핑 진입

4. **참고: 알려진 ipTIME 관련 reverse engineering 자산**
   - `hackintoanetwork/ipTIME-Router-9.58-RCE-PoC` — pre-auth RCE
   - `ddkani/iptime-debug`, `live2skull/iptime-debug` — 9.72까지 셸 진입
   - `DePierre/iptime_utils` — config backup 언팩
   - `stypr/openwrt-iptime` — AX3000M OpenWrt 포팅 (평문 SquashFS 확인 근거)
   - Pierre Kim 2015 ipTIME 9.52 advisory — 커널 메모리 릭
   - **CVE-2025-55423** — 163개 라우터 모델 영향, `upnp_relay()` (`/lib/libcgi.so`) UPnP command injection, 인증 없이 root RCE
   - **카메라/NVR 전용 공개 연구는 사실상 없음** — 코퍼스가 이미 확보된 상태에서 카메라 라인을 분석하면 신규 발견이 가능한 영역

5. **다음 액션**
   - `data/firmware/iptime/` 디렉터리 정리 (모델별 폴더링)
   - 카메라 `.bin` 우선 1~2개 추출 테스트로 평문 가설 검증
   - 평문 확인되면 `sequential_diff.py`에 ipTIME vendor 키워드 추가 후 일괄 디핑 시작
   - 1,800개 카메라 펌웨어 → 수백 개 version pair, Stage 0~1 코퍼스가 단숨에 확장됨
