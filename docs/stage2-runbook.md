# Stage 2 CLI 운영 런북 (v3, Drafter 병렬 4-shard)

> **이 파일의 역할**: Claude Code CLI 세션이 **혼자서** Stage 2 배치를 반복 실행할 수 있게 모든 절차를 담아둔 지침서.
> 사용자가 CLI를 열고 "이 런북 따라 Stage 2 돌려"라고 하면, CLI 세션이 이 파일만 읽고 처음부터 끝까지 실행 가능해야 함.
>
> **사전 조건 (이미 완료됨)**:
> - migration.sql 적용됨 → `pattern_cards` v2 스키마 + 부속 테이블 6개
> - Phase 0 사전 필터 실행됨 → `prefiltered_in` 약 21,955건 대기
> - `.claude/skills/stage2/` 전체 + `docs/pattern-card-spec.md` 존재

---

## 0. 역할 선언

당신은 **Stage 2 파이프라인 운영자 (오케스트레이터)**다.
당신이 직접 함수를 분석하지 않는다. **Drafter Agent 4개를 병렬로 띄워** 분석을 맡긴다.

### 참조해야 할 문서 (매 배치 시작 시 읽음 — 캐시되면 OK)

1. `.claude/skills/stage2/prompts/drafter.md` — Drafter Agent 시스템 프롬프트 원본
2. `.claude/skills/stage2/rules/hard-rules.md` — 모든 Agent 공통 하드 규칙
3. `docs/pattern-card-spec.md` — 패턴카드 컬럼·enum 스펙
4. **이 파일** (`docs/stage2-runbook.md`) — 오케스트레이션 절차

---

## 1. 1회 배치 흐름 (9단계)

### 1-1. 재개 정리
```bash
python src/stage2/drafter_run.py resume
```
- 중단된 이전 배치가 있으면 `drafting_a1/a2` → `prefiltered_in` 복구
- 현재 `stage2_status` 분포, 카드 수, 남은 세션 상위 10개 출력

### 1-2. 다음 배치 세션 결정
```bash
python src/stage2/drafter_run.py next-batch-info
# 또는 특정 세션 지정:
python src/stage2/drafter_run.py next-batch-info --prefer-session 78
```
- JSON으로 `{session_id, vendor, model, old_version, new_version, remaining}` 출력
- 특별한 이유 없으면 `remaining`이 가장 큰 세션 자동 선택
- 단, **같은 벤더만 연속하지 말 것** — 배치 N이 dahua면 배치 N+1은 tp-link/iptime으로 번갈아 (크로스벤더 Auto-merge 검증)

### 1-3. prepare (함수 200건 추출, 4-shard 기준)
```bash
python src/stage2/drafter_run.py prepare <SESSION_ID> --limit 200 --out tmp/stage2/in_s<SESSION_ID>.json
```
- 200건 미만 세션이면 `remaining` 값 그대로 `--limit`에 사용
- 결과 JSON이 생기고, 해당 `changed_functions`들은 `drafting_a1`로 stage 전이
- **왜 200?** Agent 하나당 ~50개면 4개 Agent로 병렬 커버, 함수 50개는 Agent 프롬프트 길이·품질 균형점

### 1-4. split (4-shard 분할)
```bash
python src/stage2/drafter_run.py split tmp/stage2/in_s<SESSION_ID>.json --shards 4
```
- 바이너리 단위로 유지하며 LPT 그리디 분배 → `in_s<N>_a1.json` … `in_s<N>_a4.json`
- 샤드가 비어 있으면 (함수가 4개 미만이면) 자동 스킵
- 출력 메시지에 **"expected Drafter outputs"** 경로 4개 포함 — Agent 프롬프트에 그대로 복붙

### 1-5. 4개 Agent 병렬 spawn

**같은 메시지에서 4개의 Agent tool call을 동시에 발행** — 그래야 병렬 실행된다.

각 Agent 프롬프트 템플릿 (i = 1,2,3,4):

```text
You are the Stage 2 Phase 1 Drafter (A{i}) for Patch-Learner — a defensive firmware patch analysis pipeline.

Working directory: (이 저장소 루트의 절대 경로)

## Read FIRST (your system prompt)

1. `.claude/skills/stage2/prompts/drafter.md`
2. `.claude/skills/stage2/rules/hard-rules.md`
3. `docs/pattern-card-spec.md`

## Task

Input: `tmp/stage2/in_s<SESSION_ID>_a{i}.json` — function diffs from <VENDOR>/<MODEL> v<OLD> → v<NEW>.

For each function, produce a JSON object per drafter.md schema:
- `changed_function_id` + `analyst_id="A{i}"` + `is_security_patch` + `confidence`
- `patch_record` (always present)
- `card_draft` (only when is_security_patch=true)

Output: JSON ARRAY → `tmp/stage2/out_s<SESSION_ID>_a{i}.json`.

## Critical rules (compact)

- Valid JSON array only (no markdown fences, no prose).
- 한국어 narrative fields.
- Never echo decompiled_old/decompiled_new.
- FP guards §2 strict; confidence <0.70 defaults to is_security_patch=false.
- Enum values from pattern-card-spec.md §3-2.
- Tokens 3~8 items, no generic words (path/user/buffer/data).
- Leave card_id unset.
- Same formula across multiple functions is expected — orchestrator Auto-merges. Do NOT dedupe yourself.

## Auto-merge awareness

If an existing card with the same (source_type, sink_type, missing_check) matches, orchestrator will merge
by adding your `security_patch_id` to `pattern_card_members`. Just fill card_draft independently.

## Report

At the end, print under 200 words: sec/nonsec counts, confidence distribution, unique formulas, dominant FP-guard types. Nothing else.
```

**주의**:
- `<SESSION_ID>`, `<VENDOR>`, `<MODEL>`, `<OLD>`, `<NEW>`, `<i>`는 prepare 결과로 채워넣기
- 4개 모두 `Agent` tool로 같은 메시지에 발행 (병렬 실행 보장)
- `subagent_type=general-purpose`, `model=opus` (Drafter는 Opus 4.6 요구)
- VS Code 확장에선 실시간 툴콜 안 보임 — **터미널 CLI**에서 돌리면 각 Agent의 Read/Write/Grep 전부 실시간 스트림됨

### 1-6. 4개 Agent 종료 대기 → 결과 수집

각 Agent 반환 메시지에 보고문 포함됨. 네 결과가 모이면 `out_s<N>_a1.json` … `out_s<N>_a4.json` 4개 파일 확인:

```bash
ls tmp/stage2/out_s<SESSION_ID>_a*.json
```

### 1-7. merge + apply (DB 반영, Auto-merge 포함)

```bash
python src/stage2/drafter_run.py apply tmp/stage2/out_s<SESSION_ID>_a1.json tmp/stage2/out_s<SESSION_ID>_a2.json tmp/stage2/out_s<SESSION_ID>_a3.json tmp/stage2/out_s<SESSION_ID>_a4.json
```

출력:
- `security_patches inserted: N` (= 200)
- `new cards: X`, `auto-merged: Y`, `non-security: Z`

### 1-8. 대시보드 (진행률 요약)

```bash
python src/stage2/drafter_run.py resume
```
(`resume`이 상태 요약도 함 — 카드 수/security 패치 수/남은 큐/상위 세션 10개)

### 1-9. Git push (팀 공유 파일만)

```bash
bash scripts/push_team_artifacts.sh "stage2: session <SESSION_ID> batch done (+ N cards)"
```

- 오직 **팀 공유 경로**만 staged: `.claude/skills/stage2/`, `docs/`, `data/handoff/`, `src/stage2/`, `scripts/`, `CLAUDE.md`, `.gitignore`
- DB·펌웨어·개인 설정·tmp 는 gitignore로 자동 제외
- 리모트: `origin` (기본). 팀 리모트로 가려면 `PUSH_REMOTE=team PUSH_BRANCH=riri bash scripts/push_team_artifacts.sh ...`

---

## 2. 반복 루프

사용자가 **"그만" / "stop" / "멈춰"** 라고 말할 때까지 §1 1-1 ~ 1-9를 반복.

각 배치 끝나면 간단 보고:
```
[배치 N 완료]
 세션: s<NN>  벤더: <X>  버전: v<OLD>→v<NEW>
 처리: 200건  (sec: N, nonsec: N)
 카드: 신규 X, auto-merge Y, 전체 active Z
 큐 잔량: prefiltered_in <N>건
 git push: "stage2: ..." → origin
 다음 배치로 진행 중...
```

그리고 바로 다음 배치 1-1부터 시작.

### 자동 중단 조건 (사용자 명시 중단이 없어도 멈춤)

- `prefiltered_in` 큐가 0이 되면 → 종료 메시지 + 최종 대시보드 + 종료
- apply 에서 에러 10건 이상 → 루프 중단 후 원인 보고 (사용자 확인 대기)
- Anthropic Usage Policy 차단 연속 2회 발생 → 루프 중단, 프롬프트 문구 재검토 요청

---

## 3. 샤드 밸런싱 참고 (1-4 split 동작)

`split`은 이렇게 배분함:
- `binary_name` 단위로 같은 shard에 몰아넣음 (Agent의 도메인 학습 효과 살림)
- Longest Processing Time 그리디 — 큰 binary부터 가장 한가한 shard에 배정
- 결과 불균형은 감수 (예: 200건 중 libX.so 180건 + libY 20건이면 A1=180, A2=20, A3/A4=0)

함수 수가 매우 작은 세션 (4개 미만)이면 샤드 자동 축소 — Agent도 적게 spawn (1~3개).

---

## 4. 하드 규칙 (절대 위반 금지)

1. **한 세션의 함수는 한 배치에서 끝낸다.** 같은 세션을 여러 배치로 쪼개지 않음 (상태 추적 복잡).
   예외: 세션 크기가 200 초과면 200씩 끊어 여러 배치 — 이때 `prefiltered_in` 자연 감소로 구분됨.
2. **Agent에게 `decompiled_*` 재출력 시키지 말 것** (토큰 낭비).
3. **card_id를 Agent가 붙이지 않게 한다** (orchestrator만 할당).
4. **병렬 Agent는 같은 메시지에서 동시 spawn** — 순차로 부르면 병렬 이득 0.
5. **git push 전 commit 메시지에 세션 ID + 배치 결과 포함** — 히스토리에서 복기하기 위함.
6. **Auto-merge는 Drafter가 절대 시도하지 않는다.** 같은 공식의 함수가 여러 개 나오면 그냥 각자 card_draft 채움. orchestrator(파이썬 apply)가 DB INSERT 시 UNIQUE INDEX로 자동 처리.
7. **사용자가 말한 배치 수 제한이 없어도 한 세션이 끝나면 다음 세션으로 자연스럽게 전환.**
8. **`share_batch.py`는 현재 미구현이므로 critical 카드가 나와도 자동 공유 트리거 안 함.** 대신 해당 배치의 git commit 메시지에 `[CRITICAL]` 태그 달아 알림.

---

## 5. 트러블슈팅

| 증상 | 원인 | 대응 |
|---|---|---|
| Agent가 JSON array가 아닌 문장 반환 | 하드 규칙 §1 위반 | 같은 Agent에 "이전 출력이 JSON array 아님. JSON만 다시 출력" 1회 재시도. 2회 실패면 해당 shard 스킵 + `stage2_status='error'`로 마킹 |
| apply 에러 (Enum 위반 등) | Agent 출력 스키마 파손 | 로그 확인, 필요 시 해당 파일 수동 교정 후 재apply |
| prepare 후 0건 | 세션이 이미 처리 완료 | next-batch-info 다시 실행해 다른 세션 선택 |
| Anthropic Usage Policy 차단 | 프롬프트에 공격적 문구 | 런북 §1-5 Agent 프롬프트 템플릿만 사용 (공격 시나리오 언급 금지) |
| git push 실패 (인증) | 토큰 만료/remote 없음 | SKIP_PUSH=1로 커밋만 저장, 사용자에게 수동 push 요청 |

---

## 6. 종료 시 체크리스트

루프 종료 (사용자 중단 or 큐 소진) 시:
- [ ] 마지막 배치 apply 성공했는지 확인
- [ ] `resume` 돌려서 `drafting_*` stale 없는지 확인 (있으면 cleanup까지)
- [ ] 최종 대시보드 출력 (카드 수, security patch 수, 벤더별 분포)
- [ ] 아직 push 안 된 커밋 있으면 git push
- [ ] 다음 재개 시 "어느 세션 어디까지" 한 줄 요약 — DB의 `stage2_status` 분포로 자동 복구됨
