---
name: stage2
description: |
  Patch-Learner Stage 2 오케스트레이션. changed_functions → (Drafter가 security_patches +
  pattern_cards 동시 생성) → hunt_findings. 3-Phase 구조 (사전필터 / Drafter / Hunter).
  Reviewer 단계는 2026-04-17에 제거. Drafter 판정이 최종, 같은 공식 카드는 자동 흡수.
  Use when asked to "stage2 돌려", "stage2 phase N", "drafter 돌려", "카드 만들어",
  "헌팅 시작", "stage2 analysis", "boot stage 2".
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Agent
  - TodoWrite
---

# Stage 2 오케스트레이션 (v3 — Reviewer 제거, 2026-04-17)

> **v3 변경:** Analyst → Reviewer → Designer 3단계를 **Drafter 단독**으로 통합. 판정+카드 작성을 한 턴에.
> 같은 공식의 카드는 자동 흡수 (pattern_card_members로 병합). 사람 검토는 Phase 5 Hunter 결과에서만.

## DB / 경로 상수

- DB: `Patch-Learner-main/src/db/patch_learner.db`
- 파이프라인 진입점: `src/analyzers/bindiff_pipeline.py`

## 3-Phase 상태 머신

```
changed_functions.stage2_status
  pending → skipped_oss / prefiltered_out / prefiltered_in
         → drafting_a1/a2 → drafted_sec / drafted_nonsec / error

pattern_cards.status
  active (기본, 생성 시 바로 active)
    → superseded_by (더 선명한 스니펫 나올 때 교체)
    → retired (precision < 0.3 + 충분한 샘플, 사람 결정)

hunt_findings.is_true_positive
  NULL (미검토) / TRUE / FALSE (사람이 확정)
```

## 실행 순서

### Phase 0 — 사전 필터 (Python, LLM 0)

OSS 바이너리 제외 + 키워드/similarity 필터로 27K → ~1.5K 감축.

```bash
sqlite3 Patch-Learner-main/src/db/patch_learner.db < .claude/skills/stage2/sql/migration.sql
sqlite3 Patch-Learner-main/src/db/patch_learner.db < .claude/skills/stage2/sql/prefilter.sql
# + Python 키워드 필터 (src/stage2/prefilter.py 예정)
```

### Phase 1 — Drafter (A1·A2 병렬)

- 시스템 프롬프트: `prompts/drafter.md`
- A1: vendor 바이너리 family (central_server, synocam_param.cgi, nvtd, ubnt_*, kb2000_daemon 등)
- A2: 그 외 (config tool, utility daemon, vendor-forked shared lib)
- 처리 단위: 한 turn에 5~10 함수 묶어 JSON array
- Agent tool로 2개 서브에이전트(Opus 4.6) 병렬 실행
- **Drafter가 판정과 카드 작성을 한 번에**:
  - `is_security_patch=false` → `security_patches` INSERT, 카드 없음, `stage2_status='drafted_nonsec'`
  - `is_security_patch=true` → `security_patches` + `pattern_cards` + 부속 테이블 INSERT,
    `stage2_status='drafted_sec'`
- **Auto-merge** (오케스트레이터 SQL): 같은 `(source_type, sink_type, missing_check)` 카드가 이미
  있으면 신규 생성 대신 기존 카드에 `pattern_card_members` 행 추가. 스니펫이 더 선명하면 version++로 교체.

### Phase 2 — Hunter H

- 시스템 프롬프트: `prompts/hunter.md`
- 타겟 펌웨어 선정 (예: TP-Link C200v1 v1.0.3)
- **Python 전처리**: 함수 F에서 source/sink/token enum 추출 → `pattern_cards` 공식 3요소 +
  `pattern_card_tokens` 인덱스 + `pattern_card_negative_tokens` 배제로 후보 1~5장 컷.
- Hunter는 후보 카드의 `vulnerable_snippet` ↔ 함수 F 모양 비교로 매칭 판정.
- 출력: `hunt_findings` INSERT (`is_true_positive=NULL`)
- 사람 검토로 최종 TP/FP 확정 → `pattern_card_stats` 자동 갱신.

## 하드 규칙 (전 Phase 공통)

`rules/hard-rules.md` 참고. 모든 system 프롬프트 상단에 하드코딩.
- 출력 JSON only · False Positive 가드 7종 · Synology `sub_6CEE0`/`sub_1E5E4` 치환 규칙
- Confidence 기준표 (0.90+ / 0.70~0.89 / 0.50~0.69 / <0.50)
- CVE 매칭 허용 리스트 (추측 금지)

## 효율 핵심

1. **사전필터로 LLM 호출 80% 컷** — Phase 0에서 ~1.5K로 감축.
2. **Reviewer 제거로 호출 횟수 1/3** — 함수 1건당 LLM 1회만. 토큰 60% 절감.
3. **Auto-merge로 카드 폭발 차단** — 같은 공식은 한 카드로 수렴.
4. **Prompt Caching** — `prompts/drafter.md` + few-shot을 `cache_control: ephemeral`.
5. **병렬 Agent** — Drafter A1·A2 동시 실행. 메인 세션 = 오케스트레이터.
6. **Tool Use JSON 스키마 강제** — 구조 위반 원천 차단.
7. **Diff 전처리** — 변수명 정규화 + `+`/`-` 포맷으로 토큰 40~60% 절감.
8. **DB 스냅샷 백업** — Phase 경계마다 `cp patch_learner.db patch_learner.db.bak.phaseN`.

## Drafter의 자기 검증 (Reviewer 부재 보상)

Reviewer가 없으므로 Drafter 프롬프트 자체에 다음을 내장 (`prompts/drafter.md`):

- Confidence 0.70 미만이면 기본적으로 `is_security_patch=false`.
- 근거가 코드에서 직접 안 보이면 confidence 0.50~0.65로 낮춰 사후 집계용 buffer 구간에 둔다.
- Synology Hard Rules가 확실히 적용된 경우에만 `severity=critical`.
- False Positive 가드 7종 엄격 적용.

## Human-in-the-loop 체크포인트 (축소)

- Phase 1 첫 500건 통과 후 수동 샘플 20개 검토 → 프롬프트 튜닝.
- `severity_hint='critical'` 카드는 팀 공유 전 전수 검토.
- Phase 2 `is_true_positive` 확정은 사람만.
- `pattern_card_stats.precision < 0.3` 카드는 retire 사람 승인 (자동 아님).

## 레퍼런스

- BC500 학습 근거: `docs/dev-notes.md` 2026-03-26 항목
- 카드 작성 스펙: `docs/pattern-card-spec.md`
- 스키마 DDL: `Patch-Learner-main/src/db/schema.sql` + `.claude/skills/stage2/sql/migration.sql`
- 알려진 CVE 패턴: `cve-2025-31700.md`, `kve.md`
