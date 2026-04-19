# Zero-Day Blind Hunt — 운영 런북

## 목적

Stage 2에서 누적한 pattern_cards를 써서, **외부 CVE 지식 없이** 새 바이너리의 모든 함수를 Drafter Agent에게 blind 감사시키고, 취약한 함수를 찾아내기. 실제 제로데이 헌팅에도 재사용.

## 전체 흐름

```
 [1] IDA 전체 함수 디컴파일              ida_user/extract_all_funcs.py
 [2] DB migration                       sql/zero_day_migration.sql
 [3] run 생성 + 함수 적재                zero_day_run.py init
 [4] 위험 키워드 prefilter               zero_day_run.py prefilter
 [5] N건 배치 prepare → shard → Agent    zero_day_run.py prepare + split + Drafter
 [6] 결과 apply → DB                    zero_day_run.py apply
 [7] 웹 대시보드에서 확인·리뷰          http://127.0.0.1:8787/zero-day/<run_id>
 [8] 반복 ([5]~[7]) 큐 소진까지
```

## 선행 조건 (최초 1회)

### 1) DB migration
```bash
python src/stage2/zero_day_run.py migrate
```
→ `zero_day_runs`, `zero_day_functions`, `zero_day_verdicts` 테이블 생성.

### 2) 웹 대시보드 기동
```powershell
cd D:\Task\4\project\web
.\run.ps1
```
또는
```bash
cd web && bash run.sh
```
→ http://127.0.0.1:8787 (읽기 전용 대시보드 + review POST)

## 1회 Run 흐름

### Step 1 — 대상 바이너리 전체 함수 디컴파일 (~45분)

`ida_user/extract_all_funcs.py` 를 idat64로 태움. `.i64` 없어도 IDA가 자동 분석. 중간 체크포인트(`.partial`) 지원. `IDA_RESUME=1` 이면 재시작 시 이어받음.

예: `sonia v2.880.0.16`
```bash
# run_full.sh 템플릿 사용 (tmp/sonia_v2880_016_full/run_full.sh)
bash tmp/sonia_v2880_016_full/run_full.sh
```
출력: `tmp/sonia_v2880_016_full/sonia_v2880_016.json` (~수백 MB)

환경변수:
- `IDA_EXPORT_DIR` — JSON 출력 디렉토리
- `IDA_BINARY_TAG` — 파일명 접미사 (`_v2880_016`)
- `IDA_MIN_FUNC_SIZE` (default 8)
- `IDA_CHECKPOINT_EVERY` (default 50)
- `IDA_RESUME` (default 1)

### Step 2 — Run 초기화

```bash
python src/stage2/zero_day_run.py init \
  --name "sonia_v2.880.0.16_blind" \
  --binary "output/dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN/v2.880.0.16_vs_v2.880.0.17/extracted/DH_IPC-HX1XXX-Kant_EngSpnRus_PN_V2.880.0000000.16.R.240830/user-x.squashfs/bin/sonia" \
  --funcs-json tmp/sonia_v2880_016_full/sonia_v2880_016.json \
  --vendor dahua --model Kant --version 2.880.0.16
```
→ `zero_day_runs.id` 발급. `zero_day_functions` 에 함수 전부 적재(`stage_status='pending'`).

### Step 3 — 위험 키워드 prefilter

```bash
python src/stage2/zero_day_run.py prefilter <run_id>
```
→ pseudocode/disasm 에 `strncpy(`, `memcpy(`, `system(`, `strcpy(`, `sprintf(` 등 위험 키워드 포함한 함수만 `prefiltered=1`. 보통 전체의 10~25% 통과.

### Step 4 — 배치 루프 (200건씩 4 Agent 병렬)

#### 4-1. prepare
```bash
python src/stage2/zero_day_run.py prepare <run_id> --limit 200 --out tmp/zd/in_r<run_id>_b<batch>.json
```
prepared 된 행은 `stage_status='drafting'` 로 전이. JSON에 함수 pseudocode + 활성 pattern_cards (106장 중 active 99장) 컨텍스트까지 함께 들어감.

#### 4-2. split
```bash
python src/stage2/zero_day_run.py split tmp/zd/in_r<run_id>_b<batch>.json --shards 4
```
→ `..._a1.json` ~ `..._a4.json` (LPT greedy로 pseudocode 길이 균형)

#### 4-3. 4 Agent 병렬 spawn (CLI 세션에서)

**동일한 메시지에서** 4개 Agent tool call — 병렬 실행 보장.

각 Agent 프롬프트 템플릿:
```
You are a Zero-Day Hunter Agent (A{i}).
Working directory: D:\Task\4\project

## Read FIRST (system prompt)
- .claude/skills/stage2/prompts/zero_day_hunter.md
- .claude/skills/stage2/rules/hard-rules.md
- docs/pattern-card-spec.md

## STRICT CONSTRAINTS
- Zero external knowledge. No CVE numbers in output.
- No reads of cve-*.md, kve*.md, advisory*, changelog*.
- No WebSearch / WebFetch.
- Base judgment ONLY on pseudocode + provided active_pattern_cards.

## Task
Read `tmp/zd/in_r<run_id>_b<batch>_a{i}.json` — a JSON with:
  - run: {vendor, model, version, binary}
  - active_pattern_cards: [ ... 카드 컨텍스트 ... ]
  - functions: [ {zdf_id, function_addr, pseudocode, disasm, calls, strings} ... ]

For each function, follow the schema in zero_day_hunter.md. Output JSON array
to `tmp/zd/in_r<run_id>_b<batch>_a{i}_out.json`.

agent_id = "A{i}"

## Report
Under 200 words: processed/vuln/benign, confidence dist, top-3 findings, temptations resisted.
```

#### 4-4. apply

4개 Agent 끝나면:
```bash
python src/stage2/zero_day_run.py apply <run_id> \
  tmp/zd/in_r<run_id>_b<batch>_a1_out.json \
  tmp/zd/in_r<run_id>_b<batch>_a2_out.json \
  tmp/zd/in_r<run_id>_b<batch>_a3_out.json \
  tmp/zd/in_r<run_id>_b<batch>_a4_out.json
```
→ `zero_day_verdicts` INSERT, 함수는 `stage_status='done'`, run 카운터 업데이트.

#### 4-5. status & web

CLI:
```bash
python src/stage2/zero_day_run.py status <run_id>
```
Web:
- 리스트: http://127.0.0.1:8787/zero-day
- 상세: http://127.0.0.1:8787/zero-day/\<run_id>
  - SSE로 2초마다 진행률 갱신
  - 취약 판정 행 클릭 → 모달로 root_cause/attack_scenario/raw_reasoning/pseudocode + review 폼

다음 배치로 반복. `prefiltered_in - done == 0` 되면 완료.

## 블라인드 제약 강제

Agent 프롬프트 최상단의 STRICT CONSTRAINTS 준수 여부를 사후 검증:
```bash
python -c "
import sqlite3
c = sqlite3.connect('Patch-Learner-main/src/db/patch_learner.db').cursor()
import re
cve_re = re.compile(r'(CVE|KVE)-\d{4}-\d+')
bad = 0
for r in c.execute('SELECT id, raw_reasoning FROM zero_day_verdicts'):
    if r[1] and cve_re.search(r[1]): bad += 1
print(f'verdicts leaking CVE id in raw_reasoning: {bad}')
"
```
0이어야 함. 1 이상이면 해당 Agent 프롬프트 재검토.

## 성공 기준 (CVE-2025-31700 검증용 1차 run)

1. 최소 1개 `verdict` 가 `source_type='http_header'` + `sink_type='stack_buffer_copy'` + `missing_check='length_bound'` 로 **matched_card_pk=106 (P-106, cve_similar=CVE-2025-31700)** 또는 novel-but-same-formula 판정.
2. 해당 verdict 의 `function_addr` 가 sonia 의 `Src/OnvifHandler.cpp` 문자열을 참조하는 함수 주소 범위에 있음 (IDA로 교차검증).
3. `raw_reasoning` 에 CVE 번호 누출 0건.

위 3개 동시 충족 시 → **블라인드 파이프라인이 실제 CVE 를 제로데이처럼 탐지했다** 결론.

## 트러블슈팅

| 증상 | 원인 | 해결 |
|---|---|---|
| `prefilter` 후 통과 함수 0건 | pseudocode 가 비어있음 (Hex-Rays 실패) | `stats.decompiled` 확인. 0 이면 IDA 라이선스/플러그인 문제 |
| Agent 가 `CVE-2025-31700` 을 raw_reasoning 에 출력 | hard-rule 미준수 | 프롬프트 위 `STRICT CONSTRAINTS` 강조. 해당 verdict 수동 삭제 + 재batch |
| `prepare` 후 이어서 `apply` 누락 | 함수들이 `drafting` 상태로 남음 | 재시작 시 `UPDATE zero_day_functions SET stage_status='pending' WHERE stage_status='drafting' AND run_id=?` 로 되돌림 |
| `status` 의 processed_functions 가 안 맞음 | apply 가 카운터 갱신 안 함 | run status 재계산: `UPDATE zero_day_runs SET processed_functions=(SELECT COUNT(*) FROM zero_day_functions WHERE run_id=? AND stage_status='done')` |
| 웹 500 에러 | DB 스키마 변경 직후 | 웹 서버 재시작 |

## 파일 레퍼런스

| 역할 | 경로 |
|---|---|
| 블라인드 프롬프트 | `.claude/skills/stage2/prompts/zero_day_hunter.md` |
| 하드 규칙 (공유) | `.claude/skills/stage2/rules/hard-rules.md` |
| 카드 스펙 | `docs/pattern-card-spec.md` |
| DB 스키마 | `.claude/skills/stage2/sql/zero_day_migration.sql` |
| 오케스트레이터 | `src/stage2/zero_day_run.py` |
| 전체 디컴파일 스크립트 | `ida_user/extract_all_funcs.py` |
| 웹 앱 | `web/app.py` + `web/api/` + `web/templates/` |
| DB | `Patch-Learner-main/src/db/patch_learner.db` |
