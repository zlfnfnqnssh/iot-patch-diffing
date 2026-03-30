# Patch-Learner 파이프라인 아키텍처 확정안

> 2026-03-25 팀 논의 결과 확정. 이후 개발 통합 시 이 문서를 기준으로 한다.

---

## 팀 논의 Q&A (2026-03-25)

### Q0. 펌웨어 해시 파일 디핑
> 두 펌웨어 버전의 파일을 해시로 비교해서 바뀐 파일을 찾는다.

**결론:** Stage 0에서 수행. SHA256 해시 비교 → changed_files 테이블.

---

### Q1. 바뀐 함수 30개, 전부 전/후 디컴파일해서 DB에 넣는다?
> aa1.1 vs aa1.2에서 30개 바뀜. 30개 다 old/new 디컴파일해서 DB에 저장?

**결론: 전부 넣는다.**

- 디컴파일 코드는 텍스트라 용량 부담 없음 (함수당 2~5KB, 30개면 150KB)
- 비보안 변경도 나중에 비교 기준이 됨 (v1.0.7에서 또 바뀌면 v1.0.6 코드가 필요)
- 논문에 "103개 중 16개가 보안 패치" 같은 정량 데이터 뽑으려면 분모(전체)가 DB에 있어야 함
- LLM 판단이 틀릴 수 있음 → 재분석 시 IDA를 다시 안 돌려도 됨

---

### Q2. 보안패치 분류를 따로 하나? 아니면 바로 분석 모델로?
> MCP가 DB에서 60개 함수를 가져옴 → LLM이 보안패치인지 분류 → 2개 나옴.
> 그 2개도 DB에 저장? 아니면 분류 모델을 스킵하고 바로 분석 모델로 넘어가서 60개 전부 검사 후 DB 저장?
> 토스 보고서 참고 중, 우리가 골라서 써먹을 게 있는지 고민 중.

**결론: 분류 단계 스킵, 60개 전부 분석 후 전부 DB 저장.**

- 토스가 2단계(Discovery→Analysis)를 쓰는 이유: 소스코드에서 source→sink 경로가 수백 개 나와서 필터링이 필요
- 우리 상황: BinDiff가 이미 "바뀐 함수"만 뽑아줌 → 이게 Discovery 역할
- 30~200개는 LLM이 전수 분석 가능한 규모 → 여기서 또 필터링하면 미탐 위험만 늘어남
- 분류와 분석을 한 프롬프트에서 동시에 처리 (출력에 `is_security_patch: true/false` 포함)
- `is_security_patch=0`인 결과도 DB에 저장 (논문 precision/recall 계산에 TN 필요)

**토스에서 가져올 것:**
1. 출력 포맷 강제 (Pydantic / tool_use) → LLM 응답 파싱 깨짐 방지
2. "과탐 > 미탐" 원칙 → 애매하면 보안패치로 판정
3. MCP 기반 코드 탐색 → 토스의 소스코드 MCP = 우리의 IDA MCP

---

### Q3. 보안패치를 또 정제해서 DB에 저장하는 단계가 필요한가?
> 보안 패치된 것들을 찾아서 LLM agent에게 분석을 또 해서 탐지엔진이 잘 써먹을 수 있게 정제.
> 토스 보고서 참고 중, 이게 필요한지 고민 중.

**결론: 별도 정제 단계 불필요.**

- Stage 2의 분석 프롬프트에서 분류 + 분석 + 헌팅 정보를 한 번에 추출
- `security_patches` 테이블 필드가 이미 헌팅용 데이터를 포함:
  - `source_desc` (오염 데이터 진입점)
  - `sink_desc` (위험 함수/동작)
  - `missing_check` (빠진 검증)
  - `hunt_strategy` (헌팅 방법)
- 정제 단계를 따로 만들면: 프롬프트 2개로 나뉘어 유지보수 부담, LLM이 원본 코드 없이 요약만 보고 정제 → 정보 손실
- 나중에 정제가 필요하면 프롬프트 개선으로 해결하는 거지 파이프라인 단계 추가가 아님

---

### Q4. DB에 있는 패턴을 타깃 펌웨어에 전부 돌리는 게 맞는가?
> 검사하고 싶은 펌웨어를 rootfs로 정제하고, DB에 모인 데이터를 기반으로 제로데이 찾기.
> 해당 펌웨어 버전에 다 돌리기하는 게 맞을까?

**결론: DB에 있는 패턴 전부 돌린다. 단, 3-Phase로.**

- Phase 1 (자동, 빠름): DB의 sink 함수(system, popen, sprintf) xref 전수 검색
- Phase 2 (LLM, 느림): Phase 1 후보만 디컴파일 → DB 패턴과 비교
- Phase 3 (사람, 정확): confidence 높은 candidate부터 IDA로 직접 확인

**규모 계산:**
- 예상 보안패턴 50개 x 바이너리 10개 = 500번 검색
- xrefs_to 호출은 초 단위 → 충분히 가능

---

### 추가 논의: severity/confidence 산정 방식

**결론: LLM 직접 판단. 임의 가중치 공식 사용 금지.**

- `confidence = 0.2*A + 0.3*B + ...` 같은 공식은 근거가 없어서 논문에서 신뢰 안 감
- severity, confidence 모두 LLM이 코드 컨텍스트를 보고 직접 출력
- 논문 평가 지표는 confidence 정확도가 아닌 **파이프라인 전체의 precision/recall**
- ground truth: Synology SA advisory의 CVE 목록과 우리 탐지 결과 대조

---

### 추가 논의: "출력 포맷 강제"란?

LLM한테 "분석해줘"라고 하면 응답 형식이 매번 다름 → DB INSERT 시 파싱 깨짐.

**해결:**
- Claude API 직접 호출 시: `tool_use` (function calling)로 JSON 스키마 강제
- Claude Code가 직접 분석 시: 프롬프트에서 JSON 출력 지정 + Pydantic 검증

사람한테 보고서 주는 게 아니라, **LLM 응답 → DB INSERT 사이의 파싱 안정성** 확보 기법.

---

## 전체 구조 (4 Stage)

```
펌웨어 A (old) ─┐
                ├─ Stage 0: 펌웨어 추출 + 해시 디핑
펌웨어 B (new) ─┘
                    ↓ changed_files
                Stage 1: BinDiff + 전체 디컴파일 → DB
                    ↓ changed_functions (전수 저장)
                Stage 2: LLM 1-pass 전수 분석
                    ↓ security_patches (전수 저장, is_security_patch 0/1)
                Stage 3: 0-day 헌팅 (DB 패턴 전수 적용)
                    ↓ hunt_findings (candidate → verified → exploitable)
```

---

## Stage 0: 펌웨어 추출 + 해시 디핑

**입력**: 펌웨어 이미지 2개 (old, new)
**출력**: `changed_files` 테이블

- 펌웨어 추출 (WSL binwalk 또는 직접 파싱)
- SHA256 해시 비교로 변경/추가/삭제 파일 분류
- ELF 바이너리 vs 텍스트 파일 분리
- 노이즈 필터링 (zoneinfo 등)

---

## Stage 1: BinDiff + 전체 디컴파일 → DB

**입력**: 변경된 ELF 바이너리 페어
**출력**: `changed_functions` 테이블 (old/new pseudocode 포함)

### IDA 방식: 1회 실행 통합 추출

```
IDA 실행 (바이너리당 1회)
  → 전체 함수 pseudocode 추출 (JSON 캐시)
  + BinExport 동시 생성
      ↓
BinDiff로 변경 함수 매칭
      ↓
이미 추출된 pseudocode에서 해당 함수 꺼내기
      ↓
old/new pseudocode 쌍을 DB에 저장
```

### 왜 전수 디컴파일인가?

바뀐 함수가 30개면 30개 **전부** old/new 디컴파일 후 DB 저장.

- 디컴파일 코드는 텍스트라 용량 부담 없음 (함수당 2~5KB)
- 비보안 변경도 나중에 가치 있음 (다음 버전 비교 기준)
- 논문에 "103개 변경 함수 중 16개가 보안 패치" 같은 정량 데이터 필요 → 분모(전체)가 DB에 있어야 함
- LLM 판단이 틀릴 수 있음 → 재분석 시 IDA를 다시 안 돌려도 됨

### 팀 방식과의 차이 (참고)

| 항목 | 팀 (2-pass) | 확정안 (1-pass) |
|------|-------------|-----------------|
| 순서 | BinDiff 먼저 → 변경 주소만 IDA 디컴파일 | IDA 먼저 (전체) → BinDiff → 캐시에서 꺼냄 |
| IDA 실행 | 바이너리당 2회 (old + new, 타겟 주소만) | 바이너리당 2회 (old + new, 전체 함수) |
| 재분석 시 | 범위 바꾸면 IDA 재실행 필요 | 캐시에서 바로 처리 |
| 데이터 | 변경 함수만 보유 | 전체 함수 보유 (추가 분석 자유) |

---

## Stage 2: LLM 1-pass 전수 분석

**입력**: `changed_functions` 테이블의 old/new pseudocode 쌍
**출력**: `security_patches` 테이블 (전수 저장)

### 핵심 결정: 분류 단계 스킵

```
(X) 2단계: 분류기(60개→2개 필터링) → 심층분석기(2개만 분석)
(O) 1단계: 심층분석기(60개 전부 분석, 출력에 is_security_patch 포함)
```

**스킵 이유:**
- BinDiff가 이미 "바뀐 함수"만 뽑아줌 → 이게 토스의 Discovery 역할
- 우리 규모: 버전 페어당 30~200개 함수 → LLM 전수 분석 가능
- 분류기를 따로 만들면 오탐/미탐이 2번 발생 (분류기가 놓치면 기회 자체가 없음)
- API 비용: 60개 함수 분석해도 $2~5 수준, 2단계로 나눠도 절약 미미

### 토스와의 비교

| 항목 | 토스 | 우리 |
|------|------|------|
| 입력 | 소스코드 (Java Spring) | 바이너리 (ARM ELF, 디컴파일 pseudocode) |
| 경로 수집 | Semgrep SAST → source-sink 경로 286개 | BinDiff → 변경 함수 60~100개 |
| 필터링 필요성 | 있음 (286개 중 50% 노이즈) | 없음 (BinDiff가 이미 필터링) |
| 분석 | Analysis 에이전트 (MCP로 코드 탐색) | LLM 1-pass (old/new 디컴파일 비교) |

### 토스에서 가져올 것

1. **출력 포맷 강제**: Claude API `tool_use` 또는 프롬프트 기반 JSON 구조화 출력 → 파싱 깨짐 방지
2. **"과탐 > 미탐" 원칙**: 애매하면 is_security_patch=1 판정. 나중에 헌팅에서 false positive는 걸러지지만 false negative는 복구 불가
3. **MCP 기반 코드 탐색**: 토스의 소스코드 MCP = 우리의 IDA MCP. 논문에서 "토스의 소스코드 MCP 접근법을 바이너리 분석에 적용"으로 작성 가능

### 심각도/신뢰도: LLM 직접 판단

```
severity   → LLM이 코드를 보고 직접 판단 (CRITICAL / HIGH / MEDIUM / LOW)
confidence → LLM이 자기 판단의 확신도를 직접 출력 (0.0 ~ 1.0)
```

**임의 가중치 공식 사용 금지.** 이유: 근거 없는 수치(0.2, 0.3 등)는 논문에서 신뢰를 얻을 수 없다.

논문 평가 지표는 LLM confidence 정확도가 아닌 **파이프라인 전체의 precision/recall**:
- Synology SA advisory에 명시된 CVE와 우리 탐지 결과를 대조 → ground truth
- precision: LLM이 보안패치라고 한 것 중 실제 보안패치 비율
- recall: 실제 보안패치 중 LLM이 잡아낸 비율

### DB 저장: 전수 저장

60개 함수 전부 분석하고 60개 결과 **전부 DB에 저장**. `is_security_patch=0`인 것도 저장.

- "보안패치 아님"이라는 판단 자체가 데이터
- 프롬프트 개선 후 재분석 시 이전 결과와 비교 가능
- 논문에서 precision/recall 계산하려면 TN(True Negative)도 필요

### security_patches 테이블 주요 필드

```
is_security_patch   BOOLEAN    -- 분류 역할
confidence          REAL       -- 판단 확신도 (LLM 직접 출력)
severity            TEXT       -- CRITICAL/HIGH/MEDIUM/LOW (LLM 직접 판단)
vuln_type           TEXT       -- 취약점 유형
cwe                 TEXT       -- CWE 번호
root_cause          TEXT       -- 무엇이 취약했는지
fix_description     TEXT       -- 어떻게 고쳤는지
source_desc         TEXT       -- 오염 데이터 진입점 (헌팅용)
sink_desc           TEXT       -- 위험 함수/동작 (헌팅용)
missing_check       TEXT       -- 빠진 검증 (헌팅용)
hunt_strategy       TEXT       -- 헌팅 방법 (헌팅용)
```

분류, 분석, 헌팅 정보를 **한 프롬프트에서 한 번에** 추출. 별도 정제 단계 불필요.

---

## Stage 3: 0-day 헌팅

**입력**: `security_patches` 테이블 (is_security_patch=1) + 타깃 펌웨어
**출력**: `hunt_findings` 테이블

DB에 축적된 **모든 보안 패턴**을 타깃 펌웨어에 전수 적용.

### 3-Phase 헌팅

```
Phase 1: 패턴 매칭 (자동, 빠름)
  - DB의 각 security_patch에서 sink 함수 추출 (system, popen, sprintf 등)
  - 타깃 펌웨어에서 해당 함수의 xref 전수 검색
  - 결과: "이 바이너리의 이 함수에서 system() 호출" 목록

Phase 2: 컨텍스트 분석 (LLM, 느림)
  - Phase 1에서 나온 후보만 디컴파일
  - DB의 패치 패턴과 비교: "이것도 같은 취약점 패턴인가?"
  - hunt_findings 테이블에 저장 (status: candidate)

Phase 3: 수동 검증 (사람, 정확)
  - candidate 중 confidence 높은 것부터 IDA로 직접 확인
  - status: verified / false_positive / exploitable
```

### 규모 예상

- 현재 DB: 38개 패턴 카드 (Ubiquiti 34 + Synology 4)
- 추가 분석 후 예상: 50~80개 보안패치
- huntable=1 필터 후: 20~50개
- 패턴 50개 x 바이너리 10개 = 500번 검색 → xrefs_to 초 단위, 충분히 가능

---

## 데이터 저장 방식

| 데이터 | 저장 방식 | 이유 |
|--------|-----------|------|
| 함수 pseudocode (전체) | JSON 파일 (캐시) | 크기 크고 에이전트가 직접 Read |
| function diffs (.c.diff) | 파일 | 그대로 유지 |
| changed_functions | SQLite DB | 조건부 처리 (WHERE binary_name = 'webd') |
| security_patches | SQLite DB | 쿼리/누적/비교 필요 |
| hunt_findings | SQLite DB | 0-day 관리, 팀 공유 |

**파이프라인 중간 데이터**는 JSON (에이전트 Read 가능, 캐시 역할).
**최종 분석 결과**는 SQLite DB (쿼리, 누적, 팀 협업).

---

## 스킵 가능한 것 / 스킵하면 안 되는 것

### 스킵 가능
- Discovery 분류 모델 (BinDiff가 대체)
- 별도 정제 단계 (한 프롬프트에서 동시 추출)
- 임의 가중치 기반 심각도 공식

### 스킵 불가
- 비보안 함수도 DB 저장 (분모 데이터, 재분석용)
- is_security_patch=0 결과도 DB 저장 (TN 데이터)
- 헌팅 시 전수 검색 (DB에 있는 패턴 전부 적용)

---

## 참고 자료

- 토스 취약점 분석 자동화: [1편](https://toss.tech/article/vulnerability-analysis-automation-1), [2편](https://toss.tech/article/vulnerability-analysis-automation-2)
- 토스 핵심 아이디어: SAST(Semgrep) + Multi-Agent + Pydantic 검증 + 오픈모델(Qwen)
- 우리와 차이: 토스는 소스코드 기반, 우리는 바이너리 디컴파일 기반