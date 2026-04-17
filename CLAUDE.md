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
| 메인 파이프라인 | `src/analyzers/bindiff_pipeline.py` |
| 순차 디핑 | `src/analyzers/sequential_diff.py` |
| IDAPython | `ida_user/extract_with_decompile.py` |
| DB 모듈 | `src/db/pipeline_db.py` |
| DB 파일 | `Patch-Learner-main/src/db/patch_learner.db` |
| 일괄 Import | `src/tools/import_existing_output.py` |
| IDA Pro | `C:\Program Files\IDA Professional 9.0\idat64.exe` |
| BinDiff | `C:\Program Files\BinDiff\bin\bindiff.exe` |

## 코드 구조

```
src/
  analyzers/
    bindiff_pipeline.py       # Stage 0~1 메인 파이프라인 (DB 자동 저장)
    sequential_diff.py        # 연속 버전 쌍 자동 실행 (vendor/model 자동 감지)
    generate_pattern_cards.py # Stage 2 패턴 카드 생성
    download_iptime_firmware.py
    run_step5_to_7.py         # 레거시
  db/
    pipeline_db.py            # PipelineDB 클래스 (세션/파일/함수 저장)
    init_db.py                # 스키마 초기화
    schema.sql                # 8개 테이블 DDL
  tools/
    import_existing_output.py # 기존 output -> DB 일괄 import
Patch-Learner-main/
  src/analyzers/              # 참조용 (DB 통합 원본)
  src/db/patch_learner.db     # 유일 DB 파일 (모든 데이터 여기)
```

## DB 파이프라인 흐름

```
firmware_versions → diff_sessions → changed_files → bindiff_results
    → changed_functions → security_patches → hunt_findings
                                          → pattern_cards
```

`bindiff_pipeline.py`에 `--vendor`, `--model`, `--old-ver`, `--new-ver` 전달 시 자동 저장.
`sequential_diff.py`는 firmware 경로에서 vendor/model을 자동 감지해서 전달.

## 현재 DB 현황 (2026-04-02)

| 테이블 | 건수 |
|--------|------|
| firmware_versions | 43 |
| diff_sessions | 39 |
| changed_files | 1,772 |
| bindiff_results | 805 |
| changed_functions | 12,055 |
| security_patches | 0 (Stage 2 미실행) |
| pattern_cards | 0 (이 DB에는 미적재) |

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

## 다음에 할 일
- TP-Link Tapo C200 Stage 2 LLM 분석 (12,055개 변경 함수 → security_patches)
- Detection Rules 자동 생성 (패턴 카드 기반)
- hunt_findings 테이블 활용한 0-day 후보 관리
- sub_6CEE0 패턴 기반 변종 헌팅
- ipTIME 펌웨어 수집 + Stage 0~1 코퍼스 확대

## 자동 문서화 규칙
코드 수정, 기능 추가, 에러 해결, 설계 변경, 분석 결과 발견 시:
1. `docs/dev-notes.md`에 `### YYYY-MM-DD | 제목` 형식으로 기록
2. GitHub push: `cd iot-patch-diffing && git add -A && git commit -m "설명" && git push origin main`

## 관련 문서
- [프로젝트 개요](docs/project-overview.md) — 기획 동기, 목표, 검증 대상
- [파이프라인 설계](docs/pipeline.md) — Stage 0~3 아키텍처
- [개발 일지](docs/dev-notes.md) — 날짜별 트러블슈팅, 분석 결과
- [아키텍처 결정](docs/architecture-decisions.md) — 팀 논의 확정안
- [패턴카드 작성 스펙 v2](docs/pattern-card-spec.md) — Phase 4 Designer/팀원용 스키마·컬럼·체크리스트
- [Stage 2 스킬](.claude/skills/stage2/SKILL.md) — 5-Phase 오케스트레이션 (사전필터/Analyst/Reviewer/Dedupe/Designer/Hunter)
