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
| 메인 파이프라인 | `Patch-Learner-main/src/analyzers/bindiff_pipeline.py` |
| IDAPython | `Patch-Learner-main/ida_user/extract_with_decompile.py` |
| DB | `Patch-Learner-main/src/db/patch_learner.db` |
| IDA Pro | `C:\Program Files\IDA Professional 9.0\idat64.exe` |
| BinDiff | `C:\Program Files\BinDiff\bin\bindiff.exe` |

## 현재 작업 상태

### Ubiquiti UniFi Camera (ARM, v4.30.0 vs v4.51.4)
- Stage 0~2 완료, 38개 패턴 카드 (DB 저장)

### Synology BC500

| 비교 | 상태 | 결과 |
|------|------|------|
| v1.0.4→v1.0.5 | ✅ 완료 | 4 패턴 카드 (CRITICAL 포함) |
| v1.0.5→v1.0.6 | ✅ 완료 | 16 보안 패치 (CRITICAL 2, HIGH 7, MEDIUM 5, LOW 2) |

### TP-Link Tapo C200v1 (MIPS, 진행 예정)
- 펌웨어: 1.0.2 ~ 1.3.6 (20개 버전, 전부 암호화 없음, binwalk 직접 추출)
- 다음 디핑: 1.0.2 → 1.0.3 → ... 순차 진행

## 다음에 할 일
- TP-Link Tapo C200v1 순차 디핑 (1.0.2→1.0.3부터)
- Detection Rules 자동 생성 (패턴 카드 기반)
- hunt_findings 테이블 활용한 0-day 후보 관리
- sub_6CEE0 패턴 기반 변종 헌팅

## 자동 문서화 규칙
코드 수정, 기능 추가, 에러 해결, 설계 변경, 분석 결과 발견 시:
1. `docs/dev-notes.md`에 `### YYYY-MM-DD | 제목` 형식으로 기록
2. GitHub push: `cd iot-patch-diffing && git add -A && git commit -m "설명" && git push origin main`

## 관련 문서
- [프로젝트 개요](docs/project-overview.md) — 기획 동기, 목표, 검증 대상
- [파이프라인 설계](docs/pipeline.md) — Stage 0~3 아키텍처
- [개발 일지](docs/dev-notes.md) — 날짜별 트러블슈팅, 분석 결과
- [아키텍처 결정](docs/architecture-decisions.md) — 팀 논의 확정안
