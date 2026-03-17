# Patch-Learner — Claude 작업 가이드

## 프로젝트 한 줄 요약
IoT 펌웨어 두 버전을 비교해 변경된 함수를 자동 추출하고, C 의사코드(pseudocode) 수준에서 보안 취약점을 분석하는 파이프라인.

## 핵심 경로

| 항목 | 경로 |
|------|------|
| 메인 파이프라인 | `Patch-Learner-main/src/analyzers/bindiff_pipeline.py` |
| IDAPython 스크립트 | `Patch-Learner-main/ida_user/extract_with_decompile.py` |
| IDA Pro 실행 파일 | `C:\Program Files\IDA Professional 9.0\idat64.exe` |
| BinDiff 실행 파일 | `C:\Program Files\BinDiff\bin\bindiff.exe` |
| 분석 결과 | `Patch-Learner-main/firmware/ubiquiti_s2/diffs/UVC_vs_uvc/` |

## 현재 작업 상태

| 단계 | 내용 | 상태 |
|------|------|------|
| Step 0~3 | 펌웨어 추출 / 해시 비교 / 분류 / 텍스트 diff | ✅ 완료 |
| Step 4 | IDA 통합 추출 (디컴파일 + BinExport) | 🔄 145/250개 (중단됨) |
| Step 5~7 | BinDiff 매칭 / Pseudocode Diff / 리포트 | ✅ 완료 (이전 실행 결과 존재) |
| 다음 단계 | LLM 보안 분석 + 패턴 카드 작성 | ⏳ 대기 |

## 다음에 할 일
`security_candidates.json` (보안 우선순위 상위 50개 함수) 기반으로
before/after pseudocode → LLM 분석 → 패턴 카드 JSON 자동 생성

## 관련 문서
- [프로젝트 개요 및 목표](docs/project-overview.md)
- [파이프라인 개발 과정](docs/pipeline.md)
- [개발 특이사항 및 트러블슈팅](docs/dev-notes.md)
