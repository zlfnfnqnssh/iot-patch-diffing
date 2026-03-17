# Patch-Learner — Claude 작업 가이드

## 프로젝트 한 줄 요약
IoT 펌웨어 두 버전을 비교해 변경된 함수를 자동 추출하고, C 의사코드(pseudocode) 수준에서 보안 취약점을 분석하는 파이프라인.

## GitHub 저장소

| 구분 | URL | 용도 |
|------|-----|------|
| 개인 (기본) | https://github.com/zlfnfnqnssh/iot-patch-diffing | 개인 개발 기록, 문서, 코드 |
| 팀 | https://github.com/seosamuel02/Patch-Learner | 팀 협업, 로컬 경로: `c:/Users/deser/Desktop/project/Patch-Learner-collab`, 브랜치: `riri` |

**규칙:** 아무 말 없으면 개인 저장소에 push. "팀쪽으로" 또는 "team에" 언급 시 팀 저장소 `riri` 브랜치에 push.

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

## 자동 문서화 규칙

다음 상황이 발생하면 **반드시** `docs/dev-notes.md`에 날짜별 항목을 추가하고, 변경된 파일을 GitHub에 자동 push한다:

- 코드 수정 (버그 수정, 로직 변경, 성능 개선 등)
- 새 기능 추가 (새 스텝, 새 스크립트, 새 옵션 등)
- 에러 발생 및 해결 (원인, 해결책 포함)
- 파이프라인 설계 변경 (방식 전환, 구조 변경 등)
- 분석 결과 발견 (노이즈 유형, 새 패턴, 통계 등)

**dev-notes.md 작성 형식:**
```
### YYYY-MM-DD | 변경 내용 한 줄 제목

**진행 내용 / 문제 / 해결:**
- 구체적 내용

**코드 변경 (있을 경우):**
코드 스니펫
```

**GitHub push 방법:**
```bash
cd c:/Users/deser/Desktop/project/iot-patch-diffing
git add -A
git commit -m "설명"
git push origin main
```

## 관련 문서
- [프로젝트 개요 및 목표](docs/project-overview.md)
- [파이프라인 개발 과정](docs/pipeline.md)
- [개발 특이사항 및 트러블슈팅](docs/dev-notes.md)
