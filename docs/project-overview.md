# 프로젝트 개요 및 목표

## 프로젝트명
**Patch-Learner: 펌웨어 패치 디핑을 통한 취약점 분석 자동화**

## 기획 동기 및 필요성

IoT 기기의 보급이 급격히 증가하면서 IP 카메라, NAS, 공유기 등의 임베디드 장비가 가정과 기업 네트워크에 널리 배치되고 있다.
이들 장비는 취약점이 발견될 때마다 펌웨어 업데이트를 배포하지만, 제조사가 공개하는 정보는 대개 "보안 취약점 수정" 수준에 머문다.

이 환경에서는 다음 문제가 반복된다.

- **패치 갭(Patch Gap) 악용**: 공격자는 패치 전후 펌웨어를 비교해 수정 지점을 역분석하고, 업데이트하지 않은 기기를 노린다.
- **수동 분석 한계**: 펌웨어 하나에도 수천 개 바이너리와 수만 개 함수가 포함될 수 있어, 사람이 직접 전수 비교하기 어렵다.
- **1-day 분석 수요**: CVE만 공개되고 세부 분석이 없는 경우, 패치 디핑이 가장 빠른 확인 수단이지만 자동화 도구가 부족하다.

## 목표

펌웨어의 이전 버전과 패치 버전을 입력으로 받아, **변경된 파일과 함수를 자동 추출하고 디컴파일 기반 차이점을 정리**하는 통합 파이프라인을 구축한다.
최종적으로는 누적된 보안 패치 패턴을 바탕으로 **다른 펌웨어에서 유사 취약점(0-day 후보)을 탐지**하는 단계까지 확장하는 것이 목표다.

## 검증 대상 펌웨어

| 제조사 | 제품 | 비교 범위 | 아키텍처 | 현재 상태 |
|--------|------|-----------|----------|-----------|
| Ubiquiti | UniFi Camera S2L | v4.30.0 vs v4.51.4 | ARM | Stage 0~2 완료 |
| Synology | BC500 IP Camera | v1.0.4 vs v1.0.5 | ARM | Stage 0~2 완료 |
| Synology | BC500 IP Camera | v1.0.5 vs v1.0.6 | ARM | Stage 0~2 완료 |
| TP-Link | Tapo C200 v1 | 연속 버전 19쌍 | MIPS | Stage 0~1 완료 |
| TP-Link | Tapo C200 v2 | 연속 버전 비교 | MIPS | Stage 0~1 완료 |
| TP-Link | Tapo C200 v3 | 1.3.5 vs 1.3.7 등 | MIPS | 복호화 경로 구현, 재실행 진행 |
| TP-Link | Tapo C200 v4 | 1.1.23 vs 1.3.7 등 | MIPS | 복호화 경로 구현, 재실행 진행 |

## 파이프라인 아키텍처

> 상세 설계는 [architecture-decisions.md](architecture-decisions.md), 구현 흐름은 [pipeline.md](pipeline.md) 참고

```
Stage 0: 펌웨어 추출 + 해시 디핑         → changed_files
Stage 1: BinDiff + 전체 디컴파일 → DB    → changed_functions
Stage 2: LLM 1-pass 전수 분석           → security_patches
Stage 3: 0-day 헌팅                     → hunt_findings
```

핵심 원칙은 다음과 같다.

- Discovery 분류 단계를 별도로 두지 않고, BinDiff가 뽑은 변경 함수 전체를 대상으로 분석한다.
- severity와 confidence는 임의 가중치 공식을 쓰지 않고 LLM이 코드 문맥을 보고 직접 판단한다.
- 비보안 변경과 `is_security_patch=0` 결과도 DB에 남겨, 재분석과 평가 지표 계산에 활용한다.
- 여러 벤더의 Stage 0~1 산출물을 먼저 축적한 뒤 Stage 2를 일괄 수행하는 순서로 운영한다.

## 현재 진행 상황 (2026-04-02)

### 완료된 축

- Ubiquiti UniFi Camera S2L과 Synology BC500 두 구간은 Stage 2까지 수행해 DB에 결과를 적재했다.
- TP-Link Tapo C200 v1, v2는 `sequential_diff.py`로 연속 버전 비교를 자동화했고, Stage 0~1 산출물을 확보했다.

### 이번 주에 보강된 축

- `sequential_diff.py`가 상위 펌웨어 폴더를 재귀 탐색해 모델별로 자동 실행하도록 정리됐다.
- `bindiff_pipeline.py`는 `binwalk` 실행 전에 `wsl --shutdown`을 호출해 WSL 충돌을 줄이도록 보강됐다.
- Tapo C200 v3, v4처럼 `signed/encrypted` 헤더가 붙은 펌웨어는 `tp-link-decrypt`를 거친 뒤 `binwalk`를 태우는 경로가 추가됐다.
- ipTIME 펌웨어 수집 자동화를 위해 `download_iptime_firmware.py`가 추가됐다.

## 주요 분석 결과

### Ubiquiti UniFi Camera (v4.30.0 vs v4.51.4)

- 분석 대상: `ubnt_cgi`, `ubnt_ctlserver`, `ubnt_networkd`
- 패턴 카드: 34개
- CVE 매칭: 15건
- 주요 발견: Command Injection, Authentication Bypass, Hardcoded Crypto Key

### Synology BC500 (v1.0.4 vs v1.0.5 / v1.0.5 vs v1.0.6)

- Format String, Memory Leak, Command Injection 계열 패치를 확인했다.
- `system()/popen()` 호출이 안전한 `execve` 래퍼 호출로 치환된 패턴을 반복적으로 확인했다.
- 두 개 버전 페어 모두 Stage 2 결과를 DB에 적재했다.

### TP-Link Tapo C200

- v1, v2는 일반 추출 경로로 연속 버전 비교 자동화를 마쳤다.
- v3, v4는 기존 경로로는 추출되지 않아 복호화 선행 경로를 추가했고, 이를 기준으로 동일 Stage 0~1 체계에 편입했다.
- 출력 경로는 `output/<모델>/v<old>_vs_v<new>/` 형태로 통일했다.

## 4월 기준 우선 과제

- Tapo C200 v3, v4 구간을 공식 출력 경로에 다시 실행해 Stage 0~1 산출물을 확정한다.
- Synology, Tapo, 이후 수집할 ipTIME/Ubiquiti 대상까지 포함해 Stage 0~1 코퍼스를 넓힌다.
- 누적된 변경 함수 집합을 기준으로 Stage 2 LLM 분석을 일괄 수행한다.

## 참고 자료

- 토스 취약점 분석 자동화: [1편](https://toss.tech/article/vulnerability-analysis-automation-1), [2편](https://toss.tech/article/vulnerability-analysis-automation-2)
- Synology 보안 공지: `SA_23_11`, `SA_23_15`, `SA_24_07`, `SA_24_17`, `SA_24_24`
- TP-Link Tapo 비공식 아카이브: `tapo-firmware/Tapo_C200`

## 기대 효과

- 수작업으로 며칠 걸리던 펌웨어 패치 분석을 자동화된 반복 작업으로 전환한다.
- C 의사코드 diff와 DB 축적을 함께 제공해, 후속 분석과 근거 정리를 동시에 가능하게 한다.
- 여러 벤더와 아키텍처를 넘나드는 보안 패치 패턴을 누적해 0-day 헌팅 단계로 확장할 수 있다.
