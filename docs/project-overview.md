# 프로젝트 개요 및 목표

## 프로젝트명
**Patch-Learner: 펌웨어 패치 디핑을 통한 취약점 분석 자동화**

## 기획 동기 및 필요성

IoT 기기의 보급이 급격히 증가하면서 IP 카메라, NAS, 공유기 등의 임베디드 장비가 가정과 기업 네트워크에 널리 배치되고 있다.
최근 국내외에서 IP 카메라 대규모 해킹 사건이 반복적으로 발생하고 있으며, 북한 등 국가 배후 해킹 그룹이 IoT 기기를 침투 경로로 활용하는 사례도 보고되고 있다.

이러한 기기들은 보안 취약점이 발견될 때마다 펌웨어 업데이트를 통해 패치를 배포하지만, 대부분의 제조사는 패치 내용을 구체적으로 공개하지 않는다.
"보안 취약점 수정" 정도의 모호한 릴리스 노트만 제공하는 것이 일반적이다.

이로 인해 다음과 같은 문제가 발생한다.

- **패치 갭(Patch Gap) 악용**: 패치 배포 후에도 업데이트를 적용하지 않은 기기가 다수 존재한다. 공격자는 패치 전후 펌웨어를 비교(패치 디핑)하여 취약점을 역으로 파악하고, 미패치 기기를 공격할 수 있다.
- **보안 연구 비효율**: 보안 연구자가 수동으로 수천 개 바이너리, 수만 개 함수를 일일이 비교하는 것은 현실적으로 불가능하다.
- **1-day 취약점 분석 수요**: CVE가 공개되었으나 상세 분석이 없는 1-day 취약점에 대해 패치 디핑은 가장 효과적인 분석 기법이지만, 이를 체계적으로 수행하는 자동화 도구가 부족하다.

## 목표

펌웨어의 이전 버전과 패치 버전을 입력으로 받아, **변경된 함수를 자동 추출하고 디컴파일 기반의 차이점 분석 결과를 제공**하는 통합 파이프라인(Patch-Learner)을 설계 및 구현한다.

최종 목표는 축적된 보안 패치 패턴을 기반으로 다른 펌웨어에서 **유사 취약점(0-day)을 자동 탐지**하는 것이다.

## 검증 대상 펌웨어

| 제조사 | 제품 | 비교 버전 | 아키텍처 | 상태 |
|--------|------|-----------|----------|------|
| Ubiquiti | UniFi Camera S2L | v4.30.0 vs v4.51.4 | ARM | 완료 (34 패턴 카드) |
| Synology | BC500 IP Camera | v1.0.4 vs v1.0.5 | ARM | 완료 (4 패턴 카드) |
| Synology | BC500 IP Camera | v1.0.5 vs v1.0.6 | ARM | 완료 (16 보안 패치) |

## 파이프라인 아키텍처 (확정)

> 상세: [architecture-decisions.md](architecture-decisions.md), [pipeline.md](pipeline.md)

```
Stage 0: 펌웨어 추출 + 해시 디핑         → changed_files
Stage 1: BinDiff + 전체 디컴파일 → DB    → changed_functions (전수)
Stage 2: LLM 1-pass 전수 분석           → security_patches (전수)
Stage 3: 0-day 헌팅                     → hunt_findings
```

**핵심 설계 결정:**
- Discovery 분류 단계 스킵 (BinDiff가 대체, 우리 규모에서 불필요)
- severity/confidence는 LLM 직접 판단 (임의 가중치 공식 금지)
- 비보안 함수 포함 전수 DB 저장 (논문 평가용 분모 데이터)
- 과탐 > 미탐 원칙

## 현재 진행 상황 (2026-03-25)

| Stage | 내용 | Ubiquiti S2L | Synology v1.0.4-v1.0.5 | Synology v1.0.5-v1.0.6 |
|-------|------|:------------:|:-----------------------:|:-----------------------:|
| Stage 0 | 추출 + 해시 디핑 | 완료 | 완료 | 완료 |
| Stage 1 | BinDiff + 디컴파일 | 완료 | 완료 | 완료 |
| Stage 2 | LLM 전수 분석 | 완료 (34카드) | 완료 (4카드) | 완료 (16패치) |
| Stage 3 | 0-day 헌팅 | 미착수 | 미착수 | 미착수 |

**DB 현황:** 총 38개 패턴 카드 (Ubiquiti 34 + Synology 4) + 16개 보안 패치 (BC500 v1.0.5→v1.0.6)

## 주요 분석 결과

### Ubiquiti UniFi Camera (v4.30.0 vs v4.51.4)
- 분석 대상: ubnt_cgi, ubnt_ctlserver, ubnt_networkd
- 패턴 카드: 34개 (CRITICAL:1, HIGH:13, MEDIUM:17, LOW:3)
- CVE 매칭: 15건 (44%) -- CVE-2021-22909, CVE-2020-8515, CVE-2022-23134 등
- 주요 발견: Command Injection(5), Authentication Bypass(2), Hardcoded Crypto Key(1)

### Synology BC500 (v1.0.4 vs v1.0.5)
- CRITICAL: Format String (CWE-134) -- synocam_param.cgi `printf(user_input)`
- MEDIUM: Memory Leak (CWE-401) x2 -- webd, synocam_param.cgi

### Synology BC500 (v1.0.5 vs v1.0.6)
- 분석 대상: central_server, synocam_param.cgi, nvtd (26,545 함수)
- 보안 패치: 16개 (CRITICAL:2, HIGH:7, MEDIUM:5, LOW:2)
- 핵심 발견: system()/popen() → sub_6CEE0(execve 래퍼) 전사 마이그레이션
- CRITICAL: /etc/passwd 외부파라미터 삽입, chpasswd 명령 인젝션
- HIGH: SynoPopen→execve 교체, rm/cp/openssl 경로 인젝션, Format String

## 추진 일정

| 월 | 내용 |
|----|------|
| 3월 | 파이프라인 설계 및 분석 환경 구축, 대상 펌웨어 수집, 아키텍처 확정 |
| 4월 | 팀 코드 통합, Stage 2 전수 분석 구현, 크로스 디바이스 검증 |
| 5월 | Stage 3 0-day 헌팅 구현, 다른 펌웨어 대상 검증 |
| 6월 | 최종 결과 정리, precision/recall 평가, 문서화 및 발표 준비 |

## 참고 자료

- 토스 취약점 분석 자동화: [1편](https://toss.tech/article/vulnerability-analysis-automation-1), [2편](https://toss.tech/article/vulnerability-analysis-automation-2)
- 토스 핵심: SAST + Multi-Agent + Pydantic / 우리: BinDiff + LLM 1-pass + Pydantic

## 연계 방안

### 산업 연계
- 보안 컨설팅 업체 / KISA 등 침해사고 분석 기관에서 활용 가능한 도구
- IoT 제조사 보안 대응팀(PSIRT)의 패치 완전성 검증에 활용

### 전공 융합
- **정보보안 + 소프트웨어공학**: 리버스 엔지니어링 + 자동화 파이프라인 설계
- **임베디드 시스템 + 보안**: ARM 펌웨어 분석 + 보안 취약점 탐지

## 기대 효과

- 수동으로 수일 소요되던 펌웨어 패치 분석을 자동화
- C 의사코드 diff 제공으로 역공학 전문가가 아니어도 패치 내용 이해 가능
- CVE 공개 후 어떤 함수가 어떻게 수정되었는지 빠른 확인
- SQLite DB에 보안 패치 축적 → 크로스 디바이스 0-day 헌팅으로 확장
