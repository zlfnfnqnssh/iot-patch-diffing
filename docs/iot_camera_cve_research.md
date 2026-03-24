# IoT 카메라 펌웨어 CVE 조사 보고서

> 마지막 업데이트: 2026-03-24
> 조사 대상: 10개 제조사 / 6개국
> **패치 디핑 가능 여부** 기준: 구버전 펌웨어를 공개 다운로드로 얻을 수 있는지

---

## 패치 디핑 적합도 요약 (한눈에 보기)

| 제조사 | 구버전 공개 여부 | 암호화 | 적합도 | 분석 상태 |
|--------|--------------|-------|--------|----------|
| Synology | **전 버전 아카이브 공개** | 없음 | **최상** | **진행 예정** (BC500 SA_23_11) |
| TP-Link Tapo | GitHub 아카이브 (비공식, 다수) | AES (복호화 도구 있음) | **상** | - |
| Reolink | GitHub 아카이브 (비공식, 190개 모델) | 없음 | **상** | - |
| Hikvision | EU 포털 (구버전 다수, 브라우저 접근) | XOR (복호화 도구 있음) | **상** | - |
| AXIS | 공식 지원 (다운로드 가능) | 부분 | **중** | - |
| D-Link | 공식 지원 (EOL 포함) | 없음~부분 | **중** | - |
| Dahua | dahuawiki.com (비공식 인덱스) | AES-256 (어려움) | **중-하** | - |
| Ubiquiti | 계정 필요 / 비공식 링크 모음 | 없음 | **중** | **분석 완료** (UniFi Camera S2L) |
| Hanwha | 공식 다운 (구버전 제한적) | 부분 | **하** | - |
| IDIS | 최신만 공개 | 미상 | **부적합** | - |

---

## 목차
1. [Synology Camera (대만)](#1-synology-camera-대만) — 최적
2. [TP-Link Tapo (중국)](#2-tp-link-tapo-중국)
3. [Reolink (중국)](#3-reolink-중국)
4. [Hikvision (중국)](#4-hikvision-중국)
5. [Ubiquiti UniFi Protect (미국)](#5-ubiquiti-unifi-protect-미국)
6. [Dahua (중국)](#6-dahua-중국)
7. [AXIS Communications (스웨덴)](#7-axis-communications-스웨덴)
8. [D-Link DCS 시리즈 (대만)](#8-d-link-dcs-시리즈-대만)
9. [Hanwha Wisenet (한국)](#9-hanwha-wisenet-한국)
10. [IDIS (한국)](#10-idis-한국)
11. [펌웨어 암호화 현황 비교](#11-펌웨어-암호화-현황-비교)

---

## 1. Synology Camera (대만) — **분석 진행 예정**

> **패치 디핑 최적 대상** — 전 버전 공개 아카이브 존재, 암호화 없음
> **다음 분석 대상:** BC500 1.0.4-0182 vs 1.0.5-0185 (SA_23_11 Format String → RCE)

### 제품 라인업
| 제품 | 형태 | 특징 |
|------|------|------|
| BC500 | 실외 총알형 | 5MP, IP67 |
| TC500 | 실외 터렛형 | 5MP, IP67 |
| CC400W | 실내 돔형 | 4MP, WiFi |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | **없음** |
| 파일 형식 | `.sa.bin` (SquashFS 내장) |
| binwalk 추출 | **바로 가능** (프로젝트에서 확인됨) |

### 전체 펌웨어 버전 목록 (실제 검증 완료 ✅)

**BC500** — 아카이브: https://archive.synology.com/download/Firmware/Camera/BC500

| 버전 | 다운로드 | CVE/SA 관련 |
|------|---------|-----------|
| 1.0.4-0182 | https://archive.synology.com/download/Firmware/Camera/BC500/1.0.4-0182 | SA_23_11 이전 (취약) — **분석 예정 (old)** |
| 1.0.5-0185 | https://archive.synology.com/download/Firmware/Camera/BC500/1.0.5-0185 | SA_23_11 **패치** — **분석 예정 (new)** |
| 1.0.6-0290 | https://archive.synology.com/download/Firmware/Camera/BC500/1.0.6-0290 | - |
| 1.0.6-0294 | https://archive.synology.com/download/Firmware/Camera/BC500/1.0.6-0294 | - |
| 1.0.7-0298 | https://archive.synology.com/download/Firmware/Camera/BC500/1.0.7-0298 | SA_23_15 **패치** (Pwn2Own 2023) |
| 1.1.0-0320 | https://archive.synology.com/download/Firmware/Camera/BC500/1.1.0-0320 | - |
| 1.1.1-0383 | https://archive.synology.com/download/Firmware/Camera/BC500/1.1.1-0383 | SA_24_07 **패치** |
| 1.1.2-0416 | https://archive.synology.com/download/Firmware/Camera/BC500/1.1.2-0416 | - |
| 1.1.3-0442 | https://archive.synology.com/download/Firmware/Camera/BC500/1.1.3-0442 | SA_24_17 이전 (취약) |
| 1.2.0-0525 | https://archive.synology.com/download/Firmware/Camera/BC500/1.2.0-0525 | SA_24_17, SA_24_24 **패치** |
| 1.2.1-0563 | https://archive.synology.com/download/Firmware/Camera/BC500/1.2.1-0563 | - |
| 1.2.2-0645 | https://archive.synology.com/download/Firmware/Camera/BC500/1.2.2-0645 | 최신 |

**TC500** — 아카이브: https://archive.synology.com/download/Firmware/Camera/TC500

| 버전 | 다운로드 | CVE/SA 관련 |
|------|---------|-----------|
| 1.0.2-0142 | https://archive.synology.com/download/Firmware/Camera/TC500/1.0.2-0142 | 최초 버전 (취약) |
| 1.0.4-0182 | https://archive.synology.com/download/Firmware/Camera/TC500/1.0.4-0182 | SA_23_11 이전 (취약) |
| 1.0.5-0185 | https://archive.synology.com/download/Firmware/Camera/TC500/1.0.5-0185 | SA_23_11 **패치** |
| 1.0.6-0290 | https://archive.synology.com/download/Firmware/Camera/TC500/1.0.6-0290 | - |
| 1.0.6-0294 | https://archive.synology.com/download/Firmware/Camera/TC500/1.0.6-0294 | - |
| 1.0.7-0298 | https://archive.synology.com/download/Firmware/Camera/TC500/1.0.7-0298 | SA_23_15 **패치** |
| 1.1.0-0320 | https://archive.synology.com/download/Firmware/Camera/TC500/1.1.0-0320 | - |
| 1.1.1-0383 | https://archive.synology.com/download/Firmware/Camera/TC500/1.1.1-0383 | SA_24_07 **패치** |
| 1.1.2-0416 | https://archive.synology.com/download/Firmware/Camera/TC500/1.1.2-0416 | - |
| 1.1.3-0442 | https://archive.synology.com/download/Firmware/Camera/TC500/1.1.3-0442 | - |
| 1.2.0-0525 | https://archive.synology.com/download/Firmware/Camera/TC500/1.2.0-0525 | SA_24_24 **패치** |
| 1.2.1-0563 | https://archive.synology.com/download/Firmware/Camera/TC500/1.2.1-0563 | - |
| 1.2.2-0645 | https://archive.synology.com/download/Firmware/Camera/TC500/1.2.2-0645 | 최신 |

**CC400W** — 아카이브: https://archive.synology.com/download/Firmware/Camera/CC400W

| 버전 | 다운로드 | CVE/SA 관련 |
|------|---------|-----------|
| 1.1.2-0418 | https://archive.synology.com/download/Firmware/Camera/CC400W/1.1.2-0418 | SA_24_17 이전 (취약) |
| 1.1.3-0442 | https://archive.synology.com/download/Firmware/Camera/CC400W/1.1.3-0442 | - |
| 1.2.0-0525 | https://archive.synology.com/download/Firmware/Camera/CC400W/1.2.0-0525 | SA_24_17, SA_24_24 **패치** |
| 1.2.1-0563 | https://archive.synology.com/download/Firmware/Camera/CC400W/1.2.1-0563 | - |
| 1.2.2-0645 | https://archive.synology.com/download/Firmware/Camera/CC400W/1.2.2-0645 | 최신 |

> 실제 파일 URL 패턴: `https://global.synologydownload.com/download/Firmware/{모델}/{버전}/Synology_{모델}_{버전}.sa.bin`
> 예: `https://global.synologydownload.com/download/Firmware/BC500/1.0.4-0182/Synology_BC500_1.0.4_0182.sa.bin` ✅ 접근 확인

### CVE 목록 및 발생 위치

| CVE / SA | CVSS | 취약 컴포넌트 | 유형 | 취약 버전 → 패치 버전 |
|----------|------|------------|------|-------------------|
| SA_23_11 / CVE-2023-5746 | Critical | **CGI 컴포넌트** (웹 CGI 핸들러) | Format String → RCE | BC500/TC500 1.0.4 → **1.0.5-0185** |
| SA_23_15 (Pwn2Own 2023) | Critical | 복합 (웹 + 인증) | RCE + 보안 우회 | 1.0.6-0294 → **1.0.7-0298** |
| SA_24_07 | Moderate | **로그인 컴포넌트** | Buffer Overflow → DoS | 1.1.0-0320 → **1.1.1-0383** |
| SA_24_17 | Critical | **CGI + 인증 모듈** | Format String + Auth Bypass + DoS | 1.1.3-0442 → **1.2.0-0525** |
| CVE-2024-11131 / SA_24_24 | Critical | 미상 (Pwn2Own 2024) | OOB Read → RCE | 1.1.3-0442 → **1.2.0-0525** |
| CVE-2024-10499 | Critical | **카메라 관리 서비스** | Command Injection → 비인증 RCE | 1.2.0-0525 이전 → **1.2.0-0525** |

> **추천 패치 디핑 쌍:**
> - `BC500 1.0.4-0182` vs `1.0.5-0185` (SA_23_11 Format String)
> - `BC500 1.1.3-0442` vs `1.2.0-0525` (SA_24_17 복합 패치)

---

## 2. TP-Link Tapo (중국)

### 제품 라인업
| 제품 | 형태 | 하드웨어 버전 |
|------|------|------------|
| C200 | 실내 팬틸트 | V1, V2, V3, V4 (각각 별도 펌웨어) |
| C210 | 실내 팬틸트 HD | V1, V2 |
| C220 | 실내 팬틸트 AI | V1 |
| C500 | 실외 고정형 | V1 |
| TC60 | 실내 | V1 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | **있음 (AES-128-CBC)** |
| 키 | RSA-PSS 서명의 랜덤 솔트 값 — **GPL 코드 공개로 복호화 가능** |
| 복호화 도구 | `tp-link-decrypt` (pip 설치 가능) |
| 복호화 후 | SquashFS — binwalk 추출 가능 |

### 펌웨어 아카이브 (실제 검증 ✅)

**GitHub 비공식 아카이브:** https://github.com/tapo-firmware/Tapo_C200 ✅

| 하드웨어 버전 | 구버전 포함 여부 | 취약 버전 포함 |
|------------|--------------|------------|
| C200 V1 | ✅ (1.0.10부터) | CVE-2021-4045 취약 버전 포함 |
| C200 V2 | ✅ (1.1.14부터) | CVE-2021-4045 취약 버전 포함 |
| C200 V3 | ✅ (1.1.13부터) | - |
| C200 V4 | ✅ (1.1.23부터) | - |

**공식 다운로드:** https://www.tp-link.com/us/support/download/tapo-c200/ ✅ (최신만)

### CVE 목록 및 발생 위치

| CVE | CVSS | 취약 컴포넌트 | 유형 | 취약 버전 → 패치 버전 |
|-----|------|------------|------|-------------------|
| CVE-2021-4045 | **9.8** | **`/usr/bin/uhttpd`** (HTTP 서버 바이너리) | Command Injection → 비인증 RCE | C200 V1/V2 **1.1.15 이하** → 1.1.16 Build 211209 |
| CVE-2025-8065 | - | **ONVIF 파서** (포트 2020) | XML Buffer Overflow → DoS | 최신 이전 → 1.4.5 Build 251104 |
| CVE-2025-14300 | 8.7 | **connectAp API** | Wi-Fi 재설정 (비인증) | 최신 이전 → 1.4.5 Build 251104 |
| CVE-2025-14553 | - | **Tapo 앱 API** | Password Hash 노출 | 앱 취약 버전 → 앱 업데이트 |
| Hard-coded Keys | - | **펌웨어 전체** | 하드코딩 암호화 키 | C200 다수 버전 |

> **추천 패치 디핑 쌍:** C200 V2 `1.1.15` vs `1.1.16` (CVE-2021-4045, uhttpd 바이너리)

---

## 3. Reolink (중국)

### 제품 라인업
| 계열 | 대표 모델 | 특징 |
|------|---------|------|
| RLC 시리즈 | RLC-410W, RLC-810A, RLC-823A | PoE 고정형, 주력 제품군 |
| E 시리즈 | E1 Outdoor, E1 Pro | WiFi 저가형 |
| Argus 시리즈 | Argus 3 Pro, Argus PT | 배터리형 |
| Duo 시리즈 | Duo 2 WiFi | 듀얼렌즈 |
| TrackMix 시리즈 | TrackMix PoE | 자동 추적 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | **없음** |
| 파일 형식 | `.pak` (squashfs 내장) |
| binwalk 추출 | **바로 가능** |

### 펌웨어 아카이브 (실제 검증 ✅)

**GitHub 비공식 아카이브:** https://github.com/AT0myks/reolink-fw-archive ✅
- 190개 이상 모델, 구버전 포함
- 하루 2회 자동 업데이트 (Wayback Machine 아카이브 포함)

**공식 다운로드:** https://reolink.com/download-center/ ✅ (최신만)

### CVE 목록 및 발생 위치

| CVE | 유형 | 취약 컴포넌트 | 영향 모델 | 패치 |
|-----|------|------------|---------|------|
| CVE-2021-40404 | Auth Bypass | **인증 모듈** | RLC-410W v3.0.0.136 | 최신 펌웨어 |
| CVE-2021-40407 | OS Command Injection | **디바이스 관리 서비스** | RLC-410W v3.0.0.136 | 최신 펌웨어 |
| CVE-2022-21236 (TALOS-2022-1446) | Information Disclosure | **네트워크 서비스** | RLC-410W | 최신 펌웨어 |
| CVE-2022-21199 (TALOS-2022-1448) | Information Disclosure | **네트워크 서비스** | RLC-410W | 최신 펌웨어 |
| CVE-2024-48644 | Account Enumeration | **로그인 API** | Duo 2 WiFi v1.0.280 | - |
| P2P 프로토콜 다수 | DoS, RCE | **P2P 통신 스택** | 다수 모델 | 각 모델 최신 |

---

## 4. Hikvision (중국)

### 제품 라인업
| 시리즈 | 모델 예시 | 용도 |
|--------|---------|------|
| DS-2CD1xxx | DS-2CD1023G2-IUF | 보급형 돔 |
| DS-2CD2xxx | DS-2CD2032, DS-2CD2142, DS-2CD2T47G2 | 중급 돔/총알 |
| DS-2CD3xxx | DS-2CD3T47G2-LI | 고급 총알 |
| DS-2CD4xxx | DS-2CD4685G0-IZS | 최고급 |
| DS-2DE/DS-2DF | DS-2DE4425IWG-E | PTZ |
| DS-7xxx NVR | DS-7616NI-K2 | NVR |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | **있음 (XOR 헤더 암호화)** |
| 방식 | 헤더를 키 `BA CD BC FE D6 CA DD D3 BA B9 A3 AB BF CB B5 BE`로 XOR, 좌측 순환 시프트 |
| 복호화 도구 | https://github.com/HaToan/Decrypt-Firmware-Hikvision ✅ |
| 복호화 후 | SquashFS / JFFS2 — binwalk 추출 가능 |
| 파일 이름 | `digicap.dav` |

### 펌웨어 아카이브

**Hikvision EU 포털 (구버전 다수):** https://www.hikvisioneurope.com/eu/portal/?dir=portal/Technical+Materials/00++Network+Camera/00++Product+Firmware ✅
- 시리즈별 디렉터리 구조
- 예: R6 플랫폼 V5.5.82_Build190909 등 구버전 포함

**공식 US 다운로드:** https://www.hikvision.com/us-en/support/download/firmware/ (브라우저 접근은 차단, 로그인 필요)

**구버전 참고:**
- https://www.nvripc.com/hikvision-ip-cameras-firmware-2021/ (2021년 버전 모음)
- https://securitycamcenter.com/firmware-hikvision-ip-camera/ (연도별 모음)

### CVE 목록 및 발생 위치

| CVE | CVSS | 취약 컴포넌트 | 유형 | 취약 버전 → 패치 |
|-----|------|------------|------|---------------|
| CVE-2021-36260 | **9.8** | **`/SDK/webLanguage` 엔드포인트** (웹서버 CGI) | Command Injection → 비인증 RCE | build 210628 이전 전 모델 → 210628 이후 |
| CVE-2024-29949 | - | **NVR 웹 서버** | 복합 취약점 | NVR V5.00.000~V5.02.005 → V5.02.006 |
| CVE-2024-29948 | - | NVR | - | V5.02.006 |
| CVE-2024-29947 | - | NVR | - | V5.02.006 |
| CVE-2024-47487 | - | **HikCentral DB** | SQL Injection | HikCentral Professional 특정 버전 |
| CVE-2023-33806 | - | **디바이스 기본 설정** | 안전하지 않은 기본 구성 | DS-D5B86RB/B V2.3.0 |

> **추천 패치 디핑 쌍:**
> - DS-2CD2xxx 모델: `build 210601` (CVE-2021-36260 취약) vs `V5.5.800 build 210628` (패치)
> - 취약 엔드포인트: `/SDK/webLanguage` — 해당 처리 바이너리의 입력 검증 함수

---

## 5. Ubiquiti UniFi Protect (미국) — **분석 완료**

> **분석 대상:** UniFi Camera S2L (v4.30.0 → v4.51.4, ARM)
> **분석 결과:** 34개 IoT 패턴 카드 (CRITICAL:1, HIGH:13, MEDIUM:17, LOW:3), CVE 매칭 15건
> **주요 발견:** Command Injection (sysExecSimple), /etc/passwd 인젝션, 인증 우회, 하드코딩 AES 키

### 제품 라인업
| 모델 | 특징 |
|------|------|
| G3 Flex | 소형 실내/실외 |
| G3 Micro | 초소형 실내 |
| G4 Bullet | 실외 총알형 |
| G4 Pro | 고해상도 실외 |
| G5 Pro | 최신 고급형 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | **없음** |
| 파일시스템 | SquashFS — binwalk 바로 가능 |
| 서명 검증 | 일부 모델 존재 (CVE-2025-23117) |

### 펌웨어 다운로드

| 소스 | URL | 상태 | 구버전 |
|------|-----|------|--------|
| 공식 (계정 필요) | https://www.ui.com/download/unifi-protect | 로그인 필요 | 일부 |
| 비공식 직접 링크 모음 | https://github.com/priiduonu/uvcfwlinks | ✅ 접근 가능 | 다수 |

### CVE 목록 및 발생 위치

| CVE | CVSS | 취약 컴포넌트 | 유형 | 취약 버전 → 패치 |
|-----|------|------------|------|---------------|
| CVE-2025-23123 | **10.0** | **카메라 펌웨어 메모리 관리** | Heap Buffer Overflow → RCE | v4.75.43 이하 → **v4.75.62** |
| CVE-2025-23115 | 9.0 | **HTTP 관리 인터페이스** | Use-After-Free → RCE | v4.74.88 이하 → v4.74.106 |
| CVE-2025-23116 | 9.6 | **Auto-Adopt 브릿지 서비스** | Auth Bypass | App v5.2.46 이하 → App v5.2.49 |
| CVE-2025-23119 | 7.5 | **카메라 CLI** | Escape Sequence Injection → RCE | v4.74.88 이하 → v4.74.106 |
| CVE-2025-23117 | - | **펌웨어 업데이트 검증** | 불충분한 서명 검증 | v4.74.88 이하 → v4.74.106 |
| CVE-2025-23118 | - | **TLS 클라이언트** | 인증서 검증 미흡 | v4.74.88 이하 → v4.74.106 |
| CVE-2026-22557/22558 | Critical | **UniFi Network Application** | 무단 접근 | 최신 → 패치 대기 |

---

## 6. Dahua (중국)

### 제품 라인업
| 시리즈 | 모델 예시 | 용도 |
|--------|---------|------|
| IPC-HDW | IPC-HDW2831T-AS | 실내 돔 |
| IPC-HFW | IPC-HFW2849S-S-IL | 실외 총알 |
| SD (PTZ) | SD3A400-GNP | 스피드돔 |
| Hero C1 | Hero C1 | 가정용 스마트 카메라 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | **있음 (AES-256, 파티션별 개별 암호화)** |
| 서명 | 모든 바이너리에 SHA+RSA 서명 |
| 복호화 난이도 | **높음** — 하드코딩 키 CVE 활용 시에만 가능 |
| 참고 도구 | https://github.com/BotoX/Dahua-Firmware-Mod-Kit |

### 펌웨어 다운로드

| 소스 | URL | 상태 | 구버전 |
|------|-----|------|--------|
| Dahua 공식 | https://www.dahuasecurity.com/support/downloadcenter | ⚠️ 브라우저는 200, curl은 403 | 일부 |
| dahuawiki.com (비공식 인덱스) | https://dahuawiki.com/Firmware_by_Device | ✅ 200 | 다수 |
| dahuawiki 검색 도구 | https://dahuawiki.com/Firmware_Search_Tool | ✅ 200 | 다수 |
| files.dahua.support | https://files.dahua.support/Firmware/ | ✅ 200 | 다수 |

### CVE 목록 및 발생 위치

| CVE | CVSS | 취약 컴포넌트 | 유형 | 패치 기준 |
|-----|------|------------|------|---------|
| CVE-2025-31700 | 8.1 | **ONVIF 프로토콜 스택** | 비인증 RCE | 2025.04.16 이후 빌드 |
| CVE-2025-31701 | 8.1 | **파일 업로드 핸들러** | 비인증 RCE | 2025.04.16 이후 빌드 |
| CVE-2021-33045 | 9.8 | **인증 모듈** | Auth Bypass | 모델별 최신 |
| CVE-2017-3xxx | - | **Sonia 웹 인터페이스** | Stack Buffer Overflow | 구형 — 당시 최신 |
| Hard-coded AES Key | - | **소프트웨어 전체** | 하드코딩 암호화 키 노출 | 특정 제품 패치 |

---

## 7. AXIS Communications (스웨덴)

### 제품 라인업
| 시리즈 | 특징 |
|--------|------|
| P 시리즈 | 고성능 고정형 |
| Q 시리즈 | PTZ/어안 |
| M 시리즈 | 중급 고정형 |
| F 시리즈 | 모듈형 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | 부분 암호화 (고급 모델) |
| Secure Boot | 일부 모델 지원 |
| 분석 난이도 | 중간 |

### 펌웨어 다운로드

| 소스 | URL | 상태 |
|------|-----|------|
| 공식 | https://www.axis.com/support/firmware | ✅ 200 (301→200 리다이렉트) |
| 보안 공지 | https://help.axis.com/en-us/security-advisories | ✅ |

### CVE 목록 및 발생 위치

| CVE | 유형 | 취약 컴포넌트 | 영향 버전 | 패치 |
|-----|------|------------|---------|------|
| CVE-2018-10660 | Shell Command Injection | **웹 인터페이스 CGI** | 펌웨어 6.30.1.3 이하 | 6.30.1.3 이후 |
| CVE-2018-10661 | Auth Bypass | **인증 모듈** | 6.30.1.3 이하 | 6.30.1.3 이후 |
| CVE-2018-10662 | 기타 | 미상 | 6.30.1.3 이하 | 6.30.1.3 이후 |
| CVE-2025-30023 | 미상 | **AXIS Camera Station Pro** | 최신 일부 | 공지 참조 |
| CVE-2025-30026 | 미상 | **AXIS Camera Station** | 최신 일부 | 공지 참조 |

---

## 8. D-Link DCS 시리즈 (대만)

### 제품 라인업
| 모델 계열 | 용도 |
|---------|------|
| DCS-930L/931L/932L/933L/934L | 가정용 실내 WiFi |
| DCS-5009L~5030L | 팬틸트 실내 |
| DCS-8300LHV2 | 고해상도 실외 |
| DNR-322L | NVR |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | 없음~부분 (구형은 대부분 평문) |
| 분석 난이도 | 낮음~중간 |
| 주의 | EOL 제품 다수 — 패치 미지원 |

### 펌웨어 다운로드

| 소스 | URL | 상태 |
|------|-----|------|
| 공식 지원 | https://support.dlink.com | ✅ 200 |
| 보안 공지 | https://supportannouncement.us.dlink.com | ✅ |

### CVE 목록 및 발생 위치

| CVE | 유형 | 취약 컴포넌트 | 영향 모델 | 패치 |
|-----|------|------------|---------|------|
| CVE-2019-10999 | Stack Buffer Overflow | **myDlink 클라우드 서비스** | DCS-5009L/5020L/930L/932L 등 10개 모델 | 각 모델 최신 |
| CVE-2022-40799 | 무결성 검증 없는 코드 다운로드 | **업데이트 모듈** | DNR-322L ≤ 2.60B15 | - |
| CVE-2023-51626 | Auth Bypass | **인증 모듈** | DCS-8300LHV2 | - |
| CVE-2023-51627 | Stack Buffer Overflow | **웹 서버** | DCS-8300LHV2 | - |
| CVE-2023-51628/51629 | RTSP 인증 취약점 | **RTSP 서버** | DCS-8300LHV2 | - |
| CISA KEV 등재 | 다수 | 다수 | D-Link 카메라/NVR | - |

---

## 9. Hanwha Wisenet (한국)

### 제품 라인업
| 시리즈 | 대표 모델 | 용도 |
|--------|---------|------|
| Wisenet Q | QNV-8080R, QNO-8080R | 중급 돔/총알 |
| Wisenet X | XNV-8080R | 고급 바리포칼 |
| Wisenet P | PNV-9080R | 프리미엄 |
| Wisenet Z | ZNV-8300 | AI 기반 |
| Wisenet A | 소형 AI 카메라 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | 부분 (모델별 상이) |
| 서명 | SHA + RSA 서명 |
| 분석 난이도 | 중간 |

### 펌웨어 다운로드

| 소스 | URL | 상태 | 구버전 |
|------|-----|------|--------|
| 공식 (미국) | https://hanwhavisionamerica.com/products-page/security-cameras/ | ✅ 200 | 제한적 |
| 공식 업데이트 도구 | Wisenet Device Manager (WDM) | 설치 필요 | - |
| 보안 공지/CVE 보고서 | https://www.hanwhavision.com/en/support/cybersecurity/ | ✅ | - |

### CVE 목록 및 발생 위치

| CVE | 유형 | 취약 컴포넌트 | 패치 버전 |
|-----|------|------------|---------|
| CVE-2023-31994 | DoS | **네트워크 서비스** | 모델별 최신 (2023.05) |
| CVE-2023-31995/31996 | 미상 | 미상 | 모델별 최신 |
| CVE-2023-5747 | 미상 | 미상 | **v2.21.03** (2023.11.10) |
| CVE-2023-5037/5038 | 미상 | 미상 | 모델별 최신 (2024.06) |
| Nozomi 5건 (2018) | Auth Bypass, RCE, DoS | **웹 인터페이스, 인증** | 당시 최신 |
| CVE-2025-8075 | XSS | **Wisenet Open Platform 웹** | - |
| CVE-2025-52601 | Hard-coded Password | **Wisenet Device Manager (WDM)** | - |

---

## 10. IDIS (한국)

### 제품 라인업
| 계열 | 대표 모델 |
|------|---------|
| DC 시리즈 | DC-D4516RX, DC-Y6513WRX 등 IP 카메라 |
| DR 시리즈 | DR-4516P NVR/DVR |
| ICM | 클라우드 관리 플랫폼 |

### 펌웨어 암호화
| 항목 | 내용 |
|------|------|
| 암호화 | 미상 (공개 분석 사례 없음) |

### 펌웨어 다운로드

| 소스 | URL | 상태 | 구버전 |
|------|-----|------|--------|
| 공식 | https://www.idisglobal.com/support/ | ✅ 200 | **최신만** — 패치 디핑 부적합 |

> **결론: IDIS는 구버전 펌웨어를 공개하지 않아 패치 디핑 불가**

### CVE 목록

| CVE | CVSS | 취약 컴포넌트 | 유형 | 패치 |
|-----|------|------------|------|------|
| CVE-2025-12556 | 8.7 | **IDIS ICM Viewer (Windows 앱)** | One-click RCE (악성 링크) | **v1.7.1** 업그레이드 |
| CVE-2021-28372 | - | **서드파티 P2P SDK** (공급망) | 다수 제조사 공통 | 각 제조사 패치 |

---

## 11. 펌웨어 암호화 현황 비교

| 제조사 | 암호화 | 방식 | 복호화 가능 | 도구 |
|--------|-------|------|-----------|------|
| Synology | **없음** | - | - | binwalk 직접 |
| Ubiquiti | **없음** | - | - | binwalk 직접 |
| Reolink | **없음** | - | - | binwalk 직접 |
| D-Link (구형) | **없음** | - | - | binwalk 직접 |
| AXIS | 부분 | 모델별 상이 | 일부 | binwalk |
| Hanwha | 부분 | SquashFS 또는 커스텀 | 일부 | - |
| Hikvision | **있음** | XOR 헤더 | **가능** | github.com/HaToan/Decrypt-Firmware-Hikvision |
| TP-Link Tapo | **있음** | AES-128-CBC | **가능** (GPL 키) | tp-link-decrypt (pip) |
| Dahua | **있음** | AES-256 파티션별 | 어려움 | github.com/BotoX/Dahua-Firmware-Mod-Kit (부분) |
| IDIS | 미상 | - | 미상 | - |

---

## 참고 출처

- [Synology Archive - Camera Firmware](https://archive.synology.com/download/Firmware/Camera)
- [Synology SA_24_24](https://www.synology.com/en-global/security/advisory/Synology_SA_24_24)
- [CVE-2023-5746 (Synology Format String)](https://www.northit.co.uk/cve/2023/5746)
- [Reolink Firmware Archive GitHub](https://github.com/AT0myks/reolink-fw-archive)
- [Tapo C200 Firmware Archive GitHub](https://github.com/tapo-firmware/Tapo_C200)
- [CVE-2021-4045 TP-Link Tapo C200 RCE (uhttpd)](https://www.hacefresko.com/posts/tp-link-tapo-c200-unauthenticated-rce)
- [TP-Link 펌웨어 AES 복호화 분석](https://watchfulip.github.io/28-12-24/tp-link_c210_v2.html)
- [CVE-2021-36260 Hikvision (/SDK/webLanguage)](https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html)
- [Hikvision 펌웨어 복호화 도구](https://github.com/HaToan/Decrypt-Firmware-Hikvision)
- [Hikvision EU 펌웨어 포털](https://www.hikvisioneurope.com/eu/portal/?dir=portal/Technical+Materials/00++Network+Camera/00++Product+Firmware)
- [Dahua CVE-2025-31700/31701 RCE](https://thehackernews.com/2025/07/critical-dahua-camera-flaws-enable.html)
- [Dahua Firmware Mod Kit](https://github.com/BotoX/Dahua-Firmware-Mod-Kit)
- [IDIS CVE-2025-12556 - Claroty](https://claroty.com/team82/research/new-architecture-new-risks-one-click-to-pwn-idis-ip-cameras)
- [CISA - Reolink P2P Advisory](https://www.cisa.gov/news-events/ics-advisories/icsa-21-019-02)
- [Nozomi - Hanwha Wisenet 5 flaws](https://www.nozominetworks.com/blog/smile-youre-being-hacked-nozomi-networks-labs-finds-five-new-flaws-in-hanwha-wisenet-cameras)
