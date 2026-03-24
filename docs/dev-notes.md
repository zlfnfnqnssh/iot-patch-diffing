# 개발 특이사항 및 트러블슈팅

## 날짜별 개발 일지

---

### 2026-03-09 ~ 03-12 | 초기 설계 및 IDAPython 방식 시도

**진행 내용:**
- 프로젝트 초기 설계: 펌웨어 추출 → 해시 비교 → IDA 분석 흐름 확정
- IDAPython으로 함수별 mnemonic 추출 후 직접 비교하는 방식 구현
- `ida_user/export_for_diff.py` 작성 (3단계 매칭: 이름 매칭 → mnem_hash → fuzzy SequenceMatcher)

**문제점:**
- PLT stub 노이즈: `printf`, `getppid` 등 3개 instruction 함수가 유사도 0.4로 잘못 분류됨 (linker 주소 재배치 때문)
- 함수 위치가 바뀌면 매칭 불가 (`sub_XXXXX` 형식 함수는 주소가 버전마다 다름)
- 5,653개 변경 함수 검출했으나 노이즈 포함 많음

---

### 2026-03-13 ~ 03-14 | BinExport 플러그인 문제 + 방식 전환 논의

**문제:**
- IDA Pro 9.0 크랙 버전에서 `binexport12_ida64.dll` 로드 실패
- 오류: `binexport12_ida64.dll: can't load file - 지정된 프로시저를 찾을 수 없습니다`
- DLL 버전 호환성 문제 (크랙 IDA 9.0과 BinExport 버전 불일치)

**임시 대응:**
- IDAPython mnemonic 비교 방식으로 중간 구현 유지
- BinDiff 위치 탐색: `C:\Program Files\BinDiff\bin\bindiff.exe` 확인

**해결:**
- 사용자가 플러그인 파일 교체 후 BinExport 연결 성공
- `C:\Users\deser\AppData\Roaming\Hex-Rays\IDA Pro\plugins` 경로에 호환 버전 설치

---

### 2026-03-15 | BinExport+BinDiff 방식으로 전면 전환

**변경 사항:**
- `bindiff_pipeline.py` 전면 재작성
- `run_ida_export()` → `run_binexport()` 교체
- `compare_function_exports()` 삭제
- `run_bindiff()` + `parse_bindiff_results()` 추가
- `import sqlite3` 추가

**핵심 변경 코드:**

```python
# BinExport 생성
cmd = [
    str(IDA_PATH), "-A",
    f"-OBinExportModule:{binexport_path}",
    "-OBinExportAutoAction:BinExportBinary",
    f"-L{log_path}",
    str(binary),
]

# BinDiff 실행
cmd = [
    str(BINDIFF_PATH),
    "--primary", str(old_binexport),
    "--secondary", str(new_binexport),
    "--output_dir", str(output_dir),
]
```

**결과 비교:**
- IDAPython 방식: 5,653개 변경 함수 (노이즈 많음)
- BinDiff 방식: 12,408개 변경 함수, 더 정확한 CFG 기반 매칭

---

### 2026-03-15 | 추출 캐시 버그 수정

**문제:**
- 파이프라인 재실행 시 펌웨어 재추출 반복 (캐시 무시)
- 원인: `.extracted_ok` 마커가 rootfs 하위 폴더에 있었음
  - 실제 위치: `extracted/UVC.S2LM_4.30.0/ubifs-root/880278559/rootfs/.extracted_ok`
  - 코드가 확인하는 위치: `extracted/UVC.S2LM_4.30.0/.extracted_ok`

**해결:**
1. 올바른 위치에 `.extracted_ok` 마커 수동 생성 (`touch`)
2. `_find_rootfs()` 헬퍼 함수 추가 — 캐시 히트 시에도 rootfs 경로 정확히 반환

```python
def _find_rootfs(out_dir: Path) -> Path:
    """추출된 디렉토리에서 rootfs (bin, usr, etc, lib 포함) 찾기."""
    candidates = [d for d in out_dir.rglob("*")
                  if _safe_is_dir(d) and _has_rootfs_dirs(d)]
    if candidates:
        return max(candidates, key=_count_files)
    return out_dir
```

---

### 2026-03-15 | 타임존 파일 노이즈 발견

**현상:**
- `/usr/share/zoneinfo/` 하위 파일 (Accra, Brisbane, Budapest 등)이 바이너리로 분류
- 이유: TZif 형식 파일에 NULL 바이트 포함 → `is_binary()` 판정
- IDA 분석 결과: 함수 0~2개, BinDiff 유사도 0%
- 184개 bindiff 디렉토리 중 112개가 타임존 노이즈

**해결:**
- `zoneinfo` 경로 포함 파일 자동 필터링 추가

---

### 2026-03-16 | IDA 통합 추출 방식으로 전환

**배경:**
- 기존: BinExport만 생성 → BinDiff로 변경 함수 찾기 → 다시 IDA 돌려서 디컴파일
- 문제: IDA를 두 번 돌려야 함 (시간 낭비)

**새 방식:**
- IDA 1회 실행으로 **BinExport 생성 + 함수 pseudocode 추출 동시 처리**
- `ida_user/extract_with_decompile.py` 작성
- 환경변수로 출력 경로 전달: `IDA_EXPORT_DIR`, `IDA_BINARY_TAG`

**테스트 결과 (ubnt_system_cfg, 32KB 바이너리):**
- 전체 245개 함수
- 디컴파일 성공: 163개
- Import thunk (스킵): 82개 (`__imp_xxx`, instruction 1개, pseudocode=null)
- BinDiff: 184개 매칭, 8개 변경, 유사도 99.3%

---

### 2026-03-18 | 파이프라인 재실행 시 캐시(이어하기) 기능 추가

**배경:**
- Step 4(IDA 통합 추출)는 바이너리 수가 많아 중간에 중단되는 경우가 많음
- 재실행 시 이미 완료된 파일까지 다시 처리해서 시간 낭비 발생

**추가된 캐시 동작:**

| 단계 | 캐시 기준 | 동작 |
|------|----------|------|
| Step 1 (해시 비교) | `hash_compare.json` 존재 여부 | 파일 있으면 재해싱 없이 로드 |
| Step 4 (IDA 추출) | `functions/{name}_old.json` + `_new.json` 둘 다 존재 | 해당 바이너리 스킵 |
| Step 5 (BinDiff) | `bindiff/{name}/*.BinDiff` 존재 여부 | 해당 바이너리 스킵 |
| Step 6 (diff 생성) | `function_diffs/{name}/*.diff` 존재 여부 | 해당 바이너리 스킵 |

**Step 4 진행률 표시 개선:**
```
[4/7] 함수 추출 + BinExport — 전체 125개 (캐시 60개 스킵, 신규 65개 처리)
      진행: 1/65 (전체 61/125)
      진행: 2/65 (전체 62/125)
      ...
```

**핵심 변경 내용:**
- `compare_dirs()`: `cache_path` 파라미터 추가, `hash_compare.json` 있으면 재사용
- `run_bindiff()`: 실행 전 `.BinDiff` 파일 존재 여부 확인 후 캐시 반환
- `generate_function_diffs()`: `*.diff` 파일 존재 시 기존 파일 기반으로 통계 반환
- `main()` Step 4: 캐시/신규 바이너리 사전 분류 후 신규만 병렬 처리

### 2026-03-17 | 보안 함수 우선순위 분류

**작업:**
- 4,676개 diff 중 보안 관련 상위 50개 선별
- `security_candidates.json` 생성

**선별 기준:**
- 보안 관련 바이너리 가중치 +50: ubnt_cgi, dropbear, libcrypto, libssl, hostapd, wpa_supplicant 등
- 보안 키워드 매칭 가중치 +20/개: auth, valid, verify, crypt, parse, token, exec, system, password 등
- 변경 규모 가중치 +1/라인 (최대 100)

**상위 결과 예시:**
- `libcrypto.so.1.1/RSA_padding_check_SSLv23` — score 192 (ssl, rsa, check)
- `libcrypto.so.1.1/X509_verify_cert` — score 190 (verify, cert)
- `libssl.so.1.1/d2i_SSL_SESSION` — score 190 (session, ssl)

---

### 2026-03-23 | 팀 GitHub 연결 + IoT 카메라 CVE 리서치 + 멀티 에이전트 패턴 카드 설계

**진행 내용:**

1. **팀 GitHub 연결**
   - `https://github.com/seosamuel02/Patch-Learner` 클론 → `Patch-Learner-collab/`
   - 작업 브랜치 `riri` 생성 및 push 완료
   - CLAUDE.md에 개인/팀 저장소 구분 규칙 추가

2. **IoT 카메라 CVE 리서치 문서 작성** (`docs/iot_camera_cve_research.md`)
   - 10개 제조사 / 6개국 조사
   - 구버전 펌웨어 아카이브 실제 접근 검증 (curl)
   - 펌웨어 암호화 여부 정리
   - Synology 전 버전 공개 아카이브 확인 (패치 디핑 최적)

3. **멀티 에이전트 패턴 카드 생성 시스템 설계**

   ```
   [Opus 4.6 — 매니저/리뷰어]
           │
           ├── 작업 분배 (top 50 → 25 + 25)
           │
           ├── Agent 1 (Sonnet) ── 후보 1~25 분석 → 패턴 카드 JSON
           ├── Agent 2 (Sonnet) ── 후보 26~50 분석 → 패턴 카드 JSON
           │   (병렬 실행)
           │
           └── 매니저 리뷰
                 ├── 카드 품질 검토, 피드백
                 └── 최종 llm_pattern_cards.json 확정
   ```

   **각 에이전트 역할:**
   - 매니저 (Opus): 작업 분배, 결과 리뷰, 보안 정확성 검토
   - Analyst Agent (Sonnet × 2): old.c/new.c 읽고 보안 분석, 패턴 카드 작성
   - API 미사용 — Claude Code Agent 툴로 서브에이전트 spawn

   **패턴 카드 필드:**
   - vulnerability_type, cwe, severity, confidence
   - summary, vulnerability_detail, fix_detail, attack_scenario
   - detection_keywords, cve_similar, is_security_relevant

4. **멀티 에이전트 패턴 카드 실행 완료**
   - Opus 4.6(매니저) + Sonnet×2(분석) 구조로 50개 함수 분석
   - Agent 1: libcrypto(15) + libssl(3) + dropbear(7) = 25개
   - Agent 2: dropbear 25개
   - 결과: `llm_pattern_cards.json` — 50카드 (33 보안관련, 17 비보안)
   - 주요 발견: RSA timing side-channel(LPC-001), EVP integer overflow(LPC-018), ECDSA nonce reuse(LPC-048)

5. **토스 보안팀 취약점 분석 자동화 분석 및 적용**
   - [toss.tech 블로그](https://toss.tech/article/vulnerability-analysis-automation-1) 2편 분석
   - 핵심 아이디어: SAST(Semgrep) + Multi-Agent + Pydantic 검증 + 오픈모델
   - 우리 프로젝트에 적용 가능한 2가지 선별:
     - Discovery → Analysis 2단계 에이전트 (토큰 50% 절감)
     - Pydantic 구조화 출력 검증 (파싱 실패 0)

6. **파이프라인 개선 구현**

   **새 파일:**
   - `src/analyzers/pattern_card_schema.py` — Pydantic 검증 스키마
     - PatternCard, DiscoveryResult 모델
     - VulnerabilityType 비정형 입력 정규화 (bof→Buffer Overflow 등)
     - CWE 형식 자동 보정 (CWE120→CWE-120)
     - CLI: `python pattern_card_schema.py cards.json`

   - `src/analyzers/multi_agent_pipeline.py` — 2단계 오케스트레이터
     - Discovery → Analysis 분리 (토스 방식 적용)
     - 4단계: discovery → process → analysis → merge
     - 프롬프트 템플릿 내장 (Discovery, Analysis, Review)
     - Pydantic 검증 + 자동 보정 통합

   **개선된 워크플로우:**
   ```
   이전:  Manager → [Analyst1(25개), Analyst2(25개)] → Review
   이후:  Manager → Discovery(50개→필터) → [Analyst1, Analyst2] → Review + Pydantic 검증
   ```

   **검증 결과:**
   - 기존 50개 패턴 카드 → 50/50 유효 (5개 자동 보정)
   - 자동 보정: `attack_scenario` "해당 없음" → "해당 없음 (상세 분석 불필요)"

---

### 2026-03-24 | IoT 바이너리 보안 분석 + Pydantic 검증 + SQLite DB 저장

**진행 내용:**

1. **IoT 보안 후보 선별 시스템 구현** (`generate_security_candidates.py`)
   - 기존: crypto/auth 키워드만 → OpenSSL/Dropbear만 50개 선별 (IoT 0개)
   - 개선: IoT 키워드 80+개 + 위험함수 14패턴 + 바이너리 우선순위
   - 결과: 5,497개 → 1,099개 선별 (20%), IoT 177개 (16%)

2. **3개 IoT 바이너리 병렬 LLM 분석**
   - ubnt_cgi (12카드): CRITICAL Command Injection 발견 (CVE-2021-22909)
   - ubnt_ctlserver (10카드): /etc/passwd 인젝션, 인증 우회 등
   - ubnt_networkd (12카드): 하드코딩 AES 키, TLV OOB 읽기, null deref 등
   - 총 34개 IoT 패턴 카드 생성

3. **Pydantic 검증 스키마** (`pattern_card_schema.py`)
   - VulnerabilityType 17개 enum + 비정형 입력 자동 정규화
   - 34/34 카드 검증 통과

4. **SQLite DB 저장** (`schema.sql` + `load_pattern_cards.py`)
   - `pattern_cards` 테이블 추가 (19개 컬럼)
   - 34개 카드 INSERT 완료
   - 인덱스: binary_name, severity, vulnerability_type, cve_similar

**주요 발견:**
- CRITICAL: WiFi SSID/passphrase → sysExecSimple 명령 주입 (CVE-2021-22909)
- HIGH: /etc/passwd 직접 쓰기로 백도어 계정 생성 가능 (CVE-2020-8515)
- HIGH: GetRequest 인증 없이 카메라 스냅샷 반환 (CVE-2022-23134)
- HIGH: 펌웨어 덤프로 AES 페어링 키 추출 가능 (CWE-321)
- 체계적 패턴: sign-extension `v|(v>>31)` 정수 언더플로우 — 코드베이스 전체에 반복

---

## 주요 노이즈 유형 정리

| 유형 | 설명 | 처리 방법 |
|------|------|----------|
| 타임존 파일 | `/usr/share/zoneinfo/` TZif 파일, 함수 0개 | 경로 필터링으로 제외 |
| PLT stub | `__imp_xxx`, instruction ≤ 3, 주소만 바뀜 | diff 생성 스킵 |
| 주소 재배치 | similarity 12.4%짜리 1-instruction 함수 | instruction 수 임계치로 필터 |
| 링커 아티팩트 | `.init_proc`, `JUMPOUT(0)` 형태 | 함수 크기로 필터 가능 |

## 알려진 제약사항

- IDA Pro 9.0 크랙 버전 사용 — 일부 플러그인 호환성 이슈 있음
- ARM 바이너리 전용 (x86 펌웨어는 추가 테스트 필요)
- `ThreadPoolExecutor(max_workers=4)` — PC 성능에 따라 조정 필요
- evostreamms (15,013개 함수), libcrypto (5,858개 함수) 등 대형 바이너리는 IDA 처리 시간 길어짐
- BinDiff는 함수가 완전히 삭제/추가된 경우 `function` 테이블에 기록 안 됨 (unmatched 함수는 별도 처리 필요)
