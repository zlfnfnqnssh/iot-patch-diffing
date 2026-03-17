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
