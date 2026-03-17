# 파이프라인 개발 과정

## 전체 구조

```
펌웨어 A (old) ─┐
                ├─ Step 0: 추출 → Step 1: 해시 비교 → Step 2: 분류
펌웨어 B (new) ─┘
                        ↓
                Step 3: 텍스트 diff
                        ↓
                Step 4: IDA 통합 추출
                (함수 디컴파일 + BinExport 동시 처리 — IDA 1회 실행)
                        ↓
                Step 5: BinDiff 함수 매칭
                        ↓
                Step 6: Pseudocode Diff 생성
                        ↓
                Step 7: 요약 리포트
```

---

## Step 0: 펌웨어 추출

- **도구**: binwalk (WSL Ubuntu)
- **방식**: `wsl -d Ubuntu -- bash -lc "binwalk -e ..."` (WSLENV="" 로 Windows PATH 차단)
- **캐싱**: `.extracted_ok` 마커 파일로 재추출 방지
- **rootfs 탐색**: `_find_rootfs()` — bin/usr/etc/lib 포함 디렉토리 자동 탐색
- **지원 포맷**: UBIFS (Ubiquiti), SquashFS (Synology)

## Step 1: 해시 비교

- SHA256으로 old/new rootfs 전체 파일 해시
- `ThreadPoolExecutor`로 병렬 해싱
- IDA 임시파일 (.id0, .id1, .nam, .til) 자동 제외
- 결과: `hash_compare.json` (changed / added / removed)

## Step 2: 파일 분류 + 노이즈 필터링

**바이너리 판별 기준:**
1. ELF 매직 바이트 (`\x7fELF`) 확인
2. 첫 8KB에서 NULL 바이트 존재 여부

**노이즈 필터링:**
- `/usr/share/zoneinfo/` 경로 → 타임존 데이터, 분석 제외
- 위 필터로 241개 변경 파일 중 116개 타임존 제거 → 실제 분석 대상 ~125개

## Step 3: 텍스트 Diff

- Python `difflib.unified_diff` 사용
- 결과: `text_diffs/*.patch`

## Step 4: IDA 통합 추출 (핵심)

**핵심 설계: IDA 1회 실행으로 두 가지 동시 처리**

```
idat64.exe -A \
  -OBinExportModule:{output}.BinExport \   ← BinExport 생성
  -S"extract_with_decompile.py" \           ← 함수 디컴파일
  -L{log} binary
```

**추출 데이터 (함수별):**

| 필드 | 설명 | 용도 |
|------|------|------|
| pseudocode | Hex-Rays C 의사코드 | 변경 함수 diff 비교 |
| disasm | 어셈블리 | pseudocode 실패 시 fallback |
| mnem_hash | mnemonic 시퀀스 MD5 | 주소 무관 동일성 판별 |
| calls | 호출 함수 목록 | 호출 관계 분석 |
| strings | 참조 문자열 | 기능 파악 |
| constants | 사용 상수값 | 매직넘버 분석 |
| bb_count | 기본 블록 수 | 함수 복잡도 |

**Import Thunk 처리:**
- `__imp_printf` 같은 PLT stub (4바이트, instruction 1개)
- Hex-Rays가 디컴파일 안 함 (pseudocode = null) → 정상 동작
- ubnt_system_cfg 기준: 245개 함수 중 82개가 import thunk

**병렬 처리:** `ThreadPoolExecutor(max_workers=4)`

**BinExport fallback:**
- IDAPython 스크립트 내에서 BinExport 트리거 안 될 경우
- `.i64` 파일 재사용하여 별도 BinExport 실행

## Step 5: BinDiff 함수 매칭

```
bindiff.exe --primary old.BinExport --secondary new.BinExport --output_dir dir
```

**매칭 알고리즘 (12가지 이상):**
- 이름 매칭 (함수명 해시)
- CFG 매칭 (제어 흐름 그래프 구조 비교)
- Call Graph 전파
- Prime Signature (기본 블록의 소수 곱)
- MD Index (그래프 위상 정보)

**결과: `.BinDiff` SQLite DB**

`function` 테이블 주요 컬럼:

| 컬럼 | 설명 |
|------|------|
| name1, name2 | old/new 함수명 |
| address1, address2 | 각 버전 함수 주소 |
| similarity | 유사도 (0.0~1.0) |
| confidence | 매칭 신뢰도 |
| basicblocks, instructions, edges | CFG 구조 정보 |

## Step 6: Pseudocode Diff 생성

**필터링:**
- PLT stub 제거: instruction 수 ≤ 3인 함수 스킵
- pseudocode 우선, 없으면 disasm fallback

**출력 (함수별 3개 파일):**
```
function_diffs/ubnt_cgi/
├── authenticateToken_old.c     ← 패치 전 C 의사코드
├── authenticateToken_new.c     ← 패치 후 C 의사코드
└── authenticateToken.c.diff    ← unified diff
```

## Step 7: 요약 리포트

- `summary_step5to7.md` — 바이너리별 변경 통계, 주요 함수 목록
- `diff_results.json` — 구조화된 분석 결과
- `function_diff_stats.json` — 함수별 diff 통계

---

## 출력 디렉토리 구조

```
UVC_vs_uvc/
├── extracted/              ← rootfs (old, new)
├── functions/              ← 함수 JSON (pseudocode + 메타데이터)
│   ├── ubnt_cgi_old.json
│   └── ubnt_cgi_new.json
├── binexport/              ← .BinExport 파일
├── bindiff/                ← 바이너리별 .BinDiff SQLite
├── text_diffs/             ← 텍스트 파일 .patch
├── function_diffs/         ← 변경 함수별 pseudocode diff
│   └── ubnt_cgi/
│       ├── sub_XXX_old.c
│       ├── sub_XXX_new.c
│       └── sub_XXX.c.diff
├── hash_compare.json
├── diff_results.json
├── security_candidates.json ← LLM 분석용 보안 우선순위 50개
├── function_diff_stats.json
└── summary_step5to7.md
```
