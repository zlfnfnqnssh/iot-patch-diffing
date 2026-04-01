# 파이프라인 개발 과정

> 설계 원칙은 [architecture-decisions.md](architecture-decisions.md) 참고

## 전체 구조 (확정 2026-03-25, 운영 업데이트 2026-04-02)

```
펌웨어 A (old) ─┐
                ├─ Stage 0: 펌웨어 추출 + 해시 디핑
펌웨어 B (new) ─┘       ↓ changed_files
                   Stage 1: BinDiff + 전체 디컴파일 → DB
                        ↓ changed_functions
                   Stage 2: LLM 1-pass 전수 분석
                        ↓ security_patches
                   Stage 3: 0-day 헌팅
                        ↓ hunt_findings
```

Stage 0~1은 여러 벤더를 상대로 반복 실행하고, Stage 2는 충분한 코퍼스가 모인 뒤 일괄 수행한다.

## Stage 0: 펌웨어 추출 + 해시 디핑

### 0-1. 추출 경로

- **Synology**: `.sa.bin` 포맷을 직접 파싱해 루트 파일시스템을 복원한다.
- **일반 펌웨어**: WSL Ubuntu에서 `binwalk -e`를 실행한다.
- **Tapo v3/v4 계열**: 헤더를 검사해 `signed/encrypted` 형식이면 `tp-link-decrypt`를 먼저 수행한 뒤 `binwalk`를 실행한다.

현재 구현에서 `binwalk` 전에는 `wsl --shutdown`을 먼저 호출한다.
이 단계는 WSL 인스턴스가 열린 상태에서 `binwalk`가 실패하던 문제를 줄이기 위한 운영 보강이다.

### 0-2. rootfs 탐색과 캐시

- 추출 결과에서 `bin`, `usr`, `etc`, `lib`가 함께 있는 디렉터리를 rootfs 후보로 본다.
- `.extracted_ok` 마커 파일을 두어 재실행 시 재추출을 피한다.
- Tapo 복호화 결과는 출력 폴더 하위 `_decrypt_cache/`에 둔다.

### 0-3. 해시 비교

- SHA256으로 old/new rootfs 전체 파일을 비교한다.
- `ThreadPoolExecutor`로 병렬 해싱한다.
- IDA 임시파일과 분석 노이즈는 제외한다.
- 결과는 `hash_compare.json`과 `changed_files` 테이블에 저장한다.

### 0-4. 파일 분류

- ELF 매직 바이트와 NULL 바이트 유무로 바이너리 여부를 판별한다.
- `/usr/share/zoneinfo/` 계열 파일은 노이즈로 보고 제외한다.
- 텍스트 파일은 `difflib.unified_diff`로 `.patch`를 생성한다.

## Stage 1: BinDiff + 전체 디컴파일 → DB

### 1-1. 함수 추출

IDA는 바이너리별로 old/new 각각 1회 실행한다.
우선 `extract_with_decompile.py`로 함수 JSON을 만들고, 같은 실행에서 `.BinExport` 생성을 시도한다.
만약 `.BinExport`가 누락되면 `-OBinExportAutoAction:BinExportBinary` 기반 fallback export를 추가로 수행한다.

추출 데이터는 다음을 포함한다.

- `pseudocode`
- `disasm`
- `mnem_hash`
- `calls`
- `strings`
- `constants`
- `bb_count`

함수 JSON 캐시는 `functions/{binary}_old.json`, `functions/{binary}_new.json`에 저장한다.

### 1-2. BinDiff 함수 매칭

```
bindiff.exe --primary old.BinExport --secondary new.BinExport --output_dir dir
```

BinDiff는 이름, CFG, Call Graph, Prime Signature 등 여러 기준으로 함수를 매칭한다.
매칭 결과는 바이너리별 `.BinDiff`와 `bindiff_results` 테이블에 저장한다.

### 1-3. 함수 단위 diff 생성

- `pseudocode`가 있으면 이를 우선 사용한다.
- 없으면 `disasm`을 fallback으로 사용한다.
- instruction 수가 매우 작은 PLT stub 함수는 제외한다.

출력 예시는 다음과 같다.

```
function_diffs/ubnt_cgi/
├── authenticateToken_old.c
├── authenticateToken_new.c
└── authenticateToken.c.diff
```

### 1-4. DB 저장

변경 함수는 old/new pseudocode 쌍과 함께 `changed_functions` 테이블에 저장한다.
비보안 함수도 저장해 분모 데이터와 재분석 기반으로 활용한다.

## Stage 2: LLM 1-pass 전수 분석

현재 설계는 BinDiff가 이미 뽑은 변경 함수 전체를 대상으로 LLM이 한 번에 분류와 분석을 수행하는 방식이다.

출력 필드는 다음을 포함한다.

- `is_security_patch`
- `severity`
- `confidence`
- `vuln_type`
- `cwe`
- `root_cause`
- `fix_description`
- `source_desc`
- `sink_desc`
- `missing_check`
- `hunt_strategy`

운영 순서는 다음과 같다.

1. 여러 벤더에 대해 Stage 0~1 결과를 먼저 축적한다.
2. 누적된 `changed_functions` 집합을 기준으로 Stage 2를 배치 실행한다.
3. 결과를 `security_patches` 테이블에 전수 저장한다.

## Stage 3: 0-day 헌팅

### Phase 1: 패턴 매칭

- `security_patches`에서 sink 함수와 검증 누락 패턴을 추출한다.
- 타깃 펌웨어에서 해당 호출과 xref를 전수 검색한다.

### Phase 2: 컨텍스트 분석

- Phase 1 후보만 다시 디컴파일한다.
- DB에 저장된 패치 패턴과 유사한지 LLM으로 판별한다.

### Phase 3: 수동 검증

- 신뢰도가 높은 후보부터 IDA에서 직접 검토한다.
- `candidate`, `verified`, `false_positive`, `exploitable` 상태로 관리한다.

## 운영 자동화 스크립트

### `src/analyzers/sequential_diff.py`

- 단일 모델 폴더 또는 상위 펌웨어 폴더를 입력으로 받는다.
- 상위 폴더를 주면 하위 모델 디렉터리를 재귀 탐색한다.
- 결과는 `output/<모델>/v<old>_vs_v<new>/`에 저장한다.
- `function_diff_stats.json`이 있으면 해당 pair를 건너뛴다.

### `src/analyzers/download_iptime_firmware.py`

- ipTIME 공지글에서 모델 목록을 읽는다.
- 다운로드 게시판의 과거 공지까지 탐색해 모델별 펌웨어를 수집한다.
- 저장 경로는 `data/firmware/iptime/<MODEL>/`이며, 모델별 manifest를 남긴다.

## 출력 디렉터리 구조

```
{model}/v{old}_vs_v{new}/
├── extracted/
├── functions/
├── binexport/
├── bindiff/
├── text_diffs/
├── function_diffs/
├── _decrypt_cache/         <- Tapo 복호화 입력/출력 캐시
├── hash_compare.json
├── diff_results.json
├── function_diff_stats.json
└── summary.md
```

## SQLite DB 구조

```
src/db/patch_learner.db
├── firmware_versions
├── diff_sessions
├── changed_files
├── bindiff_results
├── changed_functions
├── security_patches
└── hunt_findings
```

## 현재 제약사항

- IDA와 BinDiff는 Windows 상용 도구에 의존한다.
- Tapo v3/v4처럼 벤더별 전처리가 필요한 포맷은 계속 추가 보완이 필요하다.
- 대형 바이너리는 IDA 처리 시간이 길고, 장시간 실행 중 파일 잠금 이슈가 생길 수 있다.
- Stage 2와 Stage 3의 평가 자동화는 다중 벤더 코퍼스가 더 쌓인 뒤 확장할 예정이다.
