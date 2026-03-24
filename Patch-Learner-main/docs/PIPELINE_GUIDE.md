# BinDiff Pipeline 사용 가이드

## 실행 명령어

```bash
python src/analyzers/bindiff_pipeline.py --old <이전> --new <이후> --output <결과>
```

`--old`와 `--new`에는 **디렉토리** 또는 **Synology .sa.bin 파일**을 넣을 수 있다.

---

## 사용 예시

### 1. 이미 추출된 바이너리 디렉토리

```bash
python src/analyzers/bindiff_pipeline.py \
    --old firmware/synology_bc500/binaries/v1.0.6 \
    --new firmware/synology_bc500/binaries/v1.0.7 \
    --output firmware/synology_bc500/diffs/v1.0.6_vs_v1.0.7
```

### 2. Synology .sa.bin 파일 (자동 추출)

```bash
python src/analyzers/bindiff_pipeline.py \
    --old firmware/synology_bc500/raw/Synology_BC500_1.0.6_0294.sa.bin \
    --new firmware/synology_bc500/raw/Synology_BC500_1.0.7_0298.sa.bin \
    --output firmware/synology_bc500/diffs/v1.0.6_vs_v1.0.7
```

.sa.bin을 넣으면 `--output/extracted/` 아래에 자동으로 파일시스템이 추출된다.
이미 추출된 적 있으면 캐시로 스킵.

---

## 펌웨어 파일 위치

```
firmware/
├── synology_bc500/
│   ├── raw/                ← 여기에 .sa.bin 넣기
│   │   ├── Synology_BC500_1.0.6_0294.sa.bin
│   │   └── Synology_BC500_1.0.7_0298.sa.bin
│   ├── binaries/           ← 또는 추출된 ELF 바이너리만 넣기
│   │   ├── v1.0.6/
│   │   └── v1.0.7/
│   ├── binexport/          ← (파이프라인이 자동 생성)
│   ├── diffs/              ← (파이프라인이 자동 생성)
│   └── extracted/          ← (파이프라인이 자동 생성)
├── ubiquiti_cv2x/
│   └── (동일 구조)
└── hanwha_wisenet/
    └── (동일 구조)
```

---

## 실행 순서 (내부 동작)

```
Step 0. 펌웨어 추출 (Synology .sa.bin인 경우만)
        .sa.bin → 파티션 파싱 → rootfs 찾기 → squashfs 추출
        ↓
Step 1. 해시 비교
        before 전체 파일 SHA256 vs after 전체 파일 SHA256
        → changed / added / removed 분류
        → hash_compare.json 저장
        ↓
Step 2. 파일 분류
        changed 파일을 text / binary로 분류
        (ELF 매직 또는 NULL 바이트 → binary)
        ↓
Step 3. 텍스트 diff
        text 파일 → difflib unified_diff → text_diffs/*.patch
        ↓
Step 4. BinExport (병렬, ThreadPoolExecutor x4)
        binary 파일 → idat64.exe → binexport/*.BinExport
        before/after 동시 처리
        ↓
Step 5. BinDiff
        bindiff.exe로 old.BinExport vs new.BinExport 비교
        → bindiff/*.BinDiff (SQLite DB)
        → 변경 함수 추출 (similarity < 1.0)
        ↓
출력.  bindiff_results.json + summary.md
        ↓
Step 6. Pseudocode Diff 생성
        PLT stub 제거 + pseudocode diff → function_diffs/
        ↓
Step 7. 요약 리포트
        summary_step5to7.md + diff_results.json
        ↓
Step 8. IoT 보안 후보 선별
        generate_security_candidates.py
        5,497 함수 → IoT 키워드/위험함수/바이너리 가중치 → 1,099개 선별
        ↓
Step 9. Discovery → Analysis 2단계 LLM 분석
        multi_agent_pipeline.py
        Opus(supervisor) + Sonnet×3(analyst) 병렬 분석 → 패턴 카드 JSON
        ↓
Step 10. Pydantic 검증 + SQLite DB 저장
        pattern_card_schema.py + load_pattern_cards.py
        34개 IoT 패턴 카드 → patch_learner.db
```

---

## 출력 구조

```
--output 디렉토리/
├── extracted/              # .sa.bin 추출 결과 (Step 0)
│   ├── Synology_BC500_1.0.6_0294.sa/
│   └── Synology_BC500_1.0.7_0298.sa/
├── hash_compare.json       # 변경 파일 목록 (Step 1)
├── text_diffs/             # 텍스트 패치 파일들 (Step 3)
│   ├── www_index.html.patch
│   └── etc_config.conf.patch
├── binexport/              # .BinExport 파일들 (Step 4)
│   ├── webd_old.BinExport
│   ├── webd_new.BinExport
│   └── ...
├── bindiff/                # .BinDiff 파일들 (Step 5)
│   ├── webd_old_vs_webd_new.BinDiff
│   └── ...
├── bindiff_results.json    # 변경 함수 목록 (최종)
└── summary.md              # 전체 요약
```

---

## Synology .sa.bin 추출 과정

Synology 카메라 펌웨어(.sa.bin)는 암호화되어 있지 않다. 독자 컨테이너 형식:

```
┌─────────────────────────────────────┐
│ Header (0x80 bytes)                 │
│   0x08: firmware version (16 bytes) │
│   0x18: model name (16 bytes)       │
│   0x7C: num_partitions (uint16 LE)  │
├─────────────────────────────────────┤
│ Prescript  (uint32 len + data)      │
│ Postscript (uint32 len + data)      │
├─────────────────────────────────────┤
│ Partition 0: "linux"                │
│   0x40 name + uint32 sub + uint32 img + zlib data │
│ Partition 1: "rootfs"  ← 이것      │
│   zlib 해제 → UBI 이미지            │
│   UBI 내부 → squashfs (hsqs 매직)   │
│   squashfs → 파일시스템              │
│ Partition 2: "loader"               │
│ Partition 3: "fdt"                  │
└─────────────────────────────────────┘
```

1. 헤더에서 모델명/버전/파티션 수 읽기
2. 각 파티션: 0x40 바이트 이름 + zlib 압축 데이터
3. rootfs 파티션의 zlib 해제 → UBI 이미지
4. UBI 내부에서 squashfs(hsqs) 매직 검색 → squashfs 추출
5. PySquashfsImage로 파일시스템 추출

binwalk가 안 되는 이유: Synology 독자 컨테이너 형식이라 binwalk가 파티션 구조를 인식 못함.

---

## 필수 도구

| 도구 | 경로 | 용도 |
|------|------|------|
| IDA Pro 9.0 (idat64.exe) | `C:\Program Files\IDA Professional 9.0\idat64.exe` | BinExport 생성 |
| BinDiff (bindiff.exe) | `C:\Program Files\BinDiff\bin\bindiff.exe` | 바이너리 비교 |
| BinExport plugin | IDA plugins 폴더에 설치 | IDA 플러그인 |

## 필수 Python 패키지

```bash
pip install PySquashfsImage ubi_reader
```

---

## 절대경로 vs 상대경로

- **IDA, BinDiff**: 절대경로 (코드 상단에 하드코딩)
- **펌웨어, 결과**: 상대경로 사용 가능 (`firmware/synology_bc500/raw/...`)
- 경로가 다른 PC면 코드 상단의 `IDA_PATH`, `BINDIFF_PATH`만 수정
