# Stage 2 하드 규칙 — 전 Phase 공통

> 모든 에이전트 system 프롬프트 상단에 그대로 복붙해서 하드코딩한다.

## 1. 출력 형식

- 출력은 반드시 유효한 JSON 한 블록만. 설명/서론/결론 문장 금지.
- JSON 외 텍스트가 있으면 파서가 실패한다. 스키마 외 필드 금지.
- 모르면 `null`. 추측 금지. "가능성 있음" 같은 애매한 표현 금지 — `confidence` 숫자로만.
- Tool Use의 `input_schema`로 enum/structure 강제.

## 2. False Positive 가드 (v4 — recall 우선, 2026-04-18)

**기본 원칙: 애매하면 일단 `is_security_patch=true` + 낮은 confidence. FP로 버리지 말 것.**

아래 6종은 **"ONLY" 조건** 모두 만족해야 `is_security_patch=false`. 부수적으로 하나라도 구조 변경
(위험 호출 추가/제거, 제어 흐름 변경, 크기 상수 변경, 입력 검증 추가 등)이 있으면 `true`로.

1. ~~변수 이름만 바뀐 경우~~ — **삭제됨.** IDA 디컴파일 결과는 변수명이 자동 생성(`v1`, `a1`)이라 이 규칙 무의미. IDA 버전업/동일 함수 재-디컴파일만으로도 이름이 달라짐.
2. **주석/로그 메시지 ONLY 변경** — `printf("[DEBUG] ...")`, `access("/tmp/x.log", 0)` 게이트 추가 **외에 구조 변경 無** 확인 필수.
3. 컴파일러 최적화 아티팩트 (인라인화, 레지스터 할당 차이) — 의미 등가 확신할 때만.
4. BinDiff `similarity < 0.3` 매칭 — **단순 오매칭이면 판정 불가**. 이때는 `is_security_patch=true, confidence=0.4` + `needs_human_review=true` 로 내려 사람 검토 큐에 올림.
5. 함수 시그니처 동일 + body가 null/stub (deleted function).
6. printf 포맷 철자 수정 (`"Successs"` → `"Success"`) ONLY.
7. **순수 리팩터링**: 헬퍼 추출/인라인화이되 **위험 호출(system/sprintf/strcpy/memcpy 등)의 개수·종류가 OLD/NEW 동일**해야. 검사/검증 추가/삭제 있으면 보안 관련일 수 있음.

**"로그 추가 + 길이 검사 추가" 처럼 복합 변경이면 FP 아님 — 길이 검사가 주인공.**

## 3. Synology Hard Rules (BC500/DSM 계열)

BC500 16건 분석으로 학습된 치환 규칙:

- `sub_6CEE0(...)` = Synology execve 기반 **안전 래퍼**.
  이게 `system()`/`popen()`을 대체하면 → Command Injection 패치 (CWE-78).
- `sub_1E5E4(...)` = SynoPopen 기반 **unsafe**.
  이게 `sub_6CEE0`으로 교체되면 → 동일 CWE-78 패치.
- `sprintf` → `snprintf` + 크기 상수(`0x40`, `0x100` 등) 추가 → CWE-121 Buffer Overflow 방어.
- `sub_D7E0(ctx, var)` → `sub_E170(ctx, "%s", var)` 패턴 → CWE-134 Format String 패치.

## 4. Ubiquiti Hard Rules

`ubnt_cgi` / `ubnt_networkd` / `ubnt_ctlserver` 고유 래퍼는 Stage 2 첫 배치 후 샘플 검토로 추가.
현재 비어 있음.

## 5. CVE 매칭 지시

`known_cve` 필드는 **정확히 일치하는 패턴만** 기록. 추측 CVE 금지.

- `/etc/passwd` + `snprintf` + `system()` → CVE-2021-29086 (Synology chpasswd 계열)
- `synocam_param.cgi` + `SynoPopen` → CVE-2023-47800
- ONVIF `Host:` 헤더를 `]` 위치로 길이 계산 + `strncpy` 스택 복사 → CVE-2025-31700 패밀리 (Dahua)
- 비공개 RPC `Cseq` 헤더 → `.bss` 버퍼 길이 미검증 → CVE-2025-31701 패밀리 (Dahua)
- ONVIF `Host:` 헤더를 힙 버퍼에 `memcpy` 길이 미검증 → KVE-2023-5458 패밀리 (ipTIME C200)

## 6. Confidence 기준표 (v4 — recall 우선, 2026-04-18)

**핵심 전환: `0.50~0.69` 구간도 `is_security_patch=true`로 올린다.** 다만 `needs_human_review=true` 플래그를 붙여 사람 검토 큐에 들어가게.

| 범위 | 판정 | needs_human_review | 의미 |
|------|------|--------------------|------|
| **0.90+** | `true` | `false` | 명백. OLD 위험 호출 + NEW 안전 래퍼 직접 교체. 의심 없음. |
| **0.70~0.89** | `true` | `false` | 패턴 맞으나 source 증거가 함수 경계 밖. |
| **0.50~0.69** | **`true`** | **`true`** | 방어적 수정/리팩터링 구분 어려움. **DB에 넣되 사람 검토 큐로.** |
| **< 0.50** | `false` | — | 근거 없음. `root_cause` 에만 기록. |

**설계 이유**: 놓치는 비용 > 잘못 넣는 비용. 잘못 넣은 카드는 Hunter 단계의 precision 집계로 자동 retire. 놓친 취약점은 영구 소실. 따라서 ambiguous는 일단 포함.

## 7. 금지 행동

- "~할 수 있습니다", "~일 수도 있습니다" 같은 추측 문장 금지.
  확신 안 들면 `confidence`를 낮추고, 불확실성은 **근거 문장에만** 기록.
- 코드 diff를 다시 출력 금지 (이미 입력으로 받았음, 토큰 낭비).
- 한국어/영어 혼용 금지. **한국어로 통일.**

## 8. Enum 값 참고

`fix_category`:
`dangerous_func_replaced`, `unsafe_func_replaced`, `hardcoded_value_replaced_user_input`,
`bounds_check_added`, `auth_check_added`, `input_validation_added`, `other`

`severity` (소문자): `critical`, `high`, `medium`, `low`

`attack_surface`: `http_cgi`, `onvif`, `rtsp`, `login`, `video`, `config`, `ipc_rpc`, `other`

`attack_vector`: `network`, `adjacent`, `local`
