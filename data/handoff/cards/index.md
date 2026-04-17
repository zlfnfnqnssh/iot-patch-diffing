# 패턴카드 인덱스

- 총 active 카드: **61**
- 업데이트: 2026-04-18 03:38:08

| card_id | severity | 공식 | summary |
|---|---|---|---|
| [P-001](P-001.md) | low | `file_read` + `bounds_check` + `integer_op` | proc write 입력 v65를 sscanf로 파싱 후 배열 상한 비교 로직이 리팩토링됨. 구조 변경은 있으나 의미상 동치에 가까움. |
| [P-002](P-002.md) | low | `file_read` + `length_bound` + `stack_buffer_copy` | PDC_sramCreate 경로 길이/크기 계산 로직을 대대적으로 재작성. 신규 스택 버퍼 v89[114] 도입. |
| [P-003](P-003.md) | low | `net_packet` + `length_bound` + `heap_buffer_copy` | ASN.1 인코더가 오브젝트 길이를 dereference해 memcpy. 상한 비교는 있으나 length 필드 신뢰 전제. 리팩토링 상 간접접근 |
| [P-004](P-004.md) | low | `env_var` + `bounds_check` + `format_string` | date 출력에서 로컬 배열 인덱스가 음수 오프셋으로 잡혀 스택 OOB 읽기 가능성. 디컴파일 아티팩트일 수 있으나 구조 변화 뚜렷. |
| [P-005](P-005.md) | low | `cli_arg` + `bounds_check` + `ptr_arith` | 로그 컬러 테이블 인덱싱이 `s_levelColor[color]`에서 `off_28EF0[a2+10]`로 변경. 경계 검사 없는 전역 포인터 배 |
| [P-006](P-006.md) | medium | `config_field` + `length_bound` + `heap_buffer_copy` | 52바이트 스트라이드 배열에 strlen 기반 memcpy로 문자열 기록. 대상 슬롯 최대 길이와 src strlen 비교 없음. |
| [P-007](P-007.md) | low | `file_read` + `sign_check` + `integer_op` | lua zip plugin seek 연산에서 signed 비교를 unsigned 캐스팅으로 교체. overflow 방어 개선. |
| [P-008](P-008.md) | low | `env_var` + `format_specifier` + `format_string` | 로그 함수에 format 인자 자리에 상수 0x1C7을 전달하던 버그를 정상 fmt+args 호출로 교체. |
| [P-009](P-009.md) | low | `cli_arg` + `length_bound` + `stack_buffer_copy` | i2cOpen의 고정 크기 스택 버퍼에 `/dev/i2c-%s` 포맷 sprintf. 버퍼 크기 64→68로 소폭 확장됐으나 snprintf 치 |
| [P-010](P-010.md) | medium | `rpc_arg` + `auth_check` + `heap_buffer_copy` | 인증 상태 플래그(dword_4D20DC) 미확인 상태에서 AES 미디어 키를 반환 버퍼에 복사. NEW는 auth 게이트와 크기 검증을 추가. |
| [P-011](P-011.md) | low | `config_field` + `bounds_check` + `stack_buffer_copy` | UCI OSD config의 label 텍스트를 75바이트 슬롯에 strncpy로 복사. 명시 null-termination 경로 추가. |
| [P-012](P-012.md) | medium | `http_header` + `bounds_check` + `stack_buffer_copy` | HTTP Authorization 헤더 기반 Digest 검증 함수에서 nonce 복사 상한(0x31) 및 nonce count 재사용 가드(p |
| [P-013](P-013.md) | medium | `config_field` + `type_check` + `ptr_arith` | 단일 전역 슬롯에 마지막 getaddrinfo 결과를 캐시하여 다른 호스트 조회에 재사용. NEW는 호스트/포트 키 기반 8 슬롯 테이블로 교체 |
| [P-014](P-014.md) | medium | `rpc_arg` + `format_specifier` + `format_string` | 로깅 래퍼에서 vsnprintf 호출 시 va_list 포인터 전달이 OLD 디컴파일에서 누락. NEW는 va_list 명시 전달. |
| [P-015](P-015.md) | medium | `rpc_arg` + `length_bound` + `stack_buffer_copy` | Sensor plane id 로부터 얻은 32-byte 스택 버퍼를 길이 검사 없이 strcpy 로 호출자 구조체에 복사. BinDiff 매칭  |
| [P-016](P-016.md) | medium | `internal` + `format_arg_supply` + `format_string` | sprintf 포맷 문자열에 %u 있으나 대응 인자 미공급으로 스택 잔존값 노출. 수정본에서 인자 매칭 완료. |
| [P-017](P-017.md) | medium | `ioctl_input` + `rcmode_specific_size_check` + `stack_buffer_write` | OLD은 스택 v18[160]에 바이트 루프로 외부 구조체를 복사하고 v13[63]=v8[63] 인접 오프셋에 동시 기록. NEW은 고정 크기  |
| [P-018](P-018.md) | low | `procfs_write` + `length_check` + `stack_strcpy` | root-only debugfs 진입점이지만 128바이트 스택 버퍼 2개에 외부 문자열을 strcpy로 무제한 복사. 2.840 버전도 동일 패 |
| [P-019](P-019.md) | low | `procfs_write` + `length_check` + `struct_strcpy` | ProcDumpOut이 /proc debugfs 경로 문자열을 stDbgFsChnInfo의 128바이트 필드에 _memzero+strcpy로 복 |
| [P-020](P-020.md) | low | `caller_provided_struct` + `caller_side_length` + `strncpy_bounded` | OSA_thrCreateEx가 외부 스레드 이름을 strncpy 0x20 크기 제한 + 명시 terminator로 복사. 2.840은 동일 로직 |
| [P-021](P-021.md) | medium | `procfs_read` + `null_check` + `kernel_printf_deref` | debug_func_show가 NEW에서 seq_file 구조체의 +96 오프셋 포인터를 seq_printf로 직접 역참조. NULL/해제 후  |
| [P-022](P-022.md) | low | `file_read` + `bounds_check` + `ptr_arith` | proc write 입력의 모터 idx 경계 비교를 `<=`에서 `>=`로 바꿔 off-by-one 해소. 함수 포인터 테이블 호출 이전에 인덱 |
| [P-023](P-023.md) | low | `rpc_arg` + `length_bound` + `heap_buffer_copy` | I2C write 내부 루틴의 길이 n이 고정 힙 버퍼(144B) 범위를 넘을 때 memcpy 전에 `n > 0x8F` 검사 추가. OLD는 검 |
| [P-024](P-024.md) | low | `cli_arg` + `type_check` + `system_call` | 사용자 ioctl 로 받은 MAC 을 상태/유효성 검사 없이 하드웨어 레지스터에 그대로 프로그래밍. NEW 는 상태+MAC 유효성 검사 추가. |
| [P-025](P-025.md) | medium | `net_packet` + `length_bound` + `memcpy_variable_len` | beacon IE 를 개별 파싱에서 구조화된 60B key snapshot 비교로 전환. rtw_get_bcn_keys 게이트 추가. |
| [P-026](P-026.md) | low | `config_field` + `null_check` + `stack_buffer_copy` | NULL 포인터/MAC 유효성 검사 없이 efuse MAC 을 호출자 버퍼에 복사. NEW 는 NULL 체크와 rtw_check_invalid_ |
| [P-027](P-027.md) | medium | `shared_mem` + `bounds_check` + `stack_buffer_copy` | AAA stats 파서가 전역 dword_4CCB0 기반 가변 크기로 출력 버퍼를 초기화하고 채널 인덱스 일치 검증 없이 인덱스 쓰기 수행. |
| [P-028](P-028.md) | low | `shared_mem` + `type_check` + `process_spawn` | HDR linearization 갱신 경로가 work_info HDR 활성 상태 확인 없이 호출되던 것을 v7==1 AND v8!=0 가드 뒤로 |
| [P-029](P-029.md) | medium | `rpc_arg` + `bounds_check` + `ptr_arith` | AE gain LUT 탐색 함수가 경계 idx 에서 off-by-one 반환하던 것을 명시 경계 분기로 교정. |
| [P-030](P-030.md) | low | `config_field` + `type_check` + `heap_buffer_copy` | VIN 별 map2 초기화에서 pre-config 가 선적용된 상태에서도 테이블을 덮어쓰던 것을 플래그로 보호. |
| [P-031](P-031.md) | medium | `rpc_arg` + `bounds_check` + `heap_buffer_copy` | shutter ratio 설정에서 min > max 조합이 들어와도 그대로 전역에 memcpy 하던 것을 대소관계 검증으로 거부. |
| [P-032](P-032.md) | medium | `config_field` + `null_check` + `process_spawn` | motor iris 초기화가 M43 step 경로에서 motor config 획득 실패를 감지하지 못하고 미초기화 스택값을 사용하던 문제 수정. |
| [P-033](P-033.md) | medium | `config_field` + `length_bound` + `shell_exec` | 스택 버퍼에 sprintf로 cp 명령 조립 후 system() 실행하던 경로를 snprintf + 크기 상수로 교체. |
| [P-034](P-034.md) | medium | `config_field` + `length_bound` + `stack_buffer_copy` | OLD는 구성 블롭의 3바이트 조합으로 AEB 타입 ID를 만들어 스택 배열 s[232]에 바로 인덱싱. NEW는 sub_7A98 헬퍼로 범위  |
| [P-035](P-035.md) | medium | `config_field` + `length_bound` + `integer_op` | ADJ_FILTER_NUM=45 상한과 NULL 검증이 들어간 새 헬퍼 함수 도입. 호출측(sub_836E,sub_7D7C)의 배열 범위 초과를 |
| [P-036](P-036.md) | medium | `file_write` + `length_bound` + `function_pointer_call` | 사용자가 /dev 노드에 쓴 문자열을 sscanf로 파싱해 IR-cut 디바이스 인덱스와 명령 코드를 추출. OLD/NEW 모두 상한(dev<d |
| [P-037](P-037.md) | medium | `file_write` + `bounds_check` + `function_pointer_call` | IRIS proc write에 디바이스 활성 플래그 검증(v3[52]==1), 함수 포인터 NULL 검증, DEV ID 범위(dword_103F |
| [P-038](P-038.md) | low | `config_field` + `path_normalize` + `file_open` | PanTilt 초기화에서 /dev/motorPtz 하드코딩 경로 strcpy 및 snprintf 대체 경로가 제거됨. access() 기반 선택 |
| [P-039](P-039.md) | low | `rpc_arg` + `null_check` + `heap_buffer_copy` | VIDEOINPUT_proCtlSetAe에서 a2 NULL 체크가 제거되고 바로 memcpy(v2+1336,a2,128) 수행. 보안 강화 아닌 |
| [P-040](P-040.md) | medium | `rpc_arg` + `length_bound` + `memcpy_variable_len` | 플래시 파일 쓰기 래퍼에서 caller 제공 길이 a4를 청크 상한 없이 단일 호출. NEW는 chunk_size 기반 루프로 분할. |
| [P-041](P-041.md) | low | `config_field` + `bounds_check` + `ptr_arith` | UART prepare에서 채널 인덱스 상한 v1<v2 검사 및 v1 도출 로직이 제거됨. 보안 약화 패치. |
| [P-042](P-042.md) | low | `file_path` + `mode_sanitization` + `filesystem_op` | zip 아카이브 디렉터리 생성 함수의 mkdir 인자 구조가 변경됨. 시그니처 축소로 모드 계산 경로가 제거. |
| [P-043](P-043.md) | low | `file_path` + `refactor_only` + `memcpy` | zzip_open_shared_io 기본 IO 선택 및 null 처리 분기를 재구성. 주요 경계 검사는 유지. |
| [P-044](P-044.md) | medium | `ioctl_arg` + `range_check` + `array_index_write` | GPIO 번호의 bank 상한(>0x5F) 검사가 NEW에서 제거되어, 외부 a1 값으로 정적 배열 LANCHOR0_3에 OOB write 가능 |
| [P-045](P-045.md) | high | `rpc_arg` + `metachar_filter` + `process_spawn` | 외부 입력 username/password를 JSON 템플릿 snprintf에 직접 삽입하여 ubus(cloudclient/user_bind)로 |
| [P-046](P-046.md) | high | `config_field` + `auth_check` + `deserialize` | ONVIF 임시 비밀번호 인증 기대값을 펌웨어 고정 문자열로 하드코드. 펌웨어 추출 시 전 디바이스 공통 암호 우회. |
| [P-047](P-047.md) | medium | `http_body` + `metachar_filter` + `shell_exec` | NEW 분기에서 인증 미완 세션이 접근 가능한 setCloudServerType이 server_type을 화이트리스트 통과 후 shell 스크립 |
| [P-048](P-048.md) | low | `shared_mem` + `tocttou` + `integer_op` | motion detection 전역 타임스탬프 변수 갱신에 뮤텍스가 없어 race 발생 가능 — NEW에서 pthread_mutex + end- |
| [P-049](P-049.md) | high | `http_header` + `auth_check` + `process_spawn` | HTTP h264 스트림 콜백에서 약한 인증 래퍼를 digest 인증 래퍼로 교체하고 device_locked 거부 체크를 새로 추가. |
| [P-050](P-050.md) | medium | `config_field` + `metachar_filter` + `stack_buffer_copy` | uci 기반 media encrypt 비활성 경로에서 평문 하드코딩 키를 RSA 암호화 블롭으로 대체해 firmware strings 노출 표면 |
| [P-051](P-051.md) | low | `rpc_arg` + `null_check` + `ptr_arith` | 스케줄러 타임아웃 콜백이 ctx/priv_ctx NULL 검사 없이 역참조하여 커널 null-deref 가능. |
| [P-052](P-052.md) | low | `rpc_arg` + `bounds_check` + `memcpy_variable_len` | AE stat wrapper update에 a2 오프셋 기반 memcpy 3건 추가 - a2 유효 크기 보장 근거 불명. |
| [P-053](P-053.md) | low | `rpc_arg` + `tocttou` + `stack_buffer_copy` | 스케줄러 타임아웃 복구 블록을 atomic-guarded snapshot+tinyblock 태스크 큐로 전면 재작성. |
| [P-054](P-054.md) | medium | `file_read` + `length_bound` + `deserialize` | 외부 DNS 래퍼 호출을 fopen/fgets 기반 로컬 파싱으로 교체. 스택 버퍼 128바이트 고정으로 라인 길이 상한 적용. |
| [P-055](P-055.md) | low | `config_field` + `null_check` + `system_call` | OSA_fileAccess 분기 처리를 재편해 statfs 실패 경로를 공통 LABEL로 합치고 중복 로깅을 제거. |
| [P-056](P-056.md) | medium | `rpc_arg` + `tocttou` + `file_open` | DNS v4 주소 쓰기 루틴 전체를 OSA_mutexLock/Unlock로 감싸 동시 수정 시 파일 손상을 차단. |
| [P-057](P-057.md) | medium | `file_read` + `tocttou` + `file_open` | DNS v4 읽기 루틴을 write 측과 동일한 OSA_mutex 보호 경로에 합류시켜 중간 상태 노출을 차단. |
| [P-058](P-058.md) | low | `file_read` + `null_check` + `system_call` | 이더넷 디바이스 열거 루틴에 HWID 3 분기 + v6 초기화 추가. |
| [P-059](P-059.md) | low | `config_field` + `type_check` + `file_open` | boot 파라미터 조회를 NoPrint 변종으로 교체하고 복합 조건을 early-return 체인으로 분리. |
| [P-060](P-060.md) | medium | `rpc_arg` + `double_free_guard` + `ptr_arith` | vo_blk_release 호출 뒤 해당 포인터 필드를 NULL로 초기화하지 않아 이후 경로에서 dangling pointer 재참조 가능. |
| [P-061](P-061.md) | low | `cli_arg` + `null_check` + `system_call` | PCM FD 오픈 직후 fcntl 반환값 검증이 추가되어 실패 시 FD 누수 없이 종료. |
