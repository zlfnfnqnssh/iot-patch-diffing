# Stage 2 진행 상황

_업데이트: 2026-04-18 03:38:08_

## 패턴카드
- active: **61** / retired: 0 / superseded: 0

## 판정 누적
- 전체 판정: **1600**
- 보안 패치로 분류: 350 (21.9%)
- 사람 검토 대기: 355

## Stage 2 큐 상태
| status | count |
|---|---|
| prefiltered_out | 342,282 |
| skipped_oss | 48,792 |
| prefiltered_in | 19,524 |
| drafted_nonsec | 1,494 |
| drafted_sec | 104 |
| drafting_a1 | 2 |

## 공식(taint formula) 분포 (active)
| source_type | missing_check | sink_type | 카드수 | 멤버수 |
|---|---|---|---|---|
| `rpc_arg` | `length_bound` | `stack_buffer_copy` | 1 | 10 |
| `config_field` | `length_bound` | `stack_buffer_copy` | 1 | 5 |
| `rpc_arg` | `bounds_check` | `heap_buffer_copy` | 1 | 5 |
| `cli_arg` | `bounds_check` | `ptr_arith` | 1 | 4 |
| `rpc_arg` | `null_check` | `ptr_arith` | 1 | 4 |
| `config_field` | `type_check` | `heap_buffer_copy` | 1 | 3 |
| `file_read` | `length_bound` | `stack_buffer_copy` | 1 | 3 |
| `http_header` | `auth_check` | `process_spawn` | 1 | 3 |
| `procfs_write` | `length_check` | `struct_strcpy` | 1 | 3 |
| `cli_arg` | `length_bound` | `stack_buffer_copy` | 1 | 2 |
| `config_field` | `length_bound` | `heap_buffer_copy` | 1 | 2 |
| `config_field` | `null_check` | `stack_buffer_copy` | 1 | 2 |
| `file_read` | `tocttou` | `file_open` | 1 | 2 |
| `net_packet` | `length_bound` | `memcpy_variable_len` | 1 | 2 |
| `procfs_read` | `null_check` | `kernel_printf_deref` | 1 | 2 |
| `rpc_arg` | `bounds_check` | `memcpy_variable_len` | 1 | 2 |
| `rpc_arg` | `bounds_check` | `ptr_arith` | 1 | 2 |
| `rpc_arg` | `length_bound` | `heap_buffer_copy` | 1 | 2 |
| `rpc_arg` | `tocttou` | `file_open` | 1 | 2 |
| `shared_mem` | `tocttou` | `integer_op` | 1 | 2 |
| `shared_mem` | `type_check` | `process_spawn` | 1 | 2 |
| `caller_provided_struct` | `caller_side_length` | `strncpy_bounded` | 1 | 1 |
| `cli_arg` | `null_check` | `system_call` | 1 | 1 |
| `cli_arg` | `type_check` | `system_call` | 1 | 1 |
| `config_field` | `auth_check` | `deserialize` | 1 | 1 |
| `config_field` | `bounds_check` | `ptr_arith` | 1 | 1 |
| `config_field` | `bounds_check` | `stack_buffer_copy` | 1 | 1 |
| `config_field` | `length_bound` | `integer_op` | 1 | 1 |
| `config_field` | `length_bound` | `shell_exec` | 1 | 1 |
| `config_field` | `metachar_filter` | `stack_buffer_copy` | 1 | 1 |
| `config_field` | `null_check` | `process_spawn` | 1 | 1 |
| `config_field` | `null_check` | `system_call` | 1 | 1 |
| `config_field` | `path_normalize` | `file_open` | 1 | 1 |
| `config_field` | `type_check` | `file_open` | 1 | 1 |
| `config_field` | `type_check` | `ptr_arith` | 1 | 1 |
| `env_var` | `bounds_check` | `format_string` | 1 | 1 |
| `env_var` | `format_specifier` | `format_string` | 1 | 1 |
| `file_path` | `mode_sanitization` | `filesystem_op` | 1 | 1 |
| `file_path` | `refactor_only` | `memcpy` | 1 | 1 |
| `file_read` | `bounds_check` | `integer_op` | 1 | 1 |
| `file_read` | `bounds_check` | `ptr_arith` | 1 | 1 |
| `file_read` | `length_bound` | `deserialize` | 1 | 1 |
| `file_read` | `null_check` | `system_call` | 1 | 1 |
| `file_read` | `sign_check` | `integer_op` | 1 | 1 |
| `file_write` | `bounds_check` | `function_pointer_call` | 1 | 1 |
| `file_write` | `length_bound` | `function_pointer_call` | 1 | 1 |
| `http_body` | `metachar_filter` | `shell_exec` | 1 | 1 |
| `http_header` | `bounds_check` | `stack_buffer_copy` | 1 | 1 |
| `internal` | `format_arg_supply` | `format_string` | 1 | 1 |
| `ioctl_arg` | `range_check` | `array_index_write` | 1 | 1 |
| `ioctl_input` | `rcmode_specific_size_check` | `stack_buffer_write` | 1 | 1 |
| `net_packet` | `length_bound` | `heap_buffer_copy` | 1 | 1 |
| `procfs_write` | `length_check` | `stack_strcpy` | 1 | 1 |
| `rpc_arg` | `auth_check` | `heap_buffer_copy` | 1 | 1 |
| `rpc_arg` | `double_free_guard` | `ptr_arith` | 1 | 1 |
| `rpc_arg` | `format_specifier` | `format_string` | 1 | 1 |
| `rpc_arg` | `length_bound` | `memcpy_variable_len` | 1 | 1 |
| `rpc_arg` | `metachar_filter` | `process_spawn` | 1 | 1 |
| `rpc_arg` | `null_check` | `heap_buffer_copy` | 1 | 1 |
| `rpc_arg` | `tocttou` | `stack_buffer_copy` | 1 | 1 |
| `shared_mem` | `bounds_check` | `stack_buffer_copy` | 1 | 1 |

## 벤더별 멤버 누적
| vendor | 카드 멤버 수 |
|---|---|
| dahua | 88 |
| tp-link | 16 |
