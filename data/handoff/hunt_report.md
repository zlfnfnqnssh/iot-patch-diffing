# Hunter 결과 보고서

_생성: 2026-04-18 03:46:43_

- 전체 발견: **1746**
- 사람 검토 대기 (NULL): 1746
- True Positive: 0
- False Positive: 0

## 카드별 매칭 수 (Top 20)
| card_id | severity | matches | TP | FP | precision | formula |
|---|---|---|---|---|---|---|
| P-061 | low | 390 | 0 | 0 | - | `cli_arg + null_check + system_call` |
| P-054 | medium | 291 | 0 | 0 | - | `file_read + length_bound + deserialize` |
| P-045 | high | 184 | 0 | 0 | - | `rpc_arg + metachar_filter + process_spawn` |
| P-038 | low | 159 | 0 | 0 | - | `config_field + path_normalize + file_open` |
| P-056 | medium | 137 | 0 | 0 | - | `rpc_arg + tocttou + file_open` |
| P-057 | medium | 137 | 0 | 0 | - | `file_read + tocttou + file_open` |
| P-043 | low | 94 | 0 | 0 | - | `file_path + refactor_only + memcpy` |
| P-058 | low | 85 | 0 | 0 | - | `file_read + null_check + system_call` |
| P-001 | low | 40 | 0 | 0 | - | `file_read + bounds_check + integer_op` |
| P-003 | low | 37 | 0 | 0 | - | `net_packet + length_bound + heap_buffer_copy` |
| P-039 | low | 27 | 0 | 0 | - | `rpc_arg + null_check + heap_buffer_copy` |
| P-033 | medium | 23 | 0 | 0 | - | `config_field + length_bound + shell_exec` |
| P-059 | low | 23 | 0 | 0 | - | `config_field + type_check + file_open` |
| P-006 | medium | 21 | 0 | 0 | - | `config_field + length_bound + heap_buffer_copy` |
| P-049 | high | 14 | 0 | 0 | - | `http_header + auth_check + process_spawn` |
| P-008 | low | 10 | 0 | 0 | - | `env_var + format_specifier + format_string` |
| P-023 | low | 10 | 0 | 0 | - | `rpc_arg + length_bound + heap_buffer_copy` |
| P-022 | low | 8 | 0 | 0 | - | `file_read + bounds_check + ptr_arith` |
| P-020 | low | 7 | 0 | 0 | - | `caller_provided_struct + caller_side_length + strncpy_bounded` |
| P-004 | low | 6 | 0 | 0 | - | `env_var + bounds_check + format_string` |

## 높은 match_confidence 상위 30 (검토 우선)
| card_id | target (vendor/binary) | target func | conf | formula |
|---|---|---|---|---|
| [P-011](cards/P-011.md) | tp-link/Tapo_C200v1 `cet`  v1.0.17->v1.0.18 | `osd_load_cfg` | 1.00 | `config_field + stack_buffer_copy + bounds_check` |
| [P-011](cards/P-011.md) | tp-link/Tapo_C200v1 `cet`  v1.0.18->v1.1.1 | `osd_load_cfg` | 1.00 | `config_field + stack_buffer_copy + bounds_check` |
| [P-011](cards/P-011.md) | tp-link/Tapo_C200v1 `cet`  v1.3.4->v1.3.5 | `osd_load_cfg` | 1.00 | `config_field + stack_buffer_copy + bounds_check` |
| [P-012](cards/P-012.md) | tp-link/Tapo_C200v1 `cet`  v1.3.4->v1.3.5 | `sub_41B8F0` | 1.00 | `http_header + stack_buffer_copy + bounds_check` |
| [P-055](cards/P-055.md) | dahua/DH_IPC-GX2XXX-Hugo_MultiLang_PN `libpdi.so`  v3.120.0.16->v3.120.0.21 | `System_deleteLogSpace` | 1.00 | `config_field + system_call + null_check` |
| [P-041](cards/P-041.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.22->v2.860.0.31 | `AUF_runUartPrepare` | 1.00 | `config_field + ptr_arith + bounds_check` |
| [P-055](cards/P-055.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `System_deleteLogSpace` | 1.00 | `config_field + system_call + null_check` |
| [P-040](cards/P-040.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `sub_3AE14` | 1.00 | `rpc_arg + memcpy_variable_len + length_bound` |
| [P-038](cards/P-038.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `createPanTiltLocate` | 1.00 | `config_field + file_open + path_normalize` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `NetGetDNSAddress` | 1.00 | `file_read + deserialize + length_bound` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `NetGetDNSAddressip6` | 1.00 | `file_read + deserialize + length_bound` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `NetGetEthDevice` | 1.00 | `file_read + deserialize + length_bound` |
| [P-058](cards/P-058.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `NetGetEthDevice` | 1.00 | `file_read + system_call + null_check` |
| [P-056](cards/P-056.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.37->v2.860.0.38 | `NetSetDNSAddressip6` | 1.00 | `rpc_arg + file_open + tocttou` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.38->v2.880.0.16 | `NetGetDNSAddress` | 1.00 | `file_read + deserialize + length_bound` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.38->v2.880.0.16 | `NetGetDNSAddressip6` | 1.00 | `file_read + deserialize + length_bound` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.38->v2.880.0.16 | `NetGetEthDevice` | 1.00 | `file_read + deserialize + length_bound` |
| [P-058](cards/P-058.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.860.0.38->v2.880.0.16 | `NetGetEthDevice` | 1.00 | `file_read + system_call + null_check` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `systools`  v2.860.0.9->v2.860.0.13 | `sub_1989C` | 1.00 | `file_read + deserialize + length_bound` |
| [P-041](cards/P-041.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.16->v2.880.0.17 | `AUF_runUartPrepare` | 1.00 | `config_field + ptr_arith + bounds_check` |
| [P-038](cards/P-038.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `createPanTiltLocate` | 1.00 | `config_field + file_open + path_normalize` |
| [P-055](cards/P-055.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `System_deleteLogSpace` | 1.00 | `config_field + system_call + null_check` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `NetGetDNSAddress` | 1.00 | `file_read + deserialize + length_bound` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `NetGetDNSAddressip6` | 1.00 | `file_read + deserialize + length_bound` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `NetGetEthDevice` | 1.00 | `file_read + deserialize + length_bound` |
| [P-058](cards/P-058.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `NetGetEthDevice` | 1.00 | `file_read + system_call + null_check` |
| [P-054](cards/P-054.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `delRouteTable` | 1.00 | `file_read + deserialize + length_bound` |
| [P-056](cards/P-056.md) | dahua/DH_IPC-HX1XXX-Kant_EngSpnRus_PN `libpdi.so`  v2.880.0.17->v2.880.0.18 | `NetSetDNSAddressip6` | 1.00 | `rpc_arg + file_open + tocttou` |
| [P-007](cards/P-007.md) | dahua/DH_IPC-HX2(1)XXX-Euler_EngSpnRus_PN `libzzip.so`  v2.800.0.18->v2.840.0.6 | `sub_3F58` | 1.00 | `file_read + integer_op + sign_check` |
| [P-007](cards/P-007.md) | dahua/DH_IPC-HX2(1)XXX-Euler_EngSpnRus_PN `libzzip.so`  v2.800.0.18->v2.840.0.6 | `sub_411C` | 1.00 | `file_read + integer_op + sign_check` |

## 크로스벤더 매칭 (가장 흥미로운 후보)
| card_id | 원 벤더 | 매칭 벤더/모델 | 매칭 함수 | conf |
|---|---|---|---|---|
| [P-054](cards/P-054.md) | dahua | tp-link/Tapo_C200v1 v1.0.14->v1.0.16 `slpupgrade` | `main` | 0.85 |
| [P-054](cards/P-054.md) | dahua | tp-link/Tapo_C200v2 v1.1.19->v1.3.5 `slpupgrade` | `main` | 0.85 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.10->v1.0.14 `p2pd` | `_ftext` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.14->v1.0.16 `cloud-service` | `_ftext` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.18->v1.1.1 `cloud-service` | `sub_406A30` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.6->v1.0.7 `logrecordd` | `_ftext` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.7->v1.0.10 `cloud-brd` | `sub_4021D4` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.7->v1.0.10 `cloud-service` | `_ftext` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.7->v1.0.10 `p2pd` | `_ftext` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.0.7->v1.0.10 `libcommon.so` | `createProcPidFile` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.1.16->v1.1.18 `logrecordd` | `_ftext` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.1.1->v1.1.7 `cloud-service` | `main` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v1 v1.1.8->v1.1.15 `cloud-service` | `main` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v2 v1.1.14->v1.1.15 `cloud-service` | `main` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v2 v1.1.19->v1.3.5 `cloud-service` | `main` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v2 v1.1.4->v1.1.9 `cloud-service` | `main` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v2 v1.1.9->v1.1.14 `cloud-service` | `main` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v3 v1.1.22->v1.3.0 `cloud-service` | `sub_4024AC` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v3 v1.3.4->v1.3.5 `cloud-service` | `sub_402608` | 0.84 |
| [P-061](cards/P-061.md) | dahua | tp-link/Tapo_C200v4 v1.1.23->v1.3.7 `cloud-service` | `sub_12878` | 0.84 |

## 타겟 벤더별 매칭
| vendor | findings |
|---|---|
| dahua | 1116 |
| tp-link | 547 |
| ipTIME | 83 |
