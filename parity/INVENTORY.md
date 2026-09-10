# Falco tip test inventory

Source: `FALCO_TIP` commit `c0b24e3f2b9daaa60a0b85f23db5748fa3d2a5d4` (`/nvraid1tank1/work/code/falco`).

Counts use `rg -c 'TEST(_F)?\(' … -g '*.cpp'` for unit tests and `*.yaml` file count for evtgen.

## Summary

| Suite | Tests | Phase gate |
|-------|-------|------------|
| `unit_tests/engine` | 152 | Phase 1 (`falco_unit_engine`) |
| `unit_tests/falco` | 81 | Phase 2 (`falco_unit_app`) |
| `e2e_tests/evtgen_suite` | 20 | Phase 5 (`e2e_evtgen`) |

## Engine unit tests → `rustagon-engine`

| Falco file | Tests | Rustagon target |
|------------|-------|-----------------|
| `unit_tests/engine/test_rule_loader.cpp` | 104 | `rustagon-engine/tests/rule_loader.rs` |
| `unit_tests/engine/test_filter_macro_resolver.cpp` | 11 | `rustagon-engine/tests/filter_macro_resolver.rs` |
| `unit_tests/engine/test_enable_rule.cpp` | 6 | `rustagon-engine/tests/enable_rule.rs` |
| `unit_tests/engine/test_filter_details_resolver.cpp` | 5 | `rustagon-engine/tests/filter_details_resolver.rs` |
| `unit_tests/engine/test_extra_output.cpp` | 5 | `rustagon-engine/tests/extra_output.rs` |
| `unit_tests/engine/test_list_fields.cpp` | 4 | `rustagon-engine/tests/list_fields.rs` |
| `unit_tests/engine/test_falco_utils.cpp` | 4 | `rustagon-engine/tests/falco_utils.rs` |
| `unit_tests/engine/test_filter_warning_resolver.cpp` | 4 | `rustagon-engine/tests/filter_warning_resolver.rs` |
| `unit_tests/engine/test_alt_rule_loader.cpp` | 4 | `rustagon-engine/tests/alt_rule_loader.rs` |
| `unit_tests/engine/test_rulesets.cpp` | 2 | `rustagon-engine/tests/rulesets.rs` |
| `unit_tests/engine/test_plugin_requirements.cpp` | 2 | `rustagon-engine/tests/plugin_requirements.rs` |
| `unit_tests/engine/test_add_source.cpp` | 1 | `rustagon-engine/tests/add_source.rs` |

## App unit tests → `rustagon-core`

| Falco file | Tests | Rustagon target |
|------------|-------|-----------------|
| `unit_tests/falco/test_capture.cpp` | 15 | `rustagon-core/tests/capture.rs` |
| `unit_tests/falco/test_configuration_config_files.cpp` | 15 | `rustagon-core/tests/configuration_config_files.rs` |
| `unit_tests/falco/test_configuration_schema.cpp` | 8 | `rustagon-core/tests/configuration_schema.rs` |
| `unit_tests/falco/test_configuration.cpp` | 8 | `rustagon-core/tests/configuration.rs` |
| `unit_tests/falco/app/actions/test_configure_interesting_sets.cpp` | 11 | `rustagon-core/tests/actions/configure_interesting_sets.rs` |
| `unit_tests/falco/test_restart_handler.cpp` | 4 | `rustagon-core/tests/restart_handler.rs` |
| `unit_tests/falco/app/actions/test_pidfile.cpp` | 4 | `rustagon-core/tests/actions/pidfile.rs` |
| `unit_tests/falco/test_atomic_signal_handler.cpp` | 3 | `rustagon-core/tests/atomic_signal_handler.rs` |
| `unit_tests/falco/test_configuration_rule_selection.cpp` | 3 | `rustagon-core/tests/configuration_rule_selection.rs` |
| `unit_tests/falco/app/actions/test_validate_rules_files.cpp` | 3 | `rustagon-core/tests/actions/validate_rules_files.rs` |
| `unit_tests/falco/test_configuration_output_options.cpp` | 2 | `rustagon-core/tests/configuration_output_options.rs` |
| `unit_tests/falco/app/actions/test_load_config.cpp` | 2 | `rustagon-core/tests/actions/load_config.rs` |
| `unit_tests/falco/test_configuration_env_vars.cpp` | 1 | `rustagon-core/tests/configuration_env_vars.rs` |
| `unit_tests/falco/app/actions/test_configure_syscall_buffer_num.cpp` | 1 | `rustagon-core/tests/actions/configure_syscall_buffer_num.rs` |
| `unit_tests/falco/app/actions/test_select_event_sources.cpp` | 1 | `rustagon-core/tests/actions/select_event_sources.rs` |

Configuration suite glob (minimum mapping from plan):

| Falco pattern | Rustagon target |
|---------------|-----------------|
| `unit_tests/falco/test_configuration*.cpp` | `rustagon-core/tests/configuration*.rs` |

## E2E evtgen suite → workspace e2e runner

| Falco file | Rustagon target |
|------------|-----------------|
| `e2e_tests/evtgen_suite/clear_log_activities.yaml` | `tests/e2e/evtgen/clear_log_activities.yaml` |
| `e2e_tests/evtgen_suite/create_hardlink_over_sensitive_files.yaml` | `tests/e2e/evtgen/create_hardlink_over_sensitive_files.yaml` |
| `e2e_tests/evtgen_suite/create_symlink_over_sensitive_files.yaml` | `tests/e2e/evtgen/create_symlink_over_sensitive_files.yaml` |
| `e2e_tests/evtgen_suite/debugfs_launched_in_privileged_container.yaml` | `tests/e2e/evtgen/debugfs_launched_in_privileged_container.yaml` |
| `e2e_tests/evtgen_suite/detect_release_agent_file_container_escapes.yaml` | `tests/e2e/evtgen/detect_release_agent_file_container_escapes.yaml` |
| `e2e_tests/evtgen_suite/directory_traversal_monitored_file_read.yaml` | `tests/e2e/evtgen/directory_traversal_monitored_file_read.yaml` |
| `e2e_tests/evtgen_suite/disallowed_ssh_connection_non_standard_port.yaml` | `tests/e2e/evtgen/disallowed_ssh_connection_non_standard_port.yaml` |
| `e2e_tests/evtgen_suite/drop_and_execute_new_binary_in_container.yaml` | `tests/e2e/evtgen/drop_and_execute_new_binary_in_container.yaml` |
| `e2e_tests/evtgen_suite/execution_from_dev_shm.yaml` | `tests/e2e/evtgen/execution_from_dev_shm.yaml` |
| `e2e_tests/evtgen_suite/fileless_execution_via_memfd_create.yaml` | `tests/e2e/evtgen/fileless_execution_via_memfd_create.yaml` |
| `e2e_tests/evtgen_suite/find_aws_credentials.yaml` | `tests/e2e/evtgen/find_aws_credentials.yaml` |
| `e2e_tests/evtgen_suite/netcat_remote_code_execution_in_container.yaml` | `tests/e2e/evtgen/netcat_remote_code_execution_in_container.yaml` |
| `e2e_tests/evtgen_suite/packet_socket_created_in_container.yaml` | `tests/e2e/evtgen/packet_socket_created_in_container.yaml` |
| `e2e_tests/evtgen_suite/read_sensitive_file_trusted_after_startup.yaml` | `tests/e2e/evtgen/read_sensitive_file_trusted_after_startup.yaml` |
| `e2e_tests/evtgen_suite/read_sensitive_file_untrusted.yaml` | `tests/e2e/evtgen/read_sensitive_file_untrusted.yaml` |
| `e2e_tests/evtgen_suite/redirect_stdout_stdin_to_network_connection_in_container.yaml` | `tests/e2e/evtgen/redirect_stdout_stdin_to_network_connection_in_container.yaml` |
| `e2e_tests/evtgen_suite/remove_bulk_data_from_disk.yaml` | `tests/e2e/evtgen/remove_bulk_data_from_disk.yaml` |
| `e2e_tests/evtgen_suite/run_shell_untrusted.yaml` | `tests/e2e/evtgen/run_shell_untrusted.yaml` |
| `e2e_tests/evtgen_suite/search_private_keys_or_passwords.yaml` | `tests/e2e/evtgen/search_private_keys_or_passwords.yaml` |
| `e2e_tests/evtgen_suite/system_user_interactive.yaml` | `tests/e2e/evtgen/system_user_interactive.yaml` |

E2E glob (minimum mapping from plan):

| Falco pattern | Rustagon target |
|---------------|-----------------|
| `e2e_tests/evtgen_suite/*.yaml` | `tests/e2e/evtgen/` runner |
