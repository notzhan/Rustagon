# Rustagon evtgen runner

This workspace test crate vendors the 20 YAML files from Falco tip's
`e2e_tests/evtgen_suite`. It parses `tests`, expands both `matrix` and `vector`
cases, and recursively resolves `%{ item.* }` values while preserving exact
template values such as `null` and mappings.

## Offline tests

The default test suite needs no root privileges or Linux capabilities:

```sh
cargo test -p rustagon-e2e-evtgen
```

`all_twenty_evtgen_fixtures_match_offline` is table-driven over every suite
file. It selects the first expanded HostRunner case, builds its process,
container, file-descriptor, and syscall state through `rustagon_sinsp`, and
evaluates the synthetic event with `rustagon_engine`. For every suite it checks
the alert rule, priority, source, and all fixture `outputFields`.

`fixtures/rules/all_evtgen_rules.yaml` contains minimal executable excerpts
derived from falcosecurity/rules. The excerpts preserve each representative's
core observable signal while deliberately narrowing lists and conditions to
fields available in Rustagon's offline model.

## Live test

A live `ModernEbpfSource` test remains deferred. All 20 suites below are
offline-only: the Phase 4 source can attach with an eBPF object and
CAP_BPF/root, but current `sys_enter` records do not carry enough event
arguments and process/container metadata to reproduce these assertions.

To extend a suite to live coverage, add capture decoding for its syscall and
arguments, enrich the resulting event with process/FD/container state, execute
the HostRunner resources and steps in an isolated privileged test, and reuse
the same rule/source/priority/output-field assertions. Do not replace the
offline result until that privileged path passes.

## Fixture inventory (20)

- `clear_log_activities.yaml`
- `create_hardlink_over_sensitive_files.yaml`
- `create_symlink_over_sensitive_files.yaml`
- `debugfs_launched_in_privileged_container.yaml`
- `detect_release_agent_file_container_escapes.yaml`
- `directory_traversal_monitored_file_read.yaml`
- `disallowed_ssh_connection_non_standard_port.yaml`
- `drop_and_execute_new_binary_in_container.yaml`
- `execution_from_dev_shm.yaml`
- `fileless_execution_via_memfd_create.yaml`
- `find_aws_credentials.yaml`
- `netcat_remote_code_execution_in_container.yaml`
- `packet_socket_created_in_container.yaml`
- `read_sensitive_file_trusted_after_startup.yaml`
- `read_sensitive_file_untrusted.yaml`
- `redirect_stdout_stdin_to_network_connection_in_container.yaml`
- `remove_bulk_data_from_disk.yaml`
- `run_shell_untrusted.yaml`
- `search_private_keys_or_passwords.yaml`
- `system_user_interactive.yaml`
