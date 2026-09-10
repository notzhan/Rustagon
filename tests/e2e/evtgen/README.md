# Rustagon evtgen runner

This workspace test crate vendors the 20 YAML files from Falco tip's
`e2e_tests/evtgen_suite`. It parses `tests`, expands both `matrix` and `vector`
cases, and recursively resolves `%{ item.* }` values while preserving exact
template values such as `null` and mappings.

## Offline test

The default test suite needs no root privileges or Linux capabilities:

```sh
cargo test -p rustagon-e2e-evtgen
```

`run_shell_untrusted_nginx_bash_matches_offline` selects the `nginx -> bash`
HostRunner matrix case, injects synthetic exec events through
`rustagon_sinsp::Inspector`, and evaluates the resulting event with
`rustagon_engine::FalcoEngine`. It checks the alert rule, NOTICE priority,
syscall source, `proc.name=bash`, and `proc.pname=nginx`.

The checked-in rule is a minimal executable excerpt of **Run shell untrusted**.
Its source and the deliberate narrowing needed by Rustagon's currently
available fields are recorded in `fixtures/run_shell_untrusted_rules.yaml`.

## Live test

A live `ModernEbpfSource` test is deferred. The Phase 4 source can attach when
an eBPF object and CAP_BPF/root are available, but its current `sys_enter`
records do not carry the exec process metadata needed to reproduce and assert
this scenario. Task 5.2 must add that live event fidelity before claiming an
evtgen scenario pass. The parity metric therefore remains 0/20.

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
