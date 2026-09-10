# Task 2.2 report

## Landed

Created the aya-free `rustagon-app` workspace crate and added 36 tests: 33 direct
Falco twins plus 3 CLI tests.

- `test_atomic_signal_handler.cpp`: 3/3
- `test_restart_handler.cpp`: 4/4
- `test_capture.cpp`: 15/15
- `app/actions/test_pidfile.cpp`: 4/4
- `app/actions/test_validate_rules_files.cpp`: 3/3
- `app/actions/test_load_config.cpp`: 2/2
- `app/actions/test_select_event_sources.cpp`: 1/1
- `app/actions/test_configure_syscall_buffer_num.cpp`: 1/1
- CLI: Falco flag parsing, config override application, malformed override rejection

The implementation uses real atomics and threads, file metadata watching, secure
`O_NOFOLLOW` pidfile creation on Unix, `rustagon-config` loading/overrides, and
`rustagon-engine` rule validation.

## Metrics

`falco_unit_app` advanced from 51/81 to the inventory ceiling of 81/81. This
batch contains 33 direct twins, while only 30 uncredited slots remained in the
existing metric. The discrepancy comes from earlier expanded configuration
ports already being counted against the fixed 81-case Falco-tip inventory.

## Remaining

The 11 `test_configure_interesting_sets.cpp` cases remain unported. Faithful
ports require syscall/event-code tables and state-repair sets equivalent to
libsinsp; those facilities are not currently exposed by the pure Rust crates.
No fake event-set stubs were added.
