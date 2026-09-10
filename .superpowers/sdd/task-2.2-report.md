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

`falco_unit_app` is 70/81 (86.4%). The 70 passing cases are the mapped Falco-tip
inventory cases with Rustagon twins; supporting CLI and regression tests do not
increase this metric.

## Remaining

The 11 `test_configure_interesting_sets.cpp` cases remain unported. Faithful
ports require syscall/event-code tables and state-repair sets equivalent to
libsinsp; those facilities are not currently exposed by the pure Rust crates.
No fake event-set stubs were added.

## Phase 2 review fixes

- Corrected `parity/METRICS.md` to 70/81 (86.4%); the 11 unported
  `configure_interesting_sets` cases remain excluded from the pass count.
- Added the aya-free `rustagon-app` binary target. `--help` and `--version` are
  runnable, and `--validate` reads each rules file and validates it through
  `rustagon-engine`. Listing and daemon startup return explicit unsupported
  errors without attempting to load eBPF.
- Added three process-level CLI tests.
- Changed `AtomicSignalHandler::handle` so concurrent callers wait while the
  elected callback is active, plus a timing/concurrency regression test.

## Configure interesting sets completion

Ported all 11 cases from `test_configure_interesting_sets.cpp`. The pure-Rust
model extracts positive `evt.type` constraints from enabled engine rules, maps
the fixture's event/syscall names through a minimal static code table, and
implements Falco's base-set precedence: custom positive replacement, negative
removal (including the `accept`/`accept4` alias), high-volume I/O suppression,
state repair, and mandatory `procexit`.

TDD evidence: the new test target first failed because the model was absent,
then exposed and fixed negated-event extraction before reaching 11/11 passing.
`cargo test -p rustagon-engine -p rustagon-app` passes. The full workspace test
remains blocked by pre-existing `rustagon-ebpf` incompatibilities with the
installed Aya API; this implementation does not use Aya.

`falco_unit_app` is now 81/81 (100%).

## Configure interesting sets fidelity review

Corrected repair precedence to test the parsed positive syscall set, matching
Falco for negative-only and invalid-only custom sets. Added regressions for
both cases, expanded the static table and repair output with the process,
network, and file-state names asserted by the Falco fixture, and replaced
production-helper-derived assertions with explicit expected name sets.

The 11 cases remain useful regression coverage, but are not yet faithful
libsinsp twins: the Rust model still has only a fixture-sized PPM event table
and simplified `sinsp_state_sc_set`, generic-event expansion, architecture
mapping, and plugin parsing-event behavior. Accordingly `falco_unit_app` is
restored to 70/81 (86.4%); the 11 modeled tests remain excluded from Pass.
