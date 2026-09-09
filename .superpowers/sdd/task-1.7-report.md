# Task 1.7 Report: Remaining Falco engine unit suites

Status: DONE_WITH_CONCERNS

## Delivered

- Ported all 28 remaining Falco engine cases:
  - 6 enable-rule cases
  - 5 extra-output cases
  - 4 field-listing cases
  - 4 utility cases
  - 4 alternate-loader cases
  - 2 plugin-requirement cases
  - 2 ruleset cases
  - 1 source-registration case
- Added named and numeric rulesets with substring, exact, wildcard, and tag selection.
- Added `Evt` field-map event processing and alert stubs, extra output formats and formatted fields, Markdown/JSON field listing, source registration/accessors, and utility helpers.
- Added alternate loader compile-output and hook models, including source and priority filtering.
- Added semantic plugin requirement and alternative-version checks. No plugin shared objects are loaded; failures explicitly state that plugin loading is not implemented.

## TDD and verification

- RED: each new suite initially failed on absent modules, types, or methods. The plugin overlap regression then failed because a duplicate primary/alternative name was incorrectly accepted.
- GREEN: `cargo test -p rustagon-parser -p rustagon-engine` passed all affected tests, including all 28 new cases.
- `cargo clippy -p rustagon-engine --tests -- -D warnings` passed.
- `cargo fmt -p rustagon-engine -- --check` and `git diff --check` passed.
- `cargo run -q -p xtask -- parity-report` reports `falco_unit_engine` **152 / 152 / 100%**.

## Concerns

- Full `cargo test --workspace` remains blocked outside this task by the existing `rustagon-ebpf` incompatibilities with aya 0.2.1: obsolete `RingBuf` construction/reserve/submit usage and `ProbeContext::arg` `Option` handling.
- Event processing is intentionally a Phase-1 field-map stub and currently evaluates direct equality conditions only; no `.so` plugin execution was introduced.
