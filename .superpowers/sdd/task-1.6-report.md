# Task 1.6 Report: Filter details + warning resolvers

Status: DONE_WITH_CONCERNS

## Delivered

- Added public filter details resolution for fields, macros, operators, lists, event names, and nested/single/multi-value transformers.
- Added unsafe `<NA>` and deprecated-field warning resolution, including fields wrapped by transformers.
- Extended the filter AST/parser/printer with macro identifiers, transformer operands and Falco's `==`, `icontains`, and `intersects` operators.
- Added a symbolic event-type analyzer (all, finite, or unsatisfiable event sets) and integrated it with rule loading and `warn_evttypes`.
- Implemented `warn_evttypes` defaults and replacement overrides.

## Falco cases ported

- 5/5 `test_filter_details_resolver.cpp` cases.
- 4/4 `test_filter_warning_resolver.cpp` cases.
- 6/6 deferred event-type warning cases from `test_rule_loader.cpp`.
- Total newly ported Falco cases: 15. One additional Rust assertion checks the warning kind.

## TDD and verification

- RED: `cargo test -p rustagon-engine --test filter_resolvers` failed on the absent resolver modules, operand AST, and constructors.
- GREEN: the same target passed 16/16 tests.
- Affected crates: `cargo test -p rustagon-parser -p rustagon-engine` passed all tests.
- Diff hygiene: `git diff --check` passed.
- Metrics: `falco_unit_engine` 124/152 (81.6%), up from 109/152.

## Concerns

- Full `cargo test --workspace` remains blocked outside this task by existing `rustagon-ebpf` incompatibilities with aya 0.2.1 (`RingBuf` constructor/reserve/submit APIs and `ProbeContext::arg` Option handling).
- Strict all-target clippy reaches one pre-existing parser test warning at `rustagon-parser/src/parser.rs:145` (`assert_eq!(bool, true)`); this task did not modify that file.

## Review fix: finite event-type threshold

- Updated the event-type warning predicate to match Falco's threshold: unconstrained conditions and resolved finite sets larger than 100 now warn.
- Added a public loader regression test covering the exact boundary: 100 distinct `evt.type in (...)` values do not warn, while 101 do.
- RED: the focused regression test failed because the 101-value set produced no warning.
- GREEN: the focused regression test passed after the predicate fix; `cargo test -p rustagon-engine` passed all engine tests.
- Formatting and whitespace checks passed for the touched Rust files and diff. Workspace-wide `cargo fmt --all -- --check` remains blocked by pre-existing formatting drift in unrelated crates.
