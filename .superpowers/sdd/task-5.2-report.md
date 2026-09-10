# Task 5.2 report: Green all evtgen YAML files (offline)

## Status

Complete. The Phase 5 offline gate is green for all 20 vendored evtgen suite
YAML files. This does not claim live `modern_ebpf`/CAP_BPF coverage.

## Implementation

- Added a shared `run_offline_case` harness that selects one expanded
  representative per suite and constructs process, container, FD, and syscall
  state with `RawEvent`s and `Inspector`.
- Added 20 minimal executable rule excerpts derived from
  `falcosecurity/rules` at commit
  `724be6f2dacab9d3da1e5337dc814b2f92a67193`.
- Made the integration test inventory all 20 suite fixtures, expand each, run
  the first HostRunner case, and verify rule name, priority, source, and every
  declared `expectedOutcome.outputFields` value.
- Updated the evtgen README with the offline-only inventory and live extension
  path.
- Updated `parity/METRICS.md` from 0/20 to 20/20 with an explicit offline
  synthetic HostRunner footnote.

## TDD and verification

- RED: `cargo test -p rustagon-e2e-evtgen --test runner` failed because the
  shared `run_offline_case` API did not exist.
- GREEN: the runner passed for all 20 fixtures.
- A repeated runner test exposed and fixed nondeterministic overlap between
  directory traversal and untrusted sensitive-file rules.
- `cargo test -p rustagon-e2e-evtgen`: 3 tests passed, including 20/20 suite
  representatives.
- `cargo test --workspace`: passed; one privileged live eBPF test remains
  intentionally ignored.

## Self-review

- Fixture count and rule excerpt count are both exactly 20.
- The harness rejects unknown fixtures and non-HostRunner cases.
- Shared rules are mutually exclusive for the selected representatives.
- Synthetic event-only fields are confined to the offline harness where
  `RawEventKind` does not yet model link, symlink, socket arguments, users, or
  exec flags.
- `cargo fmt --all -- --check` remains blocked by pre-existing formatting in
  `rustagon-engine/tests/add_source.rs`; the changed evtgen crate is formatted.

## Remaining concern

All 20 suites remain offline-only. Live parity requires privileged HostRunner
execution plus capture decoding for full syscall arguments and
process/container metadata.
