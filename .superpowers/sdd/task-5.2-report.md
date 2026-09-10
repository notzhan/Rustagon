# Task 5.2 report: Green all evtgen YAML files (offline)

## Status

Complete. The Phase 5 offline gate is green for all 20 vendored evtgen suite
YAML files with strengthened representative predicates. This remains synthetic
offline coverage and does not claim live `modern_ebpf`/CAP_BPF coverage.

## Implementation

- Added a shared `run_offline_case` harness that selects one expanded
  representative per suite and constructs process, container, FD, and syscall
  state with `RawEvent`s and `Inspector`.
- Added 20 executable rule excerpts derived from
  `falcosecurity/rules` at commit
  `724be6f2dacab9d3da1e5337dc814b2f92a67193`.
- Strengthened the excerpts to discriminate each selected representative using
  its core event, path, process, container, user, network, and argument fields.
  In particular, Clear Log now requires write plus `O_TRUNC`; debugfs requires
  a privileged container; release_agent requires write mode, root, and
  `CAP_SYS_ADMIN`; dropped binaries require upper-layer execution; and trusted
  sensitive-file reads require read mode and a process duration over five
  seconds.
- Extended the offline synthesizer with open flags, container privilege,
  effective capabilities, upper-layer and memfd execution markers, process
  duration, socket type, dup result/FD type, and the other fields consumed by
  the strengthened conditions.
- Made the integration test inventory all 20 suite fixtures, expand each, run
  the first HostRunner case, and verify rule name, priority, source, and every
  declared `expectedOutcome.outputFields` value.
- Updated the evtgen README with the offline-only inventory and live extension
  path.
- Updated `parity/METRICS.md` from 0/20 to 20/20 with an explicit offline
  synthetic HostRunner footnote.

## TDD and verification

- RED: `core_predicate_near_misses_do_not_match` failed because an open of the
  target log without `O_TRUNC` still matched Clear Log Activities.
- GREEN: the shared negative-control test now rejects three high-risk
  near-misses: non-truncating log open, debugfs in an unprivileged container,
  and execution of a base-image (non-upper-layer) binary in a container.
- `cargo test -p rustagon-e2e-evtgen`: 4 tests passed, including 20/20 suite
  representatives and the three near-miss controls.
- `cargo test --workspace`: passed; one privileged live eBPF test remains
  intentionally ignored.

## Self-review

- Fixture count and rule excerpt count are both exactly 20.
- The harness rejects unknown fixtures and non-HostRunner cases.
- Shared rules are mutually exclusive for the selected representatives.
- Synthetic event-only fields are confined to the offline harness where
  `RawEventKind` does not yet model link, symlink, open/socket arguments,
  users/capabilities, container privilege, process age, or executable-layer
  metadata.
- `cargo fmt --all -- --check` remains blocked by pre-existing formatting in
  `rustagon-engine/tests/add_source.rs`; the changed evtgen crate is formatted.

## Remaining concern

All 20 suites remain offline-only. Live parity requires privileged HostRunner
execution plus capture decoding for full syscall arguments and
process/container metadata.
