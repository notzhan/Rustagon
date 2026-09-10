# Task 4.4 report: drop counters and interesting syscalls config

## Implemented

- Added typed `syscall_event_drops` and `base_syscalls` models to
  `rustagon-config`, including Falco defaults for drop threshold/rate/burst.
- Wired typed `base_syscalls` values into the existing
  `InterestingSetsConfig` selection behavior.
- Added cloneable atomic drop accounting in `rustagon-scap` for buffer-full,
  parse-failure, and filtered losses.
- `ModernEbpfSource` now counts malformed ring records as parse failures and
  exposes a shared counter handle.
- Exposed snapshots through `rustagon-app` metrics with Falco-tip keys
  `n_drops`, `n_drops_buffer_total`, and `n_drops_bug`; the Rustagon-specific
  filtered counter is emitted as `n_drops_filtered`.

## TDD and verification

- RED: new tests failed on absent config fields, drop counter types,
  parse-accounting helper, config conversion, and metrics integration.
- GREEN: `cargo test -p rustagon-scap -p rustagon-config -p rustagon-app`
  passes (one privileged live BPF test remains ignored).
- `cargo clippy -p rustagon-scap -p rustagon-config -p rustagon-app \
  --all-targets -- -D warnings` passes.
- `git diff --check` passes. Workspace-wide `cargo fmt --check` still reports
  pre-existing formatting drift in unrelated core/parser files; all changed
  Task 4.4 Rust files were formatted directly.

## Self-review and Phase 4 status

- Counter clones share atomics and snapshots are coherent per field for
  monotonic metrics; relaxed ordering is sufficient for independent counters.
- Ring-buffer reserve failures occur in kernel space and are not observable
  through Aya's userspace `RingBuf`, so buffer-full accounting is exposed for
  a future kernel counter-map bridge rather than incremented speculatively.
- `n_drops_filtered` is an explicit Rustagon extension; the other three metric
  keys match Falco tip.
- Acceptance is met. Phase 4 is complete; live CAP_BPF smoke remains optional
  and ignored.
