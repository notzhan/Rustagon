# Task 4.3 report: async RingBuf consumer

## Implemented

- Added `rustagon_scap::modern_ebpf::ModernEbpfSource`.
- `attach()` loads the xtask-built eBPF object with Aya 0.13, attaches
  `rustagon_sys_enter` and `rustagon_process_exit`, and registers `EVENTS`
  with Tokio `AsyncFd`.
- `EventSource::next_event()` drains the ring asynchronously and skips malformed
  records.
- Starter records are decoded field-by-field to avoid unaligned access to the
  packed PPM header. The PPM timestamp, TID, type ID, and bridge payload are
  preserved in `RawEvent`; supported event IDs map to the practical
  `RawEventKind` variant.
- `RUSTAGON_EBPF_OBJECT` overrides object discovery. Otherwise release then
  debug xtask output is searched.

## Verifier / attach evidence

`cargo xtask build-ebpf --release` succeeds. The ignored live test attempts
both program loads/attachments and triggers `openat`, but this host process is
UID 1000 with no permitted capabilities. Running the ignored test reached BPF
map creation and failed with `Operation not permitted (os error 1)`, before
verifier load. Run with root or CAP_BPF/CAP_PERFMON:

```sh
cargo test -p rustagon-scap \
  live_attach_is_verifier_clean_and_receives_an_event -- --ignored --nocapture
```

## Verification

- TDD red: parser/source symbols were absent and the new tests failed to
  compile for that reason.
- `cargo fmt --check -p rustagon-scap`
- `cargo clippy -p rustagon-scap --all-targets -- -D warnings`
- `cargo test -p rustagon-scap -p rustagon-sinsp -p rustagon-engine -p rustagon-app`
  (all pass; scap: 3 passed, 1 privileged test ignored)
- `cargo xtask check-ebpf`
- Full workspace testing still encounters the pre-existing `rustagon-core`
  failures called out in the task brief: missing `parse_rules_from_file` and
  an attempted clone of `tokio::sync::mpsc::Receiver`.

## Self-review

- No unsafe userspace decoding or libbpf dependency was introduced.
- Aya 0.13.1 is already lockfile-compatible with probe-side aya-ebpf 0.2.1.
- Entry-only probes cannot provide syscall return values or safely dereference
  captured pointers. Consequently open/accept use fd `-1`, and path/socket
  metadata is empty; full enrichment requires exit probes and kernel-side
  parameter capture in a later task.
