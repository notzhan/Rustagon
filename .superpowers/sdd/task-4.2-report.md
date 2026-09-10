# Task 4.2 report: eBPF programs for interesting syscalls

## Status

COMPLETE. The Aya 0.2 eBPF crate builds and checks through xtask.

## Implementation

- Replaced the obsolete Aya ring-buffer API with
  `RingBuf::with_byte_size`, typed `reserve`, `MaybeUninit::write`, and
  entry-owned `submit`.
- Added `rustagon_sys_enter` for `raw_syscalls/sys_enter`. On Linux x86_64 it
  selects openat, execve/execveat, connect, accept/accept4, close,
  clone/clone3, and fork.
- Added `rustagon_process_exit` for `sched/sched_process_exit`.
- Added a packed fixed-size `StarterSyscallEvent`. Every record begins with
  `rustagon_common::ppm::PpmEventHeader`, uses the Phase 4 PPM event ID, and
  carries the syscall number plus four raw arguments.
- Corrected xtask from the nonexistent `bpfel64-unknown-none` target to
  `bpfel-unknown-none` and enabled `-Z build-std=core`.
- Documented the Linux 5.8+, x86_64, nightly Rust, rust-src, and bpf-linker
  requirements in `rustagon-ebpf/BUILD.md`.

## Verification

- `cargo fmt -p rustagon-ebpf -p xtask -- --check`: pass.
- `cargo test -p rustagon-ebpf --lib`: pass, 2 tests.
- `cargo test -p rustagon-common ppm`: pass, 1 selected integration test.
- `cargo xtask check-ebpf`: pass.
- `cargo xtask build-ebpf`: pass.
- The output is an eBPF relocatable ELF with `tracepoint` and `maps` sections.

The environment initially lacked a usable linker and rust-src. Building
`bpf-linker` 0.11.1 from source failed because system `libLLVM` was absent; the
official x86_64 Linux musl release binary was installed instead. The nightly
`rust-src` component was then installed successfully.

## Self-review and limitations

- The implementation is intentionally x86_64 because raw syscall numbers are
  architecture-specific.
- Ring buffers require Linux 5.8 or newer.
- `bpf_ktime_get_ns` is monotonic; Task 4.3 must apply the boot-to-epoch
  conversion expected by the documented PPM timestamp semantics.
- The fixed bridge payload is not Falco's final parameter-length/payload wire
  encoding, and process exit does not yet collect exit status or reaper TID.
  Both are explicitly deferred to the userspace/full-encoding follow-up.
- Compilation and ELF inspection succeeded. No privileged kernel load was
  performed, so runtime verifier acceptance was not directly tested.
