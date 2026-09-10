# Rustagon eBPF build notes

The Phase 4 probes currently target Linux x86_64 and require kernel 5.8 or
newer because they use `BPF_MAP_TYPE_RINGBUF`. Attach `rustagon_sys_enter` to
`raw_syscalls/sys_enter` and `rustagon_process_exit` to
`sched/sched_process_exit`.

Building requires a nightly Rust toolchain, its `rust-src` component, and
`bpf-linker` on `PATH`:

```sh
rustup component add rust-src --toolchain nightly
# Install a prebuilt bpf-linker release from aya-rs/bpf-linker.
cargo xtask build-ebpf
cargo xtask check-ebpf
```

The target is `bpfel-unknown-none`; xtask passes `-Z build-std=core`.
Syscall numbers are currently the Linux x86_64 ABI values. Add an
architecture-specific mapping before loading these programs on another
architecture.

Records begin with `rustagon_common::ppm::PpmEventHeader` and then contain the
raw syscall number and first four arguments. This fixed bridge envelope is not
the final variable-length Falco parameter encoding; that conversion belongs to
the Phase 4 userspace consumer.
