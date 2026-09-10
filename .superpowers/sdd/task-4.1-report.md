# Task 4.1 report: Shared PPM-compatible event encoding

## Implemented

- Added a `no_std` `rustagon_common::ppm` module.
- Added transparent, unknown-value-safe `PpmEventType` codes for the Phase 4
  starter set, pinned to falcosecurity/libs `0.26.0-rc1`.
- Selected the current event revisions used by that tag's syscall table
  (`EXECVE_19`, `OPENAT_2`, `CLONE_20`, `FORK_20`, `ACCEPT_5`,
  `ACCEPT4_6`, and `PROCEXIT_1`).
- Added the packed 26-byte `ppm_evt_hdr` wire layout and documented the PPM
  parameter-length/payload framing.
- Added parameter counts from `driver/event_table.c` and an inline mapping
  table from Falco names to Rustagon constants.
- Kept the existing `EventType` and legacy fixed-size event structs unchanged,
  leaving the new PPM capture path explicitly separated under `ppm`.

## TDD evidence

- RED: the new integration test initially failed because
  `rustagon_common::ppm` did not exist.
- GREEN: event ID, parameter count, size, and alignment tests passed after the
  minimal module was added.
- RED/GREEN: the header-constructor test failed with missing `new`, then passed
  after adding the constructor.

## Verification

- `cargo test -p rustagon-common`: pass (9 tests).
- `cargo check -p rustagon-common --lib`: pass; confirms the library builds as
  `no_std`.
- `cargo test -p rustagon-parser`: pass (15 tests).
- `cargo fmt -p rustagon-common -- --check`: pass.
- `cargo check -p rustagon-ebpf`: fails on pre-existing Aya 0.2 API usage and
  host no-std panic settings (`with_byte_capacity`, reserve/submit handling,
  `ProbeContext::arg` Option handling); no failure references the new PPM API.
- `cargo test --workspace --exclude rustagon-ebpf`: blocked by pre-existing
  `rustagon-core` errors (`parse_rules_from_file` missing and cloning an
  `mpsc::Receiver`).

## Self-review

- IDs and parameter counts were checked directly against the pinned tag's
  `ppm_events_public.h`, `syscall_table.c`, and `event_table.c`.
- The event-code newtype permits unknown wire values without enum-invalid-value
  undefined behavior.
- The packed header exactly matches Falco's 26-byte, alignment-1 wire ABI.
- Variable PPM payloads remain byte-encoded rather than introducing heap or
  variable-sized eBPF-visible structures.
