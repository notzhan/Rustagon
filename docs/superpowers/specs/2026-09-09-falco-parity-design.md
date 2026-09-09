# Rustagon: Pure-Rust Falco Parity Design

**Date:** 2026-09-09  
**Status:** Draft for review  
**Approach:** Compatibility-gate vertical slices (Approach 2)  
**Falco reference tree:** `/nvraid1tank1/work/code/falco` (track tip / `master` continuously)  
**Reference tip at design time:** `c0b24e3f` (`0.44.0-rc1-60-gc0b24e3f`), engine `0.65.0`, libs pin `0.26.0-rc1`

---

## 1. Goals

Rustagon is a **drop-in replacement** for CNCF Falco so existing Falco users can switch with minimal friction:

1. **Rules compatible** with official `falcosecurity/rules` and tip rule schema.
2. **Config compatible** with tip `falco.yaml` (Stable keys required; Incubating/Sandbox as needed for seamless ops).
3. **CLI behavior compatible** for common migration flags and discovery commands (`--list`, `--list-events`, validate, version/engine info).
4. **100% of Falco-repo tests green** as the hard gate: `unit_tests/engine`, `unit_tests/falco`, `e2e_tests` (including `evtgen_suite`).
5. **libs behavioral equivalence** covered by purpose-built Rust tests (do **not** run falcosecurity/libs C++ gtests directly).
6. **Plugins later in pure Rust** (no loading of existing C/Go `.so` plugins in v1 path); config must parse and fail clearly when a plugin is not yet implemented.
7. **100% pure Rust** stack per `.cursor/rules.md`: Aya/`aya-ebpf`, Tokio async userspace, `#[repr(C)]` shared events, no libscap/libsinsp/libbpf-sys.

Non-goals for the initial plugin phase:

- Loading third-party Falco plugin `.so` via the classic plugin ABI.
- Shipping a bit-identical C++ driver-loader / DKMS kmod path (default production path is `modern_ebpf` via Aya).

---

## 2. Success Criteria

| Criterion | Definition of done |
|-----------|-------------------|
| Falco unit (engine) | All tip `unit_tests/engine` cases pass against Rustagon (ported or harnessed) |
| Falco unit (app) | All tip `unit_tests/falco` cases pass |
| E2E | All tip `e2e_tests` / `evtgen_suite` scenarios pass on `modern_ebpf` |
| libs equiv | Documented behavioral suite for filter fields, process tree, container metadata, formatting — 100% of that suite green |
| Drop-in ops | Same rules + `falco.yaml` produce equivalent alerts for syscall-sourced workloads |
| Pure Rust | CI dependency audit fails on forbidden C/C++ `-sys` / scap / sinsp bindings |
| Tip sync | Each milestone records the falco git commit being tracked; regressions from tip updates are fixed before claiming parity |

---

## 3. Architecture

```text
falco.yaml / rules / CLI
        │
        ▼
┌─────────────────── rustagon (app) ───────────────────┐
│  config · outputs · webserver · metrics · lifecycle  │
│                      │                               │
│                      ▼                               │
│              rustagon-engine                         │
│     (rule load / macros / filter AST / match)        │
│                      ▲                               │
│                      │ enriched events               │
│              rustagon-sinsp                          │
│   (process tree · container/K8s fields · evt model)  │
│                      ▲                               │
│              rustagon-scap                           │
│         (event source abstraction)                   │
│           ┌──────────┴──────────┐                    │
│           ▼                     ▼                    │
│    rustagon-ebpf (aya)    nodriver / replay / stub   │
└──────────────────────────────────────────────────────┘
```

### Phase gates (in order)

1. **Engine offline** — rule/filter unit tests green without a live driver.
2. **App contract** — config/CLI/outputs unit tests green.
3. **libs equivalence** — enrichment/field behavioral tests green.
4. **E2E evtgen** — live `modern_ebpf` E2E green.
5. **Plugins** — config stubs first; pure-Rust plugins afterward (separate milestone).

---

## 4. Crate Responsibilities

Evolve the existing workspace; rename/split as needed while shipping one user-facing binary.

| Crate | Falco / libs analogue | Responsibility |
|-------|----------------------|----------------|
| `rustagon-common` | shared PPM / event headers | `#[repr(C)]` headers, event/syscall IDs, priorities, sources; no heap types required by eBPF |
| `rustagon-ebpf` | modern_bpf driver | `aya-ebpf` programs, RingBuf export, no heap allocation |
| `rustagon-scap` | libscap | `EventSource` trait: `modern_ebpf`, `nodriver`, scap replay; async ingest into lock-free channels |
| `rustagon-sinsp` | libsinsp | process tree, fd/file/net state, container (and later K8s) fields; `Evt` + field extractors; primary home of libs-equiv tests |
| `rustagon-engine` | `userspace/engine` | YAML rule load, macro/list/exception, filter compile/eval, ruleset indexing, engine version/checksum aligned to tip |
| `rustagon-parser` | filter grammar (fold into engine) | nom/pest grammar; public API owned by engine to avoid dual semantics |
| `rustagon` (from `rustagon-core`) | `userspace/falco` | CLI, `falco.yaml`, outputs, webserver, metrics, drop handling, hot reload; Tokio orchestration |
| `rustagon-plugin` (later) | plugins | pure-Rust plugin SDK + built-in replacements; early phase only parses `load_plugins` and errors clearly |
| `xtask` | build/CI helpers | eBPF build, Falco-harness runners, forbidden-dependency audit |

### Boundary rules

- Engine never opens eBPF maps; it only consumes enriched `Evt` values.
- Scap never evaluates rules; it only produces raw/semi-structured events.
- App is the sole composition root; engine/sinsp unit tests run without root.

### Project constraints (always on)

- No C/C++ library dependencies (`libbpf-sys`, libscap, libsinsp, etc.).
- Userspace I/O is async on Tokio; prefer `tokio::sync::mpsc` / crossbeam over long-held mutexes.
- Kernel↔userspace shared structs are `#[repr(C)]` with fixed-size fields in eBPF.

---

## 5. Data Flow

1. **Capture:** `rustagon-ebpf` → RingBuf → `rustagon-scap` async consumer → `mpsc` → sinsp.
2. **Enrich:** sinsp updates process/fd/container state and fills rule fields (`proc.*`, `fd.*`, `container.*`, `evt.*`, …).
3. **Match:** engine indexes rulesets by event type, evaluates filters, emits alerts (priority, rule name, output template, tags, fields).
4. **Output:** app fans out via lock-free queues to stdout / file / syslog / http / program; webserver and metrics read runtime state.

**Offline path:** `nodriver` or scap replay → same sinsp → engine → outputs pipeline (unit/E2E without root where possible).

---

## 6. Compatibility Contract

| Surface | Commitment |
|---------|------------|
| Config | Parse and honor tip `falco.yaml` Stable keys; unknown keys warn (configurable); default engine kind `modern_ebpf` |
| Rules | Load official rules; honor `required_engine_version`, macros, lists, exceptions per tip engine |
| CLI | Support migration-critical flags (`-c`, `-r`, `-o`, `--list`, `--list-events`, validate, version/engine); binary may be `rustagon` with optional `falco` symlink/alias |
| Outputs | Text/JSON shapes aligned with tip for existing SIEM/scripts |
| Plugins | Config parses; unimplemented pure-Rust plugins return explicit errors (never silent ignore) |
| Version sync | Document aligned falco git tip; refresh engine version / field lists when tip moves |

### Errors and degradation

- Rule/config load failures surface structured `load_result` analogues and non-zero exit.
- Event drops implement tip notification/metrics semantics.
- Driver unavailable: `nodriver` is for tests only; production path must fail loudly.

---

## 7. Testing Strategy

### Layer A — Falco-repo hard gate

Against local falco tip:

- Port or harness `unit_tests/engine` and `unit_tests/falco`.
- Run `e2e_tests` / `evtgen_suite` against Rustagon `modern_ebpf`.
- Prefer reusing YAML fixtures; rewrite C++ gtest bodies as Rust `cargo test` or a thin harness that drives Rustagon.

### Layer B — libs behavioral equivalence

Do not execute libs C++ gtests. Maintain an explicit Rust suite covering:

- Filter field availability and operators
- Process tree / lineage fields
- Container metadata fields
- Output formatting
- Interesting-syscall / event-set selection behavior

Each case cites the falco/libs behavior it mirrors.

### Layer C — engineering gates

- Dependency audit (forbidden crates)
- eBPF target build (no heap allocation)
- No blocking I/O on async hot paths
- Optional alert-set diff vs tip Falco on the same evtgen workload

### Progress metrics

Track publicly:

- `falco_unit_engine_pass / total`
- `falco_unit_app_pass / total`
- `libs_equiv_pass / total`
- `e2e_evtgen_pass / total`

A phase is complete only when its ratio is 100%, then the next phase starts.

### Tip synchronization

On each milestone (or scheduled sync), record the falco commit under test. When tip changes schemas or tests, update harness/contracts first, then implementation.

---

## 8. Implementation Phases (outline for the forthcoming plan)

Detailed bite-sized tasks will live in `docs/superpowers/plans/` after this spec is approved. High-level order:

1. **Harness + metrics scaffolding** — CI counters, forbidden-dep audit, falco tip pin file.
2. **Engine parity** — rule loader, filter AST, macros/lists/exceptions → engine unit tests → 100%.
3. **App/config/outputs parity** — `falco.yaml`, CLI, outputs, webserver/metrics stubs as required by app unit tests → 100%.
4. **Sinsp field model** — evt model + extractors + libs-equiv suite → 100%.
5. **Scap + Aya modern_ebpf** — RingBuf path, interesting syscalls, drop metrics.
6. **E2E evtgen** — full suite green; optional Falco diff gate.
7. **Hardening** — hot reload, performance baselines, packaging/symlink story.
8. **Plugins (follow-on)** — pure-Rust SDK + priority built-ins (container/k8smeta/…); enable related tests afterward.

---

## 9. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Tip moves faster than Rustagon | Pin file + sync checklist; fail CI when harness expects a newer tip than implemented |
| Filter/field subtle mismatches | Golden tests from falco fixtures; alert-set diff on evtgen |
| eBPF verifier / kernel variance | Document minimum kernel; CI on representative kernels; keep programs minimal |
| Scope creep into plugin ABI | Explicit non-goal until phase 8; config errors instead of partial FFI |
| Dual parser/engine semantics | Single public engine API; fold `rustagon-parser` behind it |

---

## 10. Decisions Log

| Decision | Choice |
|----------|--------|
| Product bar | Seamless switch for Falco users (rules + config + tests) |
| Plugins | Pure Rust later; no classic `.so` ABI in early phases |
| Test corpus | Falco repo unit/E2E hard gate + libs behavioral-equivalent Rust tests |
| Version tracking | Follow local falco tip continuously |
| Delivery strategy | Compatibility-gate vertical slices (Approach 2) |

---

## 11. Next Step

After human review/approval of this spec, produce the detailed implementation task list via the writing-plans skill at:

`docs/superpowers/plans/2026-09-09-falco-parity.md`

Then submit that plan to GitHub and execute phase-by-phase.
