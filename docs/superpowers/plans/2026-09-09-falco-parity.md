# Falco Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Spec:** `docs/superpowers/specs/2026-09-09-falco-parity-design.md`
>
> **Falco tree:** `/nvraid1tank1/work/code/falco` (track tip continuously). Design-time tip: `c0b24e3f`.

**Goal:** Ship Rustagon as a pure-Rust drop-in Falco replacement: rules/`falco.yaml`/CLI compatible, Falco-repo unit+E2E 100% green, libs behavioral-equivalent tests 100% green, plugins later in pure Rust.

**Architecture:** Compatibility-gate vertical slices — engine offline → app/config/outputs → sinsp fields → aya modern_ebpf → e2e → plugins. Tokio userspace, Aya eBPF, `#[repr(C)]` shared events, no libscap/libsinsp.

**Tech Stack:** Rust 1.80+, Tokio, Aya/`aya-ebpf`, serde_yaml, nom (filter grammar), clap, tracing, crossbeam; Cargo workspace.

## Global Constraints

- Pure Rust only: forbid `libbpf-sys`, libscap, libsinsp, and other C/C++ `-sys` wrappers (see `.cursor/rules.md`).
- Userspace async-first on Tokio; no blocking I/O on async tasks.
- Kernel↔userspace shared types must be `#[repr(C)]`; eBPF has no heap allocation.
- Hard gates: Falco `unit_tests/engine`, `unit_tests/falco`, `e2e_tests` (evtgen) must reach 100%; libs covered by Rust behavioral suite (not libs C++ gtests).
- Track local falco tip; update `FALCO_TIP` pin when syncing.
- Plugins: parse config and error clearly until pure-Rust plugin milestone.

---

## File Structure (target workspace)

```text
Rustagon/
├── FALCO_TIP                          # pinned falco commit + notes
├── parity/
│   ├── METRICS.md                     # pass/total counters
│   ├── falco-fixtures/                # copied/symlinked YAML from falco tests
│   └── scripts/
│       ├── audit-deps.sh
│       └── sync-falco-tip.sh
├── rustagon-common/                   # #[repr(C)] events, PPM ids (evolves)
├── rustagon-ebpf/                     # aya-ebpf modern_ebpf
├── rustagon-scap/                     # NEW: EventSource trait + sources
├── rustagon-sinsp/                    # NEW: enrichment + field extractors
├── rustagon-engine/                   # NEW: falco engine (absorbs parser)
├── rustagon-parser/                   # filter grammar; re-exported by engine
├── rustagon-core/ → binary `rustagon` # app: CLI, config, outputs, metrics
├── xtask/                             # build-ebpf, parity-report, audit
└── docs/superpowers/{specs,plans}/
```

---

## Phase map (execute in order)

| Phase | Gate metric | Exit criterion |
|-------|-------------|----------------|
| 0 Scaffolding | harness exists | tip pin, dep audit, metrics file, crate stubs compile |
| 1 Engine | `falco_unit_engine` | 100% engine unit cases green |
| 2 App/config/outputs | `falco_unit_app` | 100% falco unit cases green |
| 3 Sinsp/libs-equiv | `libs_equiv` | 100% behavioral suite green |
| 4 Capture (scap+ebpf) | live events | modern_ebpf produces enriched evt stream |
| 5 E2E | `e2e_evtgen` | 100% evtgen suite green |
| 6 Hardening | ops | hot reload, drops/metrics parity, packaging alias |
| 7 Plugins (follow-on) | plugin tests | pure-Rust SDK + priority built-ins |

---

### Task 0.1: Tip pin + parity metrics scaffold

**Files:**
- Create: `FALCO_TIP`
- Create: `parity/METRICS.md`
- Create: `parity/scripts/sync-falco-tip.sh`
- Create: `parity/scripts/audit-deps.sh`

**Interfaces:**
- Produces: `FALCO_TIP` format consumed by CI/docs; metrics table updated every phase

- [ ] **Step 1: Write `FALCO_TIP`**

```text
commit=c0b24e3f2b9daaa60a0b85f23db5748fa3d2a5d4
describe=0.44.0-rc1-60-gc0b24e3f
engine_version=0.65.0
libs_version=0.26.0-rc1
path=/nvraid1tank1/work/code/falco
synced_utc=2026-09-09T00:00:00Z
```

- [ ] **Step 2: Write `parity/METRICS.md`**

```markdown
# Rustagon ↔ Falco Parity Metrics

| Suite | Pass | Total | % |
|-------|------|-------|---|
| falco_unit_engine | 0 | TBD | 0 |
| falco_unit_app | 0 | TBD | 0 |
| libs_equiv | 0 | TBD | 0 |
| e2e_evtgen | 0 | TBD | 0 |

Totals filled in Task 0.3 after inventory.
```

- [ ] **Step 3: Write sync + audit scripts**

`parity/scripts/sync-falco-tip.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
FALCO_PATH="${FALCO_PATH:-/nvraid1tank1/work/code/falco}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
commit=$(git -C "$FALCO_PATH" rev-parse HEAD)
describe=$(git -C "$FALCO_PATH" describe --tags --always)
{
  echo "commit=$commit"
  echo "describe=$describe"
  echo "engine_version=$(rg -n 'FALCO_ENGINE_VERSION_MINOR' "$FALCO_PATH/userspace/engine/falco_engine_version.h" | head -1)"
  echo "libs_version=see falco cmake pin"
  echo "path=$FALCO_PATH"
  echo "synced_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$ROOT/FALCO_TIP"
echo "Updated $ROOT/FALCO_TIP -> $commit"
```

`parity/scripts/audit-deps.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
FORBIDDEN='libbpf-sys|libscap|libsinsp|falcosecurity-libs|bpf-sys'
if cargo metadata --format-version 1 --no-deps >/dev/null 2>&1; then
  if cargo tree 2>/dev/null | rg -i "$FORBIDDEN"; then
    echo "FORBIDDEN dependency detected" >&2
    exit 1
  fi
fi
echo "dependency audit OK"
```

- [ ] **Step 4: Make scripts executable and run audit**

```bash
chmod +x parity/scripts/*.sh
./parity/scripts/audit-deps.sh
```

Expected: `dependency audit OK`

- [ ] **Step 5: Commit**

```bash
git add FALCO_TIP parity/METRICS.md parity/scripts
git commit -m "chore: add Falco tip pin and parity scaffolding"
```

---

### Task 0.2: Inventory Falco tests and fill totals

**Files:**
- Modify: `parity/METRICS.md`
- Create: `parity/INVENTORY.md`

**Interfaces:**
- Produces: exact test counts and file→Rust mapping list for Phases 1–2 and 5

- [ ] **Step 1: Count tests from falco tip**

```bash
FALCO=/nvraid1tank1/work/code/falco
rg -c "TEST(_F)?\\(" "$FALCO/unit_tests/engine" -g '*.cpp' | awk -F: '{s+=$2} END{print "engine",s}'
rg -c "TEST(_F)?\\(" "$FALCO/unit_tests/falco" -g '*.cpp' | awk -F: '{s+=$2} END{print "falco",s}'
ls "$FALCO/e2e_tests/evtgen_suite"/*.yaml | wc -l
```

- [ ] **Step 2: Write `parity/INVENTORY.md` listing each engine/app test file and target Rust test module**

Map at minimum:

| Falco file | Rustagon target |
|------------|-----------------|
| `unit_tests/engine/test_rule_loader.cpp` | `rustagon-engine/tests/rule_loader.rs` |
| `unit_tests/engine/test_filter_macro_resolver.cpp` | `rustagon-engine/tests/filter_macro_resolver.rs` |
| `unit_tests/engine/test_rulesets.cpp` | `rustagon-engine/tests/rulesets.rs` |
| `unit_tests/engine/test_enable_rule.cpp` | `rustagon-engine/tests/enable_rule.rs` |
| `unit_tests/engine/test_list_fields.cpp` | `rustagon-engine/tests/list_fields.rs` |
| `unit_tests/falco/test_configuration*.cpp` | `rustagon-core/tests/configuration*.rs` |
| `e2e_tests/evtgen_suite/*.yaml` | `tests/e2e/evtgen/` runner |

- [ ] **Step 3: Update `parity/METRICS.md` totals from Step 1**

- [ ] **Step 4: Commit**

```bash
git add parity/INVENTORY.md parity/METRICS.md
git commit -m "docs: inventory Falco tip tests for parity gates"
```

---

### Task 0.3: Create `rustagon-engine` crate skeleton

**Files:**
- Create: `rustagon-engine/Cargo.toml`
- Create: `rustagon-engine/src/lib.rs`
- Create: `rustagon-engine/src/load_result.rs`
- Create: `rustagon-engine/src/engine.rs`
- Modify: `Cargo.toml` (workspace members)
- Modify: `rustagon-parser/Cargo.toml` if needed for path deps

**Interfaces:**
- Produces:
  - `pub struct FalcoEngine { ... }`
  - `pub fn FalcoEngine::load_rules(&mut self, content: &str, name: &str) -> LoadResult`
  - `pub struct LoadResult { pub ok: bool, pub errors: Vec<String>, pub warnings: Vec<String> }`

- [ ] **Step 1: Add workspace member and crate files**

`rustagon-engine/Cargo.toml`:

```toml
[package]
name = "rustagon-engine"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
rustagon-common = { path = "../rustagon-common" }
rustagon-parser = { path = "../rustagon-parser" }
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
thiserror = "1.0"
nom = "7"

[dev-dependencies]
pretty_assertions = "1.4"
```

`rustagon-engine/src/lib.rs`:

```rust
mod engine;
mod load_result;

pub use engine::FalcoEngine;
pub use load_result::LoadResult;
```

- [ ] **Step 2: Write failing compile stub then minimal types**

`load_result.rs`:

```rust
#[derive(Debug, Default, Clone)]
pub struct LoadResult {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub schema_validation: String,
}

impl LoadResult {
    pub fn success() -> Self {
        Self {
            ok: true,
            schema_validation: "ok".into(),
            ..Default::default()
        }
    }
}
```

`engine.rs` minimal:

```rust
use crate::LoadResult;
use rustagon_parser::parse_rules;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct FalcoEngine {
    pub rules: HashMap<String, String>, // name -> compiled condition (placeholder)
}

impl FalcoEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_rules(&mut self, content: &str, _name: &str) -> LoadResult {
        match parse_rules(content) {
            Ok(def) => {
                for r in def.rules {
                    self.rules.insert(r.rule, r.condition);
                }
                LoadResult::success()
            }
            Err(e) => LoadResult {
                ok: false,
                errors: vec![e.to_string()],
                warnings: vec![],
                schema_validation: "failed".into(),
            },
        }
    }

    pub fn compiled_condition(&self, rule: &str) -> Option<&str> {
        self.rules.get(rule).map(String::as_str)
    }
}
```

- [ ] **Step 3: Register in workspace `Cargo.toml` members and build**

```bash
cargo build -p rustagon-engine
```

Expected: success

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml rustagon-engine
git commit -m "feat(engine): add rustagon-engine crate skeleton"
```

---

### Task 0.4: Create `rustagon-scap` and `rustagon-sinsp` stubs

**Files:**
- Create: `rustagon-scap/Cargo.toml`, `rustagon-scap/src/lib.rs`
- Create: `rustagon-sinsp/Cargo.toml`, `rustagon-sinsp/src/lib.rs`
- Modify: `Cargo.toml` workspace members

**Interfaces:**
- Produces:
  - `rustagon_scap::EventSource` async trait with `next_event(&mut self) -> Option<RawEvent>`
  - `rustagon_sinsp::Inspector::inject(&mut self, raw: RawEvent) -> Evt`
  - `rustagon_sinsp::Evt` with `get_field_as_string(&self, field: &str) -> Option<String>`

- [ ] **Step 1: Write failing tests for interfaces**

In `rustagon-sinsp/src/lib.rs` (with `#[cfg(test)]`):

```rust
#[test]
fn evt_field_stub_returns_none() {
    let evt = Evt::default();
    assert!(evt.get_field_as_string("proc.name").is_none());
}
```

- [ ] **Step 2: Implement minimal stubs**

`rustagon-scap/src/lib.rs`:

```rust
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub timestamp: u64,
    pub tid: i64,
    pub type_id: u16,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait EventSource: Send {
    async fn next_event(&mut self) -> Option<RawEvent>;
}

pub struct NodriverSource;

#[async_trait]
impl EventSource for NodriverSource {
    async fn next_event(&mut self) -> Option<RawEvent> {
        None
    }
}
```

`rustagon-sinsp/src/lib.rs`:

```rust
use rustagon_scap::RawEvent;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Evt {
    pub fields: HashMap<String, String>,
}

impl Evt {
    pub fn get_field_as_string(&self, field: &str) -> Option<String> {
        self.fields.get(field).cloned()
    }
}

#[derive(Debug, Default)]
pub struct Inspector;

impl Inspector {
    pub fn inject(&mut self, _raw: RawEvent) -> Evt {
        Evt::default()
    }
}
```

- [ ] **Step 3: Build**

```bash
cargo build -p rustagon-scap -p rustagon-sinsp
cargo test -p rustagon-sinsp
```

Expected: pass

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml rustagon-scap rustagon-sinsp
git commit -m "feat: add rustagon-scap and rustagon-sinsp stubs"
```

---

### Task 0.5: xtask parity-report + CI dep audit hook

**Files:**
- Modify: `xtask/src/main.rs`
- Create: `.github/workflows/parity.yml` (or extend existing CI)

**Interfaces:**
- Produces: `cargo xtask parity-report` prints metrics table from `parity/METRICS.md`

- [ ] **Step 1: Add `parity-report` subcommand that cats `parity/METRICS.md`**

- [ ] **Step 2: Add workflow step running `parity/scripts/audit-deps.sh` and `cargo test --workspace` (skip eBPF on CI if no bpf target)**

- [ ] **Step 3: Commit**

```bash
git commit -am "ci: add parity report and dependency audit"
```

---

## Phase 1 — Engine parity (`falco_unit_engine` → 100%)

### Task 1.1: Falco YAML document model (rule/macro/list/override)

**Files:**
- Modify: `rustagon-parser/src/parser.rs`
- Create: `rustagon-engine/src/rule_loader.rs`
- Test: `rustagon-engine/tests/rule_loader_list_append.rs`

**Interfaces:**
- Consumes: YAML multi-doc / sequence items with keys `rule`, `macro`, `list`, `override`
- Produces: `CompiledRuleset` with expanded macros/lists and override append/replace semantics

- [ ] **Step 1: Write failing test ported from Falco `list_append`**

```rust
// rustagon-engine/tests/rule_loader_list_append.rs
use rustagon_engine::FalcoEngine;

#[test]
fn list_append() {
    let yaml = r#"
- list: shell_binaries
  items: [ash, bash, csh, ksh, sh, tcsh, zsh, dash]
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open and proc.name in (shell_binaries)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- list: shell_binaries
  items: [pwsh]
  override:
    items: append
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "legit_rules.yaml");
    assert!(res.ok, "{:?}", res.errors);
    let cond = eng.compiled_condition("legit_rule").unwrap();
    assert_eq!(
        cond,
        "(evt.type = open and proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash, pwsh))"
    );
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
cargo test -p rustagon-engine list_append -- --nocapture
```

- [ ] **Step 3: Implement YAML item enum + list append in rule_loader; expand lists into compiled condition string**

Replace naive `parse_rules` path so engine loader understands `- list:` / `- macro:` / `- rule:` maps (Falco uses a YAML sequence, not only `---`).

- [ ] **Step 4: Re-run until PASS**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(engine): support list append override (Falco list_append)"
```

---

### Task 1.2: Macro expansion + condition append override

**Files:**
- Modify: `rustagon-engine/src/rule_loader.rs`
- Create: `rustagon-engine/src/macro_resolver.rs`
- Test: `rustagon-engine/tests/rule_loader_condition_append.rs`

**Interfaces:**
- Produces: `resolve_macros(condition: &str, macros: &HashMap<String, String>) -> Result<String, Error>`

- [ ] **Step 1: Port Falco `condition_append` test (see `test_rule_loader.cpp`) as Rust test**

- [ ] **Step 2: FAIL → implement macro table + `override.condition: append` → PASS**

- [ ] **Step 3: Commit** `feat(engine): macro expansion and condition append`

---

### Task 1.3: Filter expression parser (Falco filter language)

**Files:**
- Create: `rustagon-parser/src/filter/ast.rs`
- Create: `rustagon-parser/src/filter/parse.rs`
- Create: `rustagon-parser/src/filter/print.rs` (canonical string for compiled_condition asserts)
- Test: `rustagon-parser/tests/filter_parse_basic.rs`

**Interfaces:**
- Produces:
  - `pub enum Expr { And(Box<Expr>, Box<Expr>), Or(...), Not(...), Binary { field, op, value }, ... }`
  - `pub fn parse_filter(input: &str) -> Result<Expr, FilterError>`
  - `pub fn print_filter(expr: &Expr) -> String` (stable spacing matching Falco expectations)

- [ ] **Step 1: Write failing tests for `evt.type=open`, `proc.name in (a, b)`, `and`/`or`/`not`, nested parens**

```rust
use rustagon_parser::filter::{parse_filter, print_filter};

#[test]
fn parse_evt_type_eq() {
    let e = parse_filter("evt.type=open").unwrap();
    assert_eq!(print_filter(&e), "evt.type = open");
}
```

- [ ] **Step 2: Implement nom grammar covering Falco operators: `= != < <= > >= contains startswith endswith in pmatch exists glob`**

- [ ] **Step 3: `cargo test -p rustagon-parser` PASS → commit `feat(parser): Falco filter expression grammar`

---

### Task 1.4: Port remaining `test_rule_loader.cpp` cases

**Files:**
- Test: `rustagon-engine/tests/rule_loader_*.rs` (split by case groups)
- Modify: loader/override/exception handling as required

**Interfaces:**
- Consumes: fixtures mirrored from `/nvraid1tank1/work/code/falco/unit_tests/engine/test_rule_loader.cpp`
- Gate: every `TEST_F(test_falco_engine, ...)` in that file has a Rust twin

- [ ] **Step 1: Extract case names from falco file into checklist in `parity/INVENTORY.md`**

- [ ] **Step 2: For each case: write FAILING Rust test → implement → PASS → commit in small batches (5–10 cases)**

- [ ] **Step 3: Update `parity/METRICS.md` engine pass count

---

### Task 1.5: Macro resolver unit suite

**Files:**
- Test: `rustagon-engine/tests/filter_macro_resolver.rs`
- Source of truth: `falco/unit_tests/engine/test_filter_macro_resolver.cpp`

- [ ] Port all macro resolver TESTs one-by-one (TDD) until 100% of that file is green
- [ ] Commit `test(engine): port filter_macro_resolver suite`

---

### Task 1.6: Filter details + warning resolvers

**Files:**
- Create: `rustagon-engine/src/filter_details.rs`
- Create: `rustagon-engine/src/filter_warnings.rs`
- Tests from `test_filter_details_resolver.cpp`, `test_filter_warning_resolver.cpp`

- [ ] TDD port all cases → commit when file suites are green

---

### Task 1.7: Rulesets, enable/disable, extra output, list fields, utils, sources, plugins requirements

**Files:**
- `rustagon-engine/src/ruleset.rs`
- `rustagon-engine/src/enable.rs`
- `rustagon-engine/src/formats.rs`
- `rustagon-engine/src/fields.rs`
- Tests mirrored from:
  - `test_rulesets.cpp`
  - `test_enable_rule.cpp`
  - `test_extra_output.cpp`
  - `test_list_fields.cpp`
  - `test_falco_utils.cpp`
  - `test_add_source.cpp`
  - `test_plugin_requirements.cpp` (assert clear “plugin not implemented” / requirement checks without loading `.so`)
  - `test_alt_rule_loader.cpp`

**Interfaces:**
- Produces:
  - `FalcoEngine::enable_rule(substr, enabled, ruleset)`
  - `FalcoEngine::enable_rule_exact` / `enable_rule_wildcard`
  - `FalcoEngine::list_fields(source, verbose, names_only) -> String`
  - `FalcoEngine::process_event(evt, ruleset_id) -> Option<Alert>` (may stub match until Phase 3 fields exist; tests that only need load/enable must pass now)

- [ ] Port each file suite to 100% for load/enable/list APIs
- [ ] For match-dependent tests: introduce `Evt` field map double until sinsp is ready
- [ ] Update metrics; Phase 1 exit when `falco_unit_engine_pass == total`

---

## Phase 2 — App / config / outputs (`falco_unit_app` → 100%)

### Task 2.1: `falco.yaml` loader compatible with tip schema

**Files:**
- Create: `rustagon-core/src/config.rs`
- Create: `rustagon-core/src/config_schema.rs`
- Test: `rustagon-core/tests/configuration.rs` (+ split files mirroring falco)

**Interfaces:**
- Produces: `pub struct FalcoConfig { ... }` with Stable keys from tip `falco.yaml` index (rules_files, engine.kind, outputs, webserver, priority, json_output, load_plugins, …)
- `FalcoConfig::load_from_file(path) -> Result<Self, ConfigError>`
- `FalcoConfig::apply_cli_override(key, value)`

- [ ] **Step 1: Port first failing test from `test_configuration.cpp`**

- [ ] **Step 2: Implement serde model + includes (`config_files`) semantics**

- [ ] **Step 3: Continue file-by-file:**
  - `test_configuration_config_files.cpp`
  - `test_configuration_env_vars.cpp`
  - `test_configuration_output_options.cpp`
  - `test_configuration_rule_selection.cpp`
  - `test_configuration_schema.cpp`
  - fixtures under `unit_tests/falco/test_configs/`

- [ ] Commit in batches; update `falco_unit_app` metrics

---

### Task 2.2: CLI parity (clap)

**Files:**
- Modify: `rustagon-core/src/main.rs`
- Create: `rustagon-core/src/cli.rs`

**Interfaces:**
- Flags (minimum): `-c/--config`, `-r/--rules`, `-o` key=value overrides, `--list`, `--list-events`, `--validate`, `-V/--version`, `--dry-run` if present on tip

- [ ] Add clap definitions matching tip help text where practical
- [ ] Tests invoking CLI via `assert_cmd` / binary tests
- [ ] Commit `feat(cli): Falco-compatible flags`

---

### Task 2.3: Outputs channel parity

**Files:**
- Create: `rustagon-core/src/outputs/{mod,stdout,file,syslog,http,program}.rs`
- Tests from falco output-related unit coverage

**Interfaces:**
- `pub trait Output: Send { async fn deliver(&self, alert: &Alert) -> Result<(), OutputError>; }`
- Fan-out via `tokio::sync::mpsc`

- [ ] Implement stdout/file first (unit-testable), then http/syslog/program
- [ ] Match tip JSON field names when `json_output: true`

---

### Task 2.4: Webserver, metrics, restart, capture, signal handler unit suites

**Files:**
- `rustagon-core/src/webserver.rs`
- `rustagon-core/src/metrics.rs`
- `rustagon-core/src/restart.rs`
- Port: `test_restart_handler.cpp`, `test_capture.cpp`, `test_atomic_signal_handler.cpp`, `unit_tests/falco/app/**`

- [ ] TDD until `falco_unit_app` 100%
- [ ] Plugin config: parse `load_plugins` / `plugins` and return explicit error if enabled but not implemented

---

## Phase 3 — Sinsp / libs behavioral equivalence (`libs_equiv` → 100%)

### Task 3.1: Event + field registry

**Files:**
- `rustagon-sinsp/src/fields/mod.rs`
- `rustagon-sinsp/src/fields/evt.rs`, `proc.rs`, `fd.rs`, `user.rs`, `container.rs`
- `parity/libs_equiv/FIELDS.md` checklist vs tip `--list` output

**Interfaces:**
- `Inspector::get_field_names() -> Vec<FieldInfo>`
- `Evt::get_field_as_string` / typed getters
- Align names with Falco/libs syscall source fields used by official rules

- [ ] Generate baseline field list: run tip falco `--list` (or document from falco tree) into `parity/libs_equiv/fields_tip.txt`
- [ ] Implement fields incrementally with unit tests per field group
- [ ] Track `libs_equiv` metrics by field-group tests

---

### Task 3.2: Process table / thread table

**Files:**
- `rustagon-sinsp/src/proc_table.rs`
- `rustagon-sinsp/src/thread_info.rs`

**Interfaces:**
- On exec/clone/exit events, maintain `tid -> ThreadInfo { pid, ppid, comm, exe, args, ... }`
- Fields: `proc.name`, `proc.pname`, `proc.exepath`, `proc.cmdline`, `proc.pid`, `proc.ppid`, `proc.aname`, …

- [ ] Write behavioral tests constructing synthetic `RawEvent` sequences
- [ ] Commit when process-lineage field tests pass

---

### Task 3.3: FD table + file/net fields

**Files:**
- `rustagon-sinsp/src/fdtable.rs`

- [ ] Track open/close/dup/connect/accept; expose `fd.name`, `fd.type`, `fd.sip`, `fd.sport`, …
- [ ] Behavioral tests for path and socket tuples

---

### Task 3.4: Container metadata (pure Rust, no plugin .so)

**Files:**
- `rustagon-sinsp/src/container.rs`

- [ ] Read container id from cgroup; map to name/image via containerd/docker socket **using pure Rust clients** (or filesystem-only MVP first)
- [ ] Fields: `container.id`, `container.name`, `container.image`, …
- [ ] Tests with fixtures; mark socket integration tests `#[ignore]` in CI without runtime

---

### Task 3.5: Wire engine `process_event` to real `Evt`

**Files:**
- `rustagon-engine/src/engine.rs`
- `rustagon-engine/src/eval.rs`

- [ ] Evaluate compiled filters against `Evt` extractors
- [ ] Re-enable any Phase 1 tests that were using doubles
- [ ] `libs_equiv` → 100% then exit Phase 3

---

## Phase 4 — Capture path (scap + aya modern_ebpf)

### Task 4.1: Shared PPM-compatible event encoding in `rustagon-common`

**Files:**
- Expand `rustagon-common` with tip-aligned event type IDs / param layouts needed by rules (document mapping table in `rustagon-common/src/ppm.rs`)

- [ ] Keep `#[repr(C)]`; fixed-size buffers only for eBPF-visible structs
- [ ] Unit tests for sizes/alignment (`std::mem::size_of`)

---

### Task 4.2: eBPF programs for interesting syscalls

**Files:**
- `rustagon-ebpf/src/lib.rs` (+ modules per event family)
- Build via `cargo xtask build-ebpf`

**Interfaces:**
- RingBuf records matching `rustagon-common` headers
- Userspace loader in `rustagon-scap/src/modern_ebpf.rs`

- [ ] Start with execve/openat/connect/accept/close/clone/exit
- [ ] Expand set until official rules’ `evt.type` requirements for e2e are covered
- [ ] Verifier-clean build on supported kernels (document minimum in README)

---

### Task 4.3: Async RingBuf consumer

**Files:**
- `rustagon-scap/src/modern_ebpf.rs`
- Modify: `rustagon-core/src/daemon.rs`, `ringbuf.rs`

**Interfaces:**
- `ModernEbpfSource::attach() -> Result<Self>`
- `impl EventSource for ModernEbpfSource`
- Pipeline: source → sinsp → engine → outputs via `tokio::sync::mpsc`

- [ ] Integration smoke test (root): exec a binary and observe one enriched event
- [ ] Commit `feat(scap): aya modern_ebpf event source`

---

### Task 4.4: Drop counters + interesting syscalls config

**Files:**
- Map tip `base_syscalls` / `syscall_event_drops` / metrics keys in config to runtime behavior

- [ ] Unit tests for drop accounting
- [ ] Commit when metrics keys align with tip names used in unit tests

---

## Phase 5 — E2E evtgen (`e2e_evtgen` → 100%)

### Task 5.1: evtgen runner for Rustagon

**Files:**
- Create: `tests/e2e/evtgen/runner.rs` or `xtask` subcommand `e2e-evtgen`
- Create: `tests/e2e/evtgen/README.md`
- Fixtures: symlink or copy `/nvraid1tank1/work/code/falco/e2e_tests/evtgen_suite/*.yaml`

**Interfaces:**
- Parse evtgen YAML (`tests`, `rule`, `expectedOutcome`, `cases` matrix)
- Spawn process trees per `HostRunner` context
- Assert Rustagon alert matches `priority`, `outputFields`, `source`

- [ ] Implement matrix expansion
- [ ] Run one scenario `run_shell_untrusted.yaml` end-to-end (root)
- [ ] Commit runner

---

### Task 5.2: Green all evtgen YAML files

**Files:** all `e2e_tests/evtgen_suite/*.yaml` (20 at design time; re-inventory on tip sync)

- [ ] For each YAML: run → fix engine/sinsp/ebpf gaps → pass → update metrics
- [ ] Optional: diff alert set vs tip Falco binary on same host
- [ ] Exit when `e2e_evtgen_pass == total`

---

## Phase 6 — Hardening & drop-in UX

### Task 6.1: Hot reload / watch_config_files / rules watch

- Mirror tip restart handler behavior covered by unit tests; commit when green

### Task 6.2: Packaging / symlink

- Document `rustagon` binary + optional `falco` symlink
- Provide example systemd unit compatible with tip paths (`/etc/falco/falco.yaml`)

### Task 6.3: Performance baseline

- Benchmark events/sec and RSS vs tip Falco under synthetic load; record in `parity/PERF.md`
- No regress gate until baseline exists; then keep within agreed band

### Task 6.4: Tip sync playbook

- Run `parity/scripts/sync-falco-tip.sh`
- Re-inventory tests; fix breakages before claiming parity on new tip

---

## Phase 7 — Pure-Rust plugins (follow-on)

### Task 7.1: Plugin SDK (Rust)

**Files:** `rustagon-plugin/` crate — trait for source/extractor plugins without C ABI

### Task 7.2: Priority built-ins

- container / k8smeta / json equivalents as in-tree crates
- Enable corresponding config samples; add tests; only then mark plugin-related falco cases that were skipped

---

## Self-review (plan vs spec)

| Spec requirement | Plan coverage |
|------------------|---------------|
| Rules compatible | Phase 1 loaders + filter + official rules via e2e |
| falco.yaml compatible | Phase 2 config |
| CLI compatible | Task 2.2 |
| Falco unit+E2E 100% | Phases 1, 2, 5 metrics |
| libs equiv Rust tests | Phase 3 |
| Pure Rust / Aya / Tokio / repr(C) | Global constraints + Phases 0/4 |
| Plugins later pure Rust | Phase 7; early clear errors in 2.4 / 1.7 |
| Track falco tip | Task 0.1 + 6.4 |

No intentional TBDs in task acceptance criteria; evtgen/file counts are re-inventoried in Task 0.2 when tip moves.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-09-falco-parity.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — execute in this session with executing-plans checkpoints  

Which approach?
