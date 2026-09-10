# Task 5.1 report — evtgen runner

## Delivered

- Added the `rustagon-e2e-evtgen` workspace integration crate.
- Vendored all 20 Falco 5.1.0 evtgen suite YAML fixtures.
- Parsed `tests[]` and expanded `matrix` Cartesian products and `vector`
  mappings.
- Resolved `%{ item.* }` recursively in context and expected output fields,
  preserving typed values for exact templates.
- Normalized Falco's bare `runIf: %{ item.runIf }` syntax before YAML parsing.
- Added a CI-safe offline HostRunner path for the direct `nginx -> bash`
  `Run shell untrusted` case.
- Checked rule name, NOTICE priority, syscall source, `proc.name=bash`, and
  `proc.pname=nginx` after synthetic `RawEvent` injection through Inspector and
  engine evaluation.

## Rule source

The full upstream rules repository was not present locally. The minimal
checked-in excerpt preserves the upstream core semantics needed by this case
(`spawned_process`, `shell_procs`, `proc.pname exists`, and protected spawner)
and cites:

https://github.com/falcosecurity/rules/blob/724be6f2dacab9d3da1e5337dc814b2f92a67193/rules/falco_rules.yaml

## Verification

- TDD parser red: unresolved `parse_suite` / `expand_suite`.
- TDD runner red: unresolved `run_shell_untrusted_offline`.
- Compatibility red: upstream bare template syntax initially failed YAML
  decoding; normalization fixed it.
- `cargo test -p rustagon-e2e-evtgen`: 4 passed.
- `cargo test --workspace`: passed; existing privileged eBPF test ignored.
- `cargo clippy -p rustagon-e2e-evtgen --all-targets -- -D warnings`: passed.
- `cargo fmt -p rustagon-e2e-evtgen -- --check && git diff --check`: passed.

## Live status and metrics

Live `ModernEbpfSource` execution is deferred: Phase 4 sys_enter records do not
yet provide exec process metadata for this assertion. No CAP_BPF claim was
made. `parity/METRICS.md` remains unchanged at `e2e_evtgen` 0/20.

## Self-review

The diff is scoped to the new workspace member and evtgen fixtures/runner.
The offline runner rejects unsupported runners/rules, validates rule-load
errors, compares expected metadata case-insensitively where appropriate, and
reports missing/mismatched output fields. No unrelated files or metrics were
changed.
