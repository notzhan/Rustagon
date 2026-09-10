# Task 2.1 report: Falco configuration loader

## Result

Added the pure-Serde `rustagon-config` workspace crate and ported 15 Falco
configuration cases. The loader accepts the current tip `falco.yaml` without
pulling in `aya` or eBPF runtime dependencies.

## Implemented

- Typed public schema for stable configuration keys, including rules files,
  engine selection, plugins, output channels, webserver, priority, JSON output,
  rule selection, and append-output options.
- `FalcoConfig::load_from_str`, `load_from_file`, and dotted
  `apply_cli_override`.
- `config_files` scalar/list syntax, relative paths, missing-path skipping,
  directory expansion, secondary-include rejection, and append/override/add-only
  merge strategies.
- IPv4/IPv6 validation for `webserver.listen_address`.
- Unknown tip keys are retained in `FalcoConfig::extra` for forward
  compatibility.

## TDD evidence

The initial targeted run failed with unresolved `FalcoConfig` and
`RuleSelectionOperation` imports. After implementation:

`cargo test -p rustagon-config --test configuration`: 15 passed, 0 failed.

## Ported cases

Malformed YAML; stable scalar keys; engine; five output channels; valid and
invalid webserver addresses; plugin init config; ordered rule selection;
append-output; nested CLI overrides; include mapping override; default sequence
append; explicit sequence override; secondary include rejection; and loading
the repository tip `falco.yaml`.

## Remaining concerns

This batch does not yet port the full environment-variable expansion behavior,
escaped dotted-key syntax, schema diagnostics, plugin path traversal checks, or
CLI sequence append syntax from the remaining Falco configuration tests.

## Batch 2

Ported 15 more cases (30 total): scalar, embedded, repeated, escaped, undefined,
recursive, typed, and plugin-field environment expansion; JSON-string and null
plugin init configs; rejected relative plugin path traversal while allowing
absolute paths; missing/self config includes; and `append_output[]` CLI options.

The targeted test first failed in 11 new behavior cases, then passed all 30
after implementation. `falco_unit_app` is now 30/81 (37.0%).

Remaining gaps include schema validation diagnostics, escaped dotted-key
read/write syntax, wrong-strategy fallback diagnostics, config-file CLI loading,
and the reload/watch behavior that depends on the application runtime.

## Batch 2 review fix

Falco maps `init_config: null` to an empty string (`""`), not YAML null. Updated
`deserialize_plugin_init_config` to return `Value::String("")` for null input,
and adjusted `plugin_init_config_accepts_null_as_empty` to assert empty-string
semantics matching Falco.

## Batch 3

Ported 15 more cases (45 total): configuration reload and generic field reads;
escaped dotted, bracketed, and backslash key reads/writes/errors; complete,
relative-main, invalid-strategy fallback, scalar, empty, directory, and CLI
config-file loading; rule-selection CLI scalar/object forms; and fuller
append-output CLI parsing.

The new test target first failed because the YAML helper, retained merged
document access, validation warnings, and config-file CLI loader were absent.
After implementation, all 45 `rustagon-config` integration tests pass.
`falco_unit_app` is now 45/81 (55.6%).

Remaining gaps include schema validation diagnostics, config-file watch/reload
integration with the application runtime, and any unported environment edge
cases.

## Batch 4

Ported all 6 remaining `test_configuration_schema.cpp` cases:
`schema_validate_config`, `schema_ok`, `schema_wrong_key`, `schema_wrong_type`,
`schema_wrong_embedded_key`, and `schema_yaml_helper_validator`.

The crate now embeds Falco's draft-06 configuration schema from upstream tip
`c42269e0975caf66134644cb83c66c82dc76afe2`, validates loaded YAML while
preserving Falco's warning semantics, exposes explicit none/ok/failed statuses,
and strongly parses `falco_libs` so an invalid scalar node remains a load error.
Format assertions are disabled to match Falco's acceptance of the empty default
HTTP URL in `falco.yaml`.

The new target first failed on the absent schema API, then exposed the format
compatibility difference before all 6 cases passed. All 51 `rustagon-config`
integration tests pass. `falco_unit_app` is now 51/81 (63.0%).

Configuration parity is now largely exhausted; the main remaining config work
is app-runtime watch/reload/capture behavior. The remaining app inventory is
approximately 30 cases, most requiring Task 2.2 CLI/runtime or pure signal and
restart-handler seams.
