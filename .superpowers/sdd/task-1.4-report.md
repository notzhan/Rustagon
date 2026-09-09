# Task 1.4 report — batch 1

## Ported and passing

- `rule_override_append`
- `rule_append`
- `rule_override_replace`
- `rule_override_append_replace`
- `rule_incorrect_override_type`
- `rule_incorrect_append_override`
- `macro_override_append_before_macro_definition`
- `macro_append_before_macro_definition`

The tests mirror Falco's YAML, success/failure expectations, compiled or raw rule
conditions, rule metadata, deprecation warnings, schema status, and required
error substrings.

## Engine changes

- Added per-rule description, raw condition, output, and normalized priority metadata.
- Added field-level rule append/replace handling and deprecated `append: true` support.
- Preserved warnings on semantic load failures and distinguished schema-valid semantic
  errors from YAML parse errors.

## Verification

- `cargo test -p rustagon-engine`: 18 passed, 0 failed.
- Approximately 94 of the 104 `test_rule_loader.cpp` cases remain for later batches
  (counting the two previously ported cases, `list_append` and `condition_append`).

- Updated `parity/METRICS.md`: `falco_unit_engine` Pass 10, Total 152, 6.6%.

## Batch 2

### Ported and passing

- `macro_override_replace_before_macro_definition`
- `macro_override_append_after_macro_definition`
- `macro_append_after_macro_definition`
- `rule_override_append_before_rule_definition`
- `rule_override_replace_before_rule_definition`
- `rule_append_before_rule_definition`
- `rule_override_append_after_rule_definition`
- `rule_append_after_rule_definition`
- `list_override_append_wrong_key`
- `list_override_append_before_list_definition`

### Engine changes

- Reject list appends when no prior list definition exists.
- Distinguish missing-rule append and replace diagnostics.
- Preserve successful loads while reporting schema failure for unknown YAML keys.
- Normalize comma spacing in compiled conditions.

### Verification

- `cargo test -p rustagon-engine`: 28 passed, 0 failed.
- Updated `parity/METRICS.md`: `falco_unit_engine` Pass 20, Total 152, 13.2%.

## Batch 3

### Ported and passing

- `list_override_replace_before_list_definition`
- `list_append_before_list_definition`
- `list_override_append_after_list_definition`
- `list_append_after_list_definition`
- `rule_override_without_field`
- `rule_override_extra_field`
- `missing_enabled_key_with_override`
- `rule_override_with_enabled`
- `rule_not_enabled`
- `empty_append_rule_is_rejected`

### Engine changes

- Added rule enabled-state loading and field-level enabled replacement.
- Excluded disabled rules from the compiled ruleset.
- Added Falco-compatible diagnostics for absent override values, unexpected
  override fields, and empty legacy rule appends.

### Verification

- `cargo test -p rustagon-engine`: 38 passed, 0 failed.
- Updated `parity/METRICS.md`: `falco_unit_engine` Pass 30, Total 152, 19.7%.

## Batch 4

### Ported and passing

- `rule_override_exceptions_required_fields`
- `rule_enabled_warning`
- `rewrite_rule`
- `rule_enabled_is_ignored_by_append`

### Engine changes

- Validate that replacement and initial exception definitions include `fields`,
  while retaining Falco's allowance for partial append definitions.
- Support the deprecated standalone `enabled` update and emit Falco's warning.

### Blocked

- The six requested evt.type warning cases require semantic condition analysis:
  determining the set of matching event types, recognizing statically
  unsatisfiable expressions, contradictions, and unsatisfiable expanded macros.
  The current engine only normalizes condition strings, so fixture-specific
  string matching would fake parity rather than implement the subsystem.

### Verification

- TDD red run: 2 passed, 2 failed for the two missing behaviors.
- `cargo test -p rustagon-engine`: 42 passed, 0 failed.
- Updated `parity/METRICS.md`: `falco_unit_engine` Pass 44
  (`20 + 10 + 10 + 4`), Total 152, 28.9%.

## Metrics correction (post batch 4)

- Corrected `parity/METRICS.md`: `falco_unit_engine` Pass 34 (`30 + 4`), Total 152, 22.4%.
- Prior entry overstated pass count (44 / 28.9%); batch 4 adds 4 cases to batch 3's 30.

## Batch 5

### Ported and passing

- `required_engine_version_semver`
- `required_engine_version_not_semver`
- `required_engine_version_invalid`
- `list_value_with_escaping`
- `macro_name_invalid`
- `list_name_invalid`
- `exceptions_condition`
- `exceptions_append_no_values`
- `exceptions_override_no_values`
- `exceptions_names_not_unique`

### Engine changes

- Validate semantic and legacy numeric required-engine versions against Falco tip's
  engine version `0.65.0`, with Falco-compatible invalid-version diagnostics.
- Preserve quoting for whitespace-containing list values during condition compilation,
  and warn for invalid macro/list names and unused lists.
- Compile the requested single-field exception condition and support warnings for
  value-less exception appends and duplicate exception names.
- Validate exception mapping keys so typoed `value` entries produce failed schema
  validation while the load remains successful, matching Falco.

### Verification

- TDD red run: 10 failed for the ten missing behaviors; escaped-list compilation
  received an additional focused red/green cycle.
- Targeted green run: 10 passed, 0 failed.
- `cargo test -p rustagon-engine`: 52 passed, 0 failed.
- Updated `parity/METRICS.md`: `falco_unit_engine` Pass 44 (`34 + 10`),
  Total 152, 28.9%.

### Concern

- Exception condition compilation currently covers the tuple/list shape exercised by
  `exceptions_condition`; broader Falco exception operators and value shapes remain
  outside this batch.
