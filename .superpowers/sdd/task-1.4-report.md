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
