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
