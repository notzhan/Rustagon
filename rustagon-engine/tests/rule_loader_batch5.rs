use rustagon_engine::FalcoEngine;

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

fn disabled_rule() -> &'static str {
    r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
"#
}

#[test]
fn required_engine_version_semver() {
    let (_, result) = load(&format!(
        "- required_engine_version: 0.26.0\n{}",
        disabled_rule()
    ));
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
}

#[test]
fn required_engine_version_not_semver() {
    let (_, result) = load(&format!(
        "- required_engine_version: 26\n{}",
        disabled_rule()
    ));
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
}

#[test]
fn required_engine_version_invalid() {
    let (_, result) = load(&format!(
        "- required_engine_version: seven\n{}",
        disabled_rule()
    ));
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Unable to parse engine version")));
}

#[test]
fn list_value_with_escaping() {
    let (_, result) = load(
        r#"
- list: my_list
  items: [non_escaped_val, "escaped val"]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(!result.warnings.is_empty());

    let (engine, result) = load(
        r#"
- list: my_list
  items: [non_escaped_val, "escaped val"]
- rule: test_rule
  desc: test rule
  condition: proc.name in (my_list)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(proc.name in (non_escaped_val, \"escaped val\"))")
    );
}

#[test]
fn macro_name_invalid() {
    let (_, result) = load(
        r#"
- macro: test-macro
  condition: evt.type = close
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.iter().any(|warning| warning
        .contains("Macro has an invalid name. Macro names should match a regular expression")));
}

#[test]
fn list_name_invalid() {
    let (_, result) = load(
        r#"
- list: test list
  items: [open, openat, openat2]
- rule: test_rule
  desc: test rule description
  condition: evt.type in (test list)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.iter().any(|warning| warning
        .contains("List has an invalid name. List names should match a regular expression")));
}

#[test]
fn exceptions_condition() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl or proc.cmdline contains wget
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some(
            "((proc.cmdline contains curl or proc.cmdline contains wget) and not proc.cmdline contains \"curl 127.0.0.1\")"
        )
    );
}

fn rule_with_exception_and_override(override_yaml: &str) -> String {
    format!(
        r#"
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]
{override_yaml}
"#
    )
}

#[test]
fn exceptions_append_no_values() {
    let (_, result) = load(&rule_with_exception_and_override(
        r#"
- rule: test_rule
  exceptions:
    - name: test_exception
      value: curl 1.1.1.1
  append: true
"#,
    ));
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "failed");
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Overriding/appending exception with no values")));
}

#[test]
fn exceptions_override_no_values() {
    let (_, result) = load(&rule_with_exception_and_override(
        r#"
- rule: test_rule
  exceptions:
    - name: test_exception
      value: curl 1.1.1.1
  override:
    exceptions: append
"#,
    ));
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "failed");
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Overriding/appending exception with no values")));
}

#[test]
fn exceptions_names_not_unique() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]
    - name: test_exception
      fields: [proc.cmdline]
      comps: [endswith]
      values:
        - [curl 127.0.0.1]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Multiple definitions of exception")));
}
