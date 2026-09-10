use rustagon_engine::FalcoEngine;

fn load_exception(value: &str, quoted: bool) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let value = if quoted {
        format!("\"{value}\"")
    } else {
        value.to_string()
    };
    load(&format!(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - [{value}]
"#
    ))
}

fn load_field(field: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    load(&format!(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: ["{field}"]
      comps: [=]
      values:
        - [test]
"#
    ))
}

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

fn assert_condition(engine: &FalcoEngine, expected: &str) {
    assert_eq!(engine.compiled_condition("test_rule"), Some(expected));
}

#[test]
fn exceptions_values_rhs_field_ambiguous() {
    let (engine, result) = load_exception("proc.pname", false);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(&engine, "(evt.type = open and not proc.name = proc.pname)");
    assert!(result.warnings.iter().any(|warning| warning
        .contains("'proc.pname' may be a valid field misused as a const string value")));
}

#[test]
fn exceptions_values_rhs_field_ambiguous_quoted() {
    let (engine, result) = load_exception("proc.pname", true);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(&engine, "(evt.type = open and not proc.name = proc.pname)");
    assert!(result.warnings.iter().any(|warning| warning
        .contains("'proc.pname' may be a valid field misused as a const string value")));
}

#[test]
fn exceptions_values_rhs_field_ambiguous_space_quoted() {
    let (engine, result) = load_exception("proc.pname ", true);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(
        &engine,
        "(evt.type = open and not proc.name = \"proc.pname \")",
    );
    assert!(result.warnings.iter().any(|warning| warning
        .contains("'proc.pname ' may be a valid field misused as a const string value")));
}

#[test]
fn exceptions_values_rhs_transformer() {
    let (engine, result) = load_exception("toupper(proc.pname)", false);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(
        &engine,
        "(evt.type = open and not proc.name = toupper(proc.pname))",
    );
}

#[test]
fn exceptions_values_transformer_value_quoted() {
    let (engine, result) = load_exception("toupper(proc.pname)", true);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(
        &engine,
        "(evt.type = open and not proc.name = toupper(proc.pname))",
    );
}

#[test]
fn exceptions_values_transformer_space() {
    let (engine, result) = load_exception("toupper( proc.pname)", false);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(
        &engine,
        "(evt.type = open and not proc.name = \"toupper( proc.pname)\")",
    );
    assert!(result.warnings.iter().any(|warning| warning.contains(
        "'toupper( proc.pname)' may be a valid field transformer misused as a const string value"
    )));
}

#[test]
fn exceptions_values_transformer_space_quoted() {
    let (engine, result) = load_exception("toupper( proc.pname)", true);
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_condition(
        &engine,
        "(evt.type = open and not proc.name = \"toupper( proc.pname)\")",
    );
    assert!(result.warnings.iter().any(|warning| warning.contains(
        "'toupper( proc.pname)' may be a valid field transformer misused as a const string value"
    )));
}

#[test]
fn exceptions_fields_transformer() {
    let (engine, result) = load_field("tolower(proc.name)");
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
    assert_condition(
        &engine,
        "(evt.type = open and not tolower(proc.name) = test)",
    );
}

#[test]
fn exceptions_fields_transformer_quoted() {
    let (engine, result) = load_field("tolower(proc.name)");
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
    assert_condition(
        &engine,
        "(evt.type = open and not tolower(proc.name) = test)",
    );
}

#[test]
fn exceptions_fields_transformer_space_quoted() {
    let (engine, result) = load_field("tolower( proc.name)");
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
    assert_condition(
        &engine,
        "(evt.type = open and not tolower(proc.name) = test)",
    );
}
