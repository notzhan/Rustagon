use rustagon_engine::FalcoEngine;

const WARNING_ENABLED: &str = "The standalone 'enabled' key usage is deprecated";

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

#[test]
fn rule_override_exceptions_required_fields() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  exceptions:
    - name: test_exception
      fields: proc.name
      comps: in
      values: ["cat"]
- rule: test_rule
  exceptions:
    - name: test_exception
      values: [echo]
  override:
    exceptions: append
- rule: test_rule
  exceptions:
    - name: test_exception
      values: [id]
  override:
    exceptions: replace
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Item has no mapping for key 'fields'")));
}

#[test]
fn rule_enabled_warning() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
- rule: test_rule
  enabled: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains(WARNING_ENABLED)));
    assert_eq!(engine.ruleset.rules.len(), 1);
}

#[test]
fn rewrite_rule() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
- rule: test_rule
  desc: redefined rule syntax
  condition: proc.name = cat
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: WARNING
  enabled: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(engine.ruleset.rules.len(), 1);
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(proc.name = cat)")
    );
}

#[test]
fn rule_enabled_is_ignored_by_append() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
- rule: test_rule
  condition: and proc.name = cat
  append: true
  enabled: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(engine.ruleset.rules.len(), 0);
}
