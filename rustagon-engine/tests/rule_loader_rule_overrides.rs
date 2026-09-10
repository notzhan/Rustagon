use rustagon_engine::FalcoEngine;

const DEPRECATED_APPEND: &str = "'append' key is deprecated";

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

#[test]
fn rule_override_append() {
    let (engine, result) = load(
        r#"
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: legit_rule
  desc: with append
  condition: and proc.name = cat
  output: proc=%proc.name
  override:
    desc: append
    condition: append
    output: append
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(!result
        .warnings
        .iter()
        .any(|w| w.contains(DEPRECATED_APPEND)));
    let rule = engine.rule_details("legit_rule").unwrap();
    assert_eq!(rule.condition, "evt.type=open and proc.name = cat");
    assert_eq!(
        rule.output.as_deref(),
        Some("user=%user.name command=%proc.cmdline file=%fd.name proc=%proc.name")
    );
    assert_eq!(
        rule.description.as_deref(),
        Some("legit rule description with append")
    );
}

#[test]
fn rule_append() {
    let (engine, result) = load(
        r#"
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: legit_rule
  condition: and proc.name = cat
  append: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains(DEPRECATED_APPEND)));
    assert_eq!(
        engine.compiled_condition("legit_rule"),
        Some("(evt.type = open and proc.name = cat)")
    );
}

#[test]
fn rule_override_replace() {
    let (engine, result) = load(
        r#"
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: legit_rule
  desc: a replaced legit description
  condition: evt.type = close
  override:
    desc: replace
    condition: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    let rule = engine.rule_details("legit_rule").unwrap();
    assert_eq!(rule.condition, "evt.type = close");
    assert_eq!(
        rule.output.as_deref(),
        Some("user=%user.name command=%proc.cmdline file=%fd.name")
    );
    assert_eq!(
        rule.description.as_deref(),
        Some("a replaced legit description")
    );
}

#[test]
fn rule_override_append_replace() {
    let (engine, result) = load(
        r#"
- rule: legit_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: legit_rule
  desc: a replaced legit description
  condition: and proc.name = cat
  priority: WARNING
  override:
    desc: replace
    condition: append
    priority: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    let rule = engine.rule_details("legit_rule").unwrap();
    assert_eq!(rule.condition, "evt.type = close and proc.name = cat");
    assert_eq!(
        rule.output.as_deref(),
        Some("user=%user.name command=%proc.cmdline file=%fd.name")
    );
    assert_eq!(
        rule.description.as_deref(),
        Some("a replaced legit description")
    );
    assert_eq!(rule.priority.as_deref(), Some("Warning"));
}

#[test]
fn rule_incorrect_override_type() {
    let (_, result) = load(
        r#"
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: failing_rule
  desc: an appended incorrect field
  condition: and proc.name = cat
  priority: WARNING
  override:
    desc: replace
    condition: append
    priority: append
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.errors.iter().any(|e| {
        e.contains("Key 'priority' cannot be appended to, use 'replace' instead")
            && e.contains("priority: append")
    }));
}

#[test]
fn rule_incorrect_append_override() {
    let (_, result) = load(
        r#"
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: failing_rule
  desc: an appended incorrect field
  condition: and proc.name = cat
  append: true
  override:
    desc: replace
    condition: append
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains(DEPRECATED_APPEND)));
    assert!(result
        .errors
        .iter()
        .any(|e| { e.contains("Keys 'override' and 'append: true' cannot be used together") }));
}

#[test]
fn macro_override_append_before_macro_definition() {
    let (_, result) = load(
        r#"
- macro: open_simple
  condition: or evt.type = openat2
  override:
    condition: append
- macro: open_simple
  condition: evt.type in (open,openat)
- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.errors.iter().any(|e| {
        e.contains(
            "Macro uses 'append' or 'override.condition: append' but no macro by that name already exists",
        )
    }));
}

#[test]
fn macro_append_before_macro_definition() {
    let (_, result) = load(
        r#"
- macro: open_simple
  condition: or evt.type = openat2
  append: true
- macro: open_simple
  condition: evt.type in (open,openat)
- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains(DEPRECATED_APPEND)));
    assert!(result.errors.iter().any(|e| {
        e.contains(
            "Macro uses 'append' or 'override.condition: append' but no macro by that name already exists",
        )
    }));
}
