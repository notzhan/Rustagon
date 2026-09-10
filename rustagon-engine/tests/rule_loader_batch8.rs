use rustagon_engine::FalcoEngine;

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

fn assert_unknown_key(yaml: &str, key: &str) {
    let (_, result) = load(yaml);
    assert!(result.ok, "{:?}", result.errors);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains(&format!("Unknown key '{key}'"))),
        "{:?}",
        result.warnings
    );
}

#[test]
fn rule_unknown_key() {
    assert_unknown_key(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  typo_field: some_value
"#,
        "typo_field",
    );
}

#[test]
fn list_unknown_key() {
    assert_unknown_key(
        r#"
- list: my_list
  items: [cat, bash]
  typo_field: some_value

- rule: test_rule
  desc: test rule description
  condition: evt.type = close and proc.name in (my_list)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
"#,
        "typo_field",
    );
}

#[test]
fn macro_unknown_key() {
    assert_unknown_key(
        r#"
- macro: my_macro
  condition: evt.type = close
  typo_field: some_value

- rule: test_rule
  desc: test rule description
  condition: my_macro
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
"#,
        "typo_field",
    );
}

#[test]
fn list_cross_type_key_priority() {
    let (_, result) = load(
        r#"
- list: my_list
  items: [cat, bash]
  priority: INFO

- rule: test_rule
  desc: test rule description
  condition: evt.type = close and proc.name in (my_list)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Unknown key 'priority'")));
}

#[test]
fn deprecated_field_in_output() {
    let (engine, result) = load(
        r#"
- rule: test_rule_with_evt_dir_in_output
  desc: test rule with evt.dir in output
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name evt.dir=%evt.dir
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.iter().any(|warning| warning
        .contains("usage of deprecated field 'evt.dir' has been detected in the rule output")));
    assert_eq!(engine.ruleset.rules.len(), 1);
}

#[test]
fn no_deprecated_field_warning_in_output() {
    let (engine, result) = load(
        r#"
- rule: test_rule_without_evt_dir
  desc: test rule without evt.dir in output
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(!result
        .warnings
        .iter()
        .any(|warning| warning.contains("evt.dir")));
    assert_eq!(engine.ruleset.rules.len(), 1);
}

#[test]
fn deprecated_evt_dir_folded_scalar_condition_snippet() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: >
    evt.type = close and evt.dir = <
  output: user=%user.name
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    let warning = result
        .warnings
        .iter()
        .find(|warning| warning.contains("evt.dir"))
        .expect("missing evt.dir warning");
    assert!(!warning.contains("condition: >"), "{warning}");
}

#[test]
fn deprecated_evt_dir_via_macro_folded_scalar_condition_snippet() {
    let (_, result) = load(
        r#"
- macro: spawned_process
  condition: evt.type in (execve, execveat) and evt.dir = <

- rule: test_rule
  desc: test rule
  condition: >
    spawned_process and proc.name = bash
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    let warning = result
        .warnings
        .iter()
        .find(|warning| warning.contains("evt.dir") && warning.contains("spawned_process"))
        .expect("missing deprecated warning with folded rule condition snippet");
    assert!(!warning.contains("condition: >"), "{warning}");
}

#[test]
fn rule_capture_enabled() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: WARNING
  capture: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(engine.rule_details("test_rule").unwrap().capture);
}

#[test]
fn rule_capture_disabled_by_default() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    let details = engine.rule_details("test_rule").unwrap();
    assert!(!details.capture);
    assert_eq!(details.capture_duration, 0);
}
