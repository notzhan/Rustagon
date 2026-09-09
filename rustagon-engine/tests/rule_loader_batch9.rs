use rustagon_engine::FalcoEngine;

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

fn load_compound_exception(
    field: &str,
    comp: &str,
    values: &str,
) -> (FalcoEngine, rustagon_engine::LoadResult) {
    load(&format!(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [{field}]
      comps: [{comp}]
      values:
        - [{values}]
"#
    ))
}

#[test]
fn rule_capture_duration() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: WARNING
  capture: true
  capture_duration: 10000
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.rule_details("test_rule").unwrap().capture_duration,
        10000
    );
}

#[test]
fn rule_override_capture_replace() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: WARNING
  capture: true

- rule: test_rule
  capture: false
  override:
    capture: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(!engine.rule_details("test_rule").unwrap().capture);
}

#[test]
fn rule_override_capture_duration_replace() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: WARNING
  capture: true
  capture_duration: 5000

- rule: test_rule
  capture_duration: 15000
  override:
    capture_duration: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.rule_details("test_rule").unwrap().capture_duration,
        15000
    );
}

#[test]
fn rule_capture_duration_wrong_type() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: INFO
  capture_duration: "not_a_number"
"#,
    );
    assert!(!result.ok);
}

#[test]
fn rule_capture_wrong_type() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = close
  output: user=%user.name
  priority: INFO
  capture: "yes"
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "failed");
}

#[test]
fn exceptions_modifier_op_startswith_oneof() {
    let (engine, result) =
        load_compound_exception("proc.name", "startswith oneof", "[sshd, sudo, systemd]");
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = open and not proc.name startswith oneof (sshd, sudo, systemd))")
    );
}

#[test]
fn exceptions_modifier_op_contains_allof() {
    let (engine, result) =
        load_compound_exception("proc.cmdline", "contains allof", "[curl, bash]");
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = open and not proc.cmdline contains allof (curl, bash))")
    );
}

#[test]
fn exceptions_modifier_op_endswith_anyof() {
    let (engine, result) = load_compound_exception("fd.name", "endswith anyof", "[.sh, .py, .pl]");
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = open and not fd.name endswith anyof (.sh, .py, .pl))")
    );
}

#[test]
fn exceptions_modifier_op_glob_oneof() {
    let (_, result) = load_compound_exception(
        "fd.name",
        "glob oneof",
        r#"["/tmp/*.sh", "/tmp/*.py", "/dev/shm/*.sh"]"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn exceptions_modifier_op_icontains_oneof() {
    let (_, result) = load_compound_exception(
        "proc.cmdline",
        "icontains oneof",
        "[MONITOR, HEALTHCHECK, PROBE]",
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}
