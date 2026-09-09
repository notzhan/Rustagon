use rustagon_engine::FalcoEngine;

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

fn assert_rejected(yaml: &str, message: &str) {
    let (_, result) = load(yaml);
    assert!(!result.ok, "expected rejection, got: {:?}", result);
    assert!(
        result.errors.iter().any(|error| error.contains(message)),
        "expected error containing {message:?}, got {:?}",
        result.errors
    );
}

#[test]
fn exceptions_modifier_op_multi_field_mixed() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name, fd.name]
      comps: [startswith oneof, startswith]
      values:
        - [[sshd, sudo], /etc/]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some(
            "(evt.type = open and not (proc.name startswith oneof (sshd, sudo) and fd.name startswith /etc/))"
        )
    );
}

#[test]
fn exceptions_modifier_op_multi_field_both_compound() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.exepath, fd.name]
      comps: [endswith anyof, glob oneof]
      values:
        - [[/dpkg, /rpm, /pip], ["/tmp/*.deb", "/tmp/*.rpm"]]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn exceptions_modifier_op_invalid_base_operator() {
    assert_rejected(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name]
      comps: [frobulate oneof]
      values:
        - [[bash]]
"#,
        "'frobulate oneof' is not a supported comparison operator",
    );
}

#[test]
fn exceptions_modifier_op_invalid_base_operator_scalar_field() {
    assert_rejected(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: proc.name
      comps: frobulate oneof
      values:
        - [bash]
"#,
        "comps must be one of",
    );
}

#[test]
fn exceptions_modifier_op_list_op_with_modifier() {
    assert_rejected(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name]
      comps: [in oneof]
      values:
        - [[bash]]
"#,
        "'in oneof' is not a supported comparison operator",
    );
}

#[test]
fn exceptions_modifier_op_numeric_op_with_modifier() {
    assert_rejected(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.pid]
      comps: [">= oneof"]
      values:
        - [[1000]]
"#,
        "'>= oneof' is not a supported comparison operator",
    );
}

#[test]
fn exceptions_modifier_op_modifier_alone() {
    assert_rejected(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name]
      comps: [oneof]
      values:
        - [[bash]]
"#,
        "'oneof' is not a supported comparison operator",
    );
}

#[test]
fn exceptions_modifier_op_list_op_unchanged() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex_in
      fields: proc.name
      comps: in
      values:
        - cat
        - grep
    - name: ex_pmatch
      fields: proc.exepath
      comps: pmatch
      values:
        - /usr/bin/
        - /usr/local/bin/
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn exceptions_modifier_op_eq_oneof() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = execve
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name]
      comps: [= oneof]
      values:
        - [[nmap, masscan, nikto]]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = execve and not proc.name = oneof (nmap, masscan, nikto))")
    );
}

#[test]
fn exceptions_modifier_op_regex_oneof() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = execve
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name]
      comps: [regex oneof]
      values:
        - [["research[0-9]+", "pentest-[0-9]{2,4}"]]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}
