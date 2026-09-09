use rustagon_engine::FalcoEngine;

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

#[test]
fn exceptions_modifier_op_scalar_value_parenthesised() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name]
      comps: [startswith oneof]
      values:
        - [sshd]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = open and not proc.name startswith oneof (sshd))")
    );
}

#[test]
fn exceptions_modifier_op_all_three_modifiers() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = execve
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex_oneof
      fields: [proc.name]
      comps: [startswith oneof]
      values:
        - [[ssh, su]]
    - name: ex_anyof
      fields: [proc.name]
      comps: [startswith anyof]
      values:
        - [[ssh, su]]
    - name: ex_allof
      fields: [proc.cmdline]
      comps: [contains allof]
      values:
        - [[curl, ci.internal]]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some(
            "(evt.type = execve and not proc.name startswith oneof (ssh, su) and not proc.name startswith anyof (ssh, su) and not proc.cmdline contains allof (curl, ci.internal))"
        )
    );
}

#[test]
fn exceptions_modifier_op_comp_whitespace_normalized() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex_single
      fields: [proc.name]
      comps: ["  startswith oneof  "]
      values:
        - [[sshd, sudo]]
    - name: ex_multi
      fields: [proc.name, fd.name]
      comps: ["  contains  ", "  startswith anyof  "]
      values:
        - [agent, [/etc/, /var/]]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some(
            "(evt.type = open and not proc.name startswith oneof (sshd, sudo) and not (proc.name contains agent and fd.name startswith anyof (/etc/, /var/)))"
        )
    );
}

#[test]
fn exceptions_modifier_op_str_op_multi_field_regression() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: ex
      fields: [proc.name, fd.name, proc.exepath]
      comps: [contains, startswith, =]
      values:
        - [agent, /var/log/, /usr/bin/prometheus]
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some(
            "(evt.type = open and not (proc.name contains agent and fd.name startswith /var/log/ and proc.exepath = /usr/bin/prometheus))"
        )
    );
}
