use rustagon_engine::FalcoEngine;

#[test]
fn condition_append() {
    let yaml = r#"
- macro: interactive
  condition: >
    ((proc.aname=sshd and proc.name != sshd) or
    proc.name=systemd-logind or proc.name=login)

- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open and interactive
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- macro: interactive
  condition: or proc.name = ssh
  override:
    condition: append
"#;
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "legit_rules.yaml");

    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(
        engine.compiled_condition("legit_rule"),
        Some(
            "(evt.type = open and (((proc.aname = sshd and proc.name != sshd) or proc.name = systemd-logind or proc.name = login) or proc.name = ssh))"
        )
    );
}

#[test]
fn comparison_rhs_named_like_macro_is_not_expanded() {
    let yaml = r#"
- macro: ssh
  condition: proc.name=unexpected
- rule: rhs_value
  condition: evt.type=open and proc.name=ssh
"#;
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rhs_value.yaml");

    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(
        engine.compiled_condition("rhs_value"),
        Some("(evt.type = open and proc.name = ssh)")
    );
}

#[test]
fn condition_append_requires_existing_macro_or_rule() {
    for (kind, name) in [("macro", "missing_macro"), ("rule", "missing_rule")] {
        let yaml = format!(
            r#"
- {kind}: {name}
  condition: or evt.type=close
  override:
    condition: append
"#
        );
        let mut engine = FalcoEngine::new();
        let result = engine.load_rules(&yaml, "missing_append_target.yaml");

        assert!(!result.ok, "{kind} append unexpectedly succeeded");
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(kind) && error.contains(name)),
            "unclear error for {kind} append: {:?}",
            result.errors
        );
    }
}
