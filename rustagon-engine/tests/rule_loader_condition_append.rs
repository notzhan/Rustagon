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
