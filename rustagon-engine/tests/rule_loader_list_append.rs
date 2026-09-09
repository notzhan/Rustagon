use rustagon_engine::FalcoEngine;

#[test]
fn list_append() {
    let yaml = r#"
- list: shell_binaries
  items: [ash, bash, csh, ksh, sh, tcsh, zsh, dash]
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open and proc.name in (shell_binaries)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- list: shell_binaries
  items: [pwsh]
  override:
    items: append
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "legit_rules.yaml");
    assert!(res.ok, "{:?}", res.errors);
    let cond = eng.compiled_condition("legit_rule").unwrap();
    assert_eq!(
        cond,
        "(evt.type = open and proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash, pwsh))"
    );
}
