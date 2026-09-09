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

#[test]
fn equality_normalization_preserves_other_operators() {
    let yaml = r#"
- rule: operators
  condition: evt.type=open and proc.pid>=1 and proc.pid<=9 and proc.name!=bash and fd.name=~glob
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "operators.yaml");
    assert!(res.ok, "{:?}", res.errors);
    assert_eq!(
        eng.compiled_condition("operators"),
        Some("(evt.type = open and proc.pid>=1 and proc.pid<=9 and proc.name!=bash and fd.name=~glob)")
    );
}

#[test]
fn malformed_sequence_yaml_is_an_error() {
    let yaml = r#"
- rule: malformed
  condition: [unterminated
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "malformed.yaml");
    assert!(!res.ok);
    assert!(!res.errors.is_empty());
}

#[test]
fn multi_doc_legacy_yaml_loads_via_parser_fallback() {
    let yaml = r#"
rule: Rule 1
desc: First rule
condition: evt.type=open
priority: WARNING
output: Output 1
---
rule: Rule 2
desc: Second rule
condition: evt.type=close
priority: NOTICE
output: Output 2
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "multi_doc.yaml");
    assert!(res.ok, "{:?}", res.errors);
    assert!(eng.compiled_condition("Rule 1").is_some());
    assert!(eng.compiled_condition("Rule 2").is_some());
}

#[test]
fn multi_doc_starting_with_separator_loads_via_parser_fallback() {
    let yaml = r#"---
rule: Rule 1
desc: First rule
condition: evt.type=open
priority: WARNING
output: Output 1
---
rule: Rule 2
desc: Second rule
condition: evt.type=close
priority: NOTICE
output: Output 2
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "multi_doc_separator.yaml");
    assert!(res.ok, "{:?}", res.errors);
    assert!(eng.compiled_condition("Rule 1").is_some());
    assert!(eng.compiled_condition("Rule 2").is_some());
}

#[test]
fn sequence_macros_are_retained_without_expansion() {
    let yaml = r#"
- macro: spawned_process
  condition: evt.type=execve
- rule: uses_macro
  condition: spawned_process
"#;
    let mut eng = FalcoEngine::new();
    let res = eng.load_rules(yaml, "macros.yaml");
    assert!(res.ok, "{:?}", res.errors);
    assert_eq!(
        eng.ruleset
            .macros
            .get("spawned_process")
            .map(String::as_str),
        Some("evt.type=execve")
    );
    assert_eq!(
        eng.compiled_condition("uses_macro"),
        Some("(spawned_process)")
    );
}
