use rustagon_engine::{AltCompileOutput, FalcoEngine, RuleLoaderHooks};

const CONTENT: &str = r#"
- test_object: test
  property: my-value
- test_object: test2
  property: other-value
- list: shell_binaries
  items: [sh, bash]
- macro: spawned_process
  condition: evt.type=execve
- rule: test info rule
  condition: spawned_process
  output: info
  priority: INFO
  source: syscall
- rule: test k8s rule
  condition: ka.verb=create
  output: k8s
  priority: INFO
  source: k8s_audit
- rule: test debug rule
  condition: spawned_process
  output: debug
  priority: DEBUG
  source: syscall
"#;

#[test]
fn load_rules() {
    let output = AltCompileOutput::compile(CONTENT, &["syscall"]).unwrap();
    assert_eq!(output.lists.len(), 1);
    assert_eq!(output.macros.len(), 1);
    assert_eq!(output.rules.len(), 2);
}

#[test]
fn pass_compile_output_to_ruleset() {
    let output = AltCompileOutput::compile(CONTENT, &["syscall"]).unwrap();
    let ruleset = output.rules_at_or_above_priority("INFO");
    assert_eq!(ruleset, vec!["test info rule"]);
}

#[test]
fn falco_engine_alternate_loader() {
    let mut engine = FalcoEngine::new();
    engine.add_source("syscall", "filter", "formatter", "ruleset");
    let hooks = RuleLoaderHooks::new("test-reader", "test-collector", "test-compiler");
    engine.set_rule_loader_hooks(hooks.clone());
    assert_eq!(engine.rule_loader_hooks(), Some(&hooks));
    assert!(engine.load_rules(CONTENT, "rules.yaml").ok);
    let properties = engine.alternate_properties();
    assert!(properties.contains("my-value"));
    assert!(properties.contains("other-value"));
    assert!(!properties.contains("not-exists-value"));
}

#[test]
fn clone_compile_output() {
    let original = AltCompileOutput::compile(CONTENT, &["syscall"]).unwrap();
    let copy = original.clone();
    assert_eq!(copy, original);
}
