use rustagon_engine::{Evt, FalcoEngine, DEFAULT_RULESET};
use std::collections::HashMap;

const SINGLE: &str = r#"
- rule: test rule
  desc: test
  condition: evt.type=execve
  output: matched
  priority: INFO
  tags: [process]
- rule: disabled rule
  desc: disabled
  condition: evt.type=execve
  output: disabled
  priority: INFO
  enabled: false
  tags: [exec process]
"#;

const MULTI: &str = r#"
- rule: first actual rule
  condition: evt.type=execve
  output: first
  priority: INFO
  tags: [process]
- rule: second disabled rule
  condition: evt.type=execve
  output: second
  priority: INFO
  enabled: false
  tags: [exec process]
- rule: third disabled rule
  condition: evt.type=execve
  output: third
  priority: INFO
  enabled: false
  tags: [exec]
"#;

#[test]
fn enable_rule_name() {
    let mut engine = FalcoEngine::new();
    assert!(engine.load_rules(SINGLE, "rules.yaml").ok);
    assert_eq!(engine.num_rules_for_ruleset(DEFAULT_RULESET), 1);
    engine.enable_rule("test", true, "one");
    assert_eq!(engine.num_rules_for_ruleset("one"), 1);
    assert_eq!(engine.num_rules_for_ruleset("two"), 0);
    engine.enable_rule("", true, "three");
    assert_eq!(engine.num_rules_for_ruleset("three"), 2);
    engine.enable_rule("test", false, "one");
    assert_eq!(engine.num_rules_for_ruleset("one"), 0);
    let evt = Evt::new(HashMap::from([("evt.type".into(), "execve".into())]));
    let one = engine.find_ruleset_id("one");
    assert!(engine.process_event(&evt, one).is_none());
}

#[test]
fn enable_rule_tags() {
    let mut engine = FalcoEngine::new();
    engine.load_rules(SINGLE, "rules.yaml");
    engine.enable_rule_by_tag(&["process"], true, "one");
    assert_eq!(engine.num_rules_for_ruleset("one"), 1);
    engine.enable_rule_by_tag(&["process"], false, "one");
    assert_eq!(engine.num_rules_for_ruleset("one"), 0);
}

#[test]
fn enable_disabled_rule_by_tag() {
    let mut engine = FalcoEngine::new();
    engine.load_rules(SINGLE, "rules.yaml");
    engine.enable_rule_by_tag(&["exec process"], true, DEFAULT_RULESET);
    assert_eq!(engine.num_rules_for_ruleset(DEFAULT_RULESET), 2);
}

#[test]
fn enable_rule_id() {
    let mut engine = FalcoEngine::new();
    engine.load_rules(SINGLE, "rules.yaml");
    let one = engine.find_ruleset_id("one");
    let two = engine.find_ruleset_id("two");
    engine.enable_rule_id("test rule", true, one);
    assert_eq!(engine.num_rules_for_ruleset_id(one), 1);
    assert_eq!(engine.num_rules_for_ruleset_id(two), 0);
}

#[test]
fn enable_rule_name_exact() {
    let mut engine = FalcoEngine::new();
    engine.load_rules(SINGLE, "rules.yaml");
    engine.enable_rule_exact("test", true, "one");
    assert_eq!(engine.num_rules_for_ruleset("one"), 0);
    engine.enable_rule_exact("test rule", true, "one");
    assert_eq!(engine.num_rules_for_ruleset("one"), 1);
    engine.enable_rule_exact("", true, "all");
    assert_eq!(engine.num_rules_for_ruleset("all"), 2);
}

#[test]
fn enable_rule_name_wildcard() {
    let mut engine = FalcoEngine::new();
    engine.load_rules(MULTI, "rules.yaml");
    engine.enable_rule_wildcard("*rule", true, "all");
    assert_eq!(engine.num_rules_for_ruleset("all"), 3);
    engine.enable_rule_wildcard("*second*r*", true, "second");
    assert_eq!(engine.num_rules_for_ruleset("second"), 1);
    engine.enable_rule_wildcard("*", true, "star");
    assert_eq!(engine.num_rules_for_ruleset("star"), 3);
}
