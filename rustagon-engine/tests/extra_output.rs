use rustagon_engine::FalcoEngine;
use std::collections::HashMap;

fn load(engine: &mut FalcoEngine, rules: &str) {
    assert!(engine.load_rules(rules, "rules.yaml").ok);
}

#[test]
fn extra_format_all() {
    let mut engine = FalcoEngine::new();
    engine.add_extra_output_format("evt.type=%evt.type", "", &[], "");
    load(
        &mut engine,
        "- rule: legit_rule\n  condition: evt.type=open\n  output: out\n  priority: INFO\n",
    );
    assert_eq!(
        engine.rule_details("legit_rule").unwrap().output.as_deref(),
        Some("out evt.type=%evt.type")
    );
}

#[test]
fn extra_format_by_rule() {
    let mut engine = FalcoEngine::new();
    engine.add_extra_output_format("extra", "", &[], "legit_rule");
    load(&mut engine, "- rule: legit_rule\n  condition: evt.type=open\n  output: out 1\n  priority: INFO\n- rule: another_rule\n  condition: evt.type=open\n  output: out 2\n  priority: INFO\n");
    assert_eq!(
        engine.rule_details("legit_rule").unwrap().output.as_deref(),
        Some("out 1 extra")
    );
    assert_eq!(
        engine
            .rule_details("another_rule")
            .unwrap()
            .output
            .as_deref(),
        Some("out 2")
    );
}

#[test]
fn extra_format_by_tag_rule() {
    let mut engine = FalcoEngine::new();
    engine.add_extra_output_format("extra 1", "", &["tag1"], "");
    engine.add_extra_output_format("extra 2", "", &[], "another_rule");
    engine.add_extra_output_format("extra 3", "", &["tag1", "tag2"], "");
    load(&mut engine, "- rule: legit_rule\n  condition: evt.type=open\n  output: out 1\n  priority: INFO\n  tags: [tag1]\n- rule: another_rule\n  condition: evt.type=open\n  output: out 2\n  priority: INFO\n  tags: [tag1]\n- rule: a_third_rule\n  condition: evt.type=open\n  output: out 3\n  priority: INFO\n  tags: [tag1, tag2]\n");
    assert_eq!(
        engine.rule_details("legit_rule").unwrap().output.as_deref(),
        Some("out 1 extra 1")
    );
    assert_eq!(
        engine
            .rule_details("another_rule")
            .unwrap()
            .output
            .as_deref(),
        Some("out 2 extra 1 extra 2")
    );
    assert_eq!(
        engine
            .rule_details("a_third_rule")
            .unwrap()
            .output
            .as_deref(),
        Some("out 3 extra 1 extra 3")
    );
}

#[test]
fn extra_format_empty_container_info() {
    let mut engine = FalcoEngine::new();
    load(&mut engine, "- rule: legit_rule\n  condition: evt.type=open\n  output: out 1 (%container.info)\n  priority: INFO\n");
    assert_eq!(
        engine.rule_details("legit_rule").unwrap().output.as_deref(),
        Some("out 1")
    );
}

#[test]
fn extra_fields_all() {
    let mut engine = FalcoEngine::new();
    engine.add_extra_output_formatted_field("my_field", "hello %evt.num", "", &[], "");
    load(
        &mut engine,
        "- rule: legit_rule\n  condition: evt.type=open\n  output: out\n  priority: INFO\n",
    );
    assert_eq!(
        engine.rule_details("legit_rule").unwrap().formatted_fields,
        HashMap::from([("my_field".into(), "hello %evt.num".into())])
    );
}
