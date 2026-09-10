use rustagon_engine::FalcoEngine;
use rustagon_scap::{RawEvent, RawEventKind};
use rustagon_sinsp::{Evt, Inspector};
use std::collections::HashMap;

const RULE: &str = r#"
- list: shells
  items: [bash, sh]
- macro: enriched_open
  condition: evt.type = open and proc.name in (shells)
- rule: enriched open
  desc: matches fields extracted by sinsp
  condition: enriched_open and fd.num >= 3 and (fd.name = /tmp/target or container.id = ignored)
  output: enriched event matched
  priority: INFO
  source: syscall
"#;

fn raw(tid: i64, kind: RawEventKind) -> RawEvent {
    RawEvent {
        timestamp: 1,
        tid,
        type_id: 0,
        payload: Vec::new(),
        kind,
    }
}

#[test]
fn loaded_rule_matches_only_the_enriched_inspector_event() {
    let mut engine = FalcoEngine::new();
    assert!(engine.load_rules(RULE, "integration.yaml").ok);

    let mut inspector = Inspector::default();
    inspector.inject(raw(
        42,
        RawEventKind::Exec {
            pid: 42,
            ppid: 1,
            comm: "bash".into(),
            exe: "bash".into(),
            exepath: "/usr/bin/bash".into(),
            args: Vec::new(),
        },
    ));

    let non_match = inspector.inject(raw(
        42,
        RawEventKind::Open {
            fd: 3,
            path: "/tmp/other".into(),
        },
    ));
    assert!(engine.process_event(&non_match, 0).is_none());

    let matching = inspector.inject(raw(
        42,
        RawEventKind::Open {
            fd: 4,
            path: "/tmp/target".into(),
        },
    ));
    let alert = engine
        .process_event(&matching, 0)
        .expect("enriched event should match the loaded rule");

    assert_eq!(alert.rule, "enriched open");
    assert_eq!(alert.output, "enriched event matched");
}

#[test]
fn inequality_does_not_match_when_left_field_is_missing() {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(
        r#"
- rule: named process
  condition: proc.name != foo
  output: process name differs
  priority: INFO
"#,
        "inequality.yaml",
    );
    assert!(result.ok, "{:?}", result.errors);

    assert!(engine.process_event(&Evt::default(), 0).is_none());
}

#[test]
fn evaluates_not_exists_string_operators_and_transformers() {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(
        r#"
- rule: focused operators
  condition: >
    proc.name exists and not proc.name = foo and
    proc.name startswith Ba and proc.name endswith SH and
    proc.name icontains ash and tolower(proc.name) = bash
  output: focused operators matched
  priority: INFO
"#,
        "operators.yaml",
    );
    assert!(result.ok, "{:?}", result.errors);

    let matching = Evt::new(HashMap::from([("proc.name".into(), "BaSH".into())]));
    assert!(engine.process_event(&matching, 0).is_some());

    let missing = Evt::default();
    assert!(engine.process_event(&missing, 0).is_none());
}
