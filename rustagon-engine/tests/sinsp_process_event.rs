use rustagon_engine::FalcoEngine;
use rustagon_scap::{RawEvent, RawEventKind};
use rustagon_sinsp::Inspector;

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
