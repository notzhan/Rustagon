use rustagon_engine::FalcoEngine;

fn engine() -> FalcoEngine {
    let mut engine = FalcoEngine::new();
    engine.add_source("syscall", "filter", "formatter", "ruleset");
    engine
}

#[test]
fn generic_evt_class_has_no_source_label() {
    let output = engine().list_fields("", false, false);
    let generic = output.split("## Field Class: evt").nth(1).unwrap();
    assert!(!generic
        .split("## Field Class:")
        .next()
        .unwrap()
        .contains("Event Sources:"));
}

#[test]
fn syscall_evt_class_has_source_label() {
    let output = engine().list_fields("", false, false);
    let section = output
        .split("Event fields applicable to syscall events")
        .nth(1)
        .unwrap();
    assert!(section
        .split("## Field Class:")
        .next()
        .unwrap()
        .contains("Event Sources: syscall"));
}

#[test]
fn syscall_specific_class_has_source_label() {
    let output = engine().list_fields("", false, false);
    let fd = output.split("## Field Class: fd").nth(1).unwrap();
    assert!(fd.contains("Event Sources: syscall"));
}

#[test]
fn source_filter_excludes_fields_for_unknown_source() {
    assert!(engine()
        .list_fields("unknown", false, true)
        .trim()
        .is_empty());
    assert!(engine()
        .list_fields_json("unknown", false, true)
        .contains(r#""fields":[]"#));
}

#[test]
fn syscall_names_only_lists_registered_fields() {
    let output = engine().list_fields("syscall", false, true);
    assert!(output.lines().any(|field| field == "evt.type"));
    assert!(output.lines().any(|field| field == "evt.num"));
    assert!(output.lines().any(|field| field == "fd.name"));
}

#[test]
fn json_output_labels_only_source_specific_classes() {
    let value: serde_yaml::Value =
        serde_yaml::from_str(&engine().list_fields_json("", false, false)).unwrap();
    let classes = value["fieldclasses"].as_sequence().unwrap();
    let generic = classes
        .iter()
        .find(|c| c["name"] == "evt" && c["desc"].as_str().unwrap().starts_with("These fields"))
        .unwrap();
    assert!(generic.get("event_sources").is_none());
    let fd = classes.iter().find(|c| c["name"] == "fd").unwrap();
    assert_eq!(fd["event_sources"][0], "syscall");
}
