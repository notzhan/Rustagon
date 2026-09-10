use rustagon_engine::FalcoEngine;

const NO_PREVIOUS_RULE_APPEND: &str =
    "Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists";
const NO_PREVIOUS_RULE_REPLACE: &str =
    "An 'override.<key>: replace' to a rule was requested but no rule by that name already exists";
const NO_PREVIOUS_LIST: &str =
    "List uses 'append' or 'override.items: append' but no list by that name already exists";

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

#[test]
fn macro_override_replace_before_macro_definition() {
    let (engine, result) = load(
        r#"
- macro: open_simple
  condition: or evt.type = openat2
  override:
    condition: replace
- macro: open_simple
  condition: evt.type in (open,openat)
- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("((evt.type in (open, openat)))")
    );
}

#[test]
fn macro_override_append_after_macro_definition() {
    let (engine, result) = load(
        r#"
- macro: open_simple
  condition: evt.type in (open,openat)
- macro: open_simple
  condition: or evt.type = openat2
  override:
    condition: append
- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("((evt.type in (open, openat) or evt.type = openat2))")
    );
}

#[test]
fn macro_append_after_macro_definition() {
    let (engine, result) = load(
        r#"
- macro: open_simple
  condition: evt.type in (open,openat)
- macro: open_simple
  condition: or evt.type = openat2
  append: true
- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("((evt.type in (open, openat) or evt.type = openat2))")
    );
}

#[test]
fn rule_override_append_before_rule_definition() {
    let (_, result) = load(
        r#"
- rule: test_rule
  condition: and proc.name = cat
  override:
    condition: append
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains(NO_PREVIOUS_RULE_APPEND)));
}

#[test]
fn rule_override_replace_before_rule_definition() {
    let (_, result) = load(
        r#"
- rule: test_rule
  condition: and proc.name = cat
  override:
    condition: replace
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains(NO_PREVIOUS_RULE_REPLACE)));
}

#[test]
fn rule_append_before_rule_definition() {
    let (_, result) = load(
        r#"
- rule: test_rule
  condition: and proc.name = cat
  append: true
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains(NO_PREVIOUS_RULE_APPEND)));
}

#[test]
fn rule_override_append_after_rule_definition() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO
- rule: test_rule
  condition: and proc.name = cat
  override:
    condition: append
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type in (open, openat) and proc.name = cat)")
    );
}

#[test]
fn rule_append_after_rule_definition() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO
- rule: test_rule
  condition: and proc.name = cat
  append: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type in (open, openat) and proc.name = cat)")
    );
}

#[test]
fn list_override_append_wrong_key() {
    let (engine, result) = load(
        r#"
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override_written_wrong:
    items: append
- list: dev_creation_binaries
  items: [blkid]
- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "failed");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = execve and proc.name in (blkid))")
    );
}

#[test]
fn list_override_append_before_list_definition() {
    let (_, result) = load(
        r#"
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override:
    items: append
- list: dev_creation_binaries
  items: [blkid]
- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains(NO_PREVIOUS_LIST)));
}
