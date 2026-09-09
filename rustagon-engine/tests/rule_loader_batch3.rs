use rustagon_engine::FalcoEngine;

const NO_PREVIOUS_LIST: &str =
    "List uses 'append' or 'override.items: append' but no list by that name already exists";

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

#[test]
fn list_override_replace_before_list_definition() {
    let (engine, result) = load(
        r#"
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override:
    items: replace
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
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = execve and proc.name in (blkid))")
    );
}

#[test]
fn list_append_before_list_definition() {
    let (_, result) = load(
        r#"
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  append: true
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

#[test]
fn list_override_append_after_list_definition() {
    let (engine, result) = load(
        r#"
- list: dev_creation_binaries
  items: [blkid]
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override:
    items: append
- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = execve and proc.name in (blkid, csi-provisioner, csi-attacher))")
    );
}

#[test]
fn list_append_after_list_definition() {
    let (engine, result) = load(
        r#"
- list: dev_creation_binaries
  items: [blkid]
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  append: true
- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert_eq!(
        engine.compiled_condition("test_rule"),
        Some("(evt.type = execve and proc.name in (blkid, csi-provisioner, csi-attacher))")
    );
}

#[test]
fn rule_override_without_field() {
    let (_, result) = load(
        r#"
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: failing_rule
  desc: an appended incorrect field
  override:
    desc: replace
    condition: append
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.errors.iter().any(|error| error.contains(
        "An append override for 'condition' was specified but 'condition' is not defined"
    )));
}

#[test]
fn rule_override_extra_field() {
    let (_, result) = load(
        r#"
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: failing_rule
  desc: an appended incorrect field
  condition: and proc.name = cat
  priority: WARNING
  override:
    desc: replace
    condition: append
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Unexpected key 'priority'")));
}

#[test]
fn missing_enabled_key_with_override() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
- rule: test_rule
  desc: missing enabled key
  condition: and proc.name = cat
  override:
    desc: replace
    condition: append
    enabled: replace
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("'enabled' was specified but 'enabled' is not defined")));
}

#[test]
fn rule_override_with_enabled() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
- rule: test_rule
  desc: correct override
  condition: and proc.name = cat
  enabled: true
  override:
    desc: replace
    condition: append
    enabled: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
    assert_eq!(engine.ruleset.rules.len(), 1);
}

#[test]
fn rule_not_enabled() {
    let (engine, result) = load(
        r#"
- rule: test_rule
  desc: rule not enabled
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.warnings.is_empty());
    assert_eq!(engine.ruleset.rules.len(), 0);
}

#[test]
fn empty_append_rule_is_rejected() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
- rule: test_rule
  append: true
"#,
    );
    assert!(!result.ok);
    assert_eq!(result.schema_validation, "ok");
    assert!(result.errors.iter().any(|error| {
        error.contains("Appended rule must have exceptions or condition property")
    }));
}
