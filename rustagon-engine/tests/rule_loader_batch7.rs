use rustagon_engine::FalcoEngine;

fn load(yaml: &str) -> (FalcoEngine, rustagon_engine::LoadResult) {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(yaml, "rules.yaml");
    (engine, result)
}

fn different_source_yaml(extra: &str) -> String {
    format!(
        r#"
- rule: LD_PRELOAD trick
  desc: Some desc
  condition: ka.verb = GET
  output: some output
  priority: INFO
  source: k8s_audit

- rule: LD_PRELOAD trick
  desc: Some desc
  condition: and 1 = 2
  output: Some output
  priority: INFO
  source: syscall
{extra}"#
    )
}

fn assert_different_source_error(yaml: &str) {
    let (_, result) = load(yaml);
    assert!(!result.ok);
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Rule has been re-defined with a different source")));
}

#[test]
fn redefine_rule_different_source() {
    assert_different_source_error(&different_source_yaml(""));
}

#[test]
fn append_across_sources() {
    assert_different_source_error(&different_source_yaml("  append: true\n"));
}

#[test]
fn selective_replace_across_sources() {
    assert_different_source_error(
        r#"
- rule: LD_PRELOAD trick
  desc: Some desc
  condition: ka.verb = GET
  output: some output
  priority: INFO
  source: k8s_audit

- rule: LD_PRELOAD trick
  condition: 1 = 2
  override:
    condition: replace
  source: syscall
"#,
    );
}

#[test]
fn empty_source_addl_rule() {
    let (_, result) = load(
        r#"
- rule: LD_PRELOAD trick
  desc: Some desc
  condition: evt.type=execve
  output: some output
  priority: INFO
  source: syscall

- rule: LD_PRELOAD trick
  desc: Some desc
  condition: and proc.name=apache
  output: Some output
  priority: INFO
  source:
  append: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
}

#[test]
fn empty_string_source_addl_rule() {
    let (_, result) = load(
        r#"
- rule: LD_PRELOAD trick
  desc: Some desc
  condition: evt.type=execve
  output: some output
  priority: INFO
  source: syscall

- rule: LD_PRELOAD trick
  desc: Some desc
  condition: and proc.name=apache
  output: Some output
  priority: INFO
  source: ""
  append: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
}

#[test]
fn rule_with_warn_evttypes() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  warn_evttypes: false
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn rule_with_skip_if_unknown_filter() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  skip-if-unknown-filter: true
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn override_replace_warn_evttypes() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  warn_evttypes: true

- rule: test_rule
  warn_evttypes: false
  override:
    warn_evttypes: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn override_replace_capture() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: test_rule
  capture: true
  override:
    capture: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}

#[test]
fn override_replace_tags() {
    let (_, result) = load(
        r#"
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  tags: [filesystem]

- rule: test_rule
  tags: [network]
  override:
    tags: replace
"#,
    );
    assert!(result.ok, "{:?}", result.errors);
    assert_eq!(result.schema_validation, "ok");
}
