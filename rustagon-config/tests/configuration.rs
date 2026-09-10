use std::fs;

use rustagon_config::{FalcoConfig, RuleSelectionOperation};
use serde_yaml::Value;
use tempfile::tempdir;

#[test]
fn configuration_exceptions() {
    assert!(FalcoConfig::load_from_str("engine:\n  kind: modern_ebpf\n / bad").is_err());
}

#[test]
fn reads_tip_stable_scalar_keys() {
    let config = FalcoConfig::load_from_str(
        r#"
rules_files: [/etc/falco/falco_rules.yaml]
priority: warning
json_output: true
load_plugins: [k8saudit, json]
watch_config_files: false
"#,
    )
    .unwrap();

    assert_eq!(config.rules_files, ["/etc/falco/falco_rules.yaml"]);
    assert_eq!(config.priority, "warning");
    assert!(config.json_output);
    assert_eq!(config.load_plugins, ["k8saudit", "json"]);
    assert!(!config.watch_config_files);
}

#[test]
fn reads_engine_configuration() {
    let config = FalcoConfig::load_from_str(
        r#"
engine:
  kind: modern_ebpf
  modern_ebpf:
    cpus_for_each_buffer: 2
    buf_size_preset: 4
    drop_failed_exit: false
    disable_iterators: true
"#,
    )
    .unwrap();

    assert_eq!(config.engine.kind, "modern_ebpf");
    assert_eq!(config.engine.modern_ebpf.cpus_for_each_buffer, 2);
    assert!(config.engine.modern_ebpf.disable_iterators);
}

#[test]
fn reads_output_channels() {
    let config = FalcoConfig::load_from_str(
        r#"
stdout_output: { enabled: true }
syslog_output: { enabled: false }
file_output: { enabled: true, keep_alive: true, filename: /tmp/events.jsonl }
http_output: { enabled: true, url: "https://example.test/hook", insecure: true }
program_output: { enabled: true, keep_alive: false, program: logger }
"#,
    )
    .unwrap();

    assert!(config.stdout_output.enabled);
    assert!(!config.syslog_output.enabled);
    assert_eq!(config.file_output.filename, "/tmp/events.jsonl");
    assert_eq!(config.http_output.url, "https://example.test/hook");
    assert_eq!(config.program_output.program, "logger");
}

#[test]
fn accepts_ipv4_and_ipv6_webserver_addresses() {
    for address in [
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "1200::AB00:1234:2552:7777:1313",
    ] {
        let yaml = format!("webserver:\n  listen_address: '{address}'\n");
        let config = FalcoConfig::load_from_str(&yaml).unwrap();
        assert_eq!(config.webserver.listen_address, address);
    }
}

#[test]
fn rejects_invalid_webserver_address() {
    let error =
        FalcoConfig::load_from_str("webserver:\n  listen_address: 327.0.0.1\n").unwrap_err();
    assert!(error.to_string().contains("listen_address"));
}

#[test]
fn parses_plugin_init_config_as_yaml_value() {
    let config = FalcoConfig::load_from_str(
        r#"
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config:
      maxEventSize: 262144
      sslCertificate: /etc/falco/falco.pem
"#,
    )
    .unwrap();

    assert_eq!(config.plugins[0].name, "k8saudit");
    assert_eq!(
        config.plugins[0].init_config["maxEventSize"],
        Value::Number(262144.into())
    );
}

#[test]
fn parses_rule_selection_in_order() {
    let config = FalcoConfig::load_from_str(
        r#"
rules:
  - enable: { rule: "Terminal Shell in Container" }
  - disable: { tag: experimental }
  - enable: { rule: "hello*" }
"#,
    )
    .unwrap();

    assert_eq!(config.rules.len(), 3);
    assert_eq!(config.rules[0].operation, RuleSelectionOperation::Enable);
    assert_eq!(
        config.rules[0].rule.as_deref(),
        Some("Terminal Shell in Container")
    );
    assert_eq!(config.rules[1].operation, RuleSelectionOperation::Disable);
    assert_eq!(config.rules[1].tag.as_deref(), Some("experimental"));
}

#[test]
fn parses_append_output_options() {
    let config = FalcoConfig::load_from_str(
        r#"
append_output:
  - match:
      source: syscall
      tags: [persistence]
      rule: some rule
    extra_output: "parent=%proc.aname[2]"
    extra_fields:
      - proc.aname[2]: "%proc.aname[2]"
      - evt.hostname
"#,
    )
    .unwrap();

    assert_eq!(
        config.append_output[0].match_config.source.as_deref(),
        Some("syscall")
    );
    assert_eq!(config.append_output[0].match_config.tags, ["persistence"]);
    assert_eq!(config.append_output[0].extra_fields.len(), 2);
}

#[test]
fn cli_override_replaces_nested_scalar() {
    let mut config =
        FalcoConfig::load_from_str("engine:\n  kind: kmod\njson_output: false\n").unwrap();

    config
        .apply_cli_override("engine.kind", "modern_ebpf")
        .unwrap();
    config.apply_cli_override("json_output", "true").unwrap();

    assert_eq!(config.engine.kind, "modern_ebpf");
    assert!(config.json_output);
}

#[test]
fn config_files_override_mapping_nodes() {
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    let relative_child = dir.path().strip_prefix(&cwd).unwrap().join("second.yaml");
    fs::write(
        dir.path().join("main.yaml"),
        format!(
            "config_files: ['{}']\npriority: debug\nengine:\n  kind: kmod\n",
            relative_child.display()
        ),
    )
    .unwrap();
    fs::write(
        dir.path().join("second.yaml"),
        "priority: warning\nengine:\n  kind: modern_ebpf\n",
    )
    .unwrap();

    let config = FalcoConfig::load_from_file(dir.path().join("main.yaml")).unwrap();

    assert_eq!(config.loaded_files.len(), 2);
    assert_eq!(config.priority, "warning");
    assert_eq!(config.engine.kind, "modern_ebpf");
}

#[test]
fn config_files_append_sequences_by_default() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.yaml"),
        format!(
            "config_files: '{}'\nrules_files: [one.yaml]\n",
            dir.path().join("child.yaml").display()
        ),
    )
    .unwrap();
    fs::write(dir.path().join("child.yaml"), "rules_files: [two.yaml]\n").unwrap();

    let config = FalcoConfig::load_from_file(dir.path().join("main.yaml")).unwrap();

    assert_eq!(config.rules_files, ["one.yaml", "two.yaml"]);
}

#[test]
fn config_files_support_explicit_sequence_strategies() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.yaml"),
        format!(
            "config_files:\n  - path: '{}'\n    strategy: override\n  - path: '{}'\n    strategy: add-only\nrules_files: [one.yaml]\n",
            dir.path().join("child.yaml").display(),
            dir.path().join("add-only.yaml").display()
        ),
    )
    .unwrap();
    fs::write(dir.path().join("child.yaml"), "rules_files: [two.yaml]\n").unwrap();
    fs::write(
        dir.path().join("add-only.yaml"),
        "rules_files: [ignored.yaml]\npriority: warning\n",
    )
    .unwrap();

    let config = FalcoConfig::load_from_file(dir.path().join("main.yaml")).unwrap();

    assert_eq!(config.rules_files, ["two.yaml"]);
    assert_eq!(config.priority, "warning");
}

#[test]
fn secondary_config_cannot_include_files() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.yaml"),
        format!(
            "config_files: '{}'\n",
            dir.path().join("child.yaml").display()
        ),
    )
    .unwrap();
    fs::write(
        dir.path().join("child.yaml"),
        "config_files: grandchild.yaml\n",
    )
    .unwrap();

    let error = FalcoConfig::load_from_file(dir.path().join("main.yaml")).unwrap_err();

    assert!(error.to_string().contains("secondary"));
}

#[test]
fn tip_falco_yaml_loads() {
    let config = FalcoConfig::load_from_file("/nvraid1tank1/work/code/falco/falco.yaml").unwrap();

    assert_eq!(config.engine.kind, "modern_ebpf");
    assert_eq!(config.webserver.listen_port, 8765);
    assert_eq!(config.priority, "debug");
    assert_eq!(config.rules_files.len(), 3);
}

#[test]
fn expands_environment_variables_in_scalars() {
    std::env::set_var("RUSTAGON_CONFIG_ENV", "envVarValue");
    let config = FalcoConfig::load_from_str("priority: '${RUSTAGON_CONFIG_ENV}'\n").unwrap();
    assert_eq!(config.priority, "envVarValue");
}

#[test]
fn expands_environment_variables_embedded_in_strings() {
    std::env::set_var("RUSTAGON_CONFIG_ENV", "envVarValue");
    let config =
        FalcoConfig::load_from_str("rules_files: ['/foo/${RUSTAGON_CONFIG_ENV}/bar']\n").unwrap();
    assert_eq!(config.rules_files, ["/foo/envVarValue/bar"]);
}

#[test]
fn expands_multiple_environment_variables() {
    std::env::set_var("RUSTAGON_CONFIG_ENV", "envVarValue");
    let config = FalcoConfig::load_from_str(
        "rules_files: ['/${RUSTAGON_CONFIG_ENV}/${RUSTAGON_CONFIG_ENV}${RUSTAGON_CONFIG_ENV}/foo']\n",
    )
    .unwrap();
    assert_eq!(
        config.rules_files,
        ["/envVarValue/envVarValueenvVarValue/foo"]
    );
}

#[test]
fn escaped_environment_variables_remain_literal() {
    std::env::set_var("RUSTAGON_CONFIG_ENV", "envVarValue");
    let config = FalcoConfig::load_from_str("priority: '$${RUSTAGON_CONFIG_ENV}'\n").unwrap();
    assert_eq!(config.priority, "${RUSTAGON_CONFIG_ENV}");
}

#[test]
fn undefined_environment_variables_expand_to_empty() {
    std::env::remove_var("RUSTAGON_CONFIG_UNDEFINED");
    let config = FalcoConfig::load_from_str("priority: '${RUSTAGON_CONFIG_UNDEFINED}'\n").unwrap();
    assert_eq!(config.priority, "");
}

#[test]
fn environment_variable_expansion_is_recursive() {
    std::env::set_var("RUSTAGON_CONFIG_ENV", "envVarValue");
    std::env::set_var("RUSTAGON_CONFIG_NESTED", "${RUSTAGON_CONFIG_ENV}");
    let config =
        FalcoConfig::load_from_str("rules_files: ['${RUSTAGON_CONFIG_NESTED}/foo']\n").unwrap();
    assert_eq!(config.rules_files, ["envVarValue/foo"]);
}

#[test]
fn environment_expansion_preserves_boolean_and_integer_types() {
    std::env::set_var("RUSTAGON_CONFIG_BOOL", "true");
    std::env::set_var("RUSTAGON_CONFIG_INT", "12");
    let config = FalcoConfig::load_from_str(
        "json_output: ${RUSTAGON_CONFIG_BOOL}\noutput_timeout: ${RUSTAGON_CONFIG_INT}\n",
    )
    .unwrap();
    assert!(config.json_output);
    assert_eq!(config.output_timeout, 12);
}

#[test]
fn environment_variables_expand_in_plugin_fields() {
    std::env::set_var("RUSTAGON_CONFIG_ENV", "envVarValue");
    std::env::set_var("RUSTAGON_CONFIG_INT", "12");
    let config = FalcoConfig::load_from_str(
        "plugins:\n  - name: test\n    library_path: /foo/${RUSTAGON_CONFIG_ENV}/lib.so\n    open_params: ${RUSTAGON_CONFIG_INT}\n",
    )
    .unwrap();
    assert_eq!(config.plugins[0].library_path, "/foo/envVarValue/lib.so");
    assert_eq!(config.plugins[0].open_params, "12");
}

#[test]
fn plugin_init_config_accepts_json_strings() {
    let config = FalcoConfig::load_from_str(
        r#"plugins:
  - name: test
    init_config: '{"maxEventSize": 262144}'
"#,
    )
    .unwrap();
    assert_eq!(config.plugins[0].init_config["maxEventSize"], 262144);
}

#[test]
fn plugin_init_config_accepts_null_as_empty() {
    let config =
        FalcoConfig::load_from_str("plugins:\n  - name: test\n    init_config: null\n").unwrap();
    assert_eq!(
        config.plugins[0].init_config,
        Value::String(String::new())
    );
}

#[test]
fn rejects_plugin_library_path_traversal() {
    for path in [
        "../../tmp/evil.so",
        "./../../tmp/evil.so",
        "subdir/../../../tmp/evil.so",
    ] {
        let yaml = format!("plugins:\n  - name: evil\n    library_path: '{path}'\n");
        assert!(FalcoConfig::load_from_str(&yaml).is_err(), "{path}");
    }
}

#[test]
fn allows_absolute_plugin_library_paths() {
    let config = FalcoConfig::load_from_str(
        "plugins:\n  - name: test\n    library_path: /opt/falco/plugins/libtest.so\n",
    )
    .unwrap();
    assert_eq!(
        config.plugins[0].library_path,
        "/opt/falco/plugins/libtest.so"
    );
}

#[test]
fn config_files_skip_missing_paths() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    fs::write(
        &main,
        "config_files: definitely-missing.yaml\npriority: warning\n",
    )
    .unwrap();
    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.loaded_files.len(), 1);
    assert_eq!(config.priority, "warning");
}

#[test]
fn config_files_reject_self_include() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    fs::write(&main, format!("config_files: '{}'\n", main.display())).unwrap();
    assert!(FalcoConfig::load_from_file(main).is_err());
}

#[test]
fn cli_override_appends_output_options() {
    let mut config = FalcoConfig::load_from_str("").unwrap();
    config
        .apply_cli_override(
            "append_output[]",
            r#"{"match":{"source":"syscall"},"extra_fields":["evt.hostname"]}"#,
        )
        .unwrap();
    config
        .apply_cli_override(
            "append_output[]",
            r#"{"match":{"source":"k8s_audit"},"extra_output":"verb=%ka.verb"}"#,
        )
        .unwrap();
    assert_eq!(config.append_output.len(), 2);
    assert_eq!(
        config.append_output[0].match_config.source.as_deref(),
        Some("syscall")
    );
    assert_eq!(
        config.append_output[1].match_config.source.as_deref(),
        Some("k8s_audit")
    );
}
