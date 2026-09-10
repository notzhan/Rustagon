use std::fs;

use rustagon_config::{FalcoConfig, RuleSelectionOperation, YamlConfig};
use serde_yaml::Value;
use tempfile::tempdir;

const SAMPLE_YAML: &str = r#"
base_value:
  id: 1
  name: sample_name
  subvalue:
    subvalue2:
      boolean: true
base_value_2:
  sample_list: [elem1, elem2, elem3]
"#;

#[test]
fn configuration_reload() {
    let mut config = YamlConfig::default();
    config.load_from_str(SAMPLE_YAML).unwrap();
    assert!(config.is_defined("base_value").unwrap());
    config.clear();
    assert!(!config.is_defined("base_value").unwrap());
    config.load_from_str(SAMPLE_YAML).unwrap();
    assert!(config.is_defined("base_value").unwrap());
}

#[test]
fn read_yaml_fields() {
    let config = YamlConfig::parse(SAMPLE_YAML).unwrap();
    assert!(config.is_defined("base_value").unwrap());
    assert!(!config.is_defined("unknown_base_value").unwrap());
    assert_eq!(config.get("base_value.id").unwrap(), Some(&Value::from(1)));
    assert_eq!(
        config.get("base_value.subvalue.subvalue2.boolean").unwrap(),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        config.get("base_value_2.sample_list[1]").unwrap(),
        Some(&Value::String("elem2".into()))
    );
    assert_eq!(
        config
            .sequence("base_value_2.sample_list")
            .unwrap()
            .unwrap(),
        &[
            Value::String("elem1".into()),
            Value::String("elem2".into()),
            Value::String("elem3".into())
        ]
    );
}

const ESCAPED_KEYS_YAML: &str = r#"
annotations:
  kubernetes.io/role: master
  example[0]: bracket_val
nested:
  level1.with.dots:
    inner: value
escape_test:
  back\slash: bslash_val
"#;

#[test]
fn escaped_keys_read() {
    let config = YamlConfig::parse(ESCAPED_KEYS_YAML).unwrap();
    assert_eq!(
        config.get("annotations.kubernetes\\.io/role").unwrap(),
        Some(&Value::String("master".into()))
    );
    assert_eq!(
        config.get("annotations.example\\[0\\]").unwrap(),
        Some(&Value::String("bracket_val".into()))
    );
    assert_eq!(
        config.get("nested.level1\\.with\\.dots.inner").unwrap(),
        Some(&Value::String("value".into()))
    );
    assert_eq!(
        config.get("escape_test.back\\\\slash").unwrap(),
        Some(&Value::String("bslash_val".into()))
    );
}

#[test]
fn escaped_keys_write() {
    let mut config = YamlConfig::parse(ESCAPED_KEYS_YAML).unwrap();
    config
        .set(
            "annotations.kubernetes\\.io/role",
            Value::String("worker".into()),
        )
        .unwrap();
    assert_eq!(
        config.get("annotations.kubernetes\\.io/role").unwrap(),
        Some(&Value::String("worker".into()))
    );
}

#[test]
fn escaped_keys_errors() {
    let config = YamlConfig::parse(ESCAPED_KEYS_YAML).unwrap();
    assert!(config.get("annotations\\").is_err());
    assert!(config.get("annotations\\x").is_err());
}

#[test]
fn configuration_config_files_ok() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    let second = dir.path().join("conf_2.yaml");
    let third = dir.path().join("conf_3.yaml");
    fs::write(
        &main,
        format!(
            "config_files: ['{}', '{}']\nfoo: bar\nbase_value: {{id: 1, name: foo}}\n",
            second.display(),
            third.display()
        ),
    )
    .unwrap();
    fs::write(&second, "foo2: bar2\nbase_value_2: {id: 2}\n").unwrap();
    fs::write(&third, "foo3: bar3\nbase_value_3: {id: 3, name: foo3}\n").unwrap();

    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.loaded_files.len(), 3);
    assert_eq!(
        config.value("base_value.id").unwrap(),
        Some(&Value::from(1))
    );
    assert_eq!(
        config.value("foo2").unwrap(),
        Some(&Value::String("bar2".into()))
    );
    assert_eq!(
        config.value("base_value_3.name").unwrap(),
        Some(&Value::String("foo3".into()))
    );
}

#[test]
fn configuration_config_files_relative_main() {
    let cwd = std::env::current_dir().unwrap();
    let cwd_dir = tempfile::tempdir_in(&cwd).unwrap();
    let main_dir = tempdir().unwrap();
    let relative_child = cwd_dir.path().join("conf_2.yaml");
    let absolute_child = cwd_dir.path().join("conf_3.yaml");
    fs::write(&relative_child, "foo2: bar2\n").unwrap();
    fs::write(&absolute_child, "foo3: bar3\n").unwrap();
    let relative = relative_child.strip_prefix(&cwd).unwrap();
    let main = main_dir.path().join("main.yaml");
    fs::write(
        &main,
        format!(
            "config_files: ['{}', '{}']\nfoo: bar\n",
            relative.display(),
            absolute_child.display()
        ),
    )
    .unwrap();

    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.loaded_files.len(), 3);
    assert_eq!(
        config.value("foo2").unwrap(),
        Some(&Value::String("bar2".into()))
    );
    assert_eq!(
        config.value("foo3").unwrap(),
        Some(&Value::String("bar3".into()))
    );
}

#[test]
fn configuration_config_files_sequence_wrong_strategy() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    let child = dir.path().join("child.yaml");
    fs::write(
        &main,
        format!(
            "config_files:\n  - path: '{}'\n    strategy: wrong\nrules_files: [one.yaml]\n",
            child.display()
        ),
    )
    .unwrap();
    fs::write(&child, "rules_files: [two.yaml]\n").unwrap();

    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.rules_files, ["one.yaml", "two.yaml"]);
    assert_eq!(config.validation_warnings.len(), 1);
}

#[test]
fn configuration_config_files_scalar_config_files() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    let child = dir.path().join("child.yaml");
    fs::write(
        &main,
        format!("config_files: '{}'\nfoo: bar\n", child.display()),
    )
    .unwrap();
    fs::write(&child, "foo2: bar2\n").unwrap();
    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.loaded_files.len(), 2);
    assert_eq!(
        config.value("foo2").unwrap(),
        Some(&Value::String("bar2".into()))
    );
}

#[test]
fn configuration_config_files_empty_config_files() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    fs::write(&main, "config_files:\nfoo: bar\n").unwrap();
    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.loaded_files.len(), 1);
    assert_eq!(
        config.value("foo").unwrap(),
        Some(&Value::String("bar".into()))
    );
}

#[test]
fn configuration_config_files_directory() {
    let dir = tempdir().unwrap();
    let includes = dir.path().join("includes");
    fs::create_dir(&includes).unwrap();
    fs::write(
        includes.join("01.yaml"),
        "ordered: first\nbase_1: {id: 1}\n",
    )
    .unwrap();
    fs::write(
        includes.join("02.yaml"),
        "ordered: second\nbase_2: {id: 2}\n",
    )
    .unwrap();
    fs::create_dir(includes.join("nested")).unwrap();
    fs::write(includes.join("nested/ignored.yaml"), "ignored: true\n").unwrap();
    let main = dir.path().join("main.yaml");
    fs::write(&main, format!("config_files: '{}'\n", includes.display())).unwrap();

    let config = FalcoConfig::load_from_file(main).unwrap();
    assert_eq!(config.loaded_files.len(), 3);
    assert_eq!(
        config.value("ordered").unwrap(),
        Some(&Value::String("second".into()))
    );
    assert!(config.value("base_1.id").unwrap().is_some());
    assert!(config.value("base_2.id").unwrap().is_some());
    assert!(config.value("ignored").unwrap().is_none());
}

#[test]
fn configuration_config_files_cmdline() {
    let dir = tempdir().unwrap();
    let main = dir.path().join("main.yaml");
    let child = dir.path().join("child.yaml");
    fs::write(&main, "foo: bar\n").unwrap();
    fs::write(&child, "foo2: bar2\nbase_value_2: {id: 2}\n").unwrap();
    let options = [("config_files", child.to_str().unwrap()), ("foo2", "bar22")];

    let config = FalcoConfig::load_from_file_with_cli_overrides(&main, &options).unwrap();
    assert_eq!(config.loaded_files.len(), 2);
    assert_eq!(
        config.value("foo2").unwrap(),
        Some(&Value::String("bar22".into()))
    );
    assert_eq!(
        config.value("base_value_2.id").unwrap(),
        Some(&Value::from(2))
    );
}

#[test]
fn rule_selection_cli_options() {
    let mut config = FalcoConfig::load_from_str("").unwrap();
    config
        .apply_cli_override("rules[].disable.tag", "maturity_incubating")
        .unwrap();
    config
        .apply_cli_override("rules[].enable.rule", "Adding ssh keys to authorized_keys")
        .unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].operation, RuleSelectionOperation::Disable);
    assert_eq!(config.rules[0].tag.as_deref(), Some("maturity_incubating"));
    assert_eq!(config.rules[1].operation, RuleSelectionOperation::Enable);
}

#[test]
fn rule_selection_cli_options_object() {
    let mut config = FalcoConfig::load_from_str("").unwrap();
    config
        .apply_cli_override("rules[]", r#"{"disable":{"tag":"maturity_incubating"}}"#)
        .unwrap();
    config
        .apply_cli_override(
            "rules[]",
            r#"{"enable":{"rule":"Adding ssh keys to authorized_keys"}}"#,
        )
        .unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].operation, RuleSelectionOperation::Disable);
    assert_eq!(
        config.rules[1].rule.as_deref(),
        Some("Adding ssh keys to authorized_keys")
    );
}

#[test]
fn append_output_cli_options_full() {
    let mut config = FalcoConfig::load_from_str("").unwrap();
    for option in [
        r#"{"match":{"source":"syscall","tags":["persistence"],"rule":"some rule name"},"extra_output":"gparent=%proc.aname[2]"}"#,
        r#"{"match":{"tags":["persistence","execution"]},"extra_fields":[{"proc.aname[2]":"%proc.aname[2]"},{"proc.aname[3]":"%proc.aname[3]"},{"proc.aname[4]":"%proc.aname[4]"}]}"#,
        r#"{"match":{"source":"k8s_audit"},"extra_fields":["ka.verb",{"static_field":"static content"}]}"#,
    ] {
        config
            .apply_cli_override("append_output[]", option)
            .unwrap();
    }

    assert_eq!(config.append_output.len(), 3);
    assert_eq!(config.append_output[0].match_config.tags, ["persistence"]);
    assert_eq!(config.append_output[1].match_config.tags.len(), 2);
    assert_eq!(config.append_output[1].extra_fields.len(), 3);
    assert_eq!(
        config.append_output[2].extra_fields[0],
        Value::String("ka.verb".into())
    );
    assert_eq!(
        config.append_output[2].extra_fields[1]["static_field"],
        Value::String("static content".into())
    );
}
