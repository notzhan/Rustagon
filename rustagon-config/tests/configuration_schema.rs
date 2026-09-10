use rustagon_config::{FalcoConfig, ValidationStatus, YamlConfig, FALCO_CONFIG_SCHEMA};

#[test]
fn schema_validate_config() {
    let config = FalcoConfig::load_from_file("/nvraid1tank1/work/code/falco/falco.yaml").unwrap();
    assert_eq!(config.validation_status(), ValidationStatus::Ok);
}

#[test]
fn schema_ok() {
    let config = FalcoConfig::load_from_str("falco_libs:\n  thread_table_size: 50\n").unwrap();
    assert_eq!(config.validation_status(), ValidationStatus::Ok);
}

#[test]
fn schema_wrong_key() {
    let config = FalcoConfig::load_from_str("falco_libss:\n  thread_table_size: 50\n").unwrap();
    assert!(matches!(
        config.validation_status(),
        ValidationStatus::Failed(_)
    ));
}

#[test]
fn schema_wrong_type() {
    assert!(FalcoConfig::load_from_str("falco_libs: 512\n").is_err());
}

#[test]
fn schema_wrong_embedded_key() {
    let config = FalcoConfig::load_from_str("falco_libs:\n  thread_table_sizeee: 50\n").unwrap();
    assert!(matches!(
        config.validation_status(),
        ValidationStatus::Failed(_)
    ));
}

#[test]
fn schema_yaml_helper_validator() {
    let config = YamlConfig::parse("falco_libs:\n  thread_table_size: 50\n").unwrap();

    assert_eq!(config.validate(None).unwrap(), ValidationStatus::None);
    assert_eq!(
        config.validate(Some(FALCO_CONFIG_SCHEMA)).unwrap(),
        ValidationStatus::Ok
    );
}
