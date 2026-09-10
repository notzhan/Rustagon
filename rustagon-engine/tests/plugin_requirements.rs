use rustagon_engine::{FalcoEngine, PluginVersion};

fn check(loaded: &[(&str, &str)], rules: &str) -> Result<(), String> {
    let mut engine = FalcoEngine::new();
    let result = engine.load_rules(rules, "rules.yaml");
    assert!(result.ok, "{:?}", result.errors);
    engine.check_plugin_requirements(
        &loaded
            .iter()
            .map(|(name, version)| PluginVersion::new(*name, *version))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn check_plugin_requirements_success() {
    assert!(check(&[("k8saudit", "0.1.0")], "").is_ok());
    assert!(check(
        &[("k8saudit", "0.2.0")],
        "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n"
    )
    .is_ok());
    assert!(check(&[("k8saudit", "0.1.0"), ("json", "0.3.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n  - name: json\n    version: 0.3.0\n").is_ok());
    assert!(check(&[("k8saudit", "0.2.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n- required_plugin_versions:\n  - name: k8saudit\n    version: 0.2.0\n").is_ok());
    assert!(check(&[("k8saudit-other", "0.5.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n    alternatives:\n      - name: k8saudit-other\n        version: 0.4.0\n").is_ok());
    assert!(check(&[("k8saudit-other", "0.5.0"), ("json2", "0.5.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n    alternatives:\n      - name: k8saudit-other\n        version: 0.4.0\n  - name: json\n    version: 0.3.0\n    alternatives:\n      - name: json2\n        version: 0.1.0\n").is_ok());
}

#[test]
fn check_plugin_requirements_reject() {
    let rules = "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.2.0\n";
    assert!(check(&[], rules).unwrap_err().contains("k8saudit"));
    assert!(check(&[("k8saudit", "0.1.0")], rules)
        .unwrap_err()
        .contains("0.2.0"));
    assert!(check(&[("other", "1.0.0")], rules).is_err());
    assert!(check(&[("k8saudit", "0.5.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n    alternatives:\n      - name: k8saudit\n        version: 0.4.0\n").is_err());
    assert!(check(&[("k8saudit", "0.1.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n  - name: json\n    version: 0.3.0\n").is_err());
    assert!(check(&[("k8saudit", "0.1.0")], "- required_plugin_versions:\n  - name: k8saudit\n    version: 0.1.0\n- required_plugin_versions:\n  - name: k8saudit\n    version: 0.2.0\n").is_err());
}
