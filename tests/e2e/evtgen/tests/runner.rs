use rustagon_e2e_evtgen::{expand_suite, parse_suite, run_shell_untrusted_offline};
use serde_yaml::Value;
use std::fs;

const SUITE: &str = include_str!("../fixtures/run_shell_untrusted.yaml");
const RULES: &str = include_str!("../fixtures/run_shell_untrusted_rules.yaml");

#[test]
fn run_shell_untrusted_nginx_bash_matches_offline() {
    let suite = parse_suite(SUITE).expect("parse run_shell_untrusted fixture");
    let cases = expand_suite(&suite).expect("expand run_shell_untrusted matrix");
    let case = cases
        .iter()
        .find(|case| {
            case.test_name == "run_shell_untrusted_direct_spawner"
                && case.item.get("shell") == Some(&Value::String("bash".into()))
                && case.item.get("spawner") == Some(&Value::String("nginx".into()))
        })
        .expect("nginx -> bash matrix case");

    let alert = run_shell_untrusted_offline(case, RULES).expect("offline case should alert");

    assert_eq!(alert.rule, "Run shell untrusted");
    assert_eq!(alert.priority, "notice");
    assert_eq!(alert.source, "syscall");
    assert_eq!(alert.output_fields["proc.name"], "bash");
    assert_eq!(alert.output_fields["proc.pname"], "nginx");
}

#[test]
fn all_twenty_evtgen_fixtures_parse_and_expand() {
    let fixture_dir = format!("{}/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut suites = fs::read_dir(fixture_dir)
        .expect("read fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| {
            path.extension().and_then(|ext| ext.to_str()) == Some("yaml")
                && path.file_name().and_then(|name| name.to_str())
                    != Some("run_shell_untrusted_rules.yaml")
        })
        .collect::<Vec<_>>();
    suites.sort();

    assert_eq!(suites.len(), 20);
    for path in suites {
        let input = fs::read_to_string(&path).expect("read fixture");
        let suite = parse_suite(&input).unwrap_or_else(|error| {
            panic!("parse {}: {error:#}", path.display());
        });
        let expanded = expand_suite(&suite).unwrap_or_else(|error| {
            panic!("expand {}: {error:#}", path.display());
        });
        assert!(
            !expanded.is_empty(),
            "{} expanded to no cases",
            path.display()
        );
    }
}
