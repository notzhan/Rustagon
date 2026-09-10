use rustagon_e2e_evtgen::{expand_suite, parse_suite, run_offline_case};
use rustagon_engine::FalcoEngine;
use rustagon_sinsp::Evt;
use std::collections::HashMap;
use std::fs;

const RULES: &str = include_str!("../fixtures/rules/all_evtgen_rules.yaml");

#[test]
fn all_twenty_evtgen_fixtures_match_offline() {
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
        let case = &expanded[0];
        let fixture = path.file_stem().unwrap().to_str().unwrap();
        let alert = run_offline_case(fixture, case, RULES).unwrap_or_else(|error| {
            panic!("run offline {}: {error:#}", path.display());
        });
        assert_eq!(alert.rule, case.rule, "{}", path.display());
        assert_eq!(
            alert.priority,
            case.expected_outcome.priority.to_ascii_lowercase(),
            "{}",
            path.display()
        );
        assert_eq!(
            alert.source,
            case.expected_outcome.source,
            "{}",
            path.display()
        );
        assert_eq!(
            alert.output_fields.len(),
            case.expected_outcome.output_fields.len(),
            "{} did not verify every expected output field",
            path.display()
        );
    }
}

#[test]
fn core_predicate_near_misses_do_not_match() {
    let cases = [
        (
            "clear-log open without truncation",
            [
                ("evt.type", "open"),
                ("fd.name", "/var/log/eg_clear_test"),
                ("evt.arg.flags", "O_WRONLY|O_CREAT"),
            ]
            .as_slice(),
        ),
        (
            "debugfs in an unprivileged container",
            [
                ("evt.type", "execve"),
                ("proc.name", "debugfs"),
                ("container.id", "0123456789abcdef"),
                ("container.privileged", "false"),
            ]
            .as_slice(),
        ),
        (
            "base-image binary execution in a container",
            [
                ("evt.type", "execve"),
                ("proc.exe", "/tmp/eg_dropped"),
                ("container.id", "0123456789abcdef"),
                ("proc.is_exe_upper_layer", "false"),
            ]
            .as_slice(),
        ),
    ];

    for (name, fields) in cases {
        let mut engine = FalcoEngine::new();
        let loaded = engine.load_rules(RULES, "all_evtgen_rules.yaml");
        assert!(loaded.ok, "{name}: {:?}", loaded.errors);
        let event = Evt::new(
            fields
                .iter()
                .map(|(field, value)| ((*field).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        );

        assert!(
            engine.process_event(&event, 0).is_none(),
            "{name} unexpectedly matched"
        );
    }
}
