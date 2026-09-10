use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn rustagon() -> Command {
    Command::cargo_bin("rustagon").expect("rustagon binary should be built")
}

#[test]
fn help_and_version_are_available_from_the_binary() {
    rustagon()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cloud-native runtime security"));

    rustagon()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("rustagon "));
}

#[test]
fn validate_loads_rules_without_starting_ebpf() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.yaml");
    fs::write(
        &rules,
        "- rule: shell\n  condition: evt.type=open\n  output: shell\n  priority: INFO\n",
    )
    .unwrap();

    rustagon()
        .args(["--validate", rules.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("validated successfully"));
}

#[test]
fn normal_run_reports_that_daemon_startup_is_not_wired() {
    rustagon()
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "daemon startup is not available from rustagon-app",
        ));
}
