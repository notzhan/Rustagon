use rustagon_config::FalcoConfig;

#[test]
fn parses_stable_drop_and_base_syscalls_keys() {
    let config = FalcoConfig::load_from_str(
        r#"
syscall_event_drops:
  threshold: 0.25
  actions: [log, exit]
  rate: 0.5
  max_burst: 3
  simulate_drops: true
base_syscalls:
  custom_set: [openat, "!write"]
  repair: true
  all: true
"#,
    )
    .unwrap();

    assert_eq!(config.syscall_event_drops.threshold, 0.25);
    assert_eq!(config.syscall_event_drops.actions, ["log", "exit"]);
    assert_eq!(config.syscall_event_drops.rate, 0.5);
    assert_eq!(config.syscall_event_drops.max_burst, 3);
    assert!(config.syscall_event_drops.simulate_drops);
    assert_eq!(config.base_syscalls.custom_set, ["openat", "!write"]);
    assert!(config.base_syscalls.repair);
    assert!(config.base_syscalls.all);
}
