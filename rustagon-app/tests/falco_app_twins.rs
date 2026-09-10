use clap::Parser;
use rustagon_app::{
    atomic_signal_handler::AtomicSignalHandler,
    capture::{
        check_capture_stop, generate_scap_file_path, CaptureConfig, CaptureMode, CaptureStopReason,
    },
    cli::Cli,
    load_config::load_config,
    pidfile::write_pidfile,
    restart_handler::RestartHandler,
    select_event_sources::{select_event_sources, SourceSelection},
    syscall_buffer::configure_syscall_buffer_num,
    validate_rules::validate_rules_content,
};
use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Barrier,
    },
    thread,
    time::{Duration, Instant},
};

#[test]
fn cli_parses_falco_compatible_flags() {
    let cli = Cli::try_parse_from([
        "rustagon",
        "-c",
        "falco.yaml",
        "-r",
        "one.yaml",
        "-r",
        "two.yaml",
        "-o",
        "json_output=true",
        "--list",
        "--list-events",
        "--validate",
        "rules.yaml",
        "--dry-run",
    ])
    .unwrap();
    assert_eq!(cli.config.to_str(), Some("falco.yaml"));
    assert_eq!(cli.rules.len(), 2);
    assert_eq!(cli.overrides, ["json_output=true"]);
    assert!(cli.list && cli.list_events && cli.dry_run);
    assert_eq!(cli.validate, [std::path::PathBuf::from("rules.yaml")]);
}

#[test]
fn cli_applies_overrides_to_config() {
    let cli = Cli::try_parse_from(["rustagon", "-o", "json_output=true"]).unwrap();
    let mut config = rustagon_config::FalcoConfig::default();
    cli.apply_overrides(&mut config).unwrap();
    assert!(config.json_output);
}

#[test]
fn cli_rejects_override_without_equals() {
    assert!(Cli::try_parse_from(["rustagon", "-o", "json_output"]).is_err());
}

#[test]
fn atomic_signal_handler_lock_free_implementation() {
    assert!(AtomicSignalHandler::new().is_lock_free());
}

#[test]
fn atomic_signal_handler_handle_once_wait_consistency() {
    let handler = Arc::new(AtomicSignalHandler::new());
    let handled = Arc::new(AtomicUsize::new(0));
    let threads = (0..10)
        .map(|_| {
            let handler = Arc::clone(&handler);
            let handled = Arc::clone(&handled);
            thread::spawn(move || {
                while !handler.handled() {
                    if handler.triggered()
                        && handler.handle(|| thread::sleep(Duration::from_millis(50)))
                    {
                        handled.fetch_add(1, Ordering::SeqCst);
                    }
                    thread::yield_now();
                }
            })
        })
        .collect::<Vec<_>>();
    handler.trigger();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(handled.load(Ordering::SeqCst), 1);
}

#[test]
fn atomic_signal_handler_concurrent_call_waits_for_active_callback() {
    let handler = Arc::new(AtomicSignalHandler::new());
    let callback_started = Arc::new(Barrier::new(2));
    let release_callback = Arc::new(Barrier::new(2));
    handler.trigger();

    let active = {
        let handler = Arc::clone(&handler);
        let callback_started = Arc::clone(&callback_started);
        let release_callback = Arc::clone(&release_callback);
        thread::spawn(move || {
            handler.handle(|| {
                callback_started.wait();
                release_callback.wait();
            })
        })
    };
    callback_started.wait();

    let (done_tx, done_rx) = mpsc::channel();
    let waiter = {
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            let result = handler.handle(|| panic!("only the elected callback may run"));
            done_tx.send(result).unwrap();
        })
    };

    thread::sleep(Duration::from_millis(50));
    assert!(
        done_rx.try_recv().is_err(),
        "concurrent handle returned before the active callback completed"
    );
    release_callback.wait();
    assert!(active.join().unwrap());
    assert!(!done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
    waiter.join().unwrap();
}

#[test]
fn atomic_signal_handler_handle_and_reset() {
    let handler = AtomicSignalHandler::new();
    assert!(!handler.triggered());
    assert!(!handler.handled());
    assert!(!handler.handle(|| {}));
    handler.trigger();
    assert!(handler.triggered());
    assert!(!handler.handled());
    assert!(handler.handle(|| {}));
    assert!(handler.handled());
    assert!(!handler.handle(|| {}));
    handler.trigger();
    assert!(!handler.handled());
    assert!(handler.handle(|| {}));
    handler.reset();
    assert!(!handler.triggered());
    assert!(!handler.handled());
}

fn wait_until(mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    predicate()
}

#[test]
fn restart_forced_trigger_with_nothing_to_watch() {
    let checks = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&checks);
    let mut handler = RestartHandler::new(
        move || {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        },
        vec![],
    );
    handler.start().unwrap();
    handler.trigger();
    assert!(wait_until(|| handler.restart_signal().triggered()));
    assert!(checks.load(Ordering::SeqCst) >= 1);
    handler.stop();
}

#[test]
fn restart_failed_check_does_not_restart_and_can_retry() {
    let checks = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&checks);
    let mut handler = RestartHandler::new(
        move || {
            seen.fetch_add(1, Ordering::SeqCst);
            false
        },
        vec![],
    );
    handler.start().unwrap();
    handler.trigger();
    assert!(wait_until(|| checks.load(Ordering::SeqCst) >= 1));
    assert!(!handler.restart_signal().triggered());
    handler.trigger();
    assert!(wait_until(|| checks.load(Ordering::SeqCst) >= 2));
    assert!(!handler.restart_signal().triggered());
    handler.stop();
}

#[test]
fn restart_stop_with_nothing_to_watch_joins_promptly() {
    let mut handler = RestartHandler::new(|| true, vec![]);
    handler.start().unwrap();
    let started = Instant::now();
    handler.stop();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!handler.restart_signal().triggered());
}

#[test]
fn restart_watched_file_change_triggers_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(&path, "a\n").unwrap();
    let checks = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&checks);
    let mut handler = RestartHandler::new(
        move || {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        },
        vec![path.clone()],
    );
    handler.start().unwrap();
    thread::sleep(Duration::from_millis(150));
    fs::write(path, "b\n").unwrap();
    assert!(wait_until(|| handler.restart_signal().triggered()));
    assert!(checks.load(Ordering::SeqCst) >= 1);
    handler.stop();
}

#[test]
fn capture_generate_path_realistic_scenario() {
    assert_eq!(
        generate_scap_file_path(
            "/var/log/falco/captures/security_event",
            1_648_178_040_000_000_000,
            1011
        ),
        "/var/log/falco/captures/security_event_01648178040000000000_00000000000000001011.scap"
    );
}

#[test]
fn capture_generate_path_lexicographic_ordering() {
    assert!(
        generate_scap_file_path("/tmp/test", 1000, 1)
            < generate_scap_file_path("/tmp/test", 2000, 1)
    );
    assert!(
        generate_scap_file_path("/tmp/test", 2000, 1)
            < generate_scap_file_path("/tmp/test", 10000, 1)
    );
    assert!(
        generate_scap_file_path("/tmp/test", 1000, 2)
            < generate_scap_file_path("/tmp/test", 1000, 100)
    );
}

#[test]
fn capture_generate_path_empty_prefix() {
    assert_eq!(
        generate_scap_file_path("", 123, 456),
        "_00000000000000000123_00000000000000000456.scap"
    );
}

fn capture(yaml: &str) -> Result<CaptureConfig, String> {
    CaptureConfig::from_yaml(yaml)
}

#[test]
fn capture_config_disabled_by_default() {
    let c = capture("plugins:\n").unwrap();
    assert!(!c.enabled);
    assert_eq!(c.path_prefix, "/tmp/falco");
    assert_eq!(c.mode, CaptureMode::Rules);
    assert_eq!(c.default_duration_ns, 5_000_000_000);
    assert_eq!(c.max_file_size_mb, 0);
}

#[test]
fn capture_config_enabled_rules_mode() {
    let c = capture("capture:\n  enabled: true\n  path_prefix: /var/log/captures/falco\n  mode: rules\n  default_duration: 10000\n").unwrap();
    assert!(c.enabled);
    assert_eq!(c.path_prefix, "/var/log/captures/falco");
    assert_eq!(c.mode, CaptureMode::Rules);
    assert_eq!(c.default_duration_ns, 10_000_000_000);
}

#[test]
fn capture_config_enabled_all_rules_mode() {
    let c = capture("capture:\n  enabled: true\n  path_prefix: /tmp/debug/falco\n  mode: all_rules\n  default_duration: 30000\n").unwrap();
    assert!(c.enabled);
    assert_eq!(c.mode, CaptureMode::AllRules);
    assert_eq!(c.default_duration_ns, 30_000_000_000);
}

#[test]
fn capture_config_invalid_mode() {
    assert!(capture("capture:\n  enabled: true\n  mode: invalid_mode\n").is_err());
}

#[test]
fn capture_config_with_max_file_size_mb() {
    assert_eq!(
        capture("capture:\n  enabled: true\n  max_file_size_mb: 100\n")
            .unwrap()
            .max_file_size_mb,
        100
    );
}

#[test]
fn capture_config_with_all_limits() {
    let c =
        capture("capture:\n  enabled: true\n  default_duration: 15000\n  max_file_size_mb: 500\n")
            .unwrap();
    assert_eq!(c.default_duration_ns, 15_000_000_000);
    assert_eq!(c.max_file_size_mb, 500);
}

#[test]
fn capture_config_rejects_out_of_range_max_file_size_mb() {
    assert!(capture("capture:\n  enabled: true\n  max_file_size_mb: 99999999999\n").is_err());
}

#[test]
fn capture_stop_no_stop() {
    assert_eq!(check_capture_stop(100, 200, 0, 0), CaptureStopReason::None);
    assert_eq!(
        check_capture_stop(100, 200, 1024, 1),
        CaptureStopReason::None
    );
}

#[test]
fn capture_stop_time_deadline() {
    assert_eq!(
        check_capture_stop(200, 200, 0, 0),
        CaptureStopReason::TimeDeadline
    );
    assert_eq!(
        check_capture_stop(201, 200, 0, 0),
        CaptureStopReason::TimeDeadline
    );
}

#[test]
fn capture_stop_size_limit() {
    assert_eq!(
        check_capture_stop(100, 200, 1024 * 1024, 1),
        CaptureStopReason::SizeLimit
    );
    assert_eq!(
        check_capture_stop(100, 200, 2 * 1024 * 1024, 1),
        CaptureStopReason::SizeLimit
    );
    assert_eq!(
        check_capture_stop(100, 200, 1024 * 1024 - 1, 1),
        CaptureStopReason::None
    );
}

#[test]
fn capture_stop_zero_means_unlimited() {
    assert_eq!(
        check_capture_stop(100, 200, u64::MAX, 0),
        CaptureStopReason::None
    );
}

#[test]
fn capture_stop_time_wins_when_both_tripped() {
    assert_eq!(
        check_capture_stop(200, 200, 10 * 1024 * 1024, 1),
        CaptureStopReason::TimeDeadline
    );
}

#[test]
fn pidfile_empty_filename_is_noop() {
    write_pidfile("", false).unwrap();
}

#[test]
fn pidfile_dry_run_does_not_create_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dry.pid");
    write_pidfile(&path, true).unwrap();
    assert!(!path.exists());
}

#[test]
fn pidfile_writes_pid_to_file_and_truncates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.pid");
    fs::write(&path, "999999999999999999\n").unwrap();
    write_pidfile(&path, false).unwrap();
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        format!("{}\n", std::process::id())
    );
}

#[cfg(unix)]
#[test]
fn pidfile_refuses_symlinked_path() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.pid");
    let link = dir.path().join("link.pid");
    symlink(&target, &link).unwrap();
    assert!(write_pidfile(&link, false).is_err());
    assert!(!target.exists());
}

#[test]
fn validate_rules_suggests_dry_run_for_config_file() {
    let result = validate_rules_content(
        "falco.yaml",
        "rules_files:\n  - /etc/falco/falco_rules.yaml\n",
        false,
    );
    assert!(!result.success);
    assert!(result.error.contains("--validate expects a rules file"));
    assert!(result.error.contains("falco -c falco.yaml --dry-run"));
    assert!(result.output.contains("--validate expects a rules file"));
}

#[test]
fn validate_rules_preserves_json_output_for_config_file() {
    let result = validate_rules_content("falco.yaml", "rules_files:\n  - rules.yaml\n", true);
    assert!(!result.success);
    let json: serde_yaml::Value = serde_yaml::from_str(&result.output).unwrap();
    assert!(json.get("falco_load_results").is_some());
    assert!(!result.output.contains("--dry-run"));
}

#[test]
fn validate_rules_omits_config_hint_for_rules_sequence() {
    let result = validate_rules_content("rules.yaml", "- rule: missing required fields\n", false);
    assert!(!result.success);
    assert!(!result.error.contains("--validate expects"));
    assert!(!result.error.contains("--dry-run"));
}

#[test]
fn select_event_sources_pre_post_conditions() {
    assert!(select_event_sources(&[], false, &SourceSelection::default()).is_err());
    assert!(select_event_sources(&[], true, &SourceSelection::default())
        .unwrap()
        .is_empty());
    let loaded = vec!["syscall".to_string(), "some_source".to_string()];
    assert_eq!(
        select_event_sources(&loaded, false, &SourceSelection::default())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        select_event_sources(
            &loaded,
            false,
            &SourceSelection {
                enable: vec!["syscall".into()],
                disable: vec![]
            }
        )
        .unwrap(),
        ["syscall"]
    );
    assert_eq!(
        select_event_sources(
            &loaded,
            false,
            &SourceSelection {
                enable: vec![],
                disable: vec!["syscall".into()]
            }
        )
        .unwrap(),
        ["some_source"]
    );
    assert!(select_event_sources(
        &loaded,
        false,
        &SourceSelection {
            enable: vec!["unknown".into()],
            disable: vec![]
        }
    )
    .is_err());
    assert!(select_event_sources(
        &loaded,
        false,
        &SourceSelection {
            enable: vec![],
            disable: vec!["unknown".into()]
        }
    )
    .is_err());
    assert!(select_event_sources(
        &loaded,
        false,
        &SourceSelection {
            enable: vec!["syscall".into()],
            disable: vec!["syscall".into()]
        }
    )
    .is_err());
}

#[test]
fn syscall_buffer_variable_number_of_cpus() {
    let online = thread::available_parallelism().unwrap().get();
    assert_eq!(
        configure_syscall_buffer_num(false, online + 1, online),
        online + 1
    );
    assert_eq!(
        configure_syscall_buffer_num(true, online + 1, online),
        online
    );
    assert_eq!(
        configure_syscall_buffer_num(true, online.saturating_sub(1), online),
        online.saturating_sub(1)
    );
}

#[test]
fn load_config_checks_kmod_engine_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(&path, "engine:\n  kind: kmod\n  kmod:\n    buf_size_preset: 2\n    drop_failed_exit: false\n  modern_ebpf:\n    cpus_for_each_buffer: 2\n    buf_size_preset: 4\n  replay:\n    capture_file: /tmp/a.scap\n").unwrap();
    let config = load_config(&path, &[]).unwrap();
    assert_eq!(config.engine.kind, "kmod");
    assert_eq!(config.engine.kmod.buf_size_preset, 2);
    assert!(!config.engine.kmod.drop_failed_exit);
    assert_eq!(config.engine.modern_ebpf, Default::default());
    assert!(config.engine.replay.capture_file.is_empty());
}

#[test]
fn load_config_checks_modern_engine_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("falco.yaml");
    fs::write(&path, "engine:\n  kind: modern_ebpf\n  kmod:\n    buf_size_preset: 1\n    drop_failed_exit: true\n  modern_ebpf:\n    cpus_for_each_buffer: 1\n    buf_size_preset: 4\n    drop_failed_exit: true\n    disable_iterators: true\n  replay:\n    capture_file: /tmp/a.scap\n").unwrap();
    let config = load_config(&path, &[]).unwrap();
    assert_eq!(config.engine.kind, "modern_ebpf");
    assert_eq!(config.engine.modern_ebpf.cpus_for_each_buffer, 1);
    assert_eq!(config.engine.modern_ebpf.buf_size_preset, 4);
    assert!(config.engine.modern_ebpf.drop_failed_exit);
    assert!(config.engine.modern_ebpf.disable_iterators);
    assert_eq!(config.engine.kmod, Default::default());
    assert!(config.engine.replay.capture_file.is_empty());
}
