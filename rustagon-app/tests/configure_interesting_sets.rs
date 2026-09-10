use rustagon_app::interesting_sets::{
    configure_interesting_sets, default_state_syscalls, ignored_syscalls, InterestingSetsConfig,
    InterestingSetsState, RuleEventSets,
};
use rustagon_engine::FalcoEngine;
use std::collections::BTreeSet;

const SAMPLE_RULESET: &str = "sample-ruleset";
const SAMPLE_FILTERS: &[&str] = &[
    "evt.type=connect or evt.type=accept or evt.type=accept4 or evt.type=umount2",
    "evt.type in (open, ptrace, mmap, execve, read, container)",
    "evt.type in (open, execve, mprotect) and not evt.type=mprotect",
];
const GENERIC_FILTERS: &[&str] = &["evt.type=syncfs or evt.type=fanotify_init"];
const NONSYSCALL_FILTERS: &[&str] = &["evt.type in (procexit, switch, pluginevent, container)"];

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn repaired_sample_rules() -> BTreeSet<String> {
    names(&[
        "accept",
        "accept4",
        "bind",
        "capset",
        "chdir",
        "chroot",
        "clone",
        "clone3",
        "close",
        "connect",
        "execve",
        "execveat",
        "fchdir",
        "fork",
        "getsockopt",
        "mmap",
        "open",
        "prctl",
        "procexit",
        "ptrace",
        "read",
        "setgid",
        "setpgid",
        "setresgid",
        "setresuid",
        "setsid",
        "setuid",
        "socket",
        "umount2",
        "vfork",
    ])
}

fn load(filters: &[&str]) -> FalcoEngine {
    let rules = filters
        .iter()
        .enumerate()
        .map(|(index, filter)| {
            format!(
                "- rule: Dummy Rule {}\n  output: Dummy Output\n  condition: {}\n  desc: Dummy Desc\n  priority: CRITICAL\n",
                index + 1,
                filter
            )
        })
        .collect::<String>();
    let mut engine = FalcoEngine::new();
    assert!(engine.load_rules(&rules, "dummy_ruleset.yaml").ok);
    engine.enable_rule("", true, SAMPLE_RULESET);
    engine
}

fn rule_sets(filters: &[&str]) -> RuleEventSets {
    RuleEventSets::from_engine(&load(filters), "syscall", SAMPLE_RULESET)
}

fn configured(filters: &[&str], config: InterestingSetsConfig) -> InterestingSetsState {
    let mut state = InterestingSetsState {
        engine: Some(rule_sets(filters)),
        config: Some(config),
        ..Default::default()
    };
    configure_interesting_sets(&mut state).unwrap();
    state
}

#[test]
fn engine_codes_syscalls_set() {
    let engine = load(SAMPLE_FILTERS);
    assert_eq!(engine.num_rules_for_ruleset(SAMPLE_RULESET), 3);
    let sets = RuleEventSets::from_engine(&engine, "syscall", SAMPLE_RULESET);
    assert_eq!(
        sets.event_names,
        names(&[
            "connect",
            "accept",
            "accept4",
            "umount2",
            "open",
            "ptrace",
            "mmap",
            "execve",
            "read",
            "container",
            "asyncevent",
        ])
    );
    assert_eq!(
        sets.syscall_names,
        names(&[
            "connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read",
        ])
    );
}

#[test]
fn preconditions_postconditions() {
    let mut state = InterestingSetsState {
        config: Some(InterestingSetsConfig::default()),
        ..Default::default()
    };
    assert!(!configure_interesting_sets(&mut state)
        .unwrap_err()
        .is_empty());
    state.engine = Some(rule_sets(SAMPLE_FILTERS));
    state.config = None;
    assert!(!configure_interesting_sets(&mut state)
        .unwrap_err()
        .is_empty());
    state.config = Some(InterestingSetsConfig::default());
    configure_interesting_sets(&mut state).unwrap();
    let previous = state.selected_syscalls.clone();
    configure_interesting_sets(&mut state).unwrap();
    assert_eq!(state.selected_syscalls, previous);
}

#[test]
fn engine_codes_nonsyscalls_set() {
    let filters = [SAMPLE_FILTERS, GENERIC_FILTERS, NONSYSCALL_FILTERS].concat();
    let sets = rule_sets(&filters);
    let expected_events = names(&[
        "connect",
        "accept",
        "accept4",
        "umount2",
        "open",
        "ptrace",
        "mmap",
        "execve",
        "read",
        "container",
        "procexit",
        "switch",
        "pluginevent",
        "asyncevent",
        "syncfs",
        "fanotify_init",
    ]);
    assert_eq!(sets.event_names, expected_events);
    assert_eq!(
        sets.syscall_names,
        names(&[
            "connect",
            "accept",
            "accept4",
            "umount2",
            "open",
            "ptrace",
            "mmap",
            "execve",
            "read",
            "procexit",
            "switch",
            "syncfs",
            "fanotify_init",
        ])
    );
}

#[test]
fn selection_not_allevents() {
    let state = configured(SAMPLE_FILTERS, InterestingSetsConfig::default());
    let expected = names(&[
        "connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "clone",
        "clone3", "fork", "vfork", "socket", "bind", "close", "procexit",
    ]);
    assert_eq!(state.selected_syscalls, expected);
}

#[test]
fn selection_allevents() {
    let state = configured(
        SAMPLE_FILTERS,
        InterestingSetsConfig {
            base_syscalls_all: true,
            ..Default::default()
        },
    );
    let expected = names(&[
        "connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read",
        "clone", "clone3", "fork", "vfork", "socket", "bind", "close", "procexit",
    ]);
    assert_eq!(state.selected_syscalls, expected);
}

#[test]
fn selection_generic_evts() {
    let filters = [SAMPLE_FILTERS, GENERIC_FILTERS].concat();
    let state = configured(&filters, InterestingSetsConfig::default());
    assert_eq!(
        state.selected_syscalls,
        names(&[
            "connect",
            "accept",
            "accept4",
            "umount2",
            "open",
            "ptrace",
            "mmap",
            "execve",
            "syncfs",
            "fanotify_init",
            "clone",
            "clone3",
            "fork",
            "vfork",
            "socket",
            "bind",
            "close",
            "procexit",
        ])
    );
}

#[test]
fn selection_custom_base_set() {
    let mut state = InterestingSetsState {
        engine: Some(rule_sets(SAMPLE_FILTERS)),
        config: Some(InterestingSetsConfig {
            base_syscalls_all: true,
            base_syscalls_custom_set: names(&["syncfs", "!accept"]),
            base_syscalls_repair: false,
        }),
        ..Default::default()
    };
    configure_interesting_sets(&mut state).unwrap();
    assert_eq!(
        state.selected_syscalls,
        names(&[
            "connect", "umount2", "open", "ptrace", "mmap", "execve", "read", "syncfs", "procexit",
        ])
    );

    state.config.as_mut().unwrap().base_syscalls_custom_set =
        names(&["syncfs", "accept", "!accept"]);
    configure_interesting_sets(&mut state).unwrap();
    assert!(!state.selected_syscalls.contains("accept"));
    assert!(!state.selected_syscalls.contains("accept4"));

    state.config.as_mut().unwrap().base_syscalls_custom_set = names(&["syncfs"]);
    configure_interesting_sets(&mut state).unwrap();
    assert_eq!(
        state.selected_syscalls,
        names(&[
            "connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve", "read",
            "syncfs", "procexit",
        ])
    );

    state.config.as_mut().unwrap().base_syscalls_custom_set = names(&["!accept"]);
    configure_interesting_sets(&mut state).unwrap();
    assert_eq!(
        state.selected_syscalls,
        names(&[
            "connect", "umount2", "open", "ptrace", "mmap", "execve", "read", "clone", "clone3",
            "fork", "vfork", "socket", "bind", "close", "procexit",
        ])
    );

    let config = state.config.as_mut().unwrap();
    config.base_syscalls_all = false;
    config.base_syscalls_custom_set = names(&["read"]);
    configure_interesting_sets(&mut state).unwrap();
    assert_eq!(
        state.selected_syscalls,
        names(&[
            "connect", "accept", "accept4", "umount2", "open", "ptrace", "mmap", "execve",
            "procexit",
        ])
    );
}

#[test]
fn selection_custom_base_set_repair() {
    let state = configured(
        SAMPLE_FILTERS,
        InterestingSetsConfig {
            base_syscalls_custom_set: names(&["openat", "!bind"]),
            base_syscalls_repair: true,
            ..Default::default()
        },
    );
    let mut expected = repaired_sample_rules();
    expected.remove("read");
    expected.insert("openat".into());
    assert_eq!(state.selected_syscalls, expected);
}

#[test]
fn selection_empty_custom_base_set_repair() {
    let state = configured(
        SAMPLE_FILTERS,
        InterestingSetsConfig {
            base_syscalls_all: true,
            base_syscalls_repair: true,
            ..Default::default()
        },
    );
    assert_eq!(state.selected_syscalls, repaired_sample_rules());
}

#[test]
fn selection_base_syscalls_all() {
    let state = configured(
        SAMPLE_FILTERS,
        InterestingSetsConfig {
            base_syscalls_all: true,
            base_syscalls_repair: true,
            ..Default::default()
        },
    );
    assert_eq!(state.selected_syscalls, repaired_sample_rules());
}

#[test]
fn negative_only_custom_set_uses_empty_positive_repair_path() {
    let state = configured(
        SAMPLE_FILTERS,
        InterestingSetsConfig {
            base_syscalls_all: true,
            base_syscalls_custom_set: names(&["!bind"]),
            base_syscalls_repair: true,
        },
    );
    assert_eq!(state.selected_syscalls, repaired_sample_rules());
}

#[test]
fn invalid_only_custom_set_uses_empty_positive_repair_path() {
    let state = configured(
        SAMPLE_FILTERS,
        InterestingSetsConfig {
            base_syscalls_all: true,
            base_syscalls_custom_set: names(&["not_a_syscall"]),
            base_syscalls_repair: true,
        },
    );
    assert_eq!(state.selected_syscalls, repaired_sample_rules());
}

#[test]
fn ignored_set_expected_size() {
    let ignored = names(&[
        "read", "write", "pread", "pwrite", "readv", "writev", "preadv", "pwritev", "recv",
        "recvfrom", "send", "sendto",
    ]);
    let default_state = names(&[
        "clone", "clone3", "fork", "vfork", "socket", "bind", "close",
    ]);
    assert_eq!(ignored_syscalls(), ignored);
    assert_eq!(default_state_syscalls(), default_state);
    assert!(ignored.is_disjoint(&default_state));
}
