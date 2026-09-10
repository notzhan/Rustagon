//! Pure-Rust model of Falco's syscall interesting-set selection.

use rustagon_engine::FalcoEngine;
use std::collections::BTreeSet;

pub type NameSet = BTreeSet<String>;

#[derive(Clone, Copy)]
struct EventEntry {
    name: &'static str,
    syscall_code: Option<u16>,
    event_code: u16,
    generic: bool,
    asynchronous: bool,
}

const EVENTS: &[EventEntry] = &[
    EventEntry {
        name: "connect",
        syscall_code: Some(1),
        event_code: 1,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "accept",
        syscall_code: Some(2),
        event_code: 2,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "accept4",
        syscall_code: Some(2),
        event_code: 3,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "umount2",
        syscall_code: Some(4),
        event_code: 4,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "open",
        syscall_code: Some(5),
        event_code: 5,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "openat",
        syscall_code: Some(6),
        event_code: 6,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "ptrace",
        syscall_code: Some(7),
        event_code: 7,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "mmap",
        syscall_code: Some(8),
        event_code: 8,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "execve",
        syscall_code: Some(9),
        event_code: 9,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "read",
        syscall_code: Some(10),
        event_code: 10,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "mprotect",
        syscall_code: Some(11),
        event_code: 11,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "syncfs",
        syscall_code: Some(12),
        event_code: 100,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "fanotify_init",
        syscall_code: Some(13),
        event_code: 100,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "procexit",
        syscall_code: Some(14),
        event_code: 14,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "switch",
        syscall_code: Some(15),
        event_code: 15,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "pluginevent",
        syscall_code: None,
        event_code: 16,
        generic: false,
        asynchronous: true,
    },
    EventEntry {
        name: "container",
        syscall_code: None,
        event_code: 17,
        generic: false,
        asynchronous: true,
    },
    EventEntry {
        name: "clone",
        syscall_code: Some(18),
        event_code: 18,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "clone3",
        syscall_code: Some(19),
        event_code: 19,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "fork",
        syscall_code: Some(20),
        event_code: 20,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "vfork",
        syscall_code: Some(21),
        event_code: 21,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "socket",
        syscall_code: Some(22),
        event_code: 22,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "bind",
        syscall_code: Some(23),
        event_code: 23,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "close",
        syscall_code: Some(24),
        event_code: 24,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "setuid",
        syscall_code: Some(25),
        event_code: 25,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "execveat",
        syscall_code: Some(37),
        event_code: 37,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "fchdir",
        syscall_code: Some(38),
        event_code: 38,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "chdir",
        syscall_code: Some(39),
        event_code: 39,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "chroot",
        syscall_code: Some(40),
        event_code: 40,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "capset",
        syscall_code: Some(41),
        event_code: 41,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "setgid",
        syscall_code: Some(42),
        event_code: 42,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "setgid32",
        syscall_code: Some(43),
        event_code: 43,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "setpgid",
        syscall_code: Some(44),
        event_code: 44,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "setresgid",
        syscall_code: Some(45),
        event_code: 45,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "setresgid32",
        syscall_code: Some(46),
        event_code: 46,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "setresuid",
        syscall_code: Some(47),
        event_code: 47,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "setresuid32",
        syscall_code: Some(48),
        event_code: 48,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "setsid",
        syscall_code: Some(49),
        event_code: 49,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "setuid32",
        syscall_code: Some(50),
        event_code: 50,
        generic: true,
        asynchronous: false,
    },
    EventEntry {
        name: "prctl",
        syscall_code: Some(51),
        event_code: 51,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "getsockopt",
        syscall_code: Some(52),
        event_code: 52,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "write",
        syscall_code: Some(26),
        event_code: 26,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "pread",
        syscall_code: Some(27),
        event_code: 27,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "pwrite",
        syscall_code: Some(28),
        event_code: 28,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "readv",
        syscall_code: Some(29),
        event_code: 29,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "writev",
        syscall_code: Some(30),
        event_code: 30,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "preadv",
        syscall_code: Some(31),
        event_code: 31,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "pwritev",
        syscall_code: Some(32),
        event_code: 32,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "recv",
        syscall_code: Some(33),
        event_code: 33,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "recvfrom",
        syscall_code: Some(34),
        event_code: 34,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "send",
        syscall_code: Some(35),
        event_code: 35,
        generic: false,
        asynchronous: false,
    },
    EventEntry {
        name: "sendto",
        syscall_code: Some(36),
        event_code: 36,
        generic: false,
        asynchronous: false,
    },
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleEventSets {
    pub event_names: NameSet,
    pub syscall_names: NameSet,
}

impl RuleEventSets {
    pub fn from_engine(engine: &FalcoEngine, source: &str, ruleset: &str) -> Self {
        let selected_names = engine.event_names_for_ruleset(source, ruleset);
        let mut result = Self::default();
        let mut selected_event_codes = BTreeSet::new();
        for name in selected_names {
            let Some(entry) = EVENTS.iter().find(|entry| entry.name == name) else {
                continue;
            };
            selected_event_codes.insert(entry.event_code);
            if entry.asynchronous {
                result.event_names.insert("asyncevent".into());
            }
            if entry.syscall_code.is_some() {
                result.syscall_names.insert(entry.name.into());
            }
        }
        result.event_names.extend(
            EVENTS
                .iter()
                .filter(|entry| selected_event_codes.contains(&entry.event_code))
                .map(|entry| entry.name.to_string()),
        );
        result
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterestingSetsConfig {
    pub base_syscalls_all: bool,
    pub base_syscalls_custom_set: NameSet,
    pub base_syscalls_repair: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterestingSetsState {
    pub engine: Option<RuleEventSets>,
    pub config: Option<InterestingSetsConfig>,
    pub selected_syscalls: NameSet,
}

pub fn configure_interesting_sets(state: &mut InterestingSetsState) -> Result<(), String> {
    let rules = state
        .engine
        .as_ref()
        .ok_or_else(|| "engine must be non-null".to_string())?
        .syscall_names
        .clone();
    let config = state
        .config
        .as_ref()
        .ok_or_else(|| "config must be non-null".to_string())?;

    let (positive, negative) = split_custom_set(&config.base_syscalls_custom_set);
    let positive_is_empty = positive.is_empty();
    let mut base = if positive.is_empty() {
        default_state_syscalls()
    } else {
        positive
    };
    let mut selected = rules.clone();
    selected.append(&mut base);

    if config.base_syscalls_repair && positive_is_empty {
        selected = repair_state_syscalls(&rules);
    }
    remove_names_and_aliases(&mut selected, &negative);
    if !config.base_syscalls_all {
        selected.retain(|name| !ignored_syscalls().contains(name));
    }
    if config.base_syscalls_repair && !config.base_syscalls_custom_set.is_empty() {
        selected = repair_state_syscalls(&selected);
    }
    selected.insert("procexit".into());
    state.selected_syscalls = selected;
    Ok(())
}

pub fn generic_event_names() -> NameSet {
    EVENTS
        .iter()
        .filter(|entry| entry.generic)
        .map(|entry| entry.name.to_string())
        .collect()
}

pub fn default_state_syscalls() -> NameSet {
    names(&[
        "clone", "clone3", "fork", "vfork", "socket", "bind", "close",
    ])
}

pub fn ignored_syscalls() -> NameSet {
    names(&[
        "read", "write", "pread", "pwrite", "readv", "writev", "preadv", "pwritev", "recv",
        "recvfrom", "send", "sendto",
    ])
}

pub fn repair_state_syscalls(selected: &NameSet) -> NameSet {
    let mut repaired = selected.clone();
    repaired.extend(names(&[
        "clone",
        "clone3",
        "fork",
        "vfork",
        "execve",
        "execveat",
        "fchdir",
        "chdir",
        "chroot",
        "capset",
        "setgid",
        "setpgid",
        "setresgid",
        "setresuid",
        "setsid",
        "setuid",
        "prctl",
        "procexit",
    ]));
    let network = names(&[
        "accept",
        "accept4",
        "bind",
        "connect",
        "getsockopt",
        "listen",
        "recv",
        "recvfrom",
        "send",
        "sendto",
        "socket",
    ]);
    if !selected.is_disjoint(&network) {
        repaired.extend(names(&["socket", "getsockopt", "close"]));
    }
    if selected.contains("accept") || selected.contains("accept4") || selected.contains("listen") {
        repaired.insert("bind".into());
    }
    let fd_users = names(&[
        "close",
        "fanotify_init",
        "mmap",
        "open",
        "openat",
        "pread",
        "preadv",
        "pwrite",
        "pwritev",
        "read",
        "readv",
        "syncfs",
        "write",
        "writev",
    ]);
    if !selected.is_disjoint(&fd_users) {
        repaired.insert("close".into());
    }
    repaired
}

fn split_custom_set(custom: &NameSet) -> (NameSet, NameSet) {
    let valid = |name: &str| {
        EVENTS
            .iter()
            .any(|entry| entry.name == name && entry.syscall_code.is_some())
    };
    let mut positive = NameSet::new();
    let mut negative = NameSet::new();
    for value in custom {
        if let Some(name) = value.strip_prefix('!') {
            if valid(name) {
                negative.insert(name.into());
            }
        } else if valid(value) {
            positive.insert(value.clone());
        }
    }
    (positive, negative)
}

fn remove_names_and_aliases(selected: &mut NameSet, negative: &NameSet) {
    for name in negative {
        let Some(entry) = EVENTS.iter().find(|entry| entry.name == name) else {
            continue;
        };
        selected.retain(|selected_name| {
            EVENTS
                .iter()
                .find(|candidate| candidate.name == selected_name)
                .map_or(true, |candidate| {
                    candidate.syscall_code != entry.syscall_code
                })
        });
    }
}

fn names(values: &[&str]) -> NameSet {
    values.iter().map(|value| (*value).to_string()).collect()
}
