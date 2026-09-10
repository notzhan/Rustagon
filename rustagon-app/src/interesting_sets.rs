//! Pure-Rust model of Falco's syscall interesting-set selection.

use crate::ppm_events::{
    ALL_SYSCALL_NAMES, DEFAULT_STATE_SYSCALL_NAMES, EVENT_TO_SYSCALL_NAMES,
    FD_RELATED_SYSCALL_NAMES, GENERIC_SYSCALL_NAMES, IO_SYSCALL_NAMES, KERNEL_EVENT_NAMES,
    NETWORK_SYSCALL_NAMES,
};
use rustagon_engine::FalcoEngine;
use std::collections::BTreeSet;

pub type NameSet = BTreeSet<String>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleEventSets {
    pub event_names: NameSet,
    pub syscall_names: NameSet,
}

impl RuleEventSets {
    pub fn from_engine(engine: &FalcoEngine, source: &str, ruleset: &str) -> Self {
        let mut result = Self::default();
        for name in engine.event_names_for_ruleset(source, ruleset) {
            if KERNEL_EVENT_NAMES.contains(&name.as_str()) {
                result.event_names.insert(name.clone());
                extend_event_syscalls(&mut result.syscall_names, &name);
            } else if ALL_SYSCALL_NAMES.contains(&name.as_str()) {
                // Names without a dedicated event are represented by PPME_GENERIC.
                result
                    .event_names
                    .extend(GENERIC_SYSCALL_NAMES.iter().map(|name| (*name).into()));
                result.syscall_names.insert(display_name(&name).into());
            }

            // These names are also registered as async event aliases by sinsp.
            if matches!(name.as_str(), "container" | "pluginevent") {
                result.event_names.insert("asyncevent".into());
            }
        }
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
    let mut base = if positive_is_empty {
        default_state_syscalls()
    } else {
        positive
    };
    let mut selected = rules.clone();
    selected.append(&mut base);

    if config.base_syscalls_repair && positive_is_empty {
        selected = repair_state_syscalls(&rules);
    }
    selected.retain(|name| !negative.contains(name));
    if !config.base_syscalls_all {
        let ignored = ignored_syscalls();
        selected.retain(|name| !ignored.contains(name));
    }
    if config.base_syscalls_repair && !config.base_syscalls_custom_set.is_empty() {
        selected = repair_state_syscalls(&selected);
    }
    selected.insert("procexit".into());
    state.selected_syscalls = selected;
    Ok(())
}

pub fn all_syscall_names() -> NameSet {
    names(ALL_SYSCALL_NAMES)
}

pub fn generic_event_names() -> NameSet {
    names(GENERIC_SYSCALL_NAMES)
}

pub fn default_state_syscalls() -> NameSet {
    display_names(DEFAULT_STATE_SYSCALL_NAMES)
}

pub fn ignored_syscalls() -> NameSet {
    let default_state = default_state_syscalls();
    display_names(IO_SYSCALL_NAMES)
        .difference(&default_state)
        .cloned()
        .collect()
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
        "setgid32",
        "setpgid",
        "setresgid",
        "setresgid32",
        "setresuid",
        "setresuid32",
        "setsid",
        "setuid",
        "setuid32",
        "prctl",
        "procexit",
    ]));

    let selected_is_network = selected
        .iter()
        .any(|name| NETWORK_SYSCALL_NAMES.contains(&name.as_str()));
    if selected_is_network {
        repaired.extend(names(&["socket", "getsockopt", "close"]));
    }
    if selected.contains("accept") || selected.contains("accept4") || selected.contains("listen") {
        repaired.insert("bind".into());
    }
    if selected
        .iter()
        .any(|name| FD_RELATED_SYSCALL_NAMES.contains(&name.as_str()))
    {
        repaired.insert("close".into());
    }
    repaired
}

fn split_custom_set(custom: &NameSet) -> (NameSet, NameSet) {
    let mut positive = NameSet::new();
    let mut negative = NameSet::new();
    for value in custom {
        let (target, name) = if let Some(name) = value.strip_prefix('!') {
            (&mut negative, name)
        } else {
            (&mut positive, value.as_str())
        };
        extend_event_syscalls(target, name);
    }
    (positive, negative)
}

fn extend_event_syscalls(target: &mut NameSet, event_name: &str) {
    if let Some((_, syscall_names)) = EVENT_TO_SYSCALL_NAMES
        .iter()
        .find(|(name, _)| *name == event_name)
    {
        target.extend(syscall_names.iter().map(|name| display_name(name).into()));
    } else if ALL_SYSCALL_NAMES.contains(&event_name) {
        target.insert(display_name(event_name).into());
    }
}

fn names(values: &[&str]) -> NameSet {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn display_names(values: &[&str]) -> NameSet {
    values
        .iter()
        .map(|value| display_name(value).to_string())
        .collect()
}

fn display_name(syscall_name: &str) -> &str {
    match syscall_name {
        "sched_process_exit" => "procexit",
        "sched_switch" => "switch",
        _ => syscall_name,
    }
}
