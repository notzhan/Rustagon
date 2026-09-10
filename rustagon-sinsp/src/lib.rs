use rustagon_scap::{RawEvent, RawEventKind};
use std::collections::{HashMap, HashSet};

mod container;
mod fdtable;
mod fields;
mod proc_table;
mod thread_info;

pub use container::{
    container_id_from_cgroup, ContainerLookup, ContainerMetadata, FixtureContainerLookup,
};
pub use fdtable::{FdInfo, FdTable};
pub use fields::{FieldClass, FieldInfo};
pub use proc_table::ProcessTable;
pub use thread_info::ThreadInfo;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Evt {
    pub fields: HashMap<String, String>,
}

impl Evt {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Self { fields }
    }

    pub fn get_field_as_string(&self, field: &str) -> Option<String> {
        self.fields.get(field).cloned()
    }

    pub fn get_field_as_u64(&self, field: &str) -> Option<u64> {
        self.fields.get(field)?.parse().ok()
    }

    pub fn get_field_as_i64(&self, field: &str) -> Option<i64> {
        self.fields.get(field)?.parse().ok()
    }

    pub fn get_field_as_bool(&self, field: &str) -> Option<bool> {
        self.fields.get(field)?.parse().ok()
    }
}

#[derive(Debug, Default)]
pub struct Inspector {
    process_table: ProcessTable,
    fd_table: FdTable,
    container_lookup: Option<Box<dyn ContainerLookup>>,
    container_ids: HashMap<i64, String>,
}

impl Inspector {
    pub fn with_container_lookup(lookup: impl ContainerLookup + 'static) -> Self {
        Self {
            container_lookup: Some(Box::new(lookup)),
            ..Self::default()
        }
    }

    pub fn set_container_cgroup(&mut self, tid: i64, cgroup_path: &str) -> bool {
        let Some(container_id) = container_id_from_cgroup(cgroup_path) else {
            self.container_ids.remove(&tid);
            return false;
        };
        self.container_ids.insert(tid, container_id);
        true
    }

    pub fn get_field_names() -> Vec<FieldInfo> {
        fields::registry()
    }

    pub fn inject(&mut self, raw: RawEvent) -> Evt {
        let event_type = event_type_name(&raw.kind);
        let mut fd_for_enrichment = None;
        let mut close_after_enrichment = None;
        let remove_thread_after_enrichment = match &raw.kind {
            RawEventKind::Exec {
                pid,
                ppid,
                comm,
                exe,
                exepath,
                args,
            } => {
                self.process_table.upsert(ThreadInfo {
                    tid: raw.tid,
                    pid: *pid,
                    ppid: *ppid,
                    comm: comm.clone(),
                    exe: exe.clone(),
                    exepath: exepath.clone(),
                    args: args.clone(),
                });
                false
            }
            RawEventKind::Clone {
                child_tid,
                child_pid,
            } => {
                self.process_table
                    .clone_from(raw.tid, *child_tid, *child_pid);
                self.fd_table.clone_from(raw.tid, *child_tid);
                if let Some(container_id) = self.container_ids.get(&raw.tid).cloned() {
                    self.container_ids.insert(*child_tid, container_id);
                }
                false
            }
            RawEventKind::Open { fd, path } => {
                self.fd_table
                    .insert(raw.tid, *fd, FdInfo::File { path: path.clone() });
                fd_for_enrichment = Some(*fd);
                false
            }
            RawEventKind::Close { fd } => {
                fd_for_enrichment = Some(*fd);
                close_after_enrichment = Some(*fd);
                false
            }
            RawEventKind::Dup { old_fd, new_fd } => {
                self.fd_table.duplicate(raw.tid, *old_fd, *new_fd);
                fd_for_enrichment = Some(*new_fd);
                false
            }
            RawEventKind::Connect {
                fd,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
            }
            | RawEventKind::Accept {
                fd,
                source_ip,
                source_port,
                destination_ip,
                destination_port,
            } => {
                self.fd_table.insert(
                    raw.tid,
                    *fd,
                    FdInfo::Ipv4Socket {
                        source_ip: source_ip.clone(),
                        source_port: *source_port,
                        destination_ip: destination_ip.clone(),
                        destination_port: *destination_port,
                    },
                );
                fd_for_enrichment = Some(*fd);
                false
            }
            RawEventKind::Exit => true,
            RawEventKind::Other => false,
        };

        let mut evt = self.enrich(raw.tid, fd_for_enrichment);
        evt.fields.insert("evt.type".into(), event_type.into());
        if let Some(fd) = close_after_enrichment {
            self.fd_table.remove(raw.tid, fd);
        }
        if remove_thread_after_enrichment {
            self.process_table.remove(raw.tid);
            self.fd_table.remove_thread(raw.tid);
            self.container_ids.remove(&raw.tid);
        }
        evt
    }

    fn enrich(&self, tid: i64, fd: Option<i64>) -> Evt {
        let mut evt = Evt::default();
        if let Some(thread) = self.process_table.thread(tid) {
            let fields = &mut evt.fields;

            fields.insert("proc.pid".into(), thread.pid.to_string());
            fields.insert("proc.ppid".into(), thread.ppid.to_string());
            fields.insert("proc.name".into(), thread.comm.clone());
            fields.insert("proc.exe".into(), thread.exe.clone());
            fields.insert("proc.exepath".into(), thread.exepath.clone());
            fields.insert("proc.args".into(), thread.args.join(" "));
            fields.insert("proc.cmdline".into(), thread.cmdline());
            fields.insert("proc.aname[0]".into(), thread.comm.clone());

            let mut ancestor_names = Vec::new();
            let mut current = thread;
            let mut seen = HashSet::from([thread.pid]);
            for level in 1.. {
                let Some(parent) = self.process_table.parent(current) else {
                    break;
                };
                if !seen.insert(parent.pid) {
                    break;
                }
                if level == 1 {
                    fields.insert("proc.pname".into(), parent.comm.clone());
                }
                fields.insert(format!("proc.aname[{level}]"), parent.comm.clone());
                ancestor_names.push(parent.comm.clone());
                current = parent;
            }
            if !ancestor_names.is_empty() {
                fields.insert("proc.aname".into(), ancestor_names.join(" "));
            }
        }

        if let Some(fd) = fd {
            self.fd_table.enrich(tid, fd, &mut evt);
        }

        if let Some(container_id) = self.container_ids.get(&tid) {
            evt.fields
                .insert("container.id".into(), container_id.clone());
            if let Some(lookup) = self.container_lookup.as_ref() {
                if let Ok(Some(metadata)) = lookup.lookup(container_id) {
                    evt.fields.insert("container.name".into(), metadata.name);
                    evt.fields.insert("container.image".into(), metadata.image);
                }
            }
        }

        evt
    }
}

fn event_type_name(kind: &RawEventKind) -> &'static str {
    match kind {
        RawEventKind::Exec { .. } => "execve",
        RawEventKind::Clone { .. } => "clone",
        RawEventKind::Open { .. } => "open",
        RawEventKind::Close { .. } => "close",
        RawEventKind::Dup { .. } => "dup",
        RawEventKind::Connect { .. } => "connect",
        RawEventKind::Accept { .. } => "accept",
        RawEventKind::Exit => "exit",
        RawEventKind::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::{Evt, FieldClass, Inspector};
    use rustagon_scap::{RawEvent, RawEventKind};
    use std::collections::HashSet;

    fn raw(tid: i64, kind: RawEventKind) -> RawEvent {
        RawEvent {
            timestamp: 1,
            tid,
            type_id: 0,
            payload: Vec::new(),
            kind,
        }
    }

    #[test]
    fn registry_contains_official_rule_fields_for_each_supported_class() {
        let fields = Inspector::get_field_names();
        let by_name: HashSet<_> = fields.iter().map(|field| field.name).collect();

        for expected in [
            "evt.type",
            "evt.time",
            "proc.name",
            "proc.cmdline",
            "proc.pid",
            "fd.name",
            "user.name",
            "container.id",
        ] {
            assert!(
                by_name.contains(expected),
                "missing registry field {expected}"
            );
        }

        assert!(fields
            .iter()
            .any(|field| field.name == "evt.type" && field.field_class == FieldClass::Evt));
        assert!(fields
            .iter()
            .any(|field| field.name == "proc.name" && field.field_class == FieldClass::Proc));
        assert!(fields
            .iter()
            .any(|field| field.name == "fd.name" && field.field_class == FieldClass::Fd));
        assert!(fields
            .iter()
            .any(|field| field.name == "user.name" && field.field_class == FieldClass::User));
        assert!(fields.iter().any(
            |field| field.name == "container.id" && field.field_class == FieldClass::Container
        ));
    }

    #[test]
    fn registry_names_are_unique_and_sorted() {
        let fields = Inspector::get_field_names();
        let names: Vec<_> = fields.iter().map(|field| field.name).collect();
        let unique: HashSet<_> = names.iter().copied().collect();

        assert_eq!(names.len(), unique.len());
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn registry_covers_the_checked_in_libs_baseline() {
        let registry: HashSet<_> = Inspector::get_field_names()
            .into_iter()
            .map(|field| field.name)
            .collect();
        let baseline: HashSet<_> = include_str!("../../parity/libs_equiv/fields_tip.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        assert_eq!(registry, baseline);
    }

    #[test]
    fn event_getters_read_and_parse_the_field_map() {
        let mut evt = Evt::default();
        evt.fields.insert("proc.name".into(), "bash".into());
        evt.fields.insert("proc.pid".into(), "42".into());
        evt.fields.insert("evt.rawres".into(), "-2".into());
        evt.fields.insert("evt.failed".into(), "true".into());

        assert_eq!(
            evt.get_field_as_string("proc.name").as_deref(),
            Some("bash")
        );
        assert_eq!(evt.get_field_as_u64("proc.pid"), Some(42));
        assert_eq!(evt.get_field_as_i64("evt.rawres"), Some(-2));
        assert_eq!(evt.get_field_as_bool("evt.failed"), Some(true));
        assert_eq!(evt.get_field_as_u64("proc.name"), None);
        assert_eq!(evt.get_field_as_bool("missing"), None);
    }

    #[test]
    fn exec_enriches_process_identity_and_command_fields() {
        let mut inspector = Inspector::default();

        let evt = inspector.inject(raw(
            42,
            RawEventKind::Exec {
                pid: 42,
                ppid: 1,
                comm: "bash".into(),
                exe: "bash".into(),
                exepath: "/usr/bin/bash".into(),
                args: vec!["-c".into(), "echo hello".into()],
            },
        ));

        assert_eq!(evt.get_field_as_u64("proc.pid"), Some(42));
        assert_eq!(evt.get_field_as_u64("proc.ppid"), Some(1));
        assert_eq!(
            evt.get_field_as_string("proc.name").as_deref(),
            Some("bash")
        );
        assert_eq!(evt.get_field_as_string("proc.exe").as_deref(), Some("bash"));
        assert_eq!(
            evt.get_field_as_string("proc.exepath").as_deref(),
            Some("/usr/bin/bash")
        );
        assert_eq!(
            evt.get_field_as_string("proc.cmdline").as_deref(),
            Some("bash -c echo hello")
        );
    }

    #[test]
    fn forked_process_resolves_parent_and_ancestor_fields() {
        let mut inspector = Inspector::default();
        inspector.inject(raw(
            1,
            RawEventKind::Exec {
                pid: 1,
                ppid: 0,
                comm: "systemd".into(),
                exe: "systemd".into(),
                exepath: "/usr/lib/systemd/systemd".into(),
                args: Vec::new(),
            },
        ));
        inspector.inject(raw(
            10,
            RawEventKind::Exec {
                pid: 10,
                ppid: 1,
                comm: "bash".into(),
                exe: "bash".into(),
                exepath: "/usr/bin/bash".into(),
                args: Vec::new(),
            },
        ));

        inspector.inject(raw(
            10,
            RawEventKind::Clone {
                child_tid: 20,
                child_pid: 20,
            },
        ));
        let evt = inspector.inject(raw(20, RawEventKind::Other));

        assert_eq!(evt.get_field_as_u64("proc.pid"), Some(20));
        assert_eq!(evt.get_field_as_u64("proc.ppid"), Some(10));
        assert_eq!(
            evt.get_field_as_string("proc.pname").as_deref(),
            Some("bash")
        );
        assert_eq!(
            evt.get_field_as_string("proc.aname[0]").as_deref(),
            Some("bash")
        );
        assert_eq!(
            evt.get_field_as_string("proc.aname[1]").as_deref(),
            Some("bash")
        );
        assert_eq!(
            evt.get_field_as_string("proc.aname[2]").as_deref(),
            Some("systemd")
        );
        assert_eq!(
            evt.get_field_as_string("proc.aname").as_deref(),
            Some("bash systemd")
        );
    }

    #[test]
    fn thread_clone_inherits_process_and_exit_removes_only_that_thread() {
        let mut inspector = Inspector::default();
        inspector.inject(raw(
            30,
            RawEventKind::Exec {
                pid: 30,
                ppid: 1,
                comm: "worker".into(),
                exe: "worker".into(),
                exepath: "/opt/worker".into(),
                args: vec!["serve".into()],
            },
        ));
        inspector.inject(raw(
            30,
            RawEventKind::Clone {
                child_tid: 31,
                child_pid: 30,
            },
        ));

        let exit_evt = inspector.inject(raw(31, RawEventKind::Exit));
        assert_eq!(exit_evt.get_field_as_u64("proc.pid"), Some(30));
        assert_eq!(
            exit_evt.get_field_as_string("proc.cmdline").as_deref(),
            Some("worker serve")
        );
        assert_eq!(
            inspector
                .inject(raw(31, RawEventKind::Other))
                .get_field_as_string("proc.name"),
            None
        );
        assert_eq!(
            inspector
                .inject(raw(30, RawEventKind::Other))
                .get_field_as_string("proc.name")
                .as_deref(),
            Some("worker")
        );
    }

    #[test]
    fn open_tracks_and_enriches_file_descriptor() {
        let mut inspector = Inspector::default();

        let evt = inspector.inject(raw(
            42,
            RawEventKind::Open {
                fd: 3,
                path: "/var/log/app.log".into(),
            },
        ));

        assert_eq!(evt.get_field_as_i64("fd.num"), Some(3));
        assert_eq!(
            evt.get_field_as_string("fd.name").as_deref(),
            Some("/var/log/app.log")
        );
        assert_eq!(evt.get_field_as_string("fd.type").as_deref(), Some("file"));
        assert_eq!(evt.get_field_as_string("fd.typechar").as_deref(), Some("f"));
    }

    #[test]
    fn close_enriches_then_removes_file_descriptor() {
        let mut inspector = Inspector::default();
        inspector.inject(raw(
            42,
            RawEventKind::Open {
                fd: 3,
                path: "/tmp/data".into(),
            },
        ));

        let close_evt = inspector.inject(raw(42, RawEventKind::Close { fd: 3 }));
        assert_eq!(
            close_evt.get_field_as_string("fd.name").as_deref(),
            Some("/tmp/data")
        );

        let second_close = inspector.inject(raw(42, RawEventKind::Close { fd: 3 }));
        assert_eq!(second_close.get_field_as_string("fd.name"), None);
    }

    #[test]
    fn dup_copies_descriptor_state_independently() {
        let mut inspector = Inspector::default();
        inspector.inject(raw(
            42,
            RawEventKind::Open {
                fd: 3,
                path: "/etc/hosts".into(),
            },
        ));

        let dup_evt = inspector.inject(raw(
            42,
            RawEventKind::Dup {
                old_fd: 3,
                new_fd: 9,
            },
        ));
        assert_eq!(dup_evt.get_field_as_i64("fd.num"), Some(9));
        assert_eq!(
            dup_evt.get_field_as_string("fd.name").as_deref(),
            Some("/etc/hosts")
        );

        inspector.inject(raw(42, RawEventKind::Close { fd: 3 }));
        let copied_close = inspector.inject(raw(42, RawEventKind::Close { fd: 9 }));
        assert_eq!(
            copied_close.get_field_as_string("fd.name").as_deref(),
            Some("/etc/hosts")
        );
    }

    #[test]
    fn connect_enriches_ipv4_socket_tuple() {
        let mut inspector = Inspector::default();

        let evt = inspector.inject(raw(
            42,
            RawEventKind::Connect {
                fd: 4,
                source_ip: "10.0.0.2".into(),
                source_port: 32123,
                destination_ip: "203.0.113.10".into(),
                destination_port: 443,
            },
        ));

        assert_eq!(
            evt.get_field_as_string("fd.name").as_deref(),
            Some("10.0.0.2:32123->203.0.113.10:443")
        );
        assert_eq!(evt.get_field_as_string("fd.type").as_deref(), Some("ipv4"));
        assert_eq!(evt.get_field_as_string("fd.typechar").as_deref(), Some("4"));
        assert_eq!(
            evt.get_field_as_string("fd.cip").as_deref(),
            Some("10.0.0.2")
        );
        assert_eq!(evt.get_field_as_u64("fd.cport"), Some(32123));
        assert_eq!(
            evt.get_field_as_string("fd.sip").as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(evt.get_field_as_u64("fd.sport"), Some(443));
        assert_eq!(
            evt.get_field_as_string("fd.dip").as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(evt.get_field_as_u64("fd.dport"), Some(443));
    }

    #[test]
    fn accept_tracks_the_new_connected_descriptor() {
        let mut inspector = Inspector::default();

        let evt = inspector.inject(raw(
            42,
            RawEventKind::Accept {
                fd: 8,
                source_ip: "192.0.2.25".into(),
                source_port: 49800,
                destination_ip: "192.0.2.10".into(),
                destination_port: 8080,
            },
        ));

        assert_eq!(evt.get_field_as_i64("fd.num"), Some(8));
        assert_eq!(
            evt.get_field_as_string("fd.name").as_deref(),
            Some("192.0.2.25:49800->192.0.2.10:8080")
        );
        assert_eq!(
            evt.get_field_as_string("fd.cip").as_deref(),
            Some("192.0.2.25")
        );
        assert_eq!(
            evt.get_field_as_string("fd.sip").as_deref(),
            Some("192.0.2.10")
        );

        let close_evt = inspector.inject(raw(42, RawEventKind::Close { fd: 8 }));
        assert_eq!(
            close_evt.get_field_as_string("fd.name").as_deref(),
            Some("192.0.2.25:49800->192.0.2.10:8080")
        );
    }
}
