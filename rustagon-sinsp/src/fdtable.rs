use crate::Evt;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdInfo {
    File {
        path: String,
    },
    Ipv4Socket {
        source_ip: String,
        source_port: u16,
        destination_ip: String,
        destination_port: u16,
    },
}

impl FdInfo {
    fn name(&self) -> String {
        match self {
            Self::File { path } => path.clone(),
            Self::Ipv4Socket {
                source_ip,
                source_port,
                destination_ip,
                destination_port,
            } => format!("{source_ip}:{source_port}->{destination_ip}:{destination_port}"),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Ipv4Socket { .. } => "ipv4",
        }
    }

    fn type_char(&self) -> &'static str {
        match self {
            Self::File { .. } => "f",
            Self::Ipv4Socket { .. } => "4",
        }
    }

    fn enrich(&self, fd: i64, evt: &mut Evt) {
        evt.fields.insert("fd.num".into(), fd.to_string());
        evt.fields.insert("fd.name".into(), self.name());
        evt.fields.insert("fd.type".into(), self.type_name().into());
        evt.fields
            .insert("fd.typechar".into(), self.type_char().into());

        if let Self::Ipv4Socket {
            source_ip,
            source_port,
            destination_ip,
            destination_port,
        } = self
        {
            evt.fields.insert("fd.cip".into(), source_ip.clone());
            evt.fields
                .insert("fd.cport".into(), source_port.to_string());
            evt.fields.insert("fd.sip".into(), destination_ip.clone());
            evt.fields
                .insert("fd.sport".into(), destination_port.to_string());
            evt.fields.insert("fd.dip".into(), destination_ip.clone());
            evt.fields
                .insert("fd.dport".into(), destination_port.to_string());
        }
    }
}

#[derive(Debug, Default)]
pub struct FdTable {
    by_thread: HashMap<i64, HashMap<i64, FdInfo>>,
}

impl FdTable {
    pub fn insert(&mut self, tid: i64, fd: i64, info: FdInfo) {
        self.by_thread.entry(tid).or_default().insert(fd, info);
    }

    pub fn duplicate(&mut self, tid: i64, old_fd: i64, new_fd: i64) -> bool {
        let Some(info) = self.get(tid, old_fd).cloned() else {
            return false;
        };
        self.insert(tid, new_fd, info);
        true
    }

    pub fn clone_from(&mut self, parent_tid: i64, child_tid: i64) -> bool {
        let Some(fds) = self.by_thread.get(&parent_tid).cloned() else {
            return false;
        };
        self.by_thread.insert(child_tid, fds);
        true
    }

    pub fn get(&self, tid: i64, fd: i64) -> Option<&FdInfo> {
        self.by_thread.get(&tid)?.get(&fd)
    }

    pub fn remove(&mut self, tid: i64, fd: i64) -> Option<FdInfo> {
        let fds = self.by_thread.get_mut(&tid)?;
        let removed = fds.remove(&fd);
        if fds.is_empty() {
            self.by_thread.remove(&tid);
        }
        removed
    }

    pub fn remove_thread(&mut self, tid: i64) {
        self.by_thread.remove(&tid);
    }

    pub fn enrich(&self, tid: i64, fd: i64, evt: &mut Evt) {
        if let Some(info) = self.get(tid, fd) {
            info.enrich(fd, evt);
        }
    }
}
