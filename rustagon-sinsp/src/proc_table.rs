use crate::ThreadInfo;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ProcessTable {
    threads: HashMap<i64, ThreadInfo>,
}

impl ProcessTable {
    pub fn upsert(&mut self, thread: ThreadInfo) {
        self.threads.insert(thread.tid, thread);
    }

    pub fn clone_from(&mut self, parent_tid: i64, child_tid: i64, child_pid: i64) -> bool {
        let Some(mut child) = self.threads.get(&parent_tid).cloned() else {
            return false;
        };

        if child_pid != child.pid {
            child.ppid = child.pid;
        }
        child.tid = child_tid;
        child.pid = child_pid;
        self.upsert(child);
        true
    }

    pub fn remove(&mut self, tid: i64) -> Option<ThreadInfo> {
        self.threads.remove(&tid)
    }

    pub fn thread(&self, tid: i64) -> Option<&ThreadInfo> {
        self.threads.get(&tid)
    }

    pub fn process(&self, pid: i64) -> Option<&ThreadInfo> {
        self.threads
            .get(&pid)
            .or_else(|| self.threads.values().find(|thread| thread.pid == pid))
    }

    pub fn parent(&self, thread: &ThreadInfo) -> Option<&ThreadInfo> {
        self.process(thread.ppid)
    }
}
