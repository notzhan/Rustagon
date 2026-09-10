use async_trait::async_trait;

pub mod modern_ebpf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RawEventKind {
    #[default]
    Other,
    Exec {
        pid: i64,
        ppid: i64,
        comm: String,
        exe: String,
        exepath: String,
        args: Vec<String>,
    },
    Clone {
        child_tid: i64,
        child_pid: i64,
    },
    Open {
        fd: i64,
        path: String,
    },
    Close {
        fd: i64,
    },
    Dup {
        old_fd: i64,
        new_fd: i64,
    },
    Connect {
        fd: i64,
        source_ip: String,
        source_port: u16,
        destination_ip: String,
        destination_port: u16,
    },
    Accept {
        fd: i64,
        source_ip: String,
        source_port: u16,
        destination_ip: String,
        destination_port: u16,
    },
    Exit,
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub timestamp: u64,
    pub tid: i64,
    pub type_id: u16,
    pub payload: Vec<u8>,
    pub kind: RawEventKind,
}

#[async_trait]
pub trait EventSource: Send {
    async fn next_event(&mut self) -> Option<RawEvent>;
}

pub struct NodriverSource;

#[async_trait]
impl EventSource for NodriverSource {
    async fn next_event(&mut self) -> Option<RawEvent> {
        None
    }
}
