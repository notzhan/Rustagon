use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aya::{
    maps::{MapData, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use rustagon_common::ppm::{PpmEventHeader, PpmEventType};
use tokio::io::unix::AsyncFd;

use crate::{DropCounters, DropReason, EventSource, RawEvent, RawEventKind};

const HEADER_LEN: usize = core::mem::size_of::<PpmEventHeader>();
const STARTER_RECORD_LEN: usize = HEADER_LEN + core::mem::size_of::<i64>() + 4 * 8;

/// Aya-backed source for the Phase 4 modern eBPF tracepoints.
///
/// The eBPF object path can be overridden with `RUSTAGON_EBPF_OBJECT`.
pub struct ModernEbpfSource {
    ring: AsyncFd<RingBuf<MapData>>,
    drop_counters: DropCounters,
    // Programs and their links are dropped (detached) with the owning Ebpf.
    _ebpf: Ebpf,
}

impl ModernEbpfSource {
    /// Load the xtask-built object and attach both Phase 4 tracepoints.
    pub fn attach() -> Result<Self> {
        let object = ebpf_object_path()?;
        let mut ebpf = Ebpf::load_file(&object)
            .with_context(|| format!("load eBPF object {}", object.display()))?;

        attach_tracepoint(&mut ebpf, "rustagon_sys_enter", "raw_syscalls", "sys_enter")?;
        attach_tracepoint(
            &mut ebpf,
            "rustagon_process_exit",
            "sched",
            "sched_process_exit",
        )?;

        let map = ebpf.take_map("EVENTS").context("EVENTS map not found")?;
        let ring = RingBuf::try_from(map).context("EVENTS is not a ring buffer")?;
        let ring = AsyncFd::new(ring).context("register EVENTS ring buffer with Tokio")?;

        Ok(Self {
            ring,
            drop_counters: DropCounters::default(),
            _ebpf: ebpf,
        })
    }

    /// Shared counters for userspace-observable event losses.
    pub fn drop_counters(&self) -> DropCounters {
        self.drop_counters.clone()
    }
}

#[async_trait]
impl EventSource for ModernEbpfSource {
    async fn next_event(&mut self) -> Option<RawEvent> {
        loop {
            while let Some(record) = self.ring.get_mut().next() {
                if let Some(event) = parse_record_with_counters(&record, &self.drop_counters) {
                    return Some(event);
                }
            }

            let mut readiness = self.ring.readable_mut().await.ok()?;
            readiness.clear_ready();
        }
    }
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    tracepoint: &str,
) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("{program_name} program not found"))?
        .try_into()
        .with_context(|| format!("{program_name} is not a tracepoint"))?;
    program
        .load()
        .with_context(|| format!("load {program_name} (kernel verifier rejected program)"))?;
    program
        .attach(category, tracepoint)
        .with_context(|| format!("attach {program_name} to {category}/{tracepoint}"))?;
    Ok(())
}

fn ebpf_object_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTAGON_EBPF_OBJECT") {
        let path = PathBuf::from(path);
        anyhow::ensure!(path.is_file(), "eBPF object not found: {}", path.display());
        return Ok(path);
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("rustagon-scap has no workspace parent")?
        .to_path_buf();
    for profile in ["release", "debug"] {
        let candidate = workspace
            .join("target/bpfel-unknown-none")
            .join(profile)
            .join("librustagon_ebpf.so");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "rustagon-ebpf object not found; run `cargo xtask build-ebpf --release` \
         or set RUSTAGON_EBPF_OBJECT"
    )
}

#[cfg(test)]
fn parse_record(record: &[u8]) -> Option<RawEvent> {
    parse_record_with_counters(record, &DropCounters::default())
}

fn parse_record_with_counters(record: &[u8], counters: &DropCounters) -> Option<RawEvent> {
    let event = parse_record_inner(record);
    if event.is_none() {
        counters.record(DropReason::ParseFailure);
    }
    event
}

fn parse_record_inner(record: &[u8]) -> Option<RawEvent> {
    if record.len() != STARTER_RECORD_LEN {
        return None;
    }

    let timestamp = u64::from_ne_bytes(record[0..8].try_into().ok()?);
    let tid = u64::from_ne_bytes(record[8..16].try_into().ok()?);
    let declared_len = u32::from_ne_bytes(record[16..20].try_into().ok()?) as usize;
    let type_id = u16::from_ne_bytes(record[20..22].try_into().ok()?);
    if declared_len != record.len() {
        return None;
    }

    let syscall_id = i64::from_ne_bytes(record[HEADER_LEN..HEADER_LEN + 8].try_into().ok()?);
    let mut args = [0_u64; 4];
    for (index, arg) in args.iter_mut().enumerate() {
        let start = HEADER_LEN + 8 + index * 8;
        *arg = u64::from_ne_bytes(record[start..start + 8].try_into().ok()?);
    }

    let event_type = PpmEventType::from_raw(type_id);
    let tid = i64::try_from(tid).ok()?;
    let kind = if event_type == PpmEventType::EXIT_E {
        RawEventKind::Exit
    } else if event_type == PpmEventType::CLOSE_E {
        RawEventKind::Close { fd: args[0] as i64 }
    } else if event_type == PpmEventType::OPENAT_E {
        // Entry probes cannot know the resulting fd, and userspace cannot
        // safely dereference the captured filename pointer.
        RawEventKind::Open {
            fd: -1,
            path: String::new(),
        }
    } else if event_type == PpmEventType::EXECVE_E {
        RawEventKind::Exec {
            pid: tid,
            ppid: 0,
            comm: String::new(),
            exe: String::new(),
            exepath: String::new(),
            args: Vec::new(),
        }
    } else if event_type == PpmEventType::CLONE_E
        || event_type == PpmEventType::CLONE3_E
        || event_type == PpmEventType::FORK_E
    {
        RawEventKind::Clone {
            child_tid: 0,
            child_pid: 0,
        }
    } else if event_type == PpmEventType::CONNECT_E {
        RawEventKind::Connect {
            fd: args[0] as i64,
            source_ip: String::new(),
            source_port: 0,
            destination_ip: String::new(),
            destination_port: 0,
        }
    } else if event_type == PpmEventType::ACCEPT_E || event_type == PpmEventType::ACCEPT4_E {
        RawEventKind::Accept {
            fd: -1,
            source_ip: String::new(),
            source_port: 0,
            destination_ip: String::new(),
            destination_port: 0,
        }
    } else {
        let _ = syscall_id;
        RawEventKind::Other
    };

    Some(RawEvent {
        timestamp,
        tid,
        type_id,
        payload: record[HEADER_LEN..].to_vec(),
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_record, parse_record_with_counters};
    use crate::{DropCounters, RawEventKind};
    use rustagon_common::ppm::{PpmEventHeader, PpmEventType};

    const HEADER_LEN: usize = core::mem::size_of::<PpmEventHeader>();
    const RECORD_LEN: usize = HEADER_LEN + 8 + 4 * 8;

    fn record(event_type: PpmEventType, syscall_id: i64, args: [u64; 4]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_LEN);
        bytes.extend_from_slice(&123_u64.to_ne_bytes());
        bytes.extend_from_slice(&456_u64.to_ne_bytes());
        bytes.extend_from_slice(&(RECORD_LEN as u32).to_ne_bytes());
        bytes.extend_from_slice(&event_type.raw().to_ne_bytes());
        bytes.extend_from_slice(&event_type.parameter_count().to_ne_bytes());
        bytes.extend_from_slice(&syscall_id.to_ne_bytes());
        for arg in args {
            bytes.extend_from_slice(&arg.to_ne_bytes());
        }
        bytes
    }

    #[test]
    fn parses_synthetic_close_record_into_raw_event() {
        let bytes = record(PpmEventType::CLOSE_E, 3, [17, 0, 0, 0]);

        let raw = parse_record(&bytes).expect("valid starter record");

        assert_eq!(raw.timestamp, 123);
        assert_eq!(raw.tid, 456);
        assert_eq!(raw.type_id, PpmEventType::CLOSE_E.raw());
        assert_eq!(raw.payload, bytes[HEADER_LEN..]);
        assert_eq!(raw.kind, RawEventKind::Close { fd: 17 });
    }

    #[test]
    fn maps_process_exit_record() {
        let bytes = record(PpmEventType::EXIT_E, -1, [0; 4]);

        let raw = parse_record(&bytes).expect("valid exit record");

        assert_eq!(raw.kind, RawEventKind::Exit);
    }

    #[test]
    fn rejects_truncated_or_inconsistently_sized_records() {
        let mut truncated = record(PpmEventType::OPENAT_E, 257, [0; 4]);
        truncated.pop();
        assert!(parse_record(&truncated).is_none());

        let mut wrong_header_len = record(PpmEventType::OPENAT_E, 257, [0; 4]);
        wrong_header_len[16..20].copy_from_slice(&999_u32.to_ne_bytes());
        assert!(parse_record(&wrong_header_len).is_none());
    }

    #[test]
    fn malformed_ring_records_increment_parse_failures() {
        let counters = DropCounters::default();

        assert!(parse_record_with_counters(&[0; 3], &counters).is_none());

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.n_drops, 1);
        assert_eq!(snapshot.n_drops_bug, 1);
    }

    /// Requires root or CAP_BPF/CAP_PERFMON and an object built with
    /// `cargo xtask build-ebpf --release`.
    #[tokio::test]
    #[ignore = "requires BPF privileges and a built rustagon-ebpf object"]
    async fn live_attach_is_verifier_clean_and_receives_an_event() {
        use crate::EventSource;
        use std::time::Duration;

        let mut source =
            super::ModernEbpfSource::attach().expect("load and attach both tracepoints");
        std::fs::File::open("/proc/self/status").expect("trigger openat");
        let event = tokio::time::timeout(Duration::from_secs(5), source.next_event())
            .await
            .expect("event timeout");
        assert!(event.is_some());
    }
}
