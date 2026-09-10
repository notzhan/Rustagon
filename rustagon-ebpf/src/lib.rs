//! Kernel-side capture for Rustagon's Phase 4 starter syscall set.
//!
//! The programs are attached by userspace to `raw_syscalls/sys_enter` and
//! `sched/sched_process_exit`. They emit a small fixed-size transition record
//! beginning with Falco's packed [`PpmEventHeader`]. Full Falco parameter
//! encoding is intentionally deferred to the userspace consumer work.

#![no_std]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use rustagon_common::ppm::{PpmEventHeader, PpmEventType};

const RING_BUFFER_BYTES: u32 = 256 * 1024;
const RAW_SYSCALL_ID_OFFSET: usize = 8;
const RAW_SYSCALL_ARGS_OFFSET: usize = 16;

// Linux x86_64 syscall numbers. Supporting another architecture requires a
// second mapping table; see BUILD.md.
const SYS_CLOSE: i64 = 3;
const SYS_CONNECT: i64 = 42;
const SYS_ACCEPT: i64 = 43;
const SYS_CLONE: i64 = 56;
const SYS_FORK: i64 = 57;
const SYS_EXECVE: i64 = 59;
const SYS_OPENAT: i64 = 257;
const SYS_ACCEPT4: i64 = 288;
const SYS_EXECVEAT: i64 = 322;
const SYS_CLONE3: i64 = 435;

/// Fixed-size bridge record consumed by the Phase 4 userspace loader.
///
/// `args` contain the first four raw syscall arguments for syscall-entry
/// records. Process-exit records set `syscall_id` to `-1` and zero the args.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct StarterSyscallEvent {
    pub header: PpmEventHeader,
    pub syscall_id: i64,
    pub args: [u64; 4],
}

impl StarterSyscallEvent {
    const fn new(
        timestamp_ns: u64,
        tid: u64,
        event_type: PpmEventType,
        syscall_id: i64,
        args: [u64; 4],
    ) -> Self {
        Self {
            header: PpmEventHeader::new(
                timestamp_ns,
                tid,
                core::mem::size_of::<Self>() as u32,
                event_type,
            ),
            syscall_id,
            args,
        }
    }
}

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_BYTES, 0);

/// Attach to `raw_syscalls/sys_enter`.
#[tracepoint]
pub fn rustagon_sys_enter(ctx: TracePointContext) -> u32 {
    match try_sys_enter(&ctx) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[inline(always)]
fn try_sys_enter(ctx: &TracePointContext) -> Result<(), i32> {
    let syscall_id: i64 = unsafe { ctx.read_at(RAW_SYSCALL_ID_OFFSET)? };
    let Some(event_type) = event_type_for_syscall(syscall_id) else {
        return Ok(());
    };

    let args = [
        unsafe { ctx.read_at(RAW_SYSCALL_ARGS_OFFSET)? },
        unsafe { ctx.read_at(RAW_SYSCALL_ARGS_OFFSET + 8)? },
        unsafe { ctx.read_at(RAW_SYSCALL_ARGS_OFFSET + 16)? },
        unsafe { ctx.read_at(RAW_SYSCALL_ARGS_OFFSET + 24)? },
    ];
    emit(StarterSyscallEvent::new(
        unsafe { bpf_ktime_get_ns() },
        current_tid(),
        event_type,
        syscall_id,
        args,
    ));
    Ok(())
}

/// Attach to `sched/sched_process_exit`.
#[tracepoint]
pub fn rustagon_process_exit(_ctx: TracePointContext) -> u32 {
    emit(StarterSyscallEvent::new(
        unsafe { bpf_ktime_get_ns() },
        current_tid(),
        PpmEventType::EXIT_E,
        -1,
        [0; 4],
    ));
    0
}

#[inline(always)]
fn current_tid() -> u64 {
    (bpf_get_current_pid_tgid() as u32) as u64
}

#[inline(always)]
fn emit(event: StarterSyscallEvent) {
    let events = unsafe { &*core::ptr::addr_of!(EVENTS) };
    if let Some(mut entry) = events.reserve::<StarterSyscallEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

#[inline(always)]
const fn event_type_for_syscall(syscall_id: i64) -> Option<PpmEventType> {
    match syscall_id {
        SYS_OPENAT => Some(PpmEventType::OPENAT_E),
        SYS_EXECVE | SYS_EXECVEAT => Some(PpmEventType::EXECVE_E),
        SYS_CONNECT => Some(PpmEventType::CONNECT_E),
        SYS_ACCEPT => Some(PpmEventType::ACCEPT_E),
        SYS_ACCEPT4 => Some(PpmEventType::ACCEPT4_E),
        SYS_CLOSE => Some(PpmEventType::CLOSE_E),
        SYS_CLONE => Some(PpmEventType::CLONE_E),
        SYS_CLONE3 => Some(PpmEventType::CLONE3_E),
        SYS_FORK => Some(PpmEventType::FORK_E),
        _ => None,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustagon_common::ppm::PpmEventType;

    #[test]
    fn maps_phase4_syscalls_to_ppm_entry_events() {
        assert_eq!(event_type_for_syscall(257), Some(PpmEventType::OPENAT_E));
        assert_eq!(event_type_for_syscall(59), Some(PpmEventType::EXECVE_E));
        assert_eq!(event_type_for_syscall(322), Some(PpmEventType::EXECVE_E));
        assert_eq!(event_type_for_syscall(42), Some(PpmEventType::CONNECT_E));
        assert_eq!(event_type_for_syscall(43), Some(PpmEventType::ACCEPT_E));
        assert_eq!(event_type_for_syscall(288), Some(PpmEventType::ACCEPT4_E));
        assert_eq!(event_type_for_syscall(3), Some(PpmEventType::CLOSE_E));
        assert_eq!(event_type_for_syscall(56), Some(PpmEventType::CLONE_E));
        assert_eq!(event_type_for_syscall(435), Some(PpmEventType::CLONE3_E));
        assert_eq!(event_type_for_syscall(57), Some(PpmEventType::FORK_E));
        assert_eq!(event_type_for_syscall(0xffff), None);
    }

    #[test]
    fn starter_record_uses_ppm_header_and_fixed_payload() {
        let event = StarterSyscallEvent::new(123, 456, PpmEventType::OPENAT_E, 257, [1, 2, 3, 4]);
        let header = event.header;
        let timestamp_ns = header.timestamp_ns;
        let tid = header.tid;
        let len = header.len;
        let event_type = header.event_type;
        let nparams = header.nparams;

        assert_eq!(timestamp_ns, 123);
        assert_eq!(tid, 456);
        assert_eq!(len as usize, core::mem::size_of::<StarterSyscallEvent>());
        assert_eq!(event_type, PpmEventType::OPENAT_E);
        assert_eq!(nparams, PpmEventType::OPENAT_E.parameter_count());
    }
}
