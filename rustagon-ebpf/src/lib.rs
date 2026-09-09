//! Rustagon eBPF - Kernel-space event capture programs
//!
//! Pure Rust eBPF programs using aya-ebpf framework.
//! This crate compiles to eBPF bytecode that runs in the Linux kernel.
//!
//! Key constraints:
//! - NO dynamic memory allocation (Vec, String, HashMap, etc.)
//! - NO heap allocation of any kind
//! - Fixed-size stack-allocated structures only
//! - All shared structures MUST use #[repr(C)]
//! - All events written to ringbuffer via aya::maps::RingBuf

#![no_std]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
};
use core::mem;
use rustagon_common::{
    EventHeader, EventType, OpenEvent, SyscallEvent, MAX_STRING_LEN,
};

/// RingBuffer for outputting events to userspace
/// Each event is written directly without serialization
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_capacity(256 * 1024, 0);

/// Tracepoint probe for sys_enter_open
/// Captures file open syscall events
#[tracepoint]
pub fn trace_sys_enter_open(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_open(&ctx) } {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Tracepoint probe for sys_enter_openat
/// Captures openat syscall events
#[tracepoint]
pub fn trace_sys_enter_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_trace_openat(&ctx) } {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
unsafe fn try_trace_open(_ctx: &TracePointContext) -> Result<(), u64> {
    // Read syscall context from tracepoint
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xffffffff) as u32;
    let gid = (uid_gid >> 32) as u32;

    // Create event header
    let header = EventHeader {
        timestamp: aya_ebpf::helpers::bpf_ktime_get_ns(),
        event_type: EventType::Open,
        pid,
        uid,
        gid,
    };

    // Allocate event on stack (NO heap allocation)
    let mut event: OpenEvent = mem::zeroed();
    event.header = header;

    // Try to read filename from context
    // This is a simplified example - full implementation would use
    // bpf_probe_read to extract syscall arguments
    let filename = b"/tmp/example";
    let len = filename.len().min(MAX_STRING_LEN - 1);
    for i in 0..len {
        event.pathname[i] = filename[i];
    }

    // Reserve and write to ringbuffer
    let buf = EVENTS.reserve::<OpenEvent>(0)?;
    unsafe {
        core::ptr::write_unaligned(buf as *mut OpenEvent, event);
    }
    EVENTS.submit(buf, 0);

    Ok(())
}

#[inline(always)]
unsafe fn try_trace_openat(ctx: &TracePointContext) -> Result<(), u64> {
    // Same as open for this example
    try_trace_open(ctx)
}

/// KProbe on __audit_syscall_entry to capture all syscalls
#[kprobe]
pub fn trace_syscall(ctx: ProbeContext) -> u32 {
    match unsafe { try_trace_syscall(&ctx) } {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
unsafe fn try_trace_syscall(ctx: &ProbeContext) -> Result<(), u64> {
    // Get current process context
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xffffffff) as u32;
    let gid = (uid_gid >> 32) as u32;

    // Create event header
    let header = EventHeader {
        timestamp: aya_ebpf::helpers::bpf_ktime_get_ns(),
        event_type: EventType::Syscall,
        pid,
        uid,
        gid,
    };

    // Read syscall number and arguments from registers
    let syscall_id = ctx.arg::<u32>(0)?;
    let arg1 = ctx.arg::<u64>(1)?;
    let arg2 = ctx.arg::<u64>(2)?;
    let arg3 = ctx.arg::<u64>(3)?;
    let arg4 = ctx.arg::<u64>(4)?;

    // Create syscall event
    let event = SyscallEvent {
        header,
        syscall_id,
        retval: 0, // Filled in by exit probe
        arg1,
        arg2,
        arg3,
        arg4,
    };

    // Reserve and write to ringbuffer
    let buf = EVENTS.reserve::<SyscallEvent>(0)?;
    core::ptr::write_unaligned(buf as *mut SyscallEvent, event);
    EVENTS.submit(buf, 0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
