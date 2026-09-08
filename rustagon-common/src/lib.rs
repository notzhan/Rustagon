//! Rustagon Common - Shared data structures and event definitions
//!
//! This crate defines all data structures that are shared between the eBPF kernel
//! programs and the userspace daemon. All structures use #[repr(C)] to ensure
//! binary compatibility and proper memory layout for kernel-userspace communication.

#![no_std]

/// Event types supported by Rustagon
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// System call event
    Syscall = 0,
    /// File open event
    Open = 1,
    /// File close event
    Close = 2,
    /// Process execution event
    ExecVe = 3,
    /// Process exit event
    Exit = 4,
    /// Network connection event
    Connect = 5,
}

/// Common event header shared across all event types
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventHeader {
    /// Monotonic timestamp in nanoseconds
    pub timestamp: u64,
    /// Event type
    pub event_type: EventType,
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

/// Maximum length for string fields in events
pub const MAX_STRING_LEN: usize = 256;
pub const MAX_ARGS_LEN: usize = 4096;

/// System call event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallEvent {
    /// Common event header
    pub header: EventHeader,
    /// System call ID
    pub syscall_id: u32,
    /// Return value
    pub retval: i64,
    /// Argument 1
    pub arg1: u64,
    /// Argument 2
    pub arg2: u64,
    /// Argument 3
    pub arg3: u64,
    /// Argument 4
    pub arg4: u64,
}

/// File open event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OpenEvent {
    /// Common event header
    pub header: EventHeader,
    /// File path (null-terminated string)
    pub pathname: [u8; MAX_STRING_LEN],
    /// Open flags
    pub flags: u32,
    /// File permissions
    pub mode: u32,
    /// File descriptor returned
    pub fd: i32,
}

/// File close event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CloseEvent {
    /// Common event header
    pub header: EventHeader,
    /// File descriptor being closed
    pub fd: u32,
    /// Return value
    pub retval: i32,
}

/// Process execution event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecVeEvent {
    /// Common event header
    pub header: EventHeader,
    /// Executable path
    pub filename: [u8; MAX_STRING_LEN],
    /// Command line arguments (concatenated with null separators)
    pub args: [u8; MAX_ARGS_LEN],
    /// Number of arguments
    pub argc: u32,
    /// Environment variables size
    pub env_len: u32,
}

/// Process exit event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExitEvent {
    /// Common event header
    pub header: EventHeader,
    /// Exit code
    pub exit_code: i32,
    /// Execution time in nanoseconds
    pub duration: u64,
}

/// Network connection event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnectEvent {
    /// Common event header
    pub header: EventHeader,
    /// Socket address family (AF_INET, AF_INET6, etc.)
    pub family: u16,
    /// Destination port
    pub dport: u16,
    /// Source port
    pub sport: u16,
    /// IP address (supports both IPv4 and IPv6)
    pub saddr: [u8; 16],
    /// Destination address (supports both IPv4 and IPv6)
    pub daddr: [u8; 16],
}

/// Union type for all possible events
/// Used for flexible event handling in userspace
#[repr(C)]
pub union EventData {
    pub syscall: SyscallEvent,
    pub open: OpenEvent,
    pub close: CloseEvent,
    pub execve: ExecVeEvent,
    pub exit: ExitEvent,
    pub connect: ConnectEvent,
}

/// Process context information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessContext {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Thread group ID (same as PID for main thread)
    pub tgid: u32,
    /// User ID
    pub uid: u32,
    /// Effective user ID
    pub euid: u32,
    /// Group ID
    pub gid: u32,
    /// Effective group ID
    pub egid: u32,
    /// Session ID
    pub sid: u32,
    /// Process flags
    pub flags: u32,
}

/// Container context information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ContainerContext {
    /// Container ID
    pub container_id: [u8; MAX_STRING_LEN],
    /// Pod name (for Kubernetes)
    pub pod_name: [u8; MAX_STRING_LEN],
    /// Namespace (for Kubernetes)
    pub namespace: [u8; MAX_STRING_LEN],
}

/// Helper functions for working with C-compatible strings
pub mod string {
    use super::MAX_STRING_LEN;

    /// Copy a Rust string into a C-compatible null-terminated byte buffer
    pub fn to_cstring(dest: &mut [u8; MAX_STRING_LEN], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(MAX_STRING_LEN - 1);
        dest[..len].copy_from_slice(&bytes[..len]);
        dest[len] = 0;
    }

    /// Read a C-compatible null-terminated string from a buffer
    pub fn from_cstring(src: &[u8; MAX_STRING_LEN]) -> Option<&str> {
        if let Some(nul_pos) = src.iter().position(|&b| b == 0) {
            core::str::from_utf8(&src[..nul_pos]).ok()
        } else {
            None
        }
    }
}

/// Validation helpers for events
pub mod validation {
    use super::*;

    /// Check if an event header is valid
    pub fn validate_header(header: &EventHeader) -> bool {
        // Timestamp should be non-zero
        header.timestamp > 0
            // PID should be valid (0 is reserved for kernel)
            && header.pid > 0
    }

    /// Check if a syscall event is valid
    pub fn validate_syscall(event: &SyscallEvent) -> bool {
        validate_header(&event.header)
    }

    /// Check if an open event is valid
    pub fn validate_open(event: &OpenEvent) -> bool {
        validate_header(&event.header) && event.pathname[0] != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_header_size() {
        // Ensure EventHeader has predictable size for kernel-userspace communication
        assert_eq!(core::mem::size_of::<EventHeader>(), 32);
    }

    #[test]
    fn test_syscall_event_size() {
        // Ensure fixed size for ringbuffer
        assert_eq!(core::mem::size_of::<SyscallEvent>(), 80);
    }

    #[test]
    fn test_repr_c_alignment() {
        // All structs should be C-compatible with predictable alignment
        assert_eq!(core::mem::align_of::<EventHeader>(), 8);
        assert_eq!(core::mem::align_of::<SyscallEvent>(), 8);
        assert_eq!(core::mem::align_of::<OpenEvent>(), 8);
    }

    #[test]
    fn test_string_conversion() {
        let mut buf: [u8; MAX_STRING_LEN] = [0; MAX_STRING_LEN];
        string::to_cstring(&mut buf, "/tmp/test.txt");
        assert_eq!(string::from_cstring(&buf), Some("/tmp/test.txt"));
    }

    #[test]
    fn test_string_truncation() {
        let mut buf: [u8; MAX_STRING_LEN] = [0; MAX_STRING_LEN];
        let long_str = "a".repeat(MAX_STRING_LEN + 100);
        string::to_cstring(&mut buf, &long_str);
        // Should be truncated and null-terminated
        assert_eq!(buf[MAX_STRING_LEN - 1], 0);
    }
}
