//! Falco PPM-compatible event identifiers and wire header.
//!
//! The values below are pinned to falcosecurity/libs `0.26.0-rc1`. Rustagon
//! uses the newest event revision selected by that release's syscall table:
//!
//! | Falco/libs event | Rustagon constant | ID | params (E/X) |
//! | --- | --- | ---: | ---: |
//! | `PPME_SYSCALL_EXECVE_19_{E,X}` | `EXECVE_{E,X}` | 292/293 | 1/31 |
//! | `PPME_SYSCALL_OPENAT_2_{E,X}` | `OPENAT_{E,X}` | 306/307 | 4/7 |
//! | `PPME_SOCKET_CONNECT_{E,X}` | `CONNECT_{E,X}` | 22/23 | 2/4 |
//! | `PPME_SOCKET_ACCEPT_5_{E,X}` | `ACCEPT_{E,X}` | 246/247 | 0/5 |
//! | `PPME_SOCKET_ACCEPT4_6_{E,X}` | `ACCEPT4_{E,X}` | 388/389 | 1/6 |
//! | `PPME_SYSCALL_CLOSE_{E,X}` | `CLOSE_{E,X}` | 4/5 | 1/2 |
//! | `PPME_SYSCALL_CLONE_20_{E,X}` | `CLONE_{E,X}` | 222/223 | 0/21 |
//! | `PPME_SYSCALL_CLONE3_{E,X}` | `CLONE3_{E,X}` | 334/335 | 0/21 |
//! | `PPME_SYSCALL_FORK_20_{E,X}` | `FORK_{E,X}` | 224/225 | 0/21 |
//! | `PPME_PROCEXIT_1_{E,X}` | `EXIT_{E,X}`, `EXIT_GROUP_{E,X}` | 186/187 | 5/0 |
//!
//! PPM events encode a packed header, followed by one `u16` byte length per
//! parameter, followed by the parameter bytes in event-table order. Variable
//! payloads are deliberately not represented by an eBPF-visible Rust struct.

/// Size of one entry in the parameter-length array following [`PpmEventHeader`].
pub const PARAMETER_LENGTH_SIZE: usize = core::mem::size_of::<u16>();

/// A PPM event code.
///
/// This is a transparent integer rather than a Rust enum so decoding an event
/// code not yet known to Rustagon remains memory-safe.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PpmEventType(u16);

impl PpmEventType {
    pub const CLOSE_E: Self = Self(4);
    pub const CLOSE_X: Self = Self(5);
    pub const CONNECT_E: Self = Self(22);
    pub const CONNECT_X: Self = Self(23);
    pub const EXIT_E: Self = Self(186);
    pub const EXIT_X: Self = Self(187);
    pub const EXIT_GROUP_E: Self = Self::EXIT_E;
    pub const EXIT_GROUP_X: Self = Self::EXIT_X;
    pub const CLONE_E: Self = Self(222);
    pub const CLONE_X: Self = Self(223);
    pub const FORK_E: Self = Self(224);
    pub const FORK_X: Self = Self(225);
    pub const ACCEPT_E: Self = Self(246);
    pub const ACCEPT_X: Self = Self(247);
    pub const EXECVE_E: Self = Self(292);
    pub const EXECVE_X: Self = Self(293);
    pub const OPENAT_E: Self = Self(306);
    pub const OPENAT_X: Self = Self(307);
    pub const CLONE3_E: Self = Self(334);
    pub const CLONE3_X: Self = Self(335);
    pub const ACCEPT4_E: Self = Self(388);
    pub const ACCEPT4_X: Self = Self(389);

    /// Create an event type from any PPM wire value.
    pub const fn from_raw(value: u16) -> Self {
        Self(value)
    }

    /// Return the PPM wire value.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Return the parameter count from Falco's event table.
    ///
    /// Unknown event types return zero. The header remains authoritative when
    /// decoding incoming events.
    pub const fn parameter_count(self) -> u32 {
        match self.0 {
            4 => 1,
            5 => 2,
            22 => 2,
            23 => 4,
            186 => 5,
            187 => 0,
            222 | 224 | 246 | 334 => 0,
            223 | 225 | 335 => 21,
            247 => 5,
            292 => 1,
            293 => 31,
            306 => 4,
            307 => 7,
            388 => 1,
            389 => 6,
            _ => 0,
        }
    }
}

impl From<u16> for PpmEventType {
    fn from(value: u16) -> Self {
        Self::from_raw(value)
    }
}

impl From<PpmEventType> for u16 {
    fn from(value: PpmEventType) -> Self {
        value.raw()
    }
}

/// Header at the start of every Falco PPM event.
///
/// Falco declares `ppm_evt_hdr` with one-byte packing, so `repr(C, packed)` is
/// required for its 26-byte wire layout. Copy this header to an aligned local
/// value before accessing fields when decoding bytes.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpmEventHeader {
    /// Timestamp in nanoseconds from the Unix epoch.
    pub timestamp_ns: u64,
    /// Thread ID that generated the event.
    pub tid: u64,
    /// Total event length, including this header.
    pub len: u32,
    /// PPM event code.
    pub event_type: PpmEventType,
    /// Number of parameter lengths and payloads following this header.
    pub nparams: u32,
}

impl PpmEventHeader {
    /// Construct a header for an event whose final encoded length is known.
    pub const fn new(timestamp_ns: u64, tid: u64, len: u32, event_type: PpmEventType) -> Self {
        Self {
            timestamp_ns,
            tid,
            len,
            event_type,
            nparams: event_type.parameter_count(),
        }
    }
}
