use std::sync::atomic::{AtomicU8, Ordering};

const IDLE: u8 = 0;
const TRIGGERED: u8 = 1;
const HANDLING: u8 = 2;
const HANDLED: u8 = 3;

/// A signal-safe state machine that elects exactly one handler.
#[derive(Debug, Default)]
pub struct AtomicSignalHandler {
    state: AtomicU8,
}

impl AtomicSignalHandler {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(IDLE),
        }
    }

    pub const fn is_lock_free(&self) -> bool {
        cfg!(target_has_atomic = "8")
    }

    pub fn triggered(&self) -> bool {
        self.state.load(Ordering::Acquire) != IDLE
    }

    pub fn handled(&self) -> bool {
        self.state.load(Ordering::Acquire) == HANDLED
    }

    pub fn trigger(&self) {
        self.state.store(TRIGGERED, Ordering::Release);
    }

    pub fn reset(&self) {
        self.state.store(IDLE, Ordering::Release);
    }

    pub fn handle(&self, callback: impl FnOnce()) -> bool {
        if self
            .state
            .compare_exchange(TRIGGERED, HANDLING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        callback();
        self.state.store(HANDLED, Ordering::Release);
        true
    }
}
