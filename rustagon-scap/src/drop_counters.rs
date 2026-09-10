use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    BufferFull,
    ParseFailure,
    Filtered,
}

#[derive(Debug, Clone, Default)]
pub struct DropCounters {
    inner: Arc<DropCountersInner>,
}

#[derive(Debug, Default)]
struct DropCountersInner {
    n_drops: AtomicU64,
    n_drops_buffer_total: AtomicU64,
    n_drops_bug: AtomicU64,
    n_drops_filtered: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DropCountersSnapshot {
    pub n_drops: u64,
    pub n_drops_buffer_total: u64,
    pub n_drops_bug: u64,
    pub n_drops_filtered: u64,
}

impl DropCountersSnapshot {
    pub const METRIC_KEYS: [&'static str; 4] = [
        "n_drops",
        "n_drops_buffer_total",
        "n_drops_bug",
        "n_drops_filtered",
    ];
}

impl DropCounters {
    pub fn record(&self, reason: DropReason) {
        self.inner.n_drops.fetch_add(1, Ordering::Relaxed);
        let counter = match reason {
            DropReason::BufferFull => &self.inner.n_drops_buffer_total,
            DropReason::ParseFailure => &self.inner.n_drops_bug,
            DropReason::Filtered => &self.inner.n_drops_filtered,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DropCountersSnapshot {
        DropCountersSnapshot {
            n_drops: self.inner.n_drops.load(Ordering::Relaxed),
            n_drops_buffer_total: self.inner.n_drops_buffer_total.load(Ordering::Relaxed),
            n_drops_bug: self.inner.n_drops_bug.load(Ordering::Relaxed),
            n_drops_filtered: self.inner.n_drops_filtered.load(Ordering::Relaxed),
        }
    }
}
