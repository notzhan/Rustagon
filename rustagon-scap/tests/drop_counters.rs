use rustagon_scap::{DropCounters, DropReason};

#[test]
fn drop_counters_increment_tip_aligned_fields() {
    let counters = DropCounters::default();

    counters.record(DropReason::BufferFull);
    counters.record(DropReason::BufferFull);
    counters.record(DropReason::ParseFailure);
    counters.record(DropReason::Filtered);

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.n_drops, 4);
    assert_eq!(snapshot.n_drops_buffer_total, 2);
    assert_eq!(snapshot.n_drops_bug, 1);
    assert_eq!(snapshot.n_drops_filtered, 1);
}

#[test]
fn snapshot_exposes_stable_metric_key_names() {
    let keys = rustagon_scap::DropCountersSnapshot::METRIC_KEYS;

    assert_eq!(
        keys,
        [
            "n_drops",
            "n_drops_buffer_total",
            "n_drops_bug",
            "n_drops_filtered",
        ]
    );
}
