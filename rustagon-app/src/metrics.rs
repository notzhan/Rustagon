//! Falco-compatible application metric snapshots and Prometheus emission.

/// Content type used by Falco's Prometheus endpoint.
pub const CONTENT_TYPE_PROMETHEUS: &str = "text/plain; version=0.0.4";

/// Application-owned metrics that do not require a libsinsp inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub falco_version: String,
    pub outputs_queue_num_drops: u64,
    pub reload_timestamp_nanoseconds: i64,
}

impl MetricsSnapshot {
    pub fn to_prometheus(&self) -> String {
        let version = escape_label(&self.falco_version);
        format!(
            "# HELP falcosecurity_falco_version_info https://falco.org/docs/metrics/\n\
             # TYPE falcosecurity_falco_version_info gauge\n\
             falcosecurity_falco_version_info{{version=\"{version}\"}} 1\n\
             # HELP falcosecurity_falco_outputs_queue_num_drops_total https://falco.org/docs/metrics/\n\
             # TYPE falcosecurity_falco_outputs_queue_num_drops_total counter\n\
             falcosecurity_falco_outputs_queue_num_drops_total {}\n\
             # HELP falcosecurity_falco_reload_timestamp_nanoseconds https://falco.org/docs/metrics/\n\
             # TYPE falcosecurity_falco_reload_timestamp_nanoseconds gauge\n\
             falcosecurity_falco_reload_timestamp_nanoseconds {}\n",
            self.outputs_queue_num_drops, self.reload_timestamp_nanoseconds
        )
    }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}
