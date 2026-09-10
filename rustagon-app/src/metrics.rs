//! Falco-compatible application metric snapshots and Prometheus emission.

use rustagon_scap::DropCountersSnapshot;

/// Content type used by Falco's Prometheus endpoint.
pub const CONTENT_TYPE_PROMETHEUS: &str = "text/plain; version=0.0.4";

/// Application-owned metrics that do not require a libsinsp inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub falco_version: String,
    pub outputs_queue_num_drops: u64,
    pub reload_timestamp_nanoseconds: i64,
    pub scap: Option<DropCountersSnapshot>,
}

impl MetricsSnapshot {
    pub fn to_prometheus(&self) -> String {
        let version = escape_label(&self.falco_version);
        let mut output = format!(
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
        );
        if let Some(scap) = self.scap {
            output.push_str(&format!(
            "# HELP falcosecurity_scap_n_drops_total https://falco.org/docs/metrics/\n\
             # TYPE falcosecurity_scap_n_drops_total counter\n\
             falcosecurity_scap_n_drops_total {}\n\
             # HELP falcosecurity_scap_n_drops_buffer_total https://falco.org/docs/metrics/\n\
             # TYPE falcosecurity_scap_n_drops_buffer_total counter\n\
             falcosecurity_scap_n_drops_buffer_total {}\n\
             # HELP falcosecurity_scap_n_drops_bug_total https://falco.org/docs/metrics/\n\
             # TYPE falcosecurity_scap_n_drops_bug_total counter\n\
             falcosecurity_scap_n_drops_bug_total {}\n\
             # HELP falcosecurity_scap_n_drops_filtered_total Rustagon userspace-filtered syscall events\n\
             # TYPE falcosecurity_scap_n_drops_filtered_total counter\n\
             falcosecurity_scap_n_drops_filtered_total {}\n",
                scap.n_drops,
                scap.n_drops_buffer_total,
                scap.n_drops_bug,
                scap.n_drops_filtered,
            ));
        }
        output
    }

    pub fn with_scap_metrics(mut self, scap: DropCountersSnapshot) -> Self {
        self.scap = Some(scap);
        self
    }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}
