//! Ringbuffer consumer for kernel events
//!
//! Reads events from the eBPF ringbuffer and sends them to the async event channel

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::info;

/// Event received from ringbuffer
#[derive(Debug, Clone)]
pub struct RingBufEvent {
    /// Raw event data
    pub data: Vec<u8>,
}

impl RingBufEvent {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Ringbuffer consumer
pub struct RingBufConsumer;

impl RingBufConsumer {
    /// Run the ringbuffer consumer
    pub async fn run(_tx: mpsc::Sender<RingBufEvent>) -> Result<()> {
        info!("Ringbuffer consumer started");

        // Placeholder until the daemon consumes ModernEbpfSource:
        // 1. Load the eBPF program using aya
        // 2. Get the ringbuffer map
        // 3. Consume events in a loop
        // 4. Send events to the channel
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
}
