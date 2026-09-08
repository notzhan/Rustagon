//! Event runner - processes events and evaluates rules
//!
//! Receives events from ringbuffer via channel
//! Evaluates rules asynchronously without blocking

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};
use rustagon_parser::{parse_rules, RuleEvaluator, RuleDefinition};

use crate::ringbuf::RingBufEvent;

/// Event processing runner
pub struct EventRunner;

impl EventRunner {
    /// Run the event processor
    pub async fn run(
        mut rx: mpsc::Receiver<RingBufEvent>,
        _rule_def: &RuleDefinition,
    ) -> Result<()> {
        info!("Event runner started");

        // Compile rules
        let _evaluators: Vec<RuleEvaluator> = vec![];

        // Process events from channel
        while let Some(_event) = rx.recv().await {
            // In a real implementation:
            // 1. Deserialize event from raw bytes
            // 2. Evaluate each rule against the event
            // 3. Output alerts for matching rules
            // 4. All without blocking
        }

        info!("Event runner shutdown");
        Ok(())
    }
}
