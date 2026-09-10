//! Event runner - processes events and evaluates rules
//!
//! Receives events from ringbuffer via channel
//! Evaluates rules asynchronously without blocking

use anyhow::Result;
use rustagon_parser::{RuleDefinition, RuleEvaluator};
use tokio::sync::mpsc;
use tracing::info;

use crate::ringbuf::RingBufEvent;

/// Event processing runner
pub struct EventRunner;

impl EventRunner {
    /// Run the event processor
    pub async fn run(
        mut rx: mpsc::Receiver<RingBufEvent>,
        rule_def: &RuleDefinition,
    ) -> Result<()> {
        info!("Event runner started");

        let _evaluators: Result<Vec<RuleEvaluator>, _> = rule_def
            .rules
            .iter()
            .map(|rule| RuleEvaluator::new(rule.condition.clone()))
            .collect();

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
