//! Main daemon implementation
//!
//! Orchestrates:
//! - eBPF program loading
//! - Ringbuffer consumption
//! - Async event processing
//! - Graceful shutdown

use anyhow::Result;
use rustagon_parser::parse_rules_from_file;
use tokio::sync::mpsc;
use tracing::{info, error};

use crate::ringbuf::RingBufConsumer;
use crate::runner::EventRunner;

/// Main daemon function
pub async fn run(rules_file: String, num_workers: usize, _ringbuf_size: usize) -> Result<()> {
    info!("Loading rules from: {}", rules_file);

    // Parse rules
    let rule_def = parse_rules_from_file(&rules_file)?;
    info!("Loaded {} rules", rule_def.rules.len());

    // Create event channel (lock-free, multiple producers)
    let (tx, rx) = mpsc::channel(10000);

    // Spawn ringbuffer consumer task
    // This task would load the eBPF program and read events
    let ringbuf_task = {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = RingBufConsumer::run(tx).await {
                error!("Ringbuffer consumer error: {}", e);
            }
        })
    };

    // Spawn event processing workers
    let mut worker_tasks = vec![];
    for i in 0..num_workers {
        let rule_def = rule_def.clone();
        let rx = rx.clone();

        let worker_task = tokio::spawn(async move {
            info!("Event worker {} started", i);
            if let Err(e) = EventRunner::run(rx, &rule_def).await {
                error!("Worker {} error: {}", i, e);
            }
        });

        worker_tasks.push(worker_task);
    }

    // Wait for first task to complete (ringbuffer)
    ringbuf_task.await?;

    // Shutdown all worker tasks
    for task in worker_tasks {
        task.abort();
    }

    info!("Daemon shutdown");
    Ok(())
}
