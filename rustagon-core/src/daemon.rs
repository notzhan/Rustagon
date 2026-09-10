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
use tracing::{error, info};

use crate::ringbuf::RingBufConsumer;
use crate::runner::EventRunner;

/// Main daemon function
pub async fn run(rules_file: String, num_workers: usize, _ringbuf_size: usize) -> Result<()> {
    info!("Loading rules from: {}", rules_file);

    let rule_def = parse_rules_from_file(&rules_file)?;
    info!("Loaded {} rules", rule_def.rules.len());

    let workers = num_workers.max(1);
    let (tx, mut rx) = mpsc::channel(10000);

    let ringbuf_task = {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = RingBufConsumer::run(tx).await {
                error!("Ringbuffer consumer error: {}", e);
            }
        })
    };
    drop(tx);

    let mut worker_txs = Vec::with_capacity(workers);
    let mut worker_tasks = Vec::with_capacity(workers);
    for i in 0..workers {
        let (worker_tx, worker_rx) = mpsc::channel(10000);
        worker_txs.push(worker_tx);

        let rule_def = rule_def.clone();
        worker_tasks.push(tokio::spawn(async move {
            info!("Event worker {} started", i);
            if let Err(e) = EventRunner::run(worker_rx, &rule_def).await {
                error!("Worker {} error: {}", i, e);
            }
        }));
    }

    let dispatch_task = tokio::spawn(async move {
        let mut next = 0usize;
        while let Some(event) = rx.recv().await {
            if worker_txs.is_empty() {
                break;
            }
            let target = next % worker_txs.len();
            next = next.wrapping_add(1);
            if worker_txs[target].send(event).await.is_err() {
                break;
            }
        }
    });

    tokio::select! {
        result = ringbuf_task => {
            result?;
        }
        result = dispatch_task => {
            result?;
        }
    }

    for task in worker_tasks {
        task.abort();
    }

    info!("Daemon shutdown");
    Ok(())
}
