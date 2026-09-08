//! Rustagon Core - Userspace daemon for event capture and processing
//!
//! This is the main userspace component that:
//! - Loads eBPF programs
//! - Consumes events from ringbuffer
//! - Evaluates rules asynchronously
//! - Outputs alerts
//!
//! Key design principles:
//! - Fully async using Tokio runtime
//! - Lock-free event processing with channels
//! - No blocking I/O operations

mod daemon;
mod ringbuf;
mod runner;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "rustagon")]
#[command(about = "Next-generation container runtime security engine", long_about = None)]
struct Args {
    /// Path to Falco rules file
    #[arg(short, long, default_value = "rules.yaml")]
    rules: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Ringbuffer size in bytes
    #[arg(long, default_value = "262144")]
    ringbuf_size: usize,

    /// Number of event processing workers
    #[arg(long, default_value = "4")]
    workers: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Setup logging
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(&args.log_level))
        .unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // Log startup information
    tracing::info!("Starting Rustagon...");
    tracing::info!("Rules file: {}", args.rules);
    tracing::info!("Workers: {}", args.workers);

    // Run the daemon
    daemon::run(args.rules, args.workers, args.ringbuf_size).await?;

    Ok(())
}
