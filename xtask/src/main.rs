//! Build task runner for Rustagon
//!
//! Handles compilation of eBPF programs and other build tasks

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
struct Opts {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF programs
    BuildEbpf {
        /// Release build
        #[arg(long)]
        release: bool,
    },
    /// Check eBPF programs without optimizing
    CheckEbpf,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    match opts.command {
        Commands::BuildEbpf { release } => build_ebpf(release)?,
        Commands::CheckEbpf => check_ebpf()?,
    };

    Ok(())
}

/// Build eBPF programs
fn build_ebpf(release: bool) -> Result<()> {
    println!("Building eBPF programs...");

    let ebpf_dir = find_ebpf_dir()?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir);
    cmd.arg("build");
    cmd.arg("--target");
    cmd.arg("bpfel64-unknown-none");

    if release {
        cmd.arg("--release");
    }

    println!("Running: {:?}", cmd);
    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow!("eBPF build failed"));
    }

    println!("eBPF build successful");
    Ok(())
}

/// Check eBPF programs without optimizing
fn check_ebpf() -> Result<()> {
    println!("Checking eBPF programs...");

    let ebpf_dir = find_ebpf_dir()?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir);
    cmd.arg("check");
    cmd.arg("--target");
    cmd.arg("bpfel64-unknown-none");

    println!("Running: {:?}", cmd);
    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow!("eBPF check failed"));
    }

    println!("eBPF check successful");
    Ok(())
}

/// Find the eBPF project directory
fn find_ebpf_dir() -> Result<PathBuf> {
    let workspace_dir = std::env::var("CARGO_WORKSPACE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            // Try to find it relative to current directory
            let current = std::env::current_dir().ok()?;
            Some(current.parent()?.to_path_buf())
        })
        .ok_or_else(|| anyhow!("Could not find workspace directory"))?;

    let ebpf_dir = workspace_dir.join("rustagon-ebpf");

    if !ebpf_dir.exists() {
        return Err(anyhow!("eBPF directory not found: {:?}", ebpf_dir));
    }

    Ok(ebpf_dir)
}
