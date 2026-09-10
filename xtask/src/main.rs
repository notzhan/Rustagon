//! Build task runner for Rustagon
//!
//! Handles compilation of eBPF programs and other build tasks

use anyhow::{anyhow, Result};
use cargo_metadata::MetadataCommand;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

const EBPF_TARGET: &str = "bpfel-unknown-none";

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
    /// Print Falco parity metrics from parity/METRICS.md
    ParityReport,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    match opts.command {
        Commands::BuildEbpf { release } => build_ebpf(release)?,
        Commands::CheckEbpf => check_ebpf()?,
        Commands::ParityReport => parity_report()?,
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
    cmd.arg(EBPF_TARGET);
    cmd.args(["-Z", "build-std=core"]);

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
    cmd.arg(EBPF_TARGET);
    cmd.args(["-Z", "build-std=core"]);

    println!("Running: {:?}", cmd);
    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow!("eBPF check failed"));
    }

    println!("eBPF check successful");
    Ok(())
}

/// Print parity metrics table from parity/METRICS.md
fn parity_report() -> Result<()> {
    let metrics = find_workspace_dir()?.join("parity/METRICS.md");
    if !metrics.exists() {
        return Err(anyhow!("parity metrics not found: {:?}", metrics));
    }
    print!("{}", std::fs::read_to_string(&metrics)?);
    Ok(())
}

/// Find the workspace root directory
fn find_workspace_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CARGO_WORKSPACE_DIR") {
        return Ok(PathBuf::from(dir));
    }

    let manifest = locate_workspace_manifest()?;
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest)
        .no_deps()
        .exec()?;
    Ok(metadata.workspace_root.into())
}

fn locate_workspace_manifest() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            let contents = std::fs::read_to_string(&manifest)?;
            if contents.contains("[workspace]") {
                return Ok(manifest);
            }
        }
        if !dir.pop() {
            break;
        }
    }
    Err(anyhow!("Could not find workspace Cargo.toml"))
}

/// Find the eBPF project directory
fn find_ebpf_dir() -> Result<PathBuf> {
    let workspace_dir = find_workspace_dir()?;

    let ebpf_dir = workspace_dir.join("rustagon-ebpf");

    if !ebpf_dir.exists() {
        return Err(anyhow!("eBPF directory not found: {:?}", ebpf_dir));
    }

    Ok(ebpf_dir)
}
