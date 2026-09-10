use clap::Parser;
use rustagon_config::{ConfigError, FalcoConfig};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "rustagon", version, about = "Cloud-native runtime security")]
pub struct Cli {
    /// Configuration file
    #[arg(short = 'c', long = "config", default_value = "/etc/falco/falco.yaml")]
    pub config: PathBuf,

    /// Rules file or directory (repeatable)
    #[arg(short = 'r', long = "rules", action = clap::ArgAction::Append)]
    pub rules: Vec<PathBuf>,

    /// Override a configuration value as key=value
    #[arg(short = 'o', value_parser = parse_override, action = clap::ArgAction::Append)]
    pub overrides: Vec<String>,

    /// List loaded rules
    #[arg(long)]
    pub list: bool,

    /// List supported events
    #[arg(long)]
    pub list_events: bool,

    /// Validate one or more rules files
    #[arg(long, num_args = 1.., action = clap::ArgAction::Append)]
    pub validate: Vec<PathBuf>,

    /// Validate configuration and rules without starting capture
    #[arg(long)]
    pub dry_run: bool,
}

fn parse_override(value: &str) -> Result<String, String> {
    let Some((key, _)) = value.split_once('=') else {
        return Err("override must use key=value syntax".to_string());
    };
    if key.is_empty() {
        return Err("override key cannot be empty".to_string());
    }
    Ok(value.to_string())
}

impl Cli {
    pub fn apply_overrides(&self, config: &mut FalcoConfig) -> Result<(), ConfigError> {
        for value in &self.overrides {
            let (key, value) = value
                .split_once('=')
                .expect("CLI override syntax was validated by clap");
            config.apply_cli_override(key, value)?;
        }
        Ok(())
    }
}
