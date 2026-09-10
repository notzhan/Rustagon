use rustagon_config::{ConfigError, DriverConfig, FalcoConfig, ModernEbpfConfig, ReplayConfig};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadConfigError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(
        "Falco plugins are enabled ({plugins}), but pure-Rust plugin support is not implemented"
    )]
    PluginsNotImplemented { plugins: String },
}

pub fn load_config(
    path: impl AsRef<Path>,
    overrides: &[(&str, &str)],
) -> Result<FalcoConfig, LoadConfigError> {
    let mut config = FalcoConfig::load_from_file_with_cli_overrides(path, overrides)?;
    validate_plugin_support(&config)?;
    match config.engine.kind.as_str() {
        "kmod" => {
            config.engine.modern_ebpf = ModernEbpfConfig::default();
            config.engine.replay = ReplayConfig::default();
        }
        "modern_ebpf" => {
            config.engine.kmod = DriverConfig::default();
            config.engine.replay = ReplayConfig::default();
        }
        "replay" => {
            config.engine.kmod = DriverConfig::default();
            config.engine.modern_ebpf = ModernEbpfConfig::default();
        }
        _ => {}
    }
    Ok(config)
}

pub fn validate_plugin_support(config: &FalcoConfig) -> Result<(), LoadConfigError> {
    if config.load_plugins.is_empty() {
        return Ok(());
    }
    Err(LoadConfigError::PluginsNotImplemented {
        plugins: config.load_plugins.join(", "),
    })
}
