use rustagon_config::{
    ConfigError, DriverConfig, FalcoConfig, LoadPlugins, ModernEbpfConfig, ReplayConfig,
};
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
    let plugins = match &config.load_plugins {
        LoadPlugins::Enabled(false) => return Ok(()),
        LoadPlugins::Names(names) if names.is_empty() => return Ok(()),
        LoadPlugins::Names(names) => names.join(", "),
        LoadPlugins::Enabled(true) => configured_plugin_names(config),
        LoadPlugins::Omitted if config.plugins.is_empty() => return Ok(()),
        LoadPlugins::Omitted => configured_plugin_names(config),
    };

    Err(LoadConfigError::PluginsNotImplemented { plugins })
}

fn configured_plugin_names(config: &FalcoConfig) -> String {
    let names = config
        .plugins
        .iter()
        .map(|plugin| plugin.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if names.is_empty() {
        "all configured plugins".to_string()
    } else {
        names
    }
}
