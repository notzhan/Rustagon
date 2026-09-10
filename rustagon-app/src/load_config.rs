use rustagon_config::{ConfigError, DriverConfig, FalcoConfig, ModernEbpfConfig, ReplayConfig};
use std::path::Path;

pub fn load_config(
    path: impl AsRef<Path>,
    overrides: &[(&str, &str)],
) -> Result<FalcoConfig, ConfigError> {
    let mut config = FalcoConfig::load_from_file_with_cli_overrides(path, overrides)?;
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
