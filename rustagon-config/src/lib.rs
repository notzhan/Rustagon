//! Falco configuration loading without runtime or eBPF dependencies.

mod config;
mod config_schema;

pub use config::{ConfigError, FalcoConfig, YamlConfig};
pub use config_schema::{
    AppendOutput, AppendOutputMatch, ConfigFile, DriverConfig, EngineConfig, FileOutput,
    HttpOutput, MergeStrategy, ModernEbpfConfig, PluginConfig, ProgramOutput, ReplayConfig,
    RuleSelection, RuleSelectionOperation, ToggleOutput, WebserverConfig,
};
