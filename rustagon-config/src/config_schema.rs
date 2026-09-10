use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BaseSyscallsConfig {
    pub custom_set: Vec<String>,
    pub repair: bool,
    pub all: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SyscallEventDropsConfig {
    pub threshold: f64,
    pub actions: Vec<String>,
    pub rate: f64,
    pub max_burst: u32,
    pub simulate_drops: bool,
}

impl Default for SyscallEventDropsConfig {
    fn default() -> Self {
        Self {
            threshold: 0.1,
            actions: Vec::new(),
            rate: 0.03333,
            max_burst: 1,
            simulate_drops: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FalcoLibsConfig {
    pub thread_table_size: u64,
    pub thread_table_auto_purging_interval_s: u64,
    pub thread_table_auto_purging_thread_timeout_s: u64,
    pub snaplen: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub kind: String,
    pub kmod: DriverConfig,
    pub modern_ebpf: ModernEbpfConfig,
    pub replay: ReplayConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DriverConfig {
    pub buf_size_preset: u32,
    pub drop_failed_exit: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModernEbpfConfig {
    pub cpus_for_each_buffer: u32,
    pub buf_size_preset: u32,
    pub drop_failed_exit: bool,
    pub disable_iterators: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayConfig {
    pub capture_file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToggleOutput {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileOutput {
    pub enabled: bool,
    pub keep_alive: bool,
    pub filename: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpOutput {
    pub enabled: bool,
    pub url: String,
    pub user_agent: String,
    pub insecure: bool,
    pub ca_cert: String,
    pub ca_bundle: String,
    pub ca_path: String,
    pub mtls: bool,
    pub client_cert: String,
    pub client_key: String,
    pub echo: bool,
    pub compress_uploads: bool,
    pub keep_alive: bool,
    pub max_consecutive_timeouts: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProgramOutput {
    pub enabled: bool,
    pub keep_alive: bool,
    pub program: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebserverConfig {
    pub enabled: bool,
    pub threadiness: u32,
    pub listen_port: u16,
    pub listen_address: String,
    pub k8s_healthz_endpoint: String,
    pub prometheus_metrics_enabled: bool,
    pub ssl_enabled: bool,
    pub ssl_certificate: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginConfig {
    pub name: String,
    pub library_path: String,
    #[serde(deserialize_with = "deserialize_plugin_init_config")]
    pub init_config: Value,
    #[serde(deserialize_with = "deserialize_string_scalar")]
    pub open_params: String,
}

fn deserialize_plugin_init_config<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null => Ok(Value::String(String::new())),
        Value::String(ref text) if !text.is_empty() => {
            Ok(serde_yaml::from_str(text).unwrap_or(value))
        }
        _ => Ok(value),
    }
}

fn deserialize_string_scalar<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(String::new()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => Ok(value),
        _ => Err(serde::de::Error::custom("expected a scalar string value")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSelectionOperation {
    Enable,
    Disable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleSelection {
    pub operation: RuleSelectionOperation,
    pub rule: Option<String>,
    pub tag: Option<String>,
}

impl<'de> Deserialize<'de> for RuleSelection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Match {
            rule: Option<String>,
            tag: Option<String>,
        }

        #[derive(Deserialize)]
        struct Wire {
            enable: Option<Match>,
            disable: Option<Match>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let (operation, selection) = match (wire.enable, wire.disable) {
            (Some(selection), None) => (RuleSelectionOperation::Enable, selection),
            (None, Some(selection)) => (RuleSelectionOperation::Disable, selection),
            _ => {
                return Err(serde::de::Error::custom(
                    "rule selection must contain exactly one of enable or disable",
                ))
            }
        };
        Ok(Self {
            operation,
            rule: selection.rule,
            tag: selection.tag,
        })
    }
}

impl Serialize for RuleSelection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut outer = serializer.serialize_map(Some(1))?;
        let key = match self.operation {
            RuleSelectionOperation::Enable => "enable",
            RuleSelectionOperation::Disable => "disable",
        };
        let mut inner = std::collections::BTreeMap::new();
        if let Some(rule) = &self.rule {
            inner.insert("rule", rule);
        }
        if let Some(tag) = &self.tag {
            inner.insert("tag", tag);
        }
        outer.serialize_entry(key, &inner)?;
        outer.end()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppendOutputMatch {
    pub source: Option<String>,
    pub tags: Vec<String>,
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppendOutput {
    #[serde(rename = "match")]
    pub match_config: AppendOutputMatch,
    pub extra_output: Option<String>,
    pub extra_fields: Vec<Value>,
    pub suggested_output: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MergeStrategy {
    #[default]
    Append,
    Override,
    AddOnly,
}

impl<'de> Deserialize<'de> for MergeStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "append" => Ok(Self::Append),
            "override" => Ok(Self::Override),
            "add-only" => Ok(Self::AddOnly),
            // Falco reports schema validation failure but continues with append.
            _ => Ok(Self::Append),
        }
    }
}

impl Serialize for MergeStrategy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Append => "append",
            Self::Override => "override",
            Self::AddOnly => "add-only",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigFile {
    Path(String),
    Detailed {
        path: String,
        #[serde(default)]
        strategy: MergeStrategy,
    },
}

impl ConfigFile {
    pub(crate) fn parts(&self) -> (&str, MergeStrategy) {
        match self {
            Self::Path(path) => (path, MergeStrategy::Append),
            Self::Detailed { path, strategy } => (path, *strategy),
        }
    }
}

pub(crate) fn deserialize_config_files<'de, D>(deserializer: D) -> Result<Vec<ConfigFile>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Sequence(items)) => items
            .into_iter()
            .map(|item| serde_yaml::from_value(item).map_err(serde::de::Error::custom))
            .collect(),
        Some(value) => serde_yaml::from_value(value)
            .map(|item| vec![item])
            .map_err(serde::de::Error::custom),
    }
}
