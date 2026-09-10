use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use thiserror::Error;

use crate::config_schema::{
    deserialize_config_files, AppendOutput, ConfigFile, EngineConfig, FileOutput, HttpOutput,
    MergeStrategy, PluginConfig, ProgramOutput, RuleSelection, ToggleOutput, WebserverConfig,
};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid YAML configuration: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid webserver.listen_address `{0}`")]
    InvalidListenAddress(String),
    #[error("secondary configuration `{0}` cannot contain config_files")]
    SecondaryInclude(PathBuf),
    #[error("configuration cannot include itself: `{0}`")]
    SelfInclude(PathBuf),
    #[error("plugin library path escapes the plugin directory: `{0}`")]
    PluginPathTraversal(String),
    #[error("CLI override key cannot be empty")]
    EmptyOverrideKey,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FalcoConfig {
    #[serde(deserialize_with = "deserialize_config_files")]
    pub config_files: Vec<ConfigFile>,
    pub watch_config_files: bool,
    pub rules_files: Vec<String>,
    pub rules: Vec<RuleSelection>,
    pub engine: EngineConfig,
    pub load_plugins: Vec<String>,
    pub plugins: Vec<PluginConfig>,
    pub plugins_hostinfo: bool,
    pub time_format_iso_8601: bool,
    pub buffer_format_base64: bool,
    pub priority: String,
    pub json_output: bool,
    pub json_include_output_property: bool,
    pub json_include_message_property: bool,
    pub json_include_output_fields_property: bool,
    pub json_include_tags_property: bool,
    pub buffered_outputs: bool,
    pub rule_matching: String,
    pub append_output: Vec<AppendOutput>,
    pub stdout_output: ToggleOutput,
    pub syslog_output: ToggleOutput,
    pub file_output: FileOutput,
    pub http_output: HttpOutput,
    pub program_output: ProgramOutput,
    pub webserver: WebserverConfig,
    pub log_stderr: bool,
    pub log_syslog: bool,
    pub log_level: String,
    pub output_timeout: u64,
    #[serde(skip)]
    pub loaded_files: Vec<PathBuf>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl FalcoConfig {
    pub fn load_from_str(content: &str) -> Result<Self, ConfigError> {
        let mut value: Value = serde_yaml::from_str(content)?;
        expand_environment(&mut value);
        Self::from_value(value)
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut root: Value = serde_yaml::from_str(&content)?;
        expand_environment(&mut root);
        let includes = read_includes(&root)?;
        let mut loaded_files = vec![path.to_path_buf()];
        let main_identity = normalized_path(path);

        for include in includes {
            let (include_path, strategy) = include.parts();
            let resolved = PathBuf::from(include_path);

            for child_path in expand_include(&resolved)? {
                if normalized_path(&child_path) == main_identity {
                    return Err(ConfigError::SelfInclude(child_path));
                }
                let child_content =
                    fs::read_to_string(&child_path).map_err(|source| ConfigError::Read {
                        path: child_path.clone(),
                        source,
                    })?;
                let mut child: Value = serde_yaml::from_str(&child_content)?;
                expand_environment(&mut child);
                if mapping_has_key(&child, "config_files") {
                    return Err(ConfigError::SecondaryInclude(child_path));
                }
                merge_top_level(&mut root, child, strategy);
                loaded_files.push(child_path);
            }
        }

        let mut config = Self::from_value(root)?;
        config.loaded_files = loaded_files;
        Ok(config)
    }

    pub fn apply_cli_override(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        if key.is_empty() {
            return Err(ConfigError::EmptyOverrideKey);
        }

        let loaded_files = std::mem::take(&mut self.loaded_files);
        let mut document = serde_yaml::to_value(&*self)?;
        let override_value =
            serde_yaml::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.into()));
        if let Some(key) = key.strip_suffix("[]") {
            append_dotted_key(&mut document, key, override_value);
        } else {
            set_dotted_key(&mut document, key, override_value);
        }
        let mut updated = Self::from_value(document)?;
        updated.loaded_files = loaded_files;
        *self = updated;
        Ok(())
    }

    fn from_value(value: Value) -> Result<Self, ConfigError> {
        let config: Self = serde_yaml::from_value(value)?;
        if !config.webserver.listen_address.is_empty()
            && config.webserver.listen_address.parse::<IpAddr>().is_err()
        {
            return Err(ConfigError::InvalidListenAddress(
                config.webserver.listen_address.clone(),
            ));
        }
        for plugin in &config.plugins {
            if relative_path_escapes_root(Path::new(&plugin.library_path)) {
                return Err(ConfigError::PluginPathTraversal(
                    plugin.library_path.clone(),
                ));
            }
        }
        Ok(config)
    }
}

fn expand_environment(value: &mut Value) {
    match value {
        Value::String(text) => {
            let (expanded, changed, exact) = expand_environment_string(text);
            if changed && exact && !expanded.is_empty() {
                *value =
                    serde_yaml::from_str(&expanded).unwrap_or_else(|_| Value::String(expanded));
            } else if changed {
                *text = expanded;
            }
        }
        Value::Sequence(items) => {
            for item in items {
                expand_environment(item);
            }
        }
        Value::Mapping(map) => {
            for item in map.values_mut() {
                expand_environment(item);
            }
        }
        Value::Tagged(tagged) => expand_environment(&mut tagged.value),
        _ => {}
    }
}

fn expand_environment_string(input: &str) -> (String, bool, bool) {
    const ESCAPED_OPEN: &str = "\u{0}RUSTAGON_ESCAPED_ENV\u{0}";
    let exact = input.starts_with("${") && input.ends_with('}') && input.matches("${").count() == 1;
    let mut result = input.replace("$${", ESCAPED_OPEN);
    let mut changed = result != input;

    for _ in 0..32 {
        let Some(start) = result.find("${") else {
            break;
        };
        let Some(relative_end) = result[start + 2..].find('}') else {
            break;
        };
        let end = start + 2 + relative_end;
        let name = &result[start + 2..end];
        let replacement = std::env::var(name).unwrap_or_default();
        result.replace_range(start..=end, &replacement);
        changed = true;
    }

    if result.contains(ESCAPED_OPEN) {
        result = result.replace(ESCAPED_OPEN, "${");
        changed = true;
    }
    (result, changed, exact)
}

fn relative_path_escapes_root(path: &Path) -> bool {
    if path.is_absolute() {
        return false;
    }
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth == 0 => return true,
            Component::ParentDir => depth -= 1,
            _ => {}
        }
    }
    false
}

fn read_includes(root: &Value) -> Result<Vec<ConfigFile>, ConfigError> {
    let Some(value) = root
        .as_mapping()
        .and_then(|map| map.get(Value::String("config_files".into())))
    else {
        return Ok(Vec::new());
    };
    let wrapper = Value::Mapping(Mapping::from_iter([(
        Value::String("config_files".into()),
        value.clone(),
    )]));
    #[derive(Deserialize)]
    struct Includes {
        #[serde(deserialize_with = "deserialize_config_files")]
        config_files: Vec<ConfigFile>,
    }
    Ok(serde_yaml::from_value::<Includes>(wrapper)?.config_files)
}

fn expand_include(path: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let entries = fs::read_dir(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut files = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|entry| entry.is_file())
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn merge_top_level(target: &mut Value, source: Value, strategy: MergeStrategy) {
    let (Some(target), Value::Mapping(source)) = (target.as_mapping_mut(), source) else {
        return;
    };
    for (key, incoming) in source {
        if key == Value::String("config_files".into()) {
            continue;
        }
        match (strategy, target.get_mut(&key)) {
            (MergeStrategy::AddOnly, Some(_)) => {}
            (MergeStrategy::Append, Some(Value::Sequence(existing))) => {
                if let Value::Sequence(mut incoming) = incoming {
                    existing.append(&mut incoming);
                } else {
                    target.insert(key, incoming);
                }
            }
            (_, _) => {
                target.insert(key, incoming);
            }
        }
    }
}

fn mapping_has_key(value: &Value, key: &str) -> bool {
    value
        .as_mapping()
        .is_some_and(|map| map.contains_key(Value::String(key.into())))
}

fn normalized_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn set_dotted_key(document: &mut Value, key: &str, value: Value) {
    let mut current = document;
    let mut parts = key.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            if !current.is_mapping() {
                *current = Value::Mapping(Mapping::new());
            }
            current
                .as_mapping_mut()
                .expect("mapping created above")
                .insert(Value::String(part.into()), value);
            return;
        }
        if !current.is_mapping() {
            *current = Value::Mapping(Mapping::new());
        }
        current = current
            .as_mapping_mut()
            .expect("mapping created above")
            .entry(Value::String(part.into()))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
    }
}

fn append_dotted_key(document: &mut Value, key: &str, value: Value) {
    let mut current = document;
    let mut parts = key.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            if !current.is_mapping() {
                *current = Value::Mapping(Mapping::new());
            }
            let entry = current
                .as_mapping_mut()
                .expect("mapping created above")
                .entry(Value::String(part.into()))
                .or_insert_with(|| Value::Sequence(Vec::new()));
            if !entry.is_sequence() {
                *entry = Value::Sequence(Vec::new());
            }
            entry
                .as_sequence_mut()
                .expect("sequence created above")
                .push(value);
            return;
        }
        if !current.is_mapping() {
            *current = Value::Mapping(Mapping::new());
        }
        current = current
            .as_mapping_mut()
            .expect("mapping created above")
            .entry(Value::String(part.into()))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
    }
}
