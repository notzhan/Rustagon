use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};
use thiserror::Error;

use crate::config_schema::{
    deserialize_config_files, AppendOutput, BaseSyscallsConfig, ConfigFile, EngineConfig,
    FalcoLibsConfig, FileOutput, HttpOutput, MergeStrategy, PluginConfig, ProgramOutput,
    RuleSelection, SyscallEventDropsConfig, ToggleOutput, WebserverConfig,
};

pub const FALCO_CONFIG_SCHEMA: &str = include_str!("../schema/falco-config.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationStatus {
    None,
    Ok,
    Failed(Vec<String>),
}

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
    #[error("invalid configuration key `{key}`: {reason}")]
    InvalidKey { key: String, reason: String },
    #[error("invalid configuration schema: {0}")]
    Schema(String),
}

#[derive(Debug, Clone, Default)]
pub struct YamlConfig {
    document: Value,
}

impl YamlConfig {
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        config.load_from_str(content)?;
        Ok(config)
    }

    pub fn load_from_str(&mut self, content: &str) -> Result<(), ConfigError> {
        self.document = serde_yaml::from_str(content)?;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.document = Value::Null;
    }

    pub fn is_defined(&self, key: &str) -> Result<bool, ConfigError> {
        Ok(self.get(key)?.is_some())
    }

    pub fn get(&self, key: &str) -> Result<Option<&Value>, ConfigError> {
        get_key(&self.document, key)
    }

    pub fn sequence(&self, key: &str) -> Result<Option<&[Value]>, ConfigError> {
        Ok(self
            .get(key)?
            .and_then(Value::as_sequence)
            .map(Vec::as_slice))
    }

    pub fn set(&mut self, key: &str, value: Value) -> Result<(), ConfigError> {
        set_key(&mut self.document, key, value)
    }

    pub fn validate(&self, schema: Option<&str>) -> Result<ValidationStatus, ConfigError> {
        validate_document(&self.document, schema)
    }
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
    pub syscall_event_drops: SyscallEventDropsConfig,
    pub base_syscalls: BaseSyscallsConfig,
    #[serde(skip_serializing_if = "LoadPlugins::is_omitted")]
    pub load_plugins: LoadPlugins,
    pub plugins: Vec<PluginConfig>,
    pub plugins_hostinfo: bool,
    pub falco_libs: FalcoLibsConfig,
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
    #[serde(skip)]
    pub validation_warnings: Vec<String>,
    #[serde(skip)]
    document: Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LoadPlugins {
    #[default]
    Omitted,
    Enabled(bool),
    Names(Vec<String>),
}

impl LoadPlugins {
    pub fn is_omitted(&self) -> bool {
        matches!(self, Self::Omitted)
    }

    pub fn names(&self) -> &[String] {
        match self {
            Self::Names(names) => names,
            Self::Omitted | Self::Enabled(_) => &[],
        }
    }
}

impl<'de> Deserialize<'de> for LoadPlugins {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BooleanOrNames {
            Enabled(bool),
            Names(Vec<String>),
        }

        Ok(match BooleanOrNames::deserialize(deserializer)? {
            BooleanOrNames::Enabled(enabled) => Self::Enabled(enabled),
            BooleanOrNames::Names(names) => Self::Names(names),
        })
    }
}

impl Serialize for LoadPlugins {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Omitted => serializer.serialize_none(),
            Self::Enabled(enabled) => serializer.serialize_bool(*enabled),
            Self::Names(names) => names.serialize(serializer),
        }
    }
}

impl FalcoConfig {
    pub fn load_from_str(content: &str) -> Result<Self, ConfigError> {
        let mut value: Value = serde_yaml::from_str(content)?;
        expand_environment(&mut value);
        Self::from_value(value)
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::load_from_file_with_cli_overrides(path, &[])
    }

    pub fn load_from_file_with_cli_overrides(
        path: impl AsRef<Path>,
        overrides: &[(&str, &str)],
    ) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut root: Value = serde_yaml::from_str(&content)?;
        expand_environment(&mut root);
        for &(key, value) in overrides {
            if key == "config_files" {
                let value = parse_override_value(value);
                set_key(&mut root, key, value)?;
            }
        }
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
        for &(key, value) in overrides {
            if key != "config_files" {
                config.apply_cli_override(key, value)?;
            }
        }
        Ok(config)
    }

    pub fn apply_cli_override(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        if key.is_empty() {
            return Err(ConfigError::EmptyOverrideKey);
        }

        let loaded_files = std::mem::take(&mut self.loaded_files);
        let mut document = self.document.clone();
        let override_value = parse_override_value(value);
        set_key(&mut document, key, override_value)?;
        let mut updated = Self::from_value(document)?;
        updated.loaded_files = loaded_files;
        *self = updated;
        Ok(())
    }

    pub fn value(&self, key: &str) -> Result<Option<&Value>, ConfigError> {
        get_key(&self.document, key)
    }

    pub fn validation_status(&self) -> ValidationStatus {
        if self.validation_warnings.is_empty() {
            ValidationStatus::Ok
        } else {
            ValidationStatus::Failed(self.validation_warnings.clone())
        }
    }

    fn from_value(value: Value) -> Result<Self, ConfigError> {
        let validation_warnings = match validate_document(&value, Some(FALCO_CONFIG_SCHEMA))? {
            ValidationStatus::Failed(warnings) => warnings,
            ValidationStatus::None | ValidationStatus::Ok => Vec::new(),
        };
        let document = value.clone();
        let mut config: Self = serde_yaml::from_value(value)?;
        config.document = document;
        config.validation_warnings = validation_warnings;
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

fn validate_document(
    document: &Value,
    schema: Option<&str>,
) -> Result<ValidationStatus, ConfigError> {
    let Some(schema) = schema else {
        return Ok(ValidationStatus::None);
    };
    if schema.trim().is_empty() {
        return Ok(ValidationStatus::None);
    }

    let schema: serde_json::Value =
        serde_json::from_str(schema).map_err(|error| ConfigError::Schema(error.to_string()))?;
    let mut options = jsonschema::JSONSchema::options();
    options
        .with_draft(jsonschema::Draft::Draft6)
        .should_validate_formats(false);
    let validator = options
        .compile(&schema)
        .map_err(|error| ConfigError::Schema(error.to_string()))?;
    let instance =
        serde_json::to_value(document).map_err(|error| ConfigError::Schema(error.to_string()))?;
    let warnings = validator
        .validate(&instance)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    if warnings.is_empty() {
        Ok(ValidationStatus::Ok)
    } else {
        Ok(ValidationStatus::Failed(warnings))
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

fn parse_override_value(value: &str) -> Value {
    serde_yaml::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyPart {
    Field(String),
    Index(usize),
    Append,
}

fn parse_key(key: &str) -> Result<Vec<KeyPart>, ConfigError> {
    if key.is_empty() {
        return Err(ConfigError::EmptyOverrideKey);
    }
    let mut parts = Vec::new();
    let mut field = String::new();
    let chars: Vec<char> = key.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '\\' => {
                index += 1;
                let Some(&escaped) = chars.get(index) else {
                    return invalid_key(key, "trailing backslash");
                };
                if !matches!(escaped, '.' | '[' | ']' | '\\') {
                    return invalid_key(key, format!("unsupported escape `\\{escaped}`"));
                }
                field.push(escaped);
                index += 1;
            }
            '.' => {
                if field.is_empty() {
                    return invalid_key(key, "empty path component");
                }
                parts.push(KeyPart::Field(std::mem::take(&mut field)));
                index += 1;
            }
            '[' => {
                if !field.is_empty() {
                    parts.push(KeyPart::Field(std::mem::take(&mut field)));
                }
                let close = chars[index + 1..]
                    .iter()
                    .position(|character| *character == ']')
                    .map(|offset| index + 1 + offset)
                    .ok_or_else(|| ConfigError::InvalidKey {
                        key: key.into(),
                        reason: "unclosed bracket".into(),
                    })?;
                let contents: String = chars[index + 1..close].iter().collect();
                if contents.is_empty() {
                    parts.push(KeyPart::Append);
                } else {
                    let parsed = contents.parse().map_err(|_| ConfigError::InvalidKey {
                        key: key.into(),
                        reason: format!("invalid sequence index `{contents}`"),
                    })?;
                    parts.push(KeyPart::Index(parsed));
                }
                index = close + 1;
                if chars.get(index) == Some(&'.') {
                    index += 1;
                }
            }
            character => {
                field.push(character);
                index += 1;
            }
        }
    }
    if !field.is_empty() {
        parts.push(KeyPart::Field(field));
    }
    if parts.is_empty() {
        return invalid_key(key, "empty path");
    }
    Ok(parts)
}

fn invalid_key<T>(key: &str, reason: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::InvalidKey {
        key: key.into(),
        reason: reason.into(),
    })
}

fn get_key<'a>(document: &'a Value, key: &str) -> Result<Option<&'a Value>, ConfigError> {
    let parts = parse_key(key)?;
    let mut current = document;
    for part in parts {
        current = match part {
            KeyPart::Field(field) => {
                let Some(value) = current
                    .as_mapping()
                    .and_then(|map| map.get(Value::String(field)))
                else {
                    return Ok(None);
                };
                value
            }
            KeyPart::Index(index) => {
                let Some(value) = current.as_sequence().and_then(|items| items.get(index)) else {
                    return Ok(None);
                };
                value
            }
            KeyPart::Append => return invalid_key(key, "append operator is not readable"),
        };
    }
    Ok(Some(current))
}

fn set_key(document: &mut Value, key: &str, value: Value) -> Result<(), ConfigError> {
    let parts = parse_key(key)?;
    set_parts(document, &parts, value);
    Ok(())
}

fn set_parts(current: &mut Value, parts: &[KeyPart], value: Value) {
    let Some((part, rest)) = parts.split_first() else {
        *current = value;
        return;
    };
    match part {
        KeyPart::Field(field) => {
            if !current.is_mapping() {
                *current = Value::Mapping(Mapping::new());
            }
            let child = current
                .as_mapping_mut()
                .expect("mapping created above")
                .entry(Value::String(field.clone()))
                .or_insert(Value::Null);
            set_parts(child, rest, value);
        }
        KeyPart::Index(index) => {
            if !current.is_sequence() {
                *current = Value::Sequence(Vec::new());
            }
            let items = current.as_sequence_mut().expect("sequence created above");
            items.resize(index + 1, Value::Null);
            set_parts(&mut items[*index], rest, value);
        }
        KeyPart::Append => {
            if !current.is_sequence() {
                *current = Value::Sequence(Vec::new());
            }
            let mut child = Value::Null;
            set_parts(&mut child, rest, value);
            current
                .as_sequence_mut()
                .expect("sequence created above")
                .push(child);
        }
    }
}
