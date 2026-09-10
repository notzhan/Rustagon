use crate::macro_resolver;
use serde_yaml::Value;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleLoaderHooks {
    pub reader: String,
    pub collector: String,
    pub compiler: String,
}

impl RuleLoaderHooks {
    pub fn new(
        reader: impl Into<String>,
        collector: impl Into<String>,
        compiler: impl Into<String>,
    ) -> Self {
        Self {
            reader: reader.into(),
            collector: collector.into(),
            compiler: compiler.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltRule {
    pub priority: String,
    pub condition: String,
    pub output: Option<String>,
    pub source: String,
    pub tags: Vec<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AltCompileOutput {
    pub lists: HashMap<String, Vec<String>>,
    pub macros: HashMap<String, String>,
    pub rules: HashMap<String, AltRule>,
    pub defined_properties: HashSet<String>,
}

impl AltCompileOutput {
    pub fn compile(content: &str, sources: &[&str]) -> Result<Self, String> {
        let value: Value = serde_yaml::from_str(content).map_err(|error| error.to_string())?;
        let items = value
            .as_sequence()
            .ok_or_else(|| "alternate loader expects a YAML sequence".to_string())?;
        let mut output = Self::default();
        for item in items {
            let Some(mapping) = item.as_mapping() else {
                continue;
            };
            let string = |key: &str| {
                mapping
                    .get(Value::String(key.to_string()))
                    .and_then(Value::as_str)
            };
            if let Some(name) = string("test_object") {
                let _ = name;
                if let Some(property) = string("property") {
                    output.defined_properties.insert(property.to_string());
                }
            } else if let Some(name) = string("list") {
                let values = mapping
                    .get(Value::String("items".to_string()))
                    .and_then(Value::as_sequence)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                output.lists.insert(name.to_string(), values);
            } else if let Some(name) = string("macro") {
                output.macros.insert(
                    name.to_string(),
                    string("condition").unwrap_or_default().to_string(),
                );
            } else if let Some(name) = string("rule") {
                let source = string("source").unwrap_or("syscall");
                if sources.contains(&source) {
                    let tags = mapping
                        .get(Value::String("tags".to_string()))
                        .and_then(Value::as_sequence)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect();
                    output.rules.insert(
                        name.to_string(),
                        AltRule {
                            priority: string("priority").unwrap_or("DEBUG").to_string(),
                            condition: string("condition").unwrap_or_default().to_string(),
                            output: string("output").map(str::to_string),
                            source: source.to_string(),
                            tags,
                            enabled: mapping
                                .get(Value::String("enabled".to_string()))
                                .and_then(Value::as_bool)
                                .unwrap_or(true),
                        },
                    );
                }
            }
        }
        for rule in output.rules.values_mut() {
            rule.condition = macro_resolver::resolve_macros(&rule.condition, &output.macros)
                .map_err(|error| error.to_string())?;
        }
        Ok(output)
    }

    pub fn rules_at_or_above_priority(&self, minimum: &str) -> Vec<&str> {
        let minimum = priority_rank(minimum);
        let mut names = self
            .rules
            .iter()
            .filter(|(_, rule)| priority_rank(&rule.priority) <= minimum)
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }
}

fn priority_rank(priority: &str) -> usize {
    match priority.to_ascii_uppercase().as_str() {
        "EMERGENCY" => 0,
        "ALERT" => 1,
        "CRITICAL" => 2,
        "ERROR" => 3,
        "WARNING" => 4,
        "NOTICE" => 5,
        "INFORMATIONAL" | "INFO" => 6,
        "DEBUG" => 7,
        _ => usize::MAX,
    }
}
