use crate::macro_resolver;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct CompiledRuleset {
    pub rules: HashMap<String, String>,
    pub macros: HashMap<String, String>,
    pub rule_details: HashMap<String, RuleDetails>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleDetails {
    pub description: Option<String>,
    pub condition: String,
    pub output: Option<String>,
    pub priority: Option<String>,
    pub enabled: bool,
    exceptions: Vec<ExceptionSpec>,
}

#[derive(Debug, Deserialize)]
struct YamlItem {
    #[serde(default)]
    list: Option<String>,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default, rename = "macro")]
    macro_name: Option<String>,
    #[serde(default)]
    items: Vec<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    exceptions: Option<Vec<ExceptionSpec>>,
    #[serde(default)]
    required_engine_version: Option<serde_yaml::Value>,
    #[serde(default)]
    append: bool,
    #[serde(default, rename = "override")]
    override_spec: Option<OverrideSpec>,
}

#[derive(Debug, Deserialize, Default)]
struct OverrideSpec {
    #[serde(default)]
    items: Option<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    exceptions: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct ExceptionSpec {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    fields: Option<serde_yaml::Value>,
    #[serde(default)]
    comps: Option<serde_yaml::Value>,
    #[serde(default)]
    values: Option<Vec<serde_yaml::Value>>,
}

const ENGINE_VERSION: (u64, u64, u64) = (0, 65, 0);
const WARNING_APPEND: &str = "'append' key is deprecated. Add an 'append' entry (e.g. 'condition: append') under 'override' instead.";
const WARNING_ENABLED: &str = "The standalone 'enabled' key usage is deprecated. The correct approach requires also a 'replace' entry under the 'override' key (i.e. 'enabled: replace').";
const ERROR_OVERRIDE_APPEND: &str = "Keys 'override' and 'append: true' cannot be used together. Add an 'append' entry (e.g. 'condition: append') under 'override' instead.";
const ERROR_NO_PREVIOUS_MACRO: &str =
    "Macro uses 'append' or 'override.condition: append' but no macro by that name already exists";

pub(crate) struct SequenceLoad {
    pub ruleset: CompiledRuleset,
    pub warnings: Vec<String>,
    pub schema_valid: bool,
}

pub(crate) struct SequenceError {
    pub message: String,
    pub warnings: Vec<String>,
    pub schema_valid: bool,
}

fn is_falco_sequence_yaml(content: &str) -> bool {
    let trimmed = content.trim_start();
    if trimmed.starts_with("---") {
        return false;
    }
    trimmed.starts_with("- ")
        || trimmed.starts_with("-\n")
        || trimmed.starts_with("-\r\n")
        || trimmed.starts_with("-\t")
}

pub(crate) fn load_sequence(content: &str) -> Result<Option<SequenceLoad>, SequenceError> {
    let value: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(value) => value,
        Err(error) if is_falco_sequence_yaml(content) => {
            return Err(SequenceError {
                message: error.to_string(),
                warnings: vec![],
                schema_valid: false,
            })
        }
        Err(_) => return Ok(None),
    };
    if !value.is_sequence() {
        return Ok(None);
    }
    let schema_valid = sequence_schema_valid(&value);

    let yaml_items: Vec<YamlItem> =
        serde_yaml::from_value(value).map_err(|error| SequenceError {
            message: error.to_string(),
            warnings: vec![],
            schema_valid: false,
        })?;

    let mut lists: HashMap<String, Vec<String>> = HashMap::new();
    let mut rule_details: HashMap<String, RuleDetails> = HashMap::new();
    let mut macros = HashMap::new();
    let mut warnings = Vec::new();
    for item in yaml_items {
        if item.append {
            warnings.push(WARNING_APPEND.to_string());
        }
        let result = if item.required_engine_version.is_some() {
            validate_engine_version(
                item.required_engine_version
                    .as_ref()
                    .expect("checked above"),
            )
        } else if item.list.is_some() {
            apply_list(item, &mut lists, &mut warnings)
        } else if item.rule.is_some() {
            apply_rule(item, &mut rule_details, &mut warnings)
        } else if item.macro_name.is_some() {
            apply_macro(item, &mut macros, &mut warnings)
        } else {
            Err("YAML item must define list, rule, or macro".to_string())
        };
        if let Err(message) = result {
            return Err(SequenceError {
                message,
                warnings,
                schema_valid: true,
            });
        }
    }

    for name in lists.keys() {
        let reference = format!("({name})");
        if !rule_details
            .values()
            .any(|rule| rule.condition.contains(&reference))
            && !macros
                .values()
                .any(|condition| condition.contains(&reference))
        {
            warnings.push(format!(
                "A list is defined in the rules content but is not used by any other list, macro, or rule (list `{name}`)"
            ));
        }
    }

    let rules =
        rule_details
            .iter()
            .filter(|(_, details)| details.enabled)
            .map(|(name, details)| {
                let expanded = macro_resolver::resolve_macros(&details.condition, &macros)
                    .map_err(|error| SequenceError {
                        message: error.to_string(),
                        warnings: warnings.clone(),
                        schema_valid: true,
                    })?;
                Ok((
                    name.clone(),
                    compile_condition_with_exceptions(&expanded, &lists, &details.exceptions),
                ))
            })
            .collect::<Result<HashMap<_, _>, SequenceError>>()?;

    Ok(Some(SequenceLoad {
        ruleset: CompiledRuleset {
            rules,
            macros,
            rule_details,
        },
        warnings,
        schema_valid,
    }))
}

fn apply_list(
    item: YamlItem,
    lists: &mut HashMap<String, Vec<String>>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let name = item.list.expect("checked by caller");
    if !is_valid_list_name(&name) {
        warnings.push(
            "List has an invalid name. List names should match a regular expression".to_string(),
        );
    }
    let mode = item.override_spec.and_then(|spec| spec.items);
    let append = item.append || mode.as_deref() == Some("append");
    if append {
        let existing = lists.get_mut(&name).ok_or_else(|| {
            format!(
                "List uses 'append' or 'override.items: append' but no list by that name already exists (list `{name}`)"
            )
        })?;
        existing.extend(item.items);
    } else if matches!(mode.as_deref(), Some("replace") | None) {
        lists.insert(name, item.items);
    } else {
        return Err(format!("unsupported list override: {}", mode.unwrap()));
    }
    Ok(())
}

fn apply_macro(
    item: YamlItem,
    macros: &mut HashMap<String, String>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let name = item.macro_name.expect("checked by caller");
    if !is_valid_macro_name(&name) {
        warnings.push(
            "Macro has an invalid name. Macro names should match a regular expression".to_string(),
        );
    }
    let condition = item
        .condition
        .ok_or_else(|| "macro is missing condition".to_string())?;
    let mode = item.override_spec.and_then(|spec| spec.condition);
    let append = item.append || mode.as_deref() == Some("append");
    if append {
        let existing = macros
            .get_mut(&name)
            .ok_or_else(|| format!("{ERROR_NO_PREVIOUS_MACRO} (macro `{name}`)"))?;
        existing.push(' ');
        existing.push_str(condition.trim_start());
    } else if matches!(mode.as_deref(), Some("replace") | None) {
        macros.insert(name, condition);
    } else {
        return Err(format!("unsupported condition override: {}", mode.unwrap()));
    }
    Ok(())
}

fn apply_rule(
    item: YamlItem,
    rules: &mut HashMap<String, RuleDetails>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let name = item.rule.clone().expect("checked by caller");
    let overrides = item.override_spec.as_ref();
    if overrides.is_none()
        && item.condition.is_none()
        && item.output.is_none()
        && item.desc.is_none()
        && item.priority.is_none()
        && item.enabled.is_some()
    {
        let previous = rules
            .get_mut(&name)
            .ok_or_else(|| format!("No rule by that name exists (rule `{name}`)"))?;
        previous.enabled = item.enabled.expect("checked above");
        warnings.push(WARNING_ENABLED.to_string());
        return Ok(());
    }
    if item.append && overrides.is_some() {
        return Err(ERROR_OVERRIDE_APPEND.to_string());
    }
    if item.append && item.condition.is_none() && item.exceptions.is_none() {
        return Err("Appended rule must have exceptions or condition property".to_string());
    }
    if let Some(overrides) = overrides {
        for (key, present, mode) in [
            ("desc", item.desc.is_some(), overrides.desc.as_deref()),
            (
                "condition",
                item.condition.is_some(),
                overrides.condition.as_deref(),
            ),
            ("output", item.output.is_some(), overrides.output.as_deref()),
            (
                "priority",
                item.priority.is_some(),
                overrides.priority.as_deref(),
            ),
            (
                "enabled",
                item.enabled.is_some(),
                overrides.enabled.as_deref(),
            ),
            (
                "exceptions",
                item.exceptions.is_some(),
                overrides.exceptions.as_deref(),
            ),
        ] {
            if present && mode.is_none() {
                return Err(format!("Unexpected key '{key}'"));
            }
            if !present && mode.is_some() {
                return Err(if key == "condition" && mode == Some("append") {
                    "An append override for 'condition' was specified but 'condition' is not defined"
                        .to_string()
                } else {
                    format!("'{key}' was specified but '{key}' is not defined")
                });
            }
        }
    }
    let exception_mode = overrides.and_then(|spec| spec.exceptions.as_deref());
    if let Some(mode) = exception_mode {
        validate_mode("exceptions", mode)?;
    }
    validate_exceptions(
        item.exceptions.as_deref(),
        exception_mode == Some("append") || item.append,
        warnings,
    )?;
    if let Some(mode) = overrides.and_then(|spec| spec.priority.as_deref()) {
        if mode == "append" {
            return Err(
                "Key 'priority' cannot be appended to, use 'replace' instead (priority: append)"
                    .to_string(),
            );
        }
        validate_mode("priority", mode)?;
    }

    if item.append || overrides.is_some() {
        let previous = rules.get_mut(&name).ok_or_else(|| {
            if item.append || overrides.is_some_and(OverrideSpec::has_append) {
                format!(
                    "Rule uses 'append' or 'override.<key>: append' but no rule by that name already exists (rule `{name}`)"
                )
            } else {
                format!(
                    "An 'override.<key>: replace' to a rule was requested but no rule by that name already exists (rule `{name}`)"
                )
            }
        })?;
        if item.append {
            if let Some(condition) = item.condition.as_deref() {
                append_text(&mut previous.condition, condition);
            }
            if let Some(exceptions) = item.exceptions {
                previous.exceptions.extend(exceptions);
            }
            return Ok(());
        }
        apply_string_override(
            &mut previous.condition,
            item.condition.as_deref(),
            overrides.and_then(|spec| spec.condition.as_deref()),
            "condition",
        )?;
        apply_optional_override(
            &mut previous.description,
            item.desc.as_deref(),
            overrides.and_then(|spec| spec.desc.as_deref()),
            "desc",
        )?;
        apply_optional_override(
            &mut previous.output,
            item.output.as_deref(),
            overrides.and_then(|spec| spec.output.as_deref()),
            "output",
        )?;
        let priority = item.priority.as_deref().map(normalize_priority);
        apply_optional_override(
            &mut previous.priority,
            priority.as_deref(),
            overrides.and_then(|spec| spec.priority.as_deref()),
            "priority",
        )?;
        apply_bool_override(
            &mut previous.enabled,
            item.enabled,
            overrides.and_then(|spec| spec.enabled.as_deref()),
            "enabled",
        )?;
        if let Some(mode) = exception_mode {
            let exceptions = item.exceptions.unwrap_or_default();
            if mode == "append" {
                previous.exceptions.extend(exceptions);
            } else {
                previous.exceptions = exceptions;
            }
        }
    } else {
        let condition = item
            .condition
            .ok_or_else(|| "rule is missing condition".to_string())?;
        rules.insert(
            name,
            RuleDetails {
                description: item.desc,
                condition,
                output: item.output,
                priority: item.priority.map(|value| normalize_priority(&value)),
                enabled: item.enabled.unwrap_or(true),
                exceptions: item.exceptions.unwrap_or_default(),
            },
        );
    }
    Ok(())
}

fn validate_mode(key: &str, mode: &str) -> Result<(), String> {
    if matches!(mode, "append" | "replace") {
        Ok(())
    } else {
        Err(format!("unsupported {key} override: {mode}"))
    }
}

fn apply_string_override(
    target: &mut String,
    value: Option<&str>,
    mode: Option<&str>,
    key: &str,
) -> Result<(), String> {
    let Some(mode) = mode else { return Ok(()) };
    validate_mode(key, mode)?;
    let value = value.ok_or_else(|| format!("override for '{key}' requires a value"))?;
    if mode == "append" {
        append_text(target, value);
    } else {
        *target = value.to_string();
    }
    Ok(())
}

fn apply_optional_override(
    target: &mut Option<String>,
    value: Option<&str>,
    mode: Option<&str>,
    key: &str,
) -> Result<(), String> {
    let Some(mode) = mode else { return Ok(()) };
    validate_mode(key, mode)?;
    let value = value.ok_or_else(|| format!("override for '{key}' requires a value"))?;
    if mode == "append" {
        if key == "priority" {
            return Err("Key 'priority' cannot be appended to, use 'replace' instead".to_string());
        }
        match target {
            Some(target) => append_text(target, value),
            None => *target = Some(value.to_string()),
        }
    } else {
        *target = Some(value.to_string());
    }
    Ok(())
}

fn apply_bool_override(
    target: &mut bool,
    value: Option<bool>,
    mode: Option<&str>,
    key: &str,
) -> Result<(), String> {
    let Some(mode) = mode else { return Ok(()) };
    validate_mode(key, mode)?;
    if mode == "append" {
        return Err(format!(
            "Key '{key}' cannot be appended to, use 'replace' instead"
        ));
    }
    *target = value.expect("override value validated by caller");
    Ok(())
}

fn append_text(target: &mut String, value: &str) {
    target.push(' ');
    target.push_str(value.trim_start());
}

fn normalize_priority(priority: &str) -> String {
    let mut chars = priority.to_ascii_lowercase().chars().collect::<Vec<_>>();
    if let Some(first) = chars.first_mut() {
        first.make_ascii_uppercase();
    }
    chars.into_iter().collect()
}

impl OverrideSpec {
    fn has_append(&self) -> bool {
        [
            self.items.as_deref(),
            self.condition.as_deref(),
            self.desc.as_deref(),
            self.output.as_deref(),
            self.priority.as_deref(),
            self.enabled.as_deref(),
            self.exceptions.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|mode| mode == "append")
    }
}

fn validate_exceptions(
    exceptions: Option<&[ExceptionSpec]>,
    append: bool,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let Some(exceptions) = exceptions else {
        return Ok(());
    };
    if !append
        && exceptions
            .iter()
            .any(|exception| exception.fields.is_none())
    {
        return Err("Item has no mapping for key 'fields'".to_string());
    }
    if append
        && exceptions
            .iter()
            .any(|exception| exception.values.is_none())
    {
        warnings.push("Overriding/appending exception with no values".to_string());
    }
    for (index, exception) in exceptions.iter().enumerate() {
        if exception.name.is_some()
            && exceptions[..index]
                .iter()
                .any(|previous| previous.name == exception.name)
        {
            warnings.push(format!(
                "Multiple definitions of exception '{}'",
                exception.name.as_deref().expect("checked above")
            ));
        }
        if let Some(values) = exception.values.as_deref() {
            for value in values
                .iter()
                .filter_map(serde_yaml::Value::as_sequence)
                .flatten()
                .filter_map(serde_yaml::Value::as_str)
            {
                let trimmed = value.trim_end();
                if looks_like_field_name(trimmed) {
                    warnings.push(format!(
                        "'{value}' may be a valid field misused as a const string value"
                    ));
                } else if looks_like_malformed_transformer(value) {
                    warnings.push(format!(
                        "'{value}' may be a valid field transformer misused as a const string value"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn looks_like_field_name(value: &str) -> bool {
    let mut parts = value.split('.');
    parts.clone().count() >= 2
        && parts.all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        })
}

fn looks_like_malformed_transformer(value: &str) -> bool {
    let Some((name, argument)) = value.split_once('(') else {
        return false;
    };
    !name.is_empty()
        && name.chars().all(|ch| ch.is_ascii_alphabetic())
        && argument.starts_with(char::is_whitespace)
        && argument.ends_with(')')
}

fn sequence_schema_valid(value: &serde_yaml::Value) -> bool {
    const ITEM_KEYS: &[&str] = &[
        "list",
        "rule",
        "macro",
        "items",
        "condition",
        "desc",
        "output",
        "priority",
        "append",
        "override",
        "enabled",
        "exceptions",
        "required_engine_version",
        "warn_evttypes",
        "source",
        "skip-if-unknown-filter",
        "capture",
        "capture_duration",
        "tags",
    ];
    const OVERRIDE_KEYS: &[&str] = &[
        "items",
        "condition",
        "desc",
        "output",
        "priority",
        "enabled",
        "exceptions",
        "warn_evttypes",
        "capture",
        "capture_duration",
        "tags",
    ];

    value.as_sequence().is_some_and(|items| {
        items.iter().all(|item| {
            let Some(mapping) = item.as_mapping() else {
                return false;
            };
            mapping.iter().all(|(key, nested)| {
                let Some(key) = key.as_str() else {
                    return false;
                };
                if !ITEM_KEYS.contains(&key) {
                    return false;
                }
                if key == "exceptions" {
                    const EXCEPTION_KEYS: &[&str] = &["name", "fields", "comps", "values"];
                    return nested.as_sequence().is_some_and(|exceptions| {
                        exceptions.iter().all(|exception| {
                            exception.as_mapping().is_some_and(|mapping| {
                                mapping.keys().all(|key| {
                                    key.as_str()
                                        .is_some_and(|key| EXCEPTION_KEYS.contains(&key))
                                })
                            })
                        })
                    });
                }
                if key != "override" {
                    return true;
                }
                nested.as_mapping().is_some_and(|overrides| {
                    overrides.keys().all(|override_key| {
                        override_key
                            .as_str()
                            .is_some_and(|key| OVERRIDE_KEYS.contains(&key))
                    })
                })
            })
        })
    })
}

fn compile_condition(condition: &str, lists: &HashMap<String, Vec<String>>) -> String {
    let mut expanded = condition.to_string();
    for (name, items) in lists {
        let items = items
            .iter()
            .map(|item| quote_condition_item(item))
            .collect::<Vec<_>>()
            .join(", ");
        expanded = expanded.replace(&format!("({name})"), &format!("({items})"));
    }

    let expanded = expanded.replace(',', ", ");
    let mut normalized = String::with_capacity(expanded.len() + 4);
    let chars: Vec<char> = expanded.chars().collect();
    for (index, ch) in chars.iter().copied().enumerate() {
        if ch == '='
            && chars.get(index.wrapping_sub(1)) != Some(&'=')
            && chars.get(index + 1) != Some(&'=')
            && !matches!(
                chars.get(index.wrapping_sub(1)),
                Some('<' | '>' | '!' | '~')
            )
            && chars.get(index + 1) != Some(&'~')
        {
            if !normalized.ends_with(' ') {
                normalized.push(' ');
            }
            normalized.push('=');
            normalized.push(' ');
        } else {
            normalized.push(ch);
        }
    }
    let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("({normalized})")
}

fn quote_condition_item(item: &str) -> String {
    if item.chars().any(char::is_whitespace)
        && !matches!(item.as_bytes().first(), Some(b'"' | b'\''))
    {
        format!("\"{item}\"")
    } else {
        item.to_string()
    }
}

fn validate_engine_version(value: &serde_yaml::Value) -> Result<(), String> {
    let display = value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|version| version.to_string()))
        .unwrap_or_else(|| format!("{value:?}"));
    let parsed = if let Some(minor) = value.as_u64() {
        Some((0, minor, 0))
    } else {
        parse_semver(&display)
    };
    let Some(version) = parsed else {
        return Err(format!(
            "Unable to parse engine version '{display}' as a semver string. Expected \"x.y.z\" semver format."
        ));
    };
    if version > ENGINE_VERSION {
        return Err(format!(
            "Rules require engine version {}, but engine version is 0.65.0",
            display
        ));
    }
    Ok(())
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let parsed = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(parsed)
}

fn is_valid_macro_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|ch| ch.is_ascii_alphabetic())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_valid_list_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|ch| ch.is_whitespace() || "()\"'=,".contains(ch))
}

fn compile_condition_with_exceptions(
    condition: &str,
    lists: &HashMap<String, Vec<String>>,
    exceptions: &[ExceptionSpec],
) -> String {
    let mut compiled = compile_condition(condition, lists);
    for exception in exceptions {
        let Some(fields) = exception
            .fields
            .as_ref()
            .and_then(serde_yaml::Value::as_sequence)
        else {
            continue;
        };
        let Some(comps) = exception
            .comps
            .as_ref()
            .and_then(serde_yaml::Value::as_sequence)
        else {
            continue;
        };
        let Some(values) = exception.values.as_deref() else {
            continue;
        };
        for row in values {
            let Some(row) = row.as_sequence() else {
                continue;
            };
            let clauses = fields
                .iter()
                .zip(comps)
                .zip(row)
                .filter_map(|((field, comp), value)| {
                    let field = field.as_str()?;
                    let comp = comp.as_str()?;
                    let value = value.as_str()?;
                    let value = quote_condition_item(value);
                    Some(format!(
                        "{} {comp} {value}",
                        normalize_exception_field(field)
                    ))
                })
                .collect::<Vec<_>>();
            if !clauses.is_empty() {
                let inner = compiled
                    .strip_prefix('(')
                    .and_then(|value| value.strip_suffix(')'))
                    .unwrap_or(&compiled);
                let base = if inner.contains(" or ") {
                    format!("({inner})")
                } else {
                    inner.to_string()
                };
                compiled = format!("({base} and not {})", clauses.join(" and "));
            }
        }
    }
    compiled
}

fn normalize_exception_field(field: &str) -> String {
    field
        .split_once('(')
        .map(|(transformer, argument)| format!("{transformer}({}", argument.trim_start()))
        .unwrap_or_else(|| field.to_string())
}
