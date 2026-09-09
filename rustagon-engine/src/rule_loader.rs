use crate::macro_resolver;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct CompiledRuleset {
    pub rules: HashMap<String, String>,
    // Retained for Task 1.2, which will add macro expansion.
    pub macros: HashMap<String, String>,
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
    #[serde(default, rename = "override")]
    override_spec: Option<OverrideSpec>,
}

#[derive(Debug, Deserialize)]
struct OverrideSpec {
    #[serde(default)]
    items: Option<String>,
    #[serde(default)]
    condition: Option<String>,
}

enum FalcoItem {
    List {
        name: String,
        items: Vec<String>,
        append: bool,
    },
    Rule {
        name: String,
        condition: String,
        append: bool,
    },
    Macro {
        name: String,
        condition: String,
        append: bool,
    },
}

impl TryFrom<YamlItem> for FalcoItem {
    type Error = String;

    fn try_from(item: YamlItem) -> Result<Self, Self::Error> {
        if let Some(name) = item.list {
            let append = match item.override_spec.and_then(|spec| spec.items) {
                Some(mode) if mode == "append" => true,
                Some(mode) if mode == "replace" => false,
                Some(mode) => return Err(format!("unsupported list override: {mode}")),
                None => false,
            };
            return Ok(Self::List {
                name,
                items: item.items,
                append,
            });
        }
        if let Some(name) = item.rule {
            let append = condition_append(item.override_spec)?;
            return Ok(Self::Rule {
                name,
                condition: item
                    .condition
                    .ok_or_else(|| "rule is missing condition".to_string())?,
                append,
            });
        }
        if let Some(name) = item.macro_name {
            let append = condition_append(item.override_spec)?;
            return Ok(Self::Macro {
                name,
                condition: item
                    .condition
                    .ok_or_else(|| "macro is missing condition".to_string())?,
                append,
            });
        }
        Err("YAML item must define list, rule, or macro".to_string())
    }
}

fn condition_append(override_spec: Option<OverrideSpec>) -> Result<bool, String> {
    match override_spec.and_then(|spec| spec.condition) {
        Some(mode) if mode == "append" => Ok(true),
        Some(mode) if mode == "replace" => Ok(false),
        Some(mode) => Err(format!("unsupported condition override: {mode}")),
        None => Ok(false),
    }
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

pub(crate) fn load_sequence(content: &str) -> Result<Option<CompiledRuleset>, String> {
    let value: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(value) => value,
        Err(error) if is_falco_sequence_yaml(content) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    };
    if !value.is_sequence() {
        return Ok(None);
    }

    let yaml_items: Vec<YamlItem> =
        serde_yaml::from_value(value).map_err(|error| error.to_string())?;
    let items = yaml_items
        .into_iter()
        .map(FalcoItem::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let mut lists: HashMap<String, Vec<String>> = HashMap::new();
    let mut rules = HashMap::new();
    let mut macros = HashMap::new();
    for item in items {
        match item {
            FalcoItem::List {
                name,
                items,
                append,
            } => {
                if append {
                    lists.entry(name).or_default().extend(items);
                } else {
                    lists.insert(name, items);
                }
            }
            FalcoItem::Rule {
                name,
                condition,
                append,
            } => {
                append_or_replace(&mut rules, name, condition, append, "rule")?;
            }
            FalcoItem::Macro {
                name,
                condition,
                append,
            } => {
                append_or_replace(&mut macros, name, condition, append, "macro")?;
            }
        }
    }

    let rules = rules
        .into_iter()
        .map(|(name, condition)| {
            let expanded = macro_resolver::resolve_macros(&condition, &macros)
                .map_err(|error| error.to_string())?;
            Ok((name, compile_condition(&expanded, &lists)))
        })
        .collect::<Result<HashMap<_, _>, String>>()?;

    Ok(Some(CompiledRuleset { rules, macros }))
}

fn append_or_replace(
    conditions: &mut HashMap<String, String>,
    name: String,
    condition: String,
    append: bool,
    kind: &str,
) -> Result<(), String> {
    if append {
        let existing = conditions
            .get_mut(&name)
            .ok_or_else(|| format!("no {kind} by the name `{name}` exists for append"))?;
        existing.push(' ');
        existing.push_str(condition.trim_start());
    } else {
        conditions.insert(name, condition);
    }
    Ok(())
}

fn compile_condition(condition: &str, lists: &HashMap<String, Vec<String>>) -> String {
    let mut expanded = condition.to_string();
    for (name, items) in lists {
        expanded = expanded.replace(&format!("({name})"), &format!("({})", items.join(", ")));
    }

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
