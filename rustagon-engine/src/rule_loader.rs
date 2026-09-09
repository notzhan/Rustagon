use serde::Deserialize;
use std::collections::HashMap;

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
    items: String,
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
    },
    Macro,
}

impl TryFrom<YamlItem> for FalcoItem {
    type Error = String;

    fn try_from(item: YamlItem) -> Result<Self, Self::Error> {
        if let Some(name) = item.list {
            let append = match item.override_spec {
                Some(spec) if spec.items == "append" => true,
                Some(spec) if spec.items == "replace" => false,
                Some(spec) => return Err(format!("unsupported list override: {}", spec.items)),
                None => false,
            };
            return Ok(Self::List {
                name,
                items: item.items,
                append,
            });
        }
        if let Some(name) = item.rule {
            return Ok(Self::Rule {
                name,
                condition: item
                    .condition
                    .ok_or_else(|| "rule is missing condition".to_string())?,
            });
        }
        if item.macro_name.is_some() {
            return Ok(Self::Macro);
        }
        Err("YAML item must define list, rule, or macro".to_string())
    }
}

pub(crate) fn load_sequence(content: &str) -> Result<Option<HashMap<String, String>>, String> {
    let value: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(value) => value,
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
    let mut rules = Vec::new();
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
            FalcoItem::Rule { name, condition } => rules.push((name, condition)),
            FalcoItem::Macro => {}
        }
    }

    Ok(Some(
        rules
            .into_iter()
            .map(|(name, condition)| (name, compile_condition(&condition, &lists)))
            .collect(),
    ))
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
