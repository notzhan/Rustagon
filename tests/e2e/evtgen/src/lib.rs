use anyhow::{bail, Context, Result};
use rustagon_engine::FalcoEngine;
use rustagon_scap::{RawEvent, RawEventKind};
use rustagon_sinsp::Inspector;
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
pub struct Suite {
    pub tests: Vec<TestSpec>,
}

#[derive(Debug, Deserialize)]
pub struct TestSpec {
    pub name: String,
    pub rule: String,
    pub runner: String,
    #[serde(default)]
    pub context: Value,
    #[serde(rename = "expectedOutcome")]
    pub expected_outcome: ExpectedOutcome,
    #[serde(default)]
    pub cases: Vec<CaseSpec>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExpectedOutcome {
    pub source: String,
    pub priority: String,
    #[serde(default, rename = "outputFields")]
    pub output_fields: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct CaseSpec {
    pub strategy: Strategy,
    pub values: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strategy {
    Matrix,
    Vector,
}

#[derive(Debug)]
pub struct ExpandedCase {
    pub test_name: String,
    pub rule: String,
    pub runner: String,
    pub context: Value,
    pub expected_outcome: ExpectedOutcome,
    pub item: BTreeMap<String, Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OfflineAlert {
    pub rule: String,
    pub priority: String,
    pub source: String,
    pub output_fields: BTreeMap<String, String>,
}

pub fn parse_suite(input: &str) -> Result<Suite> {
    let normalized = quote_bare_templates(input);
    serde_yaml::from_str(&normalized).context("parse evtgen suite YAML")
}

pub fn expand_suite(suite: &Suite) -> Result<Vec<ExpandedCase>> {
    let mut expanded = Vec::new();
    for test in &suite.tests {
        if test.cases.is_empty() {
            expanded.push(resolve_case(test, BTreeMap::new())?);
            continue;
        }
        for case in &test.cases {
            let items = match case.strategy {
                Strategy::Vector => vec![case.values.clone()],
                Strategy::Matrix => expand_matrix(&case.values)?,
            };
            for item in items {
                expanded.push(resolve_case(test, item)?);
            }
        }
    }
    Ok(expanded)
}

pub fn run_shell_untrusted_offline(case: &ExpandedCase, rules: &str) -> Result<OfflineAlert> {
    if case.runner != "HostRunner" {
        bail!(
            "offline runner only supports HostRunner, got {:?}",
            case.runner
        );
    }
    if case.rule != "Run shell untrusted" {
        bail!("unsupported offline rule {:?}", case.rule);
    }

    let processes = case
        .context
        .get("processes")
        .and_then(Value::as_sequence)
        .context("HostRunner context must contain processes")?;
    let mut inspector = Inspector::default();
    let mut event = None;
    for (index, process) in processes.iter().enumerate() {
        let name = process
            .get("name")
            .and_then(Value::as_str)
            .context("process name must be a string")?;
        let args = process
            .get("args")
            .and_then(Value::as_str)
            .map(|args| vec![args.to_string()])
            .unwrap_or_default();
        let pid = 10_000 + index as i64;
        event = Some(inspector.inject(RawEvent {
            timestamp: index as u64 + 1,
            tid: pid,
            type_id: 0,
            payload: Vec::new(),
            kind: RawEventKind::Exec {
                pid,
                ppid: if index == 0 { 1 } else { pid - 1 },
                comm: name.into(),
                exe: name.into(),
                exepath: format!("/usr/bin/{name}"),
                args,
            },
        }));
    }
    let event = event.context("HostRunner process chain must not be empty")?;

    let mut engine = FalcoEngine::new();
    let loaded = engine.load_rules(rules, "run_shell_untrusted_rules.yaml");
    if !loaded.ok {
        bail!("load Run shell untrusted excerpt: {:?}", loaded.errors);
    }
    let details = engine
        .rule_details(&case.rule)
        .context("loaded rule details not found")?;
    let priority = details
        .priority
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if priority != case.expected_outcome.priority.to_ascii_lowercase() {
        bail!(
            "priority mismatch: expected {}, got {priority}",
            case.expected_outcome.priority
        );
    }
    if details.source() != case.expected_outcome.source {
        bail!(
            "source mismatch: expected {}, got {}",
            case.expected_outcome.source,
            details.source()
        );
    }

    let alert = engine
        .process_event(&event, 0)
        .context("synthetic process chain did not trigger the expected rule")?;
    if alert.rule != case.rule {
        bail!(
            "rule mismatch: expected {:?}, got {:?}",
            case.rule,
            alert.rule
        );
    }

    let mut output_fields = BTreeMap::new();
    for (field, expected) in &case.expected_outcome.output_fields {
        let expected = value_as_text(expected)?;
        let actual = event
            .get_field_as_string(field)
            .with_context(|| format!("event did not expose expected output field {field:?}"))?;
        if actual != expected {
            bail!("field {field:?} mismatch: expected {expected:?}, got {actual:?}");
        }
        output_fields.insert(field.clone(), actual);
    }

    Ok(OfflineAlert {
        rule: alert.rule,
        priority,
        source: details.source().into(),
        output_fields,
    })
}

fn expand_matrix(values: &BTreeMap<String, Value>) -> Result<Vec<BTreeMap<String, Value>>> {
    let mut rows = vec![BTreeMap::new()];
    for (key, choices) in values {
        let Value::Sequence(choices) = choices else {
            bail!("matrix value {key:?} must be a sequence");
        };
        let mut next = Vec::with_capacity(rows.len() * choices.len());
        for row in &rows {
            for choice in choices {
                let mut row = row.clone();
                row.insert(key.clone(), choice.clone());
                next.push(row);
            }
        }
        rows = next;
    }
    Ok(rows)
}

fn resolve_case(test: &TestSpec, item: BTreeMap<String, Value>) -> Result<ExpandedCase> {
    let context = resolve_value(&test.context, &item)?;
    let output_fields = test
        .expected_outcome
        .output_fields
        .iter()
        .map(|(name, value)| Ok((name.clone(), resolve_value(value, &item)?)))
        .collect::<Result<_>>()?;
    Ok(ExpandedCase {
        test_name: test.name.clone(),
        rule: test.rule.clone(),
        runner: test.runner.clone(),
        context,
        expected_outcome: ExpectedOutcome {
            source: test.expected_outcome.source.clone(),
            priority: test.expected_outcome.priority.clone(),
            output_fields,
        },
        item,
    })
}

fn resolve_value(value: &Value, item: &BTreeMap<String, Value>) -> Result<Value> {
    match value {
        Value::String(text) => resolve_string(text, item),
        Value::Sequence(values) => values
            .iter()
            .map(|value| resolve_value(value, item))
            .collect::<Result<Vec<_>>>()
            .map(Value::Sequence),
        Value::Mapping(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), resolve_value(value, item)?)))
            .collect::<Result<Mapping>>()
            .map(Value::Mapping),
        other => Ok(other.clone()),
    }
}

fn resolve_string(text: &str, item: &BTreeMap<String, Value>) -> Result<Value> {
    if let Some(key) = exact_template_key(text) {
        return item
            .get(key)
            .cloned()
            .with_context(|| format!("template refers to missing item {key:?}"));
    }

    let mut resolved = text.to_string();
    while let Some(start) = resolved.find("%{") {
        let rest = &resolved[start + 2..];
        let Some(end) = rest.find('}') else {
            bail!("unterminated template in {text:?}");
        };
        let expression = rest[..end].trim();
        let Some(key) = expression.strip_prefix("item.").map(str::trim) else {
            bail!("unsupported template expression {expression:?}");
        };
        let replacement = item
            .get(key)
            .with_context(|| format!("template refers to missing item {key:?}"))
            .and_then(value_as_text)?;
        resolved.replace_range(start..start + 2 + end + 1, &replacement);
    }
    Ok(Value::String(resolved))
}

fn exact_template_key(text: &str) -> Option<&str> {
    let inner = text.strip_prefix("%{")?.strip_suffix('}')?.trim();
    inner.strip_prefix("item.").map(str::trim)
}

fn value_as_text(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => Ok(value.clone()),
        _ => bail!("non-scalar value cannot be embedded in a string template"),
    }
}

fn quote_bare_templates(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            let Some((prefix, value)) = line.split_once(':') else {
                return line.to_string();
            };
            let value = value.trim();
            if value.starts_with("%{") && value.ends_with('}') {
                format!("{prefix}: \"{value}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{expand_suite, parse_suite};
    use serde_yaml::Value;

    const SUITE: &str = r#"
tests:
  - name: matrix
    rule: Example
    runner: HostRunner
    context:
      process:
        name: "%{ item.name }"
        container: "%{ item.container }"
    expectedOutcome:
      source: syscall
      priority: notice
      outputFields:
        proc.name: "prefix-%{ item.name }"
    cases:
      - strategy: matrix
        values:
          name: [bash, sh]
          container: [null, {}]
  - name: vector
    rule: Example
    runner: HostRunner
    context:
      path: "%{ item.path }"
    expectedOutcome:
      source: syscall
      priority: warning
      outputFields:
        fd.name: "%{ item.path }"
    cases:
      - strategy: vector
        values:
          path: /etc/shadow
      - strategy: vector
        values:
          path: /etc/sudoers
"#;

    #[test]
    fn matrix_expands_cartesian_product_and_preserves_typed_exact_templates() {
        let suite = parse_suite(SUITE).expect("parse suite");
        let expanded = expand_suite(&suite).expect("expand suite");
        let matrix = expanded
            .iter()
            .filter(|case| case.test_name == "matrix")
            .collect::<Vec<_>>();

        assert_eq!(matrix.len(), 4);
        assert_eq!(
            matrix[0].context["process"]["name"],
            Value::String("bash".into())
        );
        assert_eq!(matrix[0].context["process"]["container"], Value::Null);
        assert_eq!(
            matrix[2].context["process"]["container"],
            Value::Mapping(Default::default())
        );
        assert_eq!(
            matrix[0].expected_outcome.output_fields["proc.name"],
            Value::String("prefix-bash".into())
        );
    }

    #[test]
    fn vector_cases_expand_one_values_mapping_each() {
        let suite = parse_suite(SUITE).expect("parse suite");
        let expanded = expand_suite(&suite).expect("expand suite");
        let paths = expanded
            .iter()
            .filter(|case| case.test_name == "vector")
            .map(|case| case.context["path"].as_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(paths, ["/etc/shadow", "/etc/sudoers"]);
    }
}
