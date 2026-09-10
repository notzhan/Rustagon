use crate::utils::matches_wildcard;
use rustagon_parser::filter::{BinaryOp, Expr, Operand, Value};
use rustagon_sinsp::Evt;
use std::cmp::Ordering;
use std::path::Path;

pub(crate) fn matches(expr: &Expr, evt: &Evt) -> bool {
    match expr {
        Expr::And(left, right) => matches(left, evt) && matches(right, evt),
        Expr::Or(left, right) => matches(left, evt) || matches(right, evt),
        Expr::Not(inner) => !matches(inner, evt),
        Expr::Identifier(_) => false,
        Expr::Exists { left } => !operand_values(left, evt).is_empty(),
        Expr::Binary { left, op, value } => {
            compare(*op, &operand_values(left, evt), &value_strings(value))
        }
    }
}

fn operand_values(operand: &Operand, evt: &Evt) -> Vec<String> {
    match operand {
        Operand::Field(field) => evt.get_field_as_string(field).into_iter().collect(),
        Operand::Literal(value) => value_strings(value),
        Operand::List(values) => values
            .iter()
            .flat_map(|value| operand_values(value, evt))
            .collect(),
        Operand::Transformer { name, args } => {
            let values = args
                .iter()
                .flat_map(|arg| operand_values(arg, evt))
                .collect::<Vec<_>>();
            match name.as_str() {
                "tolower" => values
                    .into_iter()
                    .map(|value| value.to_lowercase())
                    .collect(),
                "toupper" => values
                    .into_iter()
                    .map(|value| value.to_uppercase())
                    .collect(),
                "basename" => values
                    .into_iter()
                    .map(|value| {
                        Path::new(&value)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or(&value)
                            .to_owned()
                    })
                    .collect(),
                _ => Vec::new(),
            }
        }
    }
}

fn value_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Bare(value) => vec![value.clone()],
        Value::Quoted(value) => vec![unquote(value)],
        Value::List(values) => values.iter().flat_map(value_strings).collect(),
    }
}

fn unquote(value: &str) -> String {
    let Some(quote) = value.chars().next() else {
        return String::new();
    };
    if !matches!(quote, '\'' | '"') || !value.ends_with(quote) {
        return value.to_owned();
    }
    value[quote.len_utf8()..value.len() - quote.len_utf8()]
        .replace("\\'", "'")
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

fn compare(op: BinaryOp, actual: &[String], expected: &[String]) -> bool {
    match op {
        BinaryOp::Eq | BinaryOp::In => pairs(actual, expected, |left, right| left == right),
        BinaryOp::NotEq => {
            !actual.is_empty() && !pairs(actual, expected, |left, right| left == right)
        }
        BinaryOp::Less => ordering(actual, expected, |order| order == Ordering::Less),
        BinaryOp::LessEq => ordering(actual, expected, |order| order != Ordering::Greater),
        BinaryOp::Greater => ordering(actual, expected, |order| order == Ordering::Greater),
        BinaryOp::GreaterEq => ordering(actual, expected, |order| order != Ordering::Less),
        BinaryOp::Contains => pairs(actual, expected, |left, right| left.contains(right)),
        BinaryOp::IContains => pairs(actual, expected, |left, right| {
            left.to_lowercase().contains(&right.to_lowercase())
        }),
        BinaryOp::StartsWith => pairs(actual, expected, |left, right| left.starts_with(right)),
        BinaryOp::EndsWith => pairs(actual, expected, |left, right| left.ends_with(right)),
        BinaryOp::Intersects => pairs(actual, expected, |left, right| {
            left.split_whitespace().any(|item| item == right)
        }),
        BinaryOp::Pmatch => pairs(actual, expected, |left, right| {
            left == right
                || left
                    .strip_prefix(right)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }),
        BinaryOp::Glob => pairs(actual, expected, |left, right| {
            matches_wildcard(right, left)
        }),
    }
}

fn pairs(actual: &[String], expected: &[String], predicate: impl Fn(&str, &str) -> bool) -> bool {
    actual.iter().any(|left| {
        expected
            .iter()
            .any(|right| predicate(left.as_str(), right.as_str()))
    })
}

fn ordering(actual: &[String], expected: &[String], predicate: impl Fn(Ordering) -> bool) -> bool {
    pairs(actual, expected, |left, right| {
        let order = match (left.parse::<f64>(), right.parse::<f64>()) {
            (Ok(left), Ok(right)) => left.partial_cmp(&right),
            _ => Some(left.cmp(right)),
        };
        order.is_some_and(&predicate)
    })
}
