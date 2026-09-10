use std::collections::HashSet;

use rustagon_parser::filter::{BinaryOp, Expr, Operand, Value};

pub const TOO_MANY_EVENT_TYPES: &str =
    "Rule matches too many evt.type values. This has a significant performance penalty.";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FilterWarning {
    UnsafeNaCheck,
    DeprecatedField(String),
}

pub fn resolve_filter_warnings(filter: &Expr) -> Vec<FilterWarning> {
    let mut warnings = Vec::new();
    visit_warnings(filter, &mut warnings);
    warnings
}

fn visit_warnings(filter: &Expr, warnings: &mut Vec<FilterWarning>) {
    match filter {
        Expr::And(left, right) | Expr::Or(left, right) => {
            visit_warnings(left, warnings);
            visit_warnings(right, warnings);
        }
        Expr::Not(inner) => visit_warnings(inner, warnings),
        Expr::Identifier(_) => {}
        Expr::Exists { left } => collect_deprecated(left, warnings),
        Expr::Binary { left, op, value } => {
            collect_deprecated(left, warnings);
            if operand_has_unsafe_field(left)
                && matches!(
                    op,
                    BinaryOp::Eq
                        | BinaryOp::NotEq
                        | BinaryOp::In
                        | BinaryOp::Intersects
                        | BinaryOp::Pmatch
                )
                && value_contains_na(value)
            {
                push_unique(warnings, FilterWarning::UnsafeNaCheck);
            }
        }
    }
}

fn collect_deprecated(operand: &Operand, warnings: &mut Vec<FilterWarning>) {
    match operand {
        Operand::Field(field) => {
            if field == "evt.dir" {
                push_unique(warnings, FilterWarning::DeprecatedField(field.clone()));
            }
        }
        Operand::Transformer { args, .. } | Operand::List(args) => {
            for arg in args {
                collect_deprecated(arg, warnings);
            }
        }
        Operand::Literal(_) => {}
    }
}

fn operand_has_unsafe_field(operand: &Operand) -> bool {
    match operand {
        Operand::Field(field) => field.starts_with("ka.") || field.starts_with("jevt."),
        Operand::Transformer { args, .. } | Operand::List(args) => {
            args.iter().any(operand_has_unsafe_field)
        }
        Operand::Literal(_) => false,
    }
}

fn value_contains_na(value: &Value) -> bool {
    match value {
        Value::Bare(value) | Value::Quoted(value) => value.trim_matches(['\'', '"']) == "<NA>",
        Value::List(values) => values.iter().any(value_contains_na),
    }
}

fn push_unique(warnings: &mut Vec<FilterWarning>, warning: FilterWarning) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EventTypeSet {
    All,
    Some(HashSet<String>),
    Empty,
}

/// Conservative symbolic event-type analysis. Warn for unconstrained conditions
/// or finite sets above Falco's 100-event performance threshold.
pub fn matches_too_many_event_types(filter: &Expr) -> bool {
    match event_types(filter) {
        EventTypeSet::All => true,
        EventTypeSet::Some(event_types) => event_types.len() > 100,
        EventTypeSet::Empty => false,
    }
}

fn event_types(filter: &Expr) -> EventTypeSet {
    match filter {
        Expr::And(left, right) => intersect(event_types(left), event_types(right)),
        Expr::Or(left, right) => union(event_types(left), event_types(right)),
        Expr::Not(inner) => match event_types(inner) {
            EventTypeSet::Empty => EventTypeSet::All,
            EventTypeSet::Some(_) | EventTypeSet::All => EventTypeSet::All,
        },
        Expr::Identifier(_) | Expr::Exists { .. } => EventTypeSet::All,
        Expr::Binary { left, op, value } => atomic_event_types(left, *op, value),
    }
}

fn atomic_event_types(left: &Operand, op: BinaryOp, value: &Value) -> EventTypeSet {
    let Operand::Field(field) = left else {
        return EventTypeSet::All;
    };
    if field == "evt.num" && op == BinaryOp::Eq && scalar_values(value).iter().any(|v| v == "0") {
        return EventTypeSet::Empty;
    }
    if !matches!(field.as_str(), "evt.type" | "evt.asynctype") {
        return EventTypeSet::All;
    }
    if !matches!(op, BinaryOp::Eq | BinaryOp::In) {
        return EventTypeSet::All;
    }
    EventTypeSet::Some(scalar_values(value).into_iter().collect())
}

fn scalar_values(value: &Value) -> Vec<String> {
    match value {
        Value::Bare(value) | Value::Quoted(value) => {
            vec![value.trim_matches(['\'', '"']).to_string()]
        }
        Value::List(values) => values.iter().flat_map(scalar_values).collect(),
    }
}

fn intersect(left: EventTypeSet, right: EventTypeSet) -> EventTypeSet {
    match (left, right) {
        (EventTypeSet::Empty, _) | (_, EventTypeSet::Empty) => EventTypeSet::Empty,
        (EventTypeSet::All, other) | (other, EventTypeSet::All) => other,
        (EventTypeSet::Some(mut left), EventTypeSet::Some(right)) => {
            left.retain(|value| right.contains(value));
            if left.is_empty() {
                EventTypeSet::Empty
            } else {
                EventTypeSet::Some(left)
            }
        }
    }
}

fn union(left: EventTypeSet, right: EventTypeSet) -> EventTypeSet {
    match (left, right) {
        (EventTypeSet::All, _) | (_, EventTypeSet::All) => EventTypeSet::All,
        (EventTypeSet::Empty, other) | (other, EventTypeSet::Empty) => other,
        (EventTypeSet::Some(mut left), EventTypeSet::Some(right)) => {
            left.extend(right);
            EventTypeSet::Some(left)
        }
    }
}
