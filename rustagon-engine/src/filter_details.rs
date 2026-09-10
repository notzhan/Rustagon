use std::collections::HashSet;

use rustagon_parser::filter::{Expr, Operand, Value};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilterDetails {
    pub known_macros: HashSet<String>,
    pub known_lists: HashSet<String>,
    pub fields: HashSet<String>,
    pub macros: HashSet<String>,
    pub operators: HashSet<String>,
    pub lists: HashSet<String>,
    pub evtnames: HashSet<String>,
    pub transformers: HashSet<String>,
}

impl FilterDetails {
    pub fn reset(&mut self) {
        self.fields.clear();
        self.macros.clear();
        self.operators.clear();
        self.lists.clear();
        self.evtnames.clear();
        self.transformers.clear();
    }
}

pub fn resolve_filter_details(filter: &Expr, details: &mut FilterDetails) {
    match filter {
        Expr::And(left, right) | Expr::Or(left, right) => {
            resolve_filter_details(left, details);
            resolve_filter_details(right, details);
        }
        Expr::Not(inner) => resolve_filter_details(inner, details),
        Expr::Identifier(identifier) => {
            if details.known_macros.contains(identifier) {
                details.macros.insert(identifier.clone());
            }
        }
        Expr::Exists { left } => {
            visit_operand(left, details);
            details.operators.insert("exists".into());
        }
        Expr::Binary { left, op, value } => {
            let mut fields = Vec::new();
            visit_operand_collect_fields(left, details, &mut fields);
            details.operators.insert(op.as_str().into());
            let event_field = fields
                .last()
                .is_some_and(|field| matches!(field.as_str(), "evt.type" | "evt.asynctype"));
            visit_value(value, details, event_field);
        }
    }
}

fn visit_operand(operand: &Operand, details: &mut FilterDetails) {
    visit_operand_collect_fields(operand, details, &mut Vec::new());
}

fn visit_operand_collect_fields(
    operand: &Operand,
    details: &mut FilterDetails,
    fields: &mut Vec<String>,
) {
    match operand {
        Operand::Field(field) => {
            details.fields.insert(field.clone());
            fields.push(field.clone());
        }
        Operand::Transformer { name, args } => {
            details.transformers.insert(name.clone());
            for arg in args {
                visit_operand_collect_fields(arg, details, fields);
            }
        }
        Operand::List(values) => {
            for value in values {
                visit_operand_collect_fields(value, details, fields);
            }
        }
        Operand::Literal(_) => {}
    }
}

fn visit_value(value: &Value, details: &mut FilterDetails, event_field: bool) {
    match value {
        Value::Bare(item) | Value::Quoted(item) => {
            let item = item.trim_matches(['\'', '"']);
            if details.known_lists.contains(item) {
                details.lists.insert(item.to_string());
            } else if event_field {
                details.evtnames.insert(item.to_string());
            }
        }
        Value::List(values) => {
            for value in values {
                visit_value(value, details, event_field);
            }
        }
    }
}
