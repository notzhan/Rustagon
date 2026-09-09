use super::ast::{Expr, Value};

pub fn print_filter(expr: &Expr) -> String {
    print_expr(expr, 0)
}

fn print_expr(expr: &Expr, parent_precedence: u8) -> String {
    let precedence = precedence(expr);
    let body = match expr {
        Expr::And(left, right) => format!(
            "{} and {}",
            print_expr(left, precedence),
            print_expr(right, precedence)
        ),
        Expr::Or(left, right) => format!(
            "{} or {}",
            print_expr(left, precedence),
            print_expr(right, precedence)
        ),
        Expr::Not(inner) => format!("not {}", print_expr(inner, precedence)),
        Expr::Binary { field, op, value } => {
            format!("{field} {} {}", op.as_str(), print_value(value))
        }
        Expr::Exists { field } => format!("{field} exists"),
    };

    if precedence < parent_precedence {
        format!("({body})")
    } else {
        body
    }
}

fn precedence(expr: &Expr) -> u8 {
    match expr {
        Expr::Or(..) => 1,
        Expr::And(..) => 2,
        Expr::Not(..) => 3,
        Expr::Binary { .. } | Expr::Exists { .. } => 4,
    }
}

fn print_value(value: &Value) -> String {
    match value {
        Value::Bare(value) | Value::Quoted(value) => value.clone(),
        Value::List(values) => format!(
            "({})",
            values
                .iter()
                .map(print_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
