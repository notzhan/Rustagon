use super::ast::{Expr, Operand, Value};

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
        Expr::Identifier(identifier) => identifier.clone(),
        Expr::Binary { left, op, value } => {
            format!(
                "{} {} {}",
                print_operand(left),
                op.as_str(),
                print_value(value)
            )
        }
        Expr::Exists { left } => format!("{} exists", print_operand(left)),
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
        Expr::Identifier(_) | Expr::Binary { .. } | Expr::Exists { .. } => 4,
    }
}

fn print_operand(operand: &Operand) -> String {
    match operand {
        Operand::Field(field) => field.clone(),
        Operand::Transformer { name, args } => format!(
            "{name}({})",
            args.iter()
                .map(print_operand)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Operand::List(values) => format!(
            "({})",
            values
                .iter()
                .map(print_operand)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Operand::Literal(value) => print_value(value),
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
