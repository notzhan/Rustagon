use std::fmt;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, multispace0},
    combinator::{all_consuming, map, value},
    error::{Error as NomError, ErrorKind},
    multi::separated_list1,
    sequence::{delimited, preceded},
    Err as NomErr, IResult,
};

use super::ast::{BinaryOp, Expr, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterError {
    message: String,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FilterError {}

pub fn parse_filter(input: &str) -> Result<Expr, FilterError> {
    all_consuming(delimited(multispace0, parse_or, multispace0))(input)
        .map(|(_, expr)| expr)
        .map_err(|error| FilterError {
            message: format!("invalid filter expression: {error:?}"),
        })
}

fn parse_or(input: &str) -> IResult<&str, Expr> {
    let (mut input, mut expr) = parse_and(input)?;
    loop {
        match preceded(multispace0, keyword("or"))(input) {
            Ok((rest, _)) => {
                let (rest, rhs) = preceded(multispace0, parse_and)(rest)?;
                expr = Expr::Or(Box::new(expr), Box::new(rhs));
                input = rest;
            }
            Err(NomErr::Error(_)) => return Ok((input, expr)),
            Err(error) => return Err(error),
        }
    }
}

fn parse_and(input: &str) -> IResult<&str, Expr> {
    let (mut input, mut expr) = parse_not(input)?;
    loop {
        match preceded(multispace0, keyword("and"))(input) {
            Ok((rest, _)) => {
                let (rest, rhs) = preceded(multispace0, parse_not)(rest)?;
                expr = Expr::And(Box::new(expr), Box::new(rhs));
                input = rest;
            }
            Err(NomErr::Error(_)) => return Ok((input, expr)),
            Err(error) => return Err(error),
        }
    }
}

fn parse_not(input: &str) -> IResult<&str, Expr> {
    if let Ok((rest, _)) = keyword("not")(input) {
        let (rest, expr) = preceded(multispace0, parse_not)(rest)?;
        return Ok((rest, Expr::Not(Box::new(expr))));
    }
    parse_primary(input)
}

fn parse_primary(input: &str) -> IResult<&str, Expr> {
    alt((
        delimited(
            delimited(multispace0, char('('), multispace0),
            parse_or,
            delimited(multispace0, char(')'), multispace0),
        ),
        parse_predicate,
    ))(input)
}

fn parse_predicate(input: &str) -> IResult<&str, Expr> {
    let (input, field) = parse_field(input)?;
    let (input, _) = multispace0(input)?;

    if let Ok((rest, _)) = keyword("exists")(input) {
        return Ok((
            rest,
            Expr::Exists {
                field: field.to_owned(),
            },
        ));
    }

    let (input, op) = parse_binary_op(input)?;
    let (input, value) = preceded(multispace0, parse_value)(input)?;
    Ok((
        input,
        Expr::Binary {
            field: field.to_owned(),
            op,
            value,
        },
    ))
}

fn parse_field(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '[' | ']'))(input)
}

fn parse_binary_op(input: &str) -> IResult<&str, BinaryOp> {
    alt((
        value(BinaryOp::NotEq, tag("!=")),
        value(BinaryOp::LessEq, tag("<=")),
        value(BinaryOp::GreaterEq, tag(">=")),
        value(BinaryOp::Eq, tag("=")),
        value(BinaryOp::Less, tag("<")),
        value(BinaryOp::Greater, tag(">")),
        value(BinaryOp::Contains, keyword("contains")),
        value(BinaryOp::StartsWith, keyword("startswith")),
        value(BinaryOp::EndsWith, keyword("endswith")),
        value(BinaryOp::In, keyword("in")),
        value(BinaryOp::Pmatch, keyword("pmatch")),
        value(BinaryOp::Glob, keyword("glob")),
    ))(input)
}

fn parse_value(input: &str) -> IResult<&str, Value> {
    alt((parse_list, parse_quoted, parse_bare))(input)
}

fn parse_list(input: &str) -> IResult<&str, Value> {
    map(
        delimited(
            delimited(multispace0, char('('), multispace0),
            separated_list1(
                delimited(multispace0, char(','), multispace0),
                parse_value_atom,
            ),
            delimited(multispace0, char(')'), multispace0),
        ),
        Value::List,
    )(input)
}

fn parse_value_atom(input: &str) -> IResult<&str, Value> {
    alt((parse_quoted, parse_bare))(input)
}

fn parse_bare(input: &str) -> IResult<&str, Value> {
    map(
        take_while1(|c: char| !c.is_whitespace() && !matches!(c, ',' | '(' | ')')),
        |token: &str| Value::Bare(token.to_owned()),
    )(input)
}

fn parse_quoted(input: &str) -> IResult<&str, Value> {
    let quote = match input.chars().next() {
        Some(quote @ ('\'' | '"')) => quote,
        _ => return Err(NomErr::Error(NomError::new(input, ErrorKind::Char))),
    };
    let mut escaped = false;
    for (offset, ch) in input[quote.len_utf8()..].char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            let end = quote.len_utf8() + offset + ch.len_utf8();
            return Ok((&input[end..], Value::Quoted(input[..end].to_owned())));
        }
    }
    Err(NomErr::Error(NomError::new(input, ErrorKind::Escaped)))
}

fn keyword(expected: &'static str) -> impl FnMut(&str) -> IResult<&str, &str> {
    move |input| {
        let (rest, matched) = tag(expected)(input)?;
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            Err(NomErr::Error(NomError::new(input, ErrorKind::Tag)))
        } else {
            Ok((rest, matched))
        }
    }
}
