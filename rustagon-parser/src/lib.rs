//! Rustagon Parser - Falco YAML rule parsing and AST evaluation
//!
//! This crate provides:
//! - YAML parsing for Falco rule files
//! - AST (Abstract Syntax Tree) evaluation for rule conditions
//! - Filter engine for event matching

mod parser;
mod evaluator;

pub use parser::{parse_rules, RuleDefinition, FalcoRule};
pub use evaluator::{RuleEvaluator, EvaluationContext};

use thiserror::Error;

/// Parser error types
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("YAML parsing error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Invalid rule format: {0}")]
    InvalidRule(String),

    #[error("AST parsing error: {0}")]
    AstParseError(String),

    #[error("Evaluation error: {0}")]
    EvaluationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ParseError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_parsing() {
        let yaml_content = r#"
        - rule: Test Rule
          desc: A test rule
          condition: >
            syscall == open and 
            (pathname contains /tmp or pathname contains /dev)
          priority: WARNING
          output: >
            File open 
            (user=%user.name command=%proc.cmdline file=%fd.name)
        "#;

        // This will be tested once parser is fully implemented
        // let rules = parse_rules(yaml_content).unwrap();
        // assert_eq!(rules.len(), 1);
    }
}
