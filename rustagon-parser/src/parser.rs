//! YAML rule file parser for Falco rules
//!
//! Parses Falco YAML rule definitions and converts them to AST

use serde::{Deserialize, Serialize};
use crate::ParseError;

/// Represents a complete Falco rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalcoRule {
    /// Rule name
    pub rule: String,
    /// Rule description
    pub desc: String,
    /// Rule condition (filter expression)
    pub condition: String,
    /// Event priority/severity
    pub priority: String,
    /// Output message template
    pub output: String,
    /// Optional tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional enabled flag
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Macro definition for rule reuse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMacro {
    /// Macro name
    pub macro: String,
    /// Macro condition
    pub condition: String,
}

/// List definition for common values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleList {
    /// List name
    pub list: String,
    /// List items
    pub items: Vec<String>,
}

/// Complete rule definition (rules + macros + lists)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    /// List of rules
    #[serde(default)]
    pub rules: Vec<FalcoRule>,
    /// Macro definitions
    #[serde(default)]
    pub macros: Vec<RuleMacro>,
    /// List definitions
    #[serde(default)]
    pub lists: Vec<RuleList>,
}

fn default_enabled() -> bool {
    true
}

/// Parse rules from YAML content
pub fn parse_rules(content: &str) -> crate::Result<RuleDefinition> {
    // First try to parse as a single document
    let def: RuleDefinition = serde_yaml::from_str(content)?;
    Ok(def)
}

/// Parse rules from a file
pub fn parse_rules_from_file(path: &str) -> crate::Result<RuleDefinition> {
    let content = std::fs::read_to_string(path)?;
    parse_rules(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_rule_parsing() {
        let yaml = r#"
        rule: Test Rule
        desc: A test rule
        condition: syscall == open
        priority: WARNING
        output: File operation
        "#;

        let rule: FalcoRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.rule, "Test Rule");
        assert_eq!(rule.priority, "WARNING");
    }

    #[test]
    fn test_rule_with_tags() {
        let yaml = r#"
        rule: Test Rule
        desc: A test rule
        condition: syscall == open
        priority: WARNING
        output: File operation
        tags:
          - filesystem
          - detection
        "#;

        let rule: FalcoRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.tags.len(), 2);
        assert!(rule.tags.contains(&"filesystem".to_string()));
    }

    #[test]
    fn test_default_enabled() {
        let yaml = r#"
        rule: Test Rule
        desc: A test rule
        condition: syscall == open
        priority: WARNING
        output: File operation
        "#;

        let rule: FalcoRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.enabled, true);
    }
}
