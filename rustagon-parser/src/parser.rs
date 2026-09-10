//! YAML rule file parser for Falco rules
//!
//! Parses Falco YAML rule definitions and converts them to AST

use serde::{Deserialize, Serialize};

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
    pub macro_name: String,
    /// Macro condition
    pub condition: String,
}

/// List definition for common values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleList {
    /// List name
    pub list_name: String,
    /// List items
    pub items: Vec<String>,
}

/// Complete rule definition (rules + macros + lists)
#[derive(Debug, Clone)]
pub struct RuleDefinition {
    /// List of rules
    pub rules: Vec<FalcoRule>,
    /// Macro definitions
    pub macros: Vec<RuleMacro>,
    /// List definitions
    pub lists: Vec<RuleList>,
}

fn default_enabled() -> bool {
    true
}

/// Parse rules from YAML content
pub fn parse_rules(content: &str) -> crate::Result<RuleDefinition> {
    // Try to parse as a list of documents (rules)
    // In Falco, each rule is a separate YAML document
    let mut rules = Vec::new();
    let macros = Vec::new();
    let lists = Vec::new();

    // Split by document separator
    for doc in content.split("---") {
        let trimmed = doc.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as a rule first
        if let Ok(rule) = serde_yaml::from_str::<FalcoRule>(trimmed) {
            rules.push(rule);
        }
        // Could add more document types here (macros, lists)
    }

    Ok(RuleDefinition {
        rules,
        macros,
        lists,
    })
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

    #[test]
    fn test_parse_multiple_rules() {
        let yaml = r#"
rule: Rule 1
desc: First rule
condition: syscall == open
priority: WARNING
output: Output 1
---
rule: Rule 2
desc: Second rule
condition: syscall == close
priority: NOTICE
output: Output 2
"#;

        let def = parse_rules(yaml).unwrap();
        assert_eq!(def.rules.len(), 2);
        assert_eq!(def.rules[0].rule, "Rule 1");
        assert_eq!(def.rules[1].rule, "Rule 2");
    }
}
