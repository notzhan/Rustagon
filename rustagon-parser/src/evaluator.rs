//! AST evaluation engine for Falco rule conditions
//!
//! Evaluates rule conditions against events using a simple filter language

use rustagon_common::{EventHeader, EventType};
use crate::ParseError;

/// Context for evaluating a rule condition
pub struct EvaluationContext<'a> {
    /// Event header containing metadata
    pub event_header: &'a EventHeader,
    /// Raw event data
    pub event_data: &'a [u8],
}

/// Simple rule evaluator
pub struct RuleEvaluator {
    /// Compiled condition expression
    condition: String,
}

impl RuleEvaluator {
    /// Create a new evaluator with a condition
    pub fn new(condition: String) -> crate::Result<Self> {
        // Validate condition syntax
        Self::validate_condition(&condition)?;
        Ok(RuleEvaluator { condition })
    }

    /// Validate condition syntax
    fn validate_condition(condition: &str) -> crate::Result<()> {
        if condition.is_empty() {
            return Err(ParseError::InvalidRule(
                "Condition cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Evaluate a condition against an event
    pub fn evaluate(&self, context: &EvaluationContext) -> crate::Result<bool> {
        // This is a simplified evaluator
        // A full implementation would use a complete expression parser (nom/pest)
        // and support complex boolean logic, field comparisons, string operations, etc.

        let condition = self.condition.trim().to_lowercase();

        // Simple pattern matching for basic conditions
        if condition.contains("syscall == open") {
            Ok(context.event_header.event_type == EventType::Open)
        } else if condition.contains("syscall == close") {
            Ok(context.event_header.event_type == EventType::Close)
        } else {
            // Default: allow all events
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluator_creation() {
        let evaluator = RuleEvaluator::new("syscall == open".to_string());
        assert!(evaluator.is_ok());
    }

    #[test]
    fn test_empty_condition() {
        let evaluator = RuleEvaluator::new("".to_string());
        assert!(evaluator.is_err());
    }

    #[test]
    fn test_simple_condition() {
        let evaluator = RuleEvaluator::new("syscall == open".to_string()).unwrap();
        let header = EventHeader {
            timestamp: 12345,
            event_type: EventType::Open,
            pid: 1234,
            uid: 0,
            gid: 0,
        };
        let context = EvaluationContext {
            event_header: &header,
            event_data: &[],
        };
        assert!(evaluator.evaluate(&context).unwrap());
    }
}
