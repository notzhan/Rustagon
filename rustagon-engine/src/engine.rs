use crate::LoadResult;
use rustagon_parser::parse_rules;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct FalcoEngine {
    pub rules: HashMap<String, String>, // name -> compiled condition (placeholder)
}

impl FalcoEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_rules(&mut self, content: &str, _name: &str) -> LoadResult {
        match parse_rules(content) {
            Ok(def) => {
                for r in def.rules {
                    self.rules.insert(r.rule, r.condition);
                }
                LoadResult::success()
            }
            Err(e) => LoadResult {
                ok: false,
                errors: vec![e.to_string()],
                warnings: vec![],
                schema_validation: "failed".into(),
            },
        }
    }

    pub fn compiled_condition(&self, rule: &str) -> Option<&str> {
        self.rules.get(rule).map(String::as_str)
    }
}
