use crate::{rule_loader, CompiledRuleset, LoadResult, RuleDetails};
use rustagon_parser::parse_rules;

#[derive(Debug, Default)]
pub struct FalcoEngine {
    pub ruleset: CompiledRuleset,
}

impl FalcoEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_rules(&mut self, content: &str, _name: &str) -> LoadResult {
        match rule_loader::load_sequence(content) {
            Ok(Some(loaded)) => {
                self.ruleset.rules.extend(loaded.ruleset.rules);
                self.ruleset.macros.extend(loaded.ruleset.macros);
                self.ruleset
                    .rule_details
                    .extend(loaded.ruleset.rule_details);
                return LoadResult {
                    warnings: loaded.warnings,
                    schema_validation: if loaded.schema_valid { "ok" } else { "failed" }.into(),
                    ..LoadResult::success()
                };
            }
            Err(error) => {
                return LoadResult {
                    ok: false,
                    errors: vec![error.message],
                    warnings: error.warnings,
                    schema_validation: if error.schema_valid { "ok" } else { "failed" }.into(),
                };
            }
            Ok(None) => {}
        }

        match parse_rules(content) {
            Ok(def) => {
                for r in def.rules {
                    self.ruleset.rules.insert(r.rule, r.condition);
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
        self.ruleset.rules.get(rule).map(String::as_str)
    }

    pub fn rule_details(&self, rule: &str) -> Option<&RuleDetails> {
        self.ruleset.rule_details.get(rule)
    }
}
