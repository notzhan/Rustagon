use crate::alt_loader::{AltCompileOutput, RuleLoaderHooks};
use crate::fields;
use crate::plugins::{requirements_satisfied, PluginRequirement, PluginVersion};
use crate::ruleset::{MatchType, Ruleset};
use crate::{rule_loader, CompiledRuleset, LoadResult, RuleDetails};
use rustagon_parser::parse_rules;
use std::collections::{HashMap, HashSet};

pub const DEFAULT_RULESET: &str = "falco-default-ruleset";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evt {
    pub fields: HashMap<String, String>,
}

impl Evt {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Self { fields }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub rule: String,
    pub output: String,
}

#[derive(Clone, Debug)]
struct ExtraOutput {
    text: String,
    source: String,
    tags: Vec<String>,
    rule: String,
}

#[derive(Clone, Debug)]
struct ExtraField {
    name: String,
    format: String,
    source: String,
    tags: Vec<String>,
    rule: String,
}

#[derive(Clone, Debug)]
struct Source {
    name: String,
    filter_factory: String,
    formatter_factory: String,
    ruleset_factory: String,
}

#[derive(Debug)]
pub struct FalcoEngine {
    pub ruleset: CompiledRuleset,
    selections: Ruleset,
    ruleset_ids: HashMap<String, u16>,
    next_ruleset_id: u16,
    extra_outputs: Vec<ExtraOutput>,
    extra_fields: Vec<ExtraField>,
    sources: Vec<Source>,
    plugin_requirements: Vec<Vec<PluginRequirement>>,
    loader_hooks: Option<RuleLoaderHooks>,
    alternate_properties: HashSet<String>,
}

impl Default for FalcoEngine {
    fn default() -> Self {
        Self {
            ruleset: CompiledRuleset::default(),
            selections: Ruleset::default(),
            ruleset_ids: HashMap::from([(DEFAULT_RULESET.to_string(), 0)]),
            next_ruleset_id: 1,
            extra_outputs: Vec::new(),
            extra_fields: Vec::new(),
            sources: Vec::new(),
            plugin_requirements: Vec::new(),
            loader_hooks: None,
            alternate_properties: HashSet::new(),
        }
    }
}

impl FalcoEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_rules(&mut self, content: &str, _name: &str) -> LoadResult {
        if self.loader_hooks.is_some() {
            let sources = self
                .sources
                .iter()
                .map(|source| source.name.as_str())
                .collect::<Vec<_>>();
            return match AltCompileOutput::compile(content, &sources) {
                Ok(output) => {
                    self.alternate_properties = output.defined_properties;
                    LoadResult::success()
                }
                Err(error) => LoadResult {
                    ok: false,
                    errors: vec![error],
                    warnings: vec![],
                    schema_validation: "failed".into(),
                },
            };
        }
        match rule_loader::load_sequence(content) {
            Ok(Some(mut loaded)) => {
                self.apply_output_formats(&mut loaded.ruleset.rule_details);
                self.plugin_requirements.extend(loaded.plugin_requirements);
                for (name, details) in &loaded.ruleset.rule_details {
                    let tags = details.tags.iter().map(String::as_str).collect::<Vec<_>>();
                    self.selections.add(name, &tags);
                    if details.enabled {
                        self.selections.enable_name(name, 0);
                    }
                }
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

    pub fn find_ruleset_id(&mut self, ruleset: &str) -> u16 {
        if let Some(id) = self.ruleset_ids.get(ruleset) {
            return *id;
        }
        let id = self.next_ruleset_id;
        self.next_ruleset_id += 1;
        self.ruleset_ids.insert(ruleset.to_string(), id);
        id
    }

    pub fn enable_rule(&mut self, pattern: &str, enabled: bool, ruleset: &str) {
        let id = self.find_ruleset_id(ruleset);
        self.set_rule_enabled(pattern, MatchType::Substring, enabled, id);
    }

    pub fn enable_rule_id(&mut self, pattern: &str, enabled: bool, ruleset_id: u16) {
        self.set_rule_enabled(pattern, MatchType::Substring, enabled, ruleset_id);
    }

    pub fn enable_rule_exact(&mut self, pattern: &str, enabled: bool, ruleset: &str) {
        let id = self.find_ruleset_id(ruleset);
        self.set_rule_enabled(pattern, MatchType::Exact, enabled, id);
    }

    pub fn enable_rule_wildcard(&mut self, pattern: &str, enabled: bool, ruleset: &str) {
        let id = self.find_ruleset_id(ruleset);
        self.set_rule_enabled(pattern, MatchType::Wildcard, enabled, id);
    }

    pub fn enable_rule_by_tag(&mut self, tags: &[&str], enabled: bool, ruleset: &str) {
        let id = self.find_ruleset_id(ruleset);
        if enabled {
            self.selections.enable_tags(tags, id);
        } else {
            self.selections.disable_tags(tags, id);
        }
    }

    pub fn num_rules_for_ruleset(&self, ruleset: &str) -> usize {
        self.ruleset_ids
            .get(ruleset)
            .map_or(0, |id| self.selections.enabled_count(*id))
    }

    pub fn num_rules_for_ruleset_id(&self, id: u16) -> usize {
        self.selections.enabled_count(id)
    }

    pub fn process_event(&self, evt: &Evt, ruleset_id: u16) -> Option<Alert> {
        self.ruleset
            .rule_details
            .iter()
            .find_map(|(name, details)| {
                if !self.selections.is_enabled(name, ruleset_id)
                    || !condition_matches(&details.condition, evt)
                {
                    return None;
                }
                Some(Alert {
                    rule: name.clone(),
                    output: details.output.clone().unwrap_or_default(),
                })
            })
    }

    pub fn add_extra_output_format(&mut self, text: &str, source: &str, tags: &[&str], rule: &str) {
        self.extra_outputs.push(ExtraOutput {
            text: text.to_string(),
            source: source.to_string(),
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            rule: rule.to_string(),
        });
    }

    pub fn add_extra_output_formatted_field(
        &mut self,
        name: &str,
        format: &str,
        source: &str,
        tags: &[&str],
        rule: &str,
    ) {
        self.extra_fields.push(ExtraField {
            name: name.to_string(),
            format: format.to_string(),
            source: source.to_string(),
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            rule: rule.to_string(),
        });
    }

    pub fn list_fields(&self, source: &str, verbose: bool, names_only: bool) -> String {
        fields::list_fields_markdown(source, verbose, names_only)
    }

    pub fn list_fields_json(&self, source: &str, verbose: bool, names_only: bool) -> String {
        fields::list_fields_json(source, verbose, names_only)
    }

    pub fn add_source(
        &mut self,
        name: &str,
        filter_factory: &str,
        formatter_factory: &str,
        ruleset_factory: &str,
    ) -> usize {
        let index = self.sources.len();
        self.sources.push(Source {
            name: name.to_string(),
            filter_factory: filter_factory.to_string(),
            formatter_factory: formatter_factory.to_string(),
            ruleset_factory: ruleset_factory.to_string(),
        });
        index
    }

    pub fn is_source_valid(&self, name: &str) -> bool {
        self.source(name).is_some()
    }

    pub fn filter_factory_for_source(&self, name: &str) -> Option<&str> {
        self.source(name)
            .map(|source| source.filter_factory.as_str())
    }

    pub fn filter_factory_for_source_index(&self, index: usize) -> Option<&str> {
        self.sources
            .get(index)
            .map(|source| source.filter_factory.as_str())
    }

    pub fn formatter_factory_for_source(&self, name: &str) -> Option<&str> {
        self.source(name)
            .map(|source| source.formatter_factory.as_str())
    }

    pub fn ruleset_factory_for_source(&self, name: &str) -> Option<&str> {
        self.source(name)
            .map(|source| source.ruleset_factory.as_str())
    }

    pub fn ruleset_for_source(&self, name: &str) -> Option<&str> {
        self.ruleset_factory_for_source(name)
    }

    pub fn check_plugin_requirements(&self, plugins: &[PluginVersion]) -> Result<(), String> {
        requirements_satisfied(&self.plugin_requirements, plugins)
    }

    pub fn set_rule_loader_hooks(&mut self, hooks: RuleLoaderHooks) {
        self.loader_hooks = Some(hooks);
    }

    pub fn rule_loader_hooks(&self) -> Option<&RuleLoaderHooks> {
        self.loader_hooks.as_ref()
    }

    pub fn alternate_properties(&self) -> &HashSet<String> {
        &self.alternate_properties
    }

    fn source(&self, name: &str) -> Option<&Source> {
        self.sources.iter().find(|source| source.name == name)
    }

    fn set_rule_enabled(&mut self, pattern: &str, kind: MatchType, enabled: bool, id: u16) {
        if enabled {
            self.selections.enable(pattern, kind, id);
        } else {
            self.selections.disable(pattern, kind, id);
        }
    }

    fn apply_output_formats(&self, rules: &mut HashMap<String, RuleDetails>) {
        for (name, details) in rules {
            if let Some(output) = details.output.as_mut() {
                *output = output.replace(" (%container.info)", "");
            }
            for extra in &self.extra_outputs {
                if applies(
                    extra.source.as_str(),
                    &extra.tags,
                    extra.rule.as_str(),
                    name,
                    details,
                ) {
                    let output = details.output.get_or_insert_with(String::new);
                    if !output.is_empty() {
                        output.push(' ');
                    }
                    output.push_str(&extra.text);
                }
            }
            for extra in &self.extra_fields {
                if applies(
                    extra.source.as_str(),
                    &extra.tags,
                    extra.rule.as_str(),
                    name,
                    details,
                ) {
                    details
                        .formatted_fields
                        .insert(extra.name.clone(), extra.format.clone());
                }
            }
        }
    }
}

fn applies(source: &str, tags: &[String], rule: &str, name: &str, details: &RuleDetails) -> bool {
    (source.is_empty() || source == details.source())
        && (rule.is_empty() || rule == name)
        && tags.iter().all(|tag| details.tags.contains(tag))
}

fn condition_matches(condition: &str, evt: &Evt) -> bool {
    let condition = condition.trim().trim_matches(['(', ')']);
    if let Some((field, value)) = condition.split_once('=') {
        return evt
            .fields
            .get(field.trim())
            .is_some_and(|actual| actual == value.trim());
    }
    false
}
