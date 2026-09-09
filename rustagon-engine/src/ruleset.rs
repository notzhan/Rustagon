use crate::utils::matches_wildcard;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    Exact,
    Substring,
    Wildcard,
}

#[derive(Debug, Default)]
pub struct Ruleset {
    rules: HashMap<String, HashSet<String>>,
    enabled: HashMap<u16, HashSet<String>>,
}

impl Ruleset {
    pub fn add(&mut self, name: &str, tags: &[&str]) {
        self.rules.insert(
            name.to_string(),
            tags.iter().map(|tag| (*tag).to_string()).collect(),
        );
    }

    pub fn enable(&mut self, pattern: &str, kind: MatchType, id: u16) {
        self.set_enabled(pattern, kind, id, true);
    }

    pub fn disable(&mut self, pattern: &str, kind: MatchType, id: u16) {
        self.set_enabled(pattern, kind, id, false);
    }

    pub fn enable_tags(&mut self, tags: &[&str], id: u16) {
        self.set_tags(tags, id, true);
    }

    pub fn disable_tags(&mut self, tags: &[&str], id: u16) {
        self.set_tags(tags, id, false);
    }

    pub fn enabled_count(&self, id: u16) -> usize {
        self.enabled.get(&id).map_or(0, HashSet::len)
    }

    pub fn is_enabled(&self, name: &str, id: u16) -> bool {
        self.enabled
            .get(&id)
            .is_some_and(|names| names.contains(name))
    }

    pub(crate) fn enable_name(&mut self, name: &str, id: u16) {
        self.enabled.entry(id).or_default().insert(name.to_string());
    }

    fn set_enabled(&mut self, pattern: &str, kind: MatchType, id: u16, enabled: bool) {
        let matches = self
            .rules
            .keys()
            .filter(|name| match kind {
                MatchType::Exact => pattern.is_empty() || name.as_str() == pattern,
                MatchType::Substring => name.contains(pattern),
                MatchType::Wildcard => matches_wildcard(pattern, name),
            })
            .cloned()
            .collect::<Vec<_>>();
        let names = self.enabled.entry(id).or_default();
        for name in matches {
            if enabled {
                names.insert(name);
            } else {
                names.remove(&name);
            }
        }
    }

    fn set_tags(&mut self, tags: &[&str], id: u16, enabled: bool) {
        let matches = self
            .rules
            .iter()
            .filter(|(_, rule_tags)| tags.iter().any(|tag| rule_tags.contains(*tag)))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let names = self.enabled.entry(id).or_default();
        for name in matches {
            if enabled {
                names.insert(name);
            } else {
                names.remove(&name);
            }
        }
    }
}
