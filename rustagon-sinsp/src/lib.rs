use rustagon_scap::RawEvent;
use std::collections::HashMap;

mod fields;

pub use fields::{FieldClass, FieldInfo};

#[derive(Debug, Default, Clone)]
pub struct Evt {
    pub fields: HashMap<String, String>,
}

impl Evt {
    pub fn get_field_as_string(&self, field: &str) -> Option<String> {
        self.fields.get(field).cloned()
    }

    pub fn get_field_as_u64(&self, field: &str) -> Option<u64> {
        self.fields.get(field)?.parse().ok()
    }

    pub fn get_field_as_i64(&self, field: &str) -> Option<i64> {
        self.fields.get(field)?.parse().ok()
    }

    pub fn get_field_as_bool(&self, field: &str) -> Option<bool> {
        self.fields.get(field)?.parse().ok()
    }
}

#[derive(Debug, Default)]
pub struct Inspector;

impl Inspector {
    pub fn get_field_names() -> Vec<FieldInfo> {
        fields::registry()
    }

    pub fn inject(&mut self, _raw: RawEvent) -> Evt {
        Evt::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{Evt, FieldClass, Inspector};
    use std::collections::HashSet;

    #[test]
    fn registry_contains_official_rule_fields_for_each_supported_class() {
        let fields = Inspector::get_field_names();
        let by_name: HashSet<_> = fields.iter().map(|field| field.name).collect();

        for expected in [
            "evt.type",
            "evt.time",
            "proc.name",
            "proc.cmdline",
            "proc.pid",
            "fd.name",
            "user.name",
            "container.id",
        ] {
            assert!(
                by_name.contains(expected),
                "missing registry field {expected}"
            );
        }

        assert!(fields
            .iter()
            .any(|field| field.name == "evt.type" && field.field_class == FieldClass::Evt));
        assert!(fields
            .iter()
            .any(|field| field.name == "proc.name" && field.field_class == FieldClass::Proc));
        assert!(fields
            .iter()
            .any(|field| field.name == "fd.name" && field.field_class == FieldClass::Fd));
        assert!(fields
            .iter()
            .any(|field| field.name == "user.name" && field.field_class == FieldClass::User));
        assert!(fields.iter().any(
            |field| field.name == "container.id" && field.field_class == FieldClass::Container
        ));
    }

    #[test]
    fn registry_names_are_unique_and_sorted() {
        let fields = Inspector::get_field_names();
        let names: Vec<_> = fields.iter().map(|field| field.name).collect();
        let unique: HashSet<_> = names.iter().copied().collect();

        assert_eq!(names.len(), unique.len());
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn registry_covers_the_checked_in_libs_baseline() {
        let registry: HashSet<_> = Inspector::get_field_names()
            .into_iter()
            .map(|field| field.name)
            .collect();
        let baseline: HashSet<_> = include_str!("../../parity/libs_equiv/fields_tip.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        assert_eq!(registry, baseline);
    }

    #[test]
    fn event_getters_read_and_parse_the_field_map() {
        let mut evt = Evt::default();
        evt.fields.insert("proc.name".into(), "bash".into());
        evt.fields.insert("proc.pid".into(), "42".into());
        evt.fields.insert("evt.rawres".into(), "-2".into());
        evt.fields.insert("evt.failed".into(), "true".into());

        assert_eq!(
            evt.get_field_as_string("proc.name").as_deref(),
            Some("bash")
        );
        assert_eq!(evt.get_field_as_u64("proc.pid"), Some(42));
        assert_eq!(evt.get_field_as_i64("evt.rawres"), Some(-2));
        assert_eq!(evt.get_field_as_bool("evt.failed"), Some(true));
        assert_eq!(evt.get_field_as_u64("proc.name"), None);
        assert_eq!(evt.get_field_as_bool("missing"), None);
    }
}
