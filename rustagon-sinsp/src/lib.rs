use rustagon_scap::RawEvent;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Evt {
    pub fields: HashMap<String, String>,
}

impl Evt {
    pub fn get_field_as_string(&self, field: &str) -> Option<String> {
        self.fields.get(field).cloned()
    }
}

#[derive(Debug, Default)]
pub struct Inspector;

impl Inspector {
    pub fn inject(&mut self, _raw: RawEvent) -> Evt {
        Evt::default()
    }
}

#[cfg(test)]
mod tests {
    use super::Evt;

    #[test]
    fn evt_field_stub_returns_none() {
        let evt = Evt::default();
        assert!(evt.get_field_as_string("proc.name").is_none());
    }
}
