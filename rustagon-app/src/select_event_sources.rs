use std::collections::HashSet;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SourceSelection {
    pub enable: Vec<String>,
    pub disable: Vec<String>,
}

pub fn select_event_sources(
    loaded: &[String],
    capture_mode: bool,
    selection: &SourceSelection,
) -> Result<Vec<String>, String> {
    if capture_mode {
        return Ok(Vec::new());
    }
    if loaded.is_empty() {
        return Err("event sources must be loaded before selection".to_string());
    }
    if !selection.enable.is_empty() && !selection.disable.is_empty() {
        return Err("enable and disable source options cannot be mixed".to_string());
    }

    let known = loaded.iter().map(String::as_str).collect::<HashSet<_>>();
    for source in selection.enable.iter().chain(&selection.disable) {
        if !known.contains(source.as_str()) {
            return Err(format!("unknown event source: {source}"));
        }
    }

    if !selection.enable.is_empty() {
        let enabled = selection
            .enable
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        Ok(loaded
            .iter()
            .filter(|source| enabled.contains(source.as_str()))
            .cloned()
            .collect())
    } else {
        let disabled = selection
            .disable
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        Ok(loaded
            .iter()
            .filter(|source| !disabled.contains(source.as_str()))
            .cloned()
            .collect())
    }
}
