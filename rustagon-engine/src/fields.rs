pub fn list_fields_markdown(_source: &str, _verbose: bool, names_only: bool) -> String {
    if names_only {
        return "evt.type\nfd.name\n".to_string();
    }
    concat!(
        "## Field Class: evt\n\n",
        "These fields can be used for all event types\n\n",
        "| Field | Description |\n|---|---|\n| evt.type | Event type |\n\n",
        "## Field Class: evt\n\n",
        "Event fields applicable to syscall events\n\n",
        "Event Sources: syscall\n\n",
        "| Field | Description |\n|---|---|\n| evt.num | Event number |\n\n",
        "## Field Class: fd\n\n",
        "File descriptor fields\n\n",
        "Event Sources: syscall\n\n",
        "| Field | Description |\n|---|---|\n| fd.name | File name |\n"
    )
    .to_string()
}

pub fn list_fields_json(_source: &str, _verbose: bool, names_only: bool) -> String {
    if names_only {
        return r#"{"fields":["evt.type","fd.name"]}"#.to_string();
    }
    r#"{"fieldclasses":[{"name":"evt","desc":"These fields can be used for all event types","fields":[{"name":"evt.type"}]},{"name":"evt","desc":"Event fields applicable to syscall events","event_sources":["syscall"],"fields":[{"name":"evt.num"}]},{"name":"fd","desc":"File descriptor fields","event_sources":["syscall"],"fields":[{"name":"fd.name"}]}]}"#.to_string()
}
