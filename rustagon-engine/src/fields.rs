struct Field {
    name: &'static str,
    description: &'static str,
}

struct FieldClass {
    name: &'static str,
    description: &'static str,
    sources: &'static [&'static str],
    fields: &'static [Field],
}

const FIELD_CLASSES: &[FieldClass] = &[
    FieldClass {
        name: "evt",
        description: "These fields can be used for all event types",
        sources: &[],
        fields: &[Field {
            name: "evt.type",
            description: "Event type",
        }],
    },
    FieldClass {
        name: "evt",
        description: "Event fields applicable to syscall events",
        sources: &["syscall"],
        fields: &[Field {
            name: "evt.num",
            description: "Event number",
        }],
    },
    FieldClass {
        name: "fd",
        description: "File descriptor fields",
        sources: &["syscall"],
        fields: &[Field {
            name: "fd.name",
            description: "File name",
        }],
    },
];

fn classes_for_source(source: &str) -> Vec<&'static FieldClass> {
    if source.is_empty() {
        return FIELD_CLASSES.iter().collect();
    }
    if !FIELD_CLASSES
        .iter()
        .any(|class| class.sources.contains(&source))
    {
        return Vec::new();
    }
    FIELD_CLASSES
        .iter()
        .filter(|class| class.sources.is_empty() || class.sources.contains(&source))
        .collect()
}

pub fn list_fields_markdown(source: &str, _verbose: bool, names_only: bool) -> String {
    let classes = classes_for_source(source);
    if names_only {
        return classes
            .iter()
            .flat_map(|class| class.fields)
            .map(|field| field.name)
            .collect::<Vec<_>>()
            .join("\n")
            + if classes.is_empty() { "" } else { "\n" };
    }

    let mut output = String::new();
    for class in classes {
        output.push_str(&format!(
            "## Field Class: {}\n\n{}\n\n",
            class.name, class.description
        ));
        if !class.sources.is_empty() {
            output.push_str(&format!("Event Sources: {}\n\n", class.sources.join(", ")));
        }
        output.push_str("| Field | Description |\n|---|---|\n");
        for field in class.fields {
            output.push_str(&format!("| {} | {} |\n", field.name, field.description));
        }
        output.push('\n');
    }
    output
}

pub fn list_fields_json(source: &str, _verbose: bool, names_only: bool) -> String {
    let classes = classes_for_source(source);
    if names_only {
        let fields = classes
            .iter()
            .flat_map(|class| class.fields)
            .map(|field| format!(r#""{}""#, field.name))
            .collect::<Vec<_>>()
            .join(",");
        return format!(r#"{{"fields":[{fields}]}}"#);
    }

    let classes = classes
        .iter()
        .map(|class| {
            let sources = if class.sources.is_empty() {
                String::new()
            } else {
                format!(
                    r#","event_sources":[{}]"#,
                    class
                        .sources
                        .iter()
                        .map(|source| format!(r#""{source}""#))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            let fields = class
                .fields
                .iter()
                .map(|field| format!(r#"{{"name":"{}"}}"#, field.name))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"name":"{}","desc":"{}"{sources},"fields":[{fields}]}}"#,
                class.name, class.description
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"fieldclasses":[{classes}]}}"#)
}
