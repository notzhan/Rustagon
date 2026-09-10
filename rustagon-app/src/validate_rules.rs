use rustagon_engine::FalcoEngine;

const CONFIG_HINT: &str =
    "--validate expects a rules file, that is a YAML list of rule, macro, and list items.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    pub success: bool,
    pub error: String,
    pub output: String,
}

pub fn validate_rules_content(
    filename: &str,
    content: &str,
    json_output: bool,
) -> ValidationResult {
    let parsed = serde_yaml::from_str::<serde_yaml::Value>(content);
    if matches!(parsed, Ok(serde_yaml::Value::Mapping(_))) {
        let error = format!("{CONFIG_HINT}\nTry `falco -c {filename} --dry-run` instead.");
        let output = if json_output {
            serde_json::json!({
                "falco_load_results": [{
                    "filename": filename,
                    "successful": false,
                    "errors": ["rules document must be a YAML sequence"]
                }]
            })
            .to_string()
        } else {
            error.clone()
        };
        return ValidationResult {
            success: false,
            error,
            output,
        };
    }

    let mut engine = FalcoEngine::new();
    let loaded = engine.load_rules(content, filename);
    let error = loaded.errors.join("\n");
    let output = if json_output {
        serde_json::json!({
            "falco_load_results": [{
                "filename": filename,
                "successful": loaded.ok,
                "errors": loaded.errors,
                "warnings": loaded.warnings
            }]
        })
        .to_string()
    } else {
        error.clone()
    };
    ValidationResult {
        success: loaded.ok,
        error,
        output,
    }
}
