use clap::Parser;
use rustagon_app::{cli::Cli, validate_rules::validate_rules_content};
use rustagon_config::FalcoConfig;
use std::{fs, process::ExitCode};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustagon: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    if !cli.validate.is_empty() {
        let mut config = FalcoConfig::default();
        cli.apply_overrides(&mut config)
            .map_err(|error| error.to_string())?;

        let mut valid = true;
        for path in &cli.validate {
            let content = fs::read_to_string(path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
            let result =
                validate_rules_content(&path.display().to_string(), &content, config.json_output);
            if !result.output.is_empty() {
                if config.json_output {
                    println!("{}", result.output);
                } else {
                    eprintln!("{}", result.output);
                }
            }
            valid &= result.success;
        }

        if valid {
            println!("Rules files validated successfully");
            return Ok(());
        }
        return Err("rules validation failed".to_string());
    }

    if cli.list || cli.list_events {
        return Err("rule and event listing are not implemented yet".to_string());
    }

    Err(
        "daemon startup is not available from rustagon-app; use the rustagon-core binary"
            .to_string(),
    )
}
