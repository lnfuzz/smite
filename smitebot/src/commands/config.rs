//! Campaign configuration validation.

use std::collections::HashMap;
use std::path::PathBuf;

use clap::Args;
use serde::Serialize;

use crate::config::CampaignConfig;
use crate::error::CliError;

/// Command handler for `smitebot config`.
pub struct ConfigCommand;

/// CLI arguments for `smitebot config`.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    json: bool,
}

/// JSON-serializable report for `smitebot config --json`.
#[derive(Debug, Serialize)]
struct ConfigReport {
    target: String,
    scenario: String,
    aflpp_path: String,
    smite_dir: String,
    runners: u16,
    seed_dir: Option<String>,
    output_dir: String,
    sharedir: String,
    image: String,
    afl_env: HashMap<String, String>,
    afl_flags: Vec<String>,
    errors: Vec<String>,
    valid: bool,
}

/// JSON-serializable error report when config fails to load.
#[derive(Debug, Serialize)]
struct ConfigErrorReport {
    error: String,
    valid: bool,
}

impl ConfigCommand {
    /// Validates a campaign configuration file and reports the result.
    ///
    /// The report (plain or JSON) is the artifact and is always printed here, so
    /// a failure returns [`CliError::Reported`]: `main` only sets the exit code.
    pub fn execute(args: &ConfigArgs) -> Result<(), CliError> {
        match CampaignConfig::load(&args.path) {
            Ok(config) => {
                let errors = config.check_paths();
                let valid = errors.is_empty();

                if args.json {
                    let report = ConfigReport {
                        target: config.target.to_string(),
                        scenario: config.scenario.clone(),
                        aflpp_path: config.aflpp_path.display().to_string(),
                        smite_dir: config.smite_dir.display().to_string(),
                        runners: config.runners,
                        seed_dir: config.seed_dir.as_ref().map(|p| p.display().to_string()),
                        output_dir: config.output_dir.display().to_string(),
                        sharedir: config.sharedir.display().to_string(),
                        image: config.image_tag(),
                        afl_env: config.afl_env.clone(),
                        afl_flags: config.afl_flags.clone(),
                        errors,
                        valid,
                    };
                    let json = serde_json::to_string_pretty(&report)
                        .expect("ConfigReport is always serializable");
                    println!("{json}");
                } else {
                    println!("target:     {}", config.target);
                    println!("scenario:   {}", config.scenario);
                    println!("aflpp_path: {}", config.aflpp_path.display());
                    println!("smite_dir:  {}", config.smite_dir.display());
                    println!("runners:    {}", config.runners);
                    match &config.seed_dir {
                        Some(dir) => println!("seed_dir:   {}", dir.display()),
                        None => println!("seed_dir:   (empty corpus)"),
                    }
                    println!("output_dir: {}", config.output_dir.display());
                    println!("sharedir:   {}", config.sharedir.display());
                    println!("image:      {}", config.image_tag());
                    for (key, val) in &config.afl_env {
                        println!("afl_env:    {key}={val}");
                    }
                    for flag in &config.afl_flags {
                        println!("afl_flags:  {flag}");
                    }
                    for error in &errors {
                        eprintln!("error: {error}");
                    }
                }
                if valid {
                    Ok(())
                } else {
                    Err(CliError::Reported)
                }
            }
            Err(e) => {
                if args.json {
                    let report = ConfigErrorReport {
                        error: e.to_string(),
                        valid: false,
                    };
                    let json = serde_json::to_string_pretty(&report)
                        .expect("ConfigErrorReport is always serializable");
                    println!("{json}");
                } else {
                    eprintln!("error: {e}");
                }
                Err(CliError::Reported)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_report_json_is_machine_readable() {
        let report = ConfigReport {
            target: "lnd".to_string(),
            scenario: "encrypted_bytes".to_string(),
            aflpp_path: "/home/user/AFLplusplus".to_string(),
            smite_dir: ".".to_string(),
            runners: 8,
            seed_dir: Some("/tmp/seeds".to_string()),
            output_dir: "/tmp/out".to_string(),
            sharedir: "/tmp/nyx".to_string(),
            image: "smite-lnd-encrypted_bytes".to_string(),
            afl_env: HashMap::from([("AFL_KEEP_TIMEOUTS".to_string(), "1".to_string())]),
            afl_flags: vec!["-t".to_string(), "1000+".to_string()],
            errors: vec!["aflpp_path does not exist: /home/user/AFLplusplus".to_string()],
            valid: false,
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["target"], "lnd");
        assert_eq!(parsed["runners"], 8);
        assert_eq!(parsed["valid"], false);
        assert_eq!(parsed["seed_dir"], "/tmp/seeds");
        assert_eq!(parsed["afl_env"]["AFL_KEEP_TIMEOUTS"], "1");
        assert_eq!(parsed["afl_flags"][0], "-t");
        assert_eq!(
            parsed["errors"][0],
            "aflpp_path does not exist: /home/user/AFLplusplus"
        );
    }

    #[test]
    fn config_error_report_json_is_machine_readable() {
        let report = ConfigErrorReport {
            error: "failed to parse config.toml".to_string(),
            valid: false,
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["valid"], false);
        assert!(parsed["error"].is_string());
    }
}
