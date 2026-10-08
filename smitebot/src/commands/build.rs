//! Docker image builds for Smite workloads.
//! The command keeps Docker's output visible so rebuild failures are easy to debug.

use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use clap::Args;

use crate::config::{self, CampaignConfig, Target};
use crate::error::CliError;

/// Command handler for `smitebot build`.
pub struct BuildCommand;

/// CLI arguments for `smitebot build`.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Path to a campaign configuration TOML file. When provided, settings are
    /// read from the file and CLI flags override individual values.
    config: Option<PathBuf>,
    /// Target implementation to build; overrides the config value.
    #[arg(long, required_unless_present = "config")]
    target: Option<Target>,
    /// Scenario binary selected by the workload Dockerfile; overrides the config value.
    #[arg(long, required_unless_present = "config")]
    scenario: Option<String>,
    /// Build the coverage-instrumented Docker image.
    #[arg(long)]
    coverage: bool,
    /// Docker image tag; overrides the config value and the default smite naming convention.
    #[arg(long)]
    image: Option<String>,
    /// Path to smite repository root; overrides the config value.
    #[arg(long)]
    smite_dir: Option<PathBuf>,
    /// Pass --no-cache to docker build.
    #[arg(long)]
    no_cache: bool,
}

/// Fully resolved Docker build inputs.
#[derive(Debug, PartialEq, Eq)]
pub struct BuildInputs {
    /// Docker image tag to produce.
    pub image: String,
    /// Workload Dockerfile selected from the resolved target and the coverage flag.
    pub dockerfile: PathBuf,
    /// Smite repository root used as the Docker build context.
    pub smite_dir: PathBuf,
    /// Scenario passed to Docker as `--build-arg SCENARIO=...`.
    pub scenario: String,
    /// Whether Docker should rebuild without using its layer cache.
    pub no_cache: bool,
    /// Target implementation being built.
    pub target: Target,
}

impl BuildInputs {
    /// Resolves Docker build inputs from a campaign configuration.
    pub fn from_config(config: &CampaignConfig, image: &str) -> Self {
        Self {
            image: image.to_string(),
            dockerfile: config
                .smite_dir
                .join("workloads")
                .join(config.target.to_string())
                .join("Dockerfile"),
            smite_dir: config.smite_dir.clone(),
            scenario: config.scenario.clone(),
            no_cache: false,
            target: config.target,
        }
    }

    /// Resolves Docker build inputs from an optional config, overriding with CLI args.
    ///
    /// Clap enforces that `--target` and `--scenario` are present when no config
    /// file is provided; `--smite-dir` defaults to the current directory.
    fn resolve(config: Option<&CampaignConfig>, args: &BuildArgs) -> Self {
        let target = args
            .target
            .or(config.map(|c| c.target))
            .expect("clap ensures --target is present when config is absent");
        let scenario = args
            .scenario
            .clone()
            .or_else(|| config.map(|c| c.scenario.clone()))
            .expect("clap ensures --scenario is present when config is absent");
        let smite_dir = args
            .smite_dir
            .clone()
            .or_else(|| config.map(|c| c.smite_dir.clone()))
            .unwrap_or_else(|| PathBuf::from("."));

        let dockerfile_name = if args.coverage {
            "Dockerfile.coverage"
        } else {
            "Dockerfile"
        };

        let image = args.image.clone().unwrap_or_else(|| {
            config
                .and_then(|c| c.image.clone())
                .unwrap_or_else(|| default_workload_image_tag(target, &scenario, args.coverage))
        });

        Self {
            image,
            dockerfile: smite_dir
                .join("workloads")
                .join(target.to_string())
                .join(dockerfile_name),
            smite_dir,
            scenario,
            no_cache: args.no_cache,
            target,
        }
    }
}

impl BuildCommand {
    /// Builds the requested Smite Docker image.
    pub fn execute(args: &BuildArgs) -> Result<(), CliError> {
        let config = match &args.config {
            Some(path) => Some(CampaignConfig::load(path)?),
            None => None,
        };
        let inputs = BuildInputs::resolve(config.as_ref(), args);
        if let Some(err) =
            config::check_scenario_exists(&inputs.smite_dir, inputs.target, &inputs.scenario)
        {
            return Err(CliError::Msg(err));
        }
        log::info!(
            "building {} with {}",
            inputs.image,
            inputs.dockerfile.display()
        );
        run_build(&inputs)
    }
}

/// Checks that the Dockerfile exists and runs `docker build`.
///
/// Shared by `smitebot build` and `smitebot start`.
pub fn run_build(inputs: &BuildInputs) -> Result<(), CliError> {
    if !inputs.dockerfile.exists() {
        return Err(CliError::Msg(format!(
            "Dockerfile not found: {}",
            inputs.dockerfile.display()
        )));
    }

    let status = run_docker_build(inputs)
        .map_err(|e| CliError::Msg(format!("failed to run docker build: {e}")))?;

    if !status.success() {
        return Err(CliError::Msg(format!("docker build failed with {status}")));
    }

    log::info!("built {}", inputs.image);
    Ok(())
}

/// Returns the default image tag used by Smite's manual Docker build flow.
fn default_workload_image_tag(target: Target, scenario: &str, coverage: bool) -> String {
    let suffix = if coverage { "-coverage" } else { "" };
    format!("smite-{target}-{scenario}{suffix}")
}

/// Runs `docker build`, streaming stdout/stderr directly to the terminal.
fn run_docker_build(inputs: &BuildInputs) -> std::io::Result<ExitStatus> {
    let mut command = Command::new("docker");
    command.arg("build");
    if inputs.no_cache {
        command.arg("--no-cache");
    }
    command
        .arg("-t")
        .arg(&inputs.image)
        .arg("--build-arg")
        .arg(format!("SCENARIO={}", inputs.scenario))
        .arg("-f")
        .arg(&inputs.dockerfile)
        .arg(&inputs.smite_dir);

    command.status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    fn sample_config() -> CampaignConfig {
        CampaignConfig {
            target: Target::Ldk,
            scenario: "init".to_string(),
            aflpp_path: PathBuf::from("/home/user/AFLplusplus"),
            smite_dir: PathBuf::from("/repo/smite"),
            runners: 1,
            seed_dir: None,
            output_dir: PathBuf::from("/tmp/out"),
            sharedir: PathBuf::from("/tmp/nyx"),
            image: None,
            afl_env: HashMap::new(),
            afl_flags: Vec::new(),
            tmux_session: None,
        }
    }

    fn sample_build_args() -> BuildArgs {
        BuildArgs {
            config: None,
            target: None,
            scenario: None,
            coverage: false,
            image: None,
            smite_dir: None,
            no_cache: false,
        }
    }

    #[test]
    fn default_workload_image_tag_matches_smite_convention() {
        assert_eq!(
            default_workload_image_tag(Target::Lnd, "encrypted_bytes", false),
            "smite-lnd-encrypted_bytes"
        );
        assert_eq!(
            default_workload_image_tag(Target::Cln, "noise", true),
            "smite-cln-noise-coverage"
        );
    }

    #[test]
    fn resolve_uses_config_values_by_default() {
        let config = sample_config();
        let args = sample_build_args();
        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.image, "smite-ldk-init");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/ldk/Dockerfile")
        );
        assert_eq!(inputs.smite_dir, Path::new("/repo/smite"));
        assert_eq!(inputs.scenario, "init");
        assert!(!inputs.no_cache);
    }

    #[test]
    fn resolve_overrides_target_and_scenario() {
        let config = sample_config();
        let mut args = sample_build_args();
        args.target = Some(Target::Cln);
        args.scenario = Some("noise".to_string());

        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.image, "smite-cln-noise");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/cln/Dockerfile")
        );
    }

    #[test]
    fn resolve_selects_expected_dockerfile_for_each_target() {
        let config = sample_config();
        let cases = [
            (Target::Lnd, "/repo/smite/workloads/lnd/Dockerfile"),
            (Target::Cln, "/repo/smite/workloads/cln/Dockerfile"),
            (Target::Ldk, "/repo/smite/workloads/ldk/Dockerfile"),
            (Target::Eclair, "/repo/smite/workloads/eclair/Dockerfile"),
        ];

        for (target, expected_dockerfile) in cases {
            let mut args = sample_build_args();
            args.target = Some(target);
            let inputs = BuildInputs::resolve(Some(&config), &args);

            assert_eq!(inputs.dockerfile, Path::new(expected_dockerfile));
        }
    }

    #[test]
    fn resolve_supports_coverage_and_custom_image() {
        let config = sample_config();
        let mut args = sample_build_args();
        args.target = Some(Target::Eclair);
        args.scenario = Some("encrypted_bytes".to_string());
        args.coverage = true;
        args.image = Some("local/eclair-eb:debug".to_string());
        args.no_cache = true;

        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.image, "local/eclair-eb:debug");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/eclair/Dockerfile.coverage")
        );
        assert!(inputs.no_cache);
    }

    #[test]
    fn resolve_uses_config_image_over_default() {
        let mut config = sample_config();
        config.image = Some("custom-image:v1".to_string());
        let args = sample_build_args();

        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.image, "custom-image:v1");
    }

    #[test]
    fn resolve_cli_image_overrides_config_image() {
        let mut config = sample_config();
        config.image = Some("custom-image:v1".to_string());
        let mut args = sample_build_args();
        args.image = Some("cli-image:latest".to_string());

        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.image, "cli-image:latest");
    }

    #[test]
    fn resolve_uses_default_coverage_image_when_not_overridden() {
        let mut config = sample_config();
        config.target = Target::Cln;
        config.scenario = "noise".to_string();
        let mut args = sample_build_args();
        args.coverage = true;

        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.image, "smite-cln-noise-coverage");
        assert_eq!(
            inputs.dockerfile,
            Path::new("/repo/smite/workloads/cln/Dockerfile.coverage")
        );
    }

    #[test]
    fn resolve_overrides_smite_dir() {
        let config = sample_config();
        let mut args = sample_build_args();
        args.smite_dir = Some(PathBuf::from("/tmp/local-smite"));

        let inputs = BuildInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.smite_dir, Path::new("/tmp/local-smite"));
        assert_eq!(
            inputs.dockerfile,
            Path::new("/tmp/local-smite/workloads/ldk/Dockerfile")
        );
    }

    #[test]
    fn resolve_without_config_uses_cli_args() {
        let mut args = sample_build_args();
        args.target = Some(Target::Lnd);
        args.scenario = Some("encrypted_bytes".to_string());

        let inputs = BuildInputs::resolve(None, &args);

        assert_eq!(inputs.image, "smite-lnd-encrypted_bytes");
        assert_eq!(inputs.dockerfile, Path::new("./workloads/lnd/Dockerfile"));
        assert_eq!(inputs.smite_dir, Path::new("."));
        assert_eq!(inputs.scenario, "encrypted_bytes");
    }
}
