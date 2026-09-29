//! Host prerequisite checks for Smite fuzzing campaigns.
//! The output is intentionally stable so CI and operators can diff or parse it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use clap::Args;
use serde::Serialize;

use crate::config::CampaignConfig;
use crate::utils::{afl_bin_dir, find_in_path, is_executable};

/// AFL++ binaries required for campaign execution and corpus minimization.
const AFL_TOOLS: &[&str] = &["afl-fuzz", "afl-cmin", "afl-tmin", "afl-whatsup"];

/// Host tools required for campaign operations.
const HOST_TOOLS: &[&str] = &["bash", "python", "python3", "tmux"];

/// Repository scripts required by doctor and upcoming orchestration commands.
const REQUIRED_SCRIPTS: &[&str] = &[
    "setup-nyx.sh",
    "coverage-report.sh",
    "symbolize-crash.sh",
    "enable-vmware-backdoor.sh",
];

/// Workload Dockerfiles required for normal and coverage image builds.
const REQUIRED_DOCKERFILES: &[&str] = &[
    "workloads/lnd/Dockerfile",
    "workloads/lnd/Dockerfile.coverage",
    "workloads/ldk/Dockerfile",
    "workloads/ldk/Dockerfile.coverage",
    "workloads/cln/Dockerfile",
    "workloads/cln/Dockerfile.coverage",
    "workloads/eclair/Dockerfile",
    "workloads/eclair/Dockerfile.coverage",
];

/// Command handler for `smitebot doctor`.
pub struct DoctorCommand;

/// CLI arguments for `smitebot doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Path to a campaign configuration TOML file. When provided, settings are
    /// read from the file and CLI flags override individual values.
    config: Option<PathBuf>,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    json: bool,
    /// Path to AFL++ source tree; overrides the config value.
    #[arg(long, required_unless_present = "config")]
    aflpp_path: Option<PathBuf>,
    /// Path to smite repository root; overrides the config value.
    #[arg(long)]
    smite_dir: Option<PathBuf>,
}

/// Fully resolved doctor check inputs.
struct DoctorInputs {
    /// Path to the AFL++ source tree.
    aflpp_root: PathBuf,
    /// Smite repository root for checking scripts and Dockerfiles.
    smite_dir: PathBuf,
}

impl DoctorInputs {
    /// Resolves doctor inputs from an optional config, overriding with CLI args.
    ///
    /// Clap enforces that `--aflpp-path` is present when no config file is
    /// provided; `--smite-dir` defaults to the current directory.
    fn resolve(config: Option<&CampaignConfig>, args: &DoctorArgs) -> Self {
        let aflpp_root = args
            .aflpp_path
            .clone()
            .or_else(|| config.map(|c| c.aflpp_path.clone()))
            .expect("clap ensures --aflpp-path is present when config is absent");
        let smite_dir = args
            .smite_dir
            .clone()
            .or_else(|| config.map(|c| c.smite_dir.clone()))
            .unwrap_or_else(|| PathBuf::from("."));

        Self {
            aflpp_root,
            smite_dir,
        }
    }
}

/// A single prerequisite check and its outcome.
#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CheckFailure>,
}

impl DoctorCheck {
    /// Creates a report entry from a named doctor check result.
    fn new(name: impl Into<String>, result: Result<(), CheckFailure>) -> Self {
        Self {
            name: name.into(),
            passed: result.is_ok(),
            reason: result.err(),
        }
    }
}

/// Aggregate report for human output or JSON serialization.
#[derive(Debug, Serialize)]
struct DoctorReport {
    overall: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, thiserror::Error)]
enum CheckFailure {
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error(
        "neither vmx nor svm flag found in /proc/cpuinfo; enable VT-x (Intel) or AMD-V (AMD) in your BIOS/UEFI settings"
    )]
    MissingCpuVirtualization,
    #[error("{} not found", .0.display())]
    MissingPath(PathBuf),
    #[error("{} not executable; run: chmod +x {}", .0.display(), .0.display())]
    NotExecutable(PathBuf),
    #[error("{}: {error}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        error: io::Error,
    },
    #[error("{0} not found on PATH")]
    ToolNotFound(String),
    #[error("{command}: {detail}")]
    Command { command: String, detail: String },
    #[error(
        "libnyx.so not found under --aflpp-path; rebuild AFL++ with Nyx support (see nyx_mode/README.md in your AFL++ source tree)"
    )]
    LibnyxNotFound,
    #[error(
        "nyx_mode/packer/packer not found under --aflpp-path; Nyx packer is required for scripts/setup-nyx.sh"
    )]
    NyxPackerNotFound,
    #[error("backdoor disabled; run ./scripts/enable-vmware-backdoor.sh to enable")]
    VMwareBackdoorDisabled,
}

impl CheckFailure {
    /// Creates an I/O failure associated with a filesystem path.
    fn io(path: &Path, error: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            error,
        }
    }
}

impl Serialize for CheckFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Keep JSON schema simple: serialize as the user-facing string.
        serializer.serialize_str(&self.to_string())
    }
}

impl DoctorCommand {
    /// Runs all doctor checks and prints either human-readable or JSON output.
    pub fn execute(args: &DoctorArgs) -> bool {
        let config = match &args.config {
            Some(path) => match CampaignConfig::load(path) {
                Ok(c) => Some(c),
                Err(e) => {
                    log::error!("{e}");
                    return false;
                }
            },
            None => None,
        };
        let inputs = DoctorInputs::resolve(config.as_ref(), args);
        let afl_bin = afl_bin_dir(&inputs.aflpp_root);
        let smite_dir = &inputs.smite_dir;

        // Keep a predictable order for operator readability and stable JSON output.
        let mut checks = vec![
            DoctorCheck::new("x86_64 architecture", check_architecture()),
            DoctorCheck::new(
                "CPU virtualization enabled (vmx/svm)",
                check_cpu_virtualization_enabled(),
            ),
            DoctorCheck::new("/dev/kvm accessible", check_kvm_access()),
            DoctorCheck::new("Docker daemon reachable", check_docker_daemon()),
            DoctorCheck::new("AFL++ built with Nyx support", check_libnyx(&afl_bin)),
            DoctorCheck::new("Nyx packer available", check_nyx_packer(&inputs.aflpp_root)),
            DoctorCheck::new("VMware backdoor enabled", check_vmware_backdoor_enabled()),
        ];

        for &tool in AFL_TOOLS {
            checks.push(DoctorCheck::new(
                tool,
                require_executable(&afl_bin.join(tool)),
            ));
        }

        for &tool in HOST_TOOLS {
            checks.push(DoctorCheck::new(tool, require_tool_on_path(tool)));
        }

        for script in REQUIRED_SCRIPTS {
            let path = smite_dir.join("scripts").join(script);
            checks.push(DoctorCheck::new(
                format!("script executable: scripts/{script}"),
                require_executable(&path),
            ));
        }

        for dockerfile in REQUIRED_DOCKERFILES {
            let path = smite_dir.join(dockerfile);
            checks.push(DoctorCheck::new(
                format!("dockerfile present: {dockerfile}"),
                require_exists(&path),
            ));
        }

        let overall = checks.iter().all(|check| check.passed);
        let report = DoctorReport { overall, checks };

        if args.json {
            // JSON output is used by CI or external tooling to surface failures.
            let json =
                serde_json::to_string_pretty(&report).expect("DoctorReport is always serializable");
            println!("{json}");
        } else {
            print_human_report(&report);
        }

        report.overall
    }
}

/// Prints a compact checklist report intended for interactive terminal use.
fn print_human_report(report: &DoctorReport) {
    for check in &report.checks {
        match &check.reason {
            None => println!("[ok] {}", check.name),
            Some(reason) => println!("[fail] {}: {reason}", check.name),
        }
    }

    let total = report.checks.len();
    if report.overall {
        println!("\nsmitebot doctor: all {total} checks passed");
    } else {
        let failed = report.checks.iter().filter(|check| !check.passed).count();
        println!("\nsmitebot doctor: {failed} of {total} checks failed");
    }
}

/// Verifies that the host architecture is supported by Nyx mode.
fn check_architecture() -> Result<(), CheckFailure> {
    let arch = std::env::consts::ARCH;
    if arch == "x86_64" {
        Ok(())
    } else {
        Err(CheckFailure::UnsupportedArchitecture(arch.to_string()))
    }
}

/// Checks for CPU virtualization flags required by KVM acceleration.
fn check_cpu_virtualization_enabled() -> Result<(), CheckFailure> {
    let path = Path::new("/proc/cpuinfo");
    let cpuinfo = fs::read_to_string(path).map_err(|e| CheckFailure::io(path, e))?;

    let has_flag = cpuinfo
        .split_whitespace()
        .any(|flag| flag == "vmx" || flag == "svm");

    if has_flag {
        Ok(())
    } else {
        Err(CheckFailure::MissingCpuVirtualization)
    }
}

/// Verifies that `/dev/kvm` exists and is openable by the current user.
fn check_kvm_access() -> Result<(), CheckFailure> {
    let path = Path::new("/dev/kvm");
    require_exists(path)?;
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| CheckFailure::io(path, e))?;
    Ok(())
}

/// Checks that the Docker CLI can reach a running Docker daemon.
fn check_docker_daemon() -> Result<(), CheckFailure> {
    require_tool_on_path("docker")?;

    let output = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map_err(|e| CheckFailure::Command {
            command: "docker version".to_string(),
            detail: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(CheckFailure::Command {
            command: "docker version".to_string(),
            detail: command_failure_detail(&output),
        })
    }
}

/// Checks whether `libnyx.so` exists in AFL++'s binary directory.
fn check_libnyx(afl_bin: &Path) -> Result<(), CheckFailure> {
    if afl_bin.join("libnyx.so").exists() {
        Ok(())
    } else {
        Err(CheckFailure::LibnyxNotFound)
    }
}

/// Checks for the Nyx packer tree `scripts/setup-nyx.sh` needs to build a sharedir.
///
/// The packer lives in the AFL++ source tree rather than next to the binaries,
/// so it is resolved from the configured root instead of [`afl_bin_dir`].
fn check_nyx_packer(aflpp_root: &Path) -> Result<(), CheckFailure> {
    if aflpp_root
        .join("nyx_mode")
        .join("packer")
        .join("packer")
        .is_dir()
    {
        Ok(())
    } else {
        Err(CheckFailure::NyxPackerNotFound)
    }
}

/// Checks whether the KVM `VMware` backdoor needed by Nyx is enabled.
fn check_vmware_backdoor_enabled() -> Result<(), CheckFailure> {
    let path = Path::new("/sys/module/kvm/parameters/enable_vmware_backdoor");
    let contents = fs::read_to_string(path).map_err(|e| CheckFailure::io(path, e))?;

    if contents.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(CheckFailure::VMwareBackdoorDisabled)
    }
}

/// Returns success only when the path exists.
fn require_exists(path: &Path) -> Result<(), CheckFailure> {
    if path.exists() {
        Ok(())
    } else {
        Err(CheckFailure::MissingPath(path.to_path_buf()))
    }
}

/// Returns success only when the path exists and has an executable bit set.
fn require_executable(path: &Path) -> Result<(), CheckFailure> {
    require_exists(path)?;
    if is_executable(path) {
        Ok(())
    } else {
        Err(CheckFailure::NotExecutable(path.to_path_buf()))
    }
}

/// Returns success when a tool is executable on `PATH`.
fn require_tool_on_path(tool: &str) -> Result<(), CheckFailure> {
    if find_in_path(tool).is_some() {
        Ok(())
    } else {
        Err(CheckFailure::ToolNotFound(tool.to_string()))
    }
}

/// Builds a useful failure detail from a completed command.
fn command_failure_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = stderr.trim();
    let stdout = stdout.trim();

    match (stderr, stdout) {
        ("", "") => output.status.to_string(),
        ("", out) => format!("{} ({out})", output.status),
        (err, _) => format!("{} ({err})", output.status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::config::Target;

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

    fn sample_doctor_args() -> DoctorArgs {
        DoctorArgs {
            config: None,
            json: false,
            aflpp_path: None,
            smite_dir: None,
        }
    }

    #[test]
    fn resolve_uses_config_values_by_default() {
        let config = sample_config();
        let args = sample_doctor_args();
        let inputs = DoctorInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.aflpp_root, Path::new("/home/user/AFLplusplus"));
        assert_eq!(inputs.smite_dir, Path::new("/repo/smite"));
    }

    #[test]
    fn resolve_overrides_aflpp_path() {
        let config = sample_config();
        let mut args = sample_doctor_args();
        args.aflpp_path = Some(PathBuf::from("/tmp/other-aflpp"));

        let inputs = DoctorInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.aflpp_root, Path::new("/tmp/other-aflpp"));
        assert_eq!(inputs.smite_dir, Path::new("/repo/smite"));
    }

    #[test]
    fn resolve_overrides_smite_dir() {
        let config = sample_config();
        let mut args = sample_doctor_args();
        args.smite_dir = Some(PathBuf::from("/tmp/local-smite"));

        let inputs = DoctorInputs::resolve(Some(&config), &args);

        assert_eq!(inputs.smite_dir, Path::new("/tmp/local-smite"));
    }

    #[test]
    fn resolve_without_config_uses_cli_args() {
        let mut args = sample_doctor_args();
        args.aflpp_path = Some(PathBuf::from("/opt/aflpp"));

        let inputs = DoctorInputs::resolve(None, &args);

        assert_eq!(inputs.aflpp_root, Path::new("/opt/aflpp"));
        assert_eq!(inputs.smite_dir, Path::new("."));
    }

    #[test]
    fn resolve_without_config_overrides_smite_dir() {
        let mut args = sample_doctor_args();
        args.aflpp_path = Some(PathBuf::from("/opt/aflpp"));
        args.smite_dir = Some(PathBuf::from("/custom/smite"));

        let inputs = DoctorInputs::resolve(None, &args);

        assert_eq!(inputs.smite_dir, Path::new("/custom/smite"));
    }

    #[test]
    fn require_exists_reports_missing_path() {
        let path = Path::new("/definitely/not/a/smitebot/path");
        let err = require_exists(path).unwrap_err();
        assert_eq!(err.to_string(), "/definitely/not/a/smitebot/path not found");
    }

    #[test]
    fn require_executable_rejects_non_executable_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("tool");
        fs::write(&path, "#!/bin/sh\n").unwrap();

        let err = require_executable(&path).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{p} not executable; run: chmod +x {p}", p = path.display())
        );
    }

    #[test]
    fn require_executable_finds_afl_tool_under_aflpp_root() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let tool_path = tempdir.path().join("afl-fuzz");
        fs::write(&tool_path, "#!/bin/sh\n").unwrap();
        // Force executable permissions so the test doesn't depend on umask defaults.
        let mut perms = fs::metadata(&tool_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tool_path, perms).unwrap();

        assert!(require_executable(&tempdir.path().join("afl-fuzz")).is_ok());
    }

    #[test]
    fn check_nyx_packer_accepts_aflpp_root_with_packer() {
        let tempdir = tempfile::tempdir().unwrap();
        fs::create_dir_all(tempdir.path().join("nyx_mode/packer/packer")).unwrap();

        assert!(check_nyx_packer(tempdir.path()).is_ok());
    }

    #[test]
    fn check_nyx_packer_rejects_bin_dir_of_installed_package() {
        let tempdir = tempfile::tempdir().unwrap();
        fs::create_dir_all(tempdir.path().join("nyx_mode/packer/packer")).unwrap();
        let bin = tempdir.path().join("bin");
        fs::create_dir(&bin).unwrap();

        let err = check_nyx_packer(&bin).unwrap_err();
        assert!(err.to_string().contains("nyx_mode/packer/packer not found"));
    }

    #[test]
    fn doctor_report_json_is_machine_readable() {
        let report = DoctorReport {
            overall: false,
            checks: vec![
                DoctorCheck::new("check-a", Ok(())),
                DoctorCheck::new("check-b", Err(CheckFailure::MissingCpuVirtualization)),
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["overall"], false);
        assert_eq!(parsed["checks"][0]["name"], "check-a");
        assert!(parsed["checks"][0].get("reason").is_none());
        assert_eq!(parsed["checks"][1]["passed"], false);
        assert_eq!(
            parsed["checks"][1]["reason"],
            "neither vmx nor svm flag found in /proc/cpuinfo; enable VT-x (Intel) or AMD-V (AMD) in your BIOS/UEFI settings"
        );
    }

    #[test]
    fn command_failure_detail_prefers_stderr() {
        let output = output_with("stdout msg", "stderr msg");
        assert_eq!(
            command_failure_detail(&output),
            "exit status: 1 (stderr msg)"
        );
    }

    #[test]
    fn command_failure_detail_uses_stdout_if_stderr_empty() {
        let output = output_with("stdout msg", "");
        assert_eq!(
            command_failure_detail(&output),
            "exit status: 1 (stdout msg)"
        );
    }

    #[test]
    fn command_failure_detail_handles_no_output() {
        let output = output_with("", "");
        assert_eq!(command_failure_detail(&output), "exit status: 1");
    }

    fn output_with(stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;

        // Build a synthetic Output so tests don't rely on executing external commands.
        std::process::Output {
            status: ExitStatus::from_raw(1 << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }
}
