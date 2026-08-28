//! Campaign launch orchestration.
//!
//! Builds the Docker image, prepares the Nyx sharedir, spawns parallel
//! `afl-fuzz` processes inside a tmux session, and persists campaign state so
//! that `stop` and `status` can manage the running campaign later.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;

use crate::commands::build::{BuildInputs, run_build};
use crate::config::CampaignConfig;
use crate::state::{CampaignState, RunnerState, Status};
use crate::tmux;
use crate::utils::{setup_nyx, shell_quote};

/// How long to wait for `fuzzer_stats` before treating alive runners as started.
///
/// This is not a correctness gate: a runner whose window dies is caught within
/// one `VERIFY_POLL_INTERVAL` (see `verify_startup`), and a large seed corpus can
/// take minutes to calibrate before `fuzzer_stats` appears. So on deadline, live
/// windows are handed off as running rather than failed. The value only bounds
/// how long we block the terminal before that hand-off; kept short so a slow
/// calibration is not held hostage to a long wait.
const VERIFY_TIMEOUT: Duration = Duration::from_mins(1);

/// How often to poll `fuzzer_stats` files during startup verification.
const VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// AFL++ power schedules for round-robin distribution across runners.
// Index 0 (explore) is AFL++'s default schedule; the primary runs it implicitly
// with no -p flag, so secondaries cycling past the end wrap onto the safe default.
const POWER_SCHEDULES: &[&str] = &["explore", "fast", "coe", "lin", "quad", "exploit", "rare"];

/// Command handler for `smitebot start`.
pub struct StartCommand;

/// CLI arguments for `smitebot start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the campaign configuration TOML file.
    path: PathBuf,
}

impl StartCommand {
    /// Launches a fuzzing campaign from the given configuration.
    pub fn execute(args: &StartArgs) -> bool {
        let config = match CampaignConfig::load(&args.path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        let path_errors = config.check_paths();
        if !path_errors.is_empty() {
            for err in &path_errors {
                log::error!("{err}");
            }
            return false;
        }

        if !tmux::is_available() {
            log::error!("tmux is not available; install it or run `smitebot doctor` for details");
            return false;
        }

        let campaign_id = config.campaign_id();
        let tmux_session = config
            .tmux_session
            .clone()
            .unwrap_or_else(|| campaign_id.clone());

        if tmux::session_exists(&tmux_session) {
            log::error!(
                "tmux session '{tmux_session}' already exists — is another campaign running?"
            );
            return false;
        }

        if let Some(stats) = existing_campaign_runner(&config.output_dir, config.runners) {
            log::error!(
                "output_dir already holds a campaign ({}); smitebot start only \
                 begins fresh campaigns and does not resume — remove the directory \
                 or set a different output_dir",
                stats.display()
            );
            return false;
        }

        let image = config.image_tag();

        log::info!("building Docker image {image}");
        let inputs = BuildInputs::from_config(&config, &image);
        if !run_build(&inputs) {
            return false;
        }

        if config.scenario.starts_with("ir") && !build_ir_mutator(&config.smite_dir) {
            return false;
        }

        log::info!("setting up Nyx sharedir at {}", config.sharedir.display());
        if !setup_nyx(&config, &image) {
            return false;
        }

        let seed_dir = match ensure_seed_dir(&config) {
            Ok(dir) => dir,
            Err(e) => {
                log::error!("failed to prepare seed directory: {e}");
                return false;
            }
        };

        let Some(runs_dir) = CampaignState::runs_dir() else {
            log::error!("unable to determine home directory");
            return false;
        };

        let state_path = runs_dir.join(&campaign_id).join("state.json");

        let Some(git_hash) = smite_git_hash(&config.smite_dir) else {
            log::error!("could not determine smite git hash");
            return false;
        };
        let Some(image_digest) = docker_image_id(&image) else {
            log::error!("could not determine Docker image digest for {image}");
            return false;
        };

        let mut state = CampaignState::new(
            campaign_id,
            &config,
            image,
            image_digest,
            git_hash,
            tmux_session,
        );

        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        if !launch_runners(&config, &seed_dir, &mut state, &state_path) {
            return false;
        }
        if let Err(e) = state.save(&state_path) {
            log::error!("{e}");
            return false;
        }

        log::info!("campaign {} is running", state.id);
        log::info!("state saved to {}", state_path.display());

        log::info!("attaching to tmux session '{}'", state.tmux_session);
        if let Err(e) = tmux::attach(&state.tmux_session) {
            log::warn!("failed to attach to tmux session: {e}");
        }

        true
    }
}

/// Spawns all runners inside a tmux session, verifies they produce
/// `fuzzer_stats`, and updates campaign state with PIDs.
fn launch_runners(
    config: &CampaignConfig,
    seed_dir: &Path,
    state: &mut CampaignState,
    state_path: &Path,
) -> bool {
    let session = &state.tmux_session;
    log::info!(
        "starting {} runners in tmux session '{session}'",
        config.runners
    );

    let testcache_mb = testcache_size_mb();
    let mut runners = Vec::new();

    for id in 0..config.runners {
        let cmd = build_runner_shell_cmd(config, id, seed_dir, testcache_mb);
        let window_name = tmux::runner_window_name(id);

        let result = if id == 0 {
            tmux::create_session(session, &window_name, &cmd)
        } else {
            tmux::add_window(session, &window_name, &cmd)
        };

        if let Err(e) = result {
            log::error!("failed to create tmux window for runner {id}: {e}");
            state.runners = runners;
            fail_campaign(state, state_path);
            return false;
        }

        runners.push(RunnerState { id, pid: None });
    }

    state.runners = runners;

    if let Err(e) = state.save(state_path) {
        log::warn!("failed to save state: {e}");
    }

    log::info!("verifying runners started");
    if !verify_startup(
        session,
        &config.output_dir,
        &mut state.runners,
        VERIFY_TIMEOUT,
    ) {
        // verify_startup has already logged the specific reason per runner
        // (window died, or ceiling reached).
        log::error!("one or more runners failed to start");
        fail_campaign(state, state_path);
        return false;
    }

    state.status = Status::Running;
    true
}

/// Marks the campaign as failed, logs instructions to inspect the tmux session,
/// and persists the updated state.
fn fail_campaign(state: &mut CampaignState, state_path: &Path) {
    if !state.runners.is_empty() {
        log::info!(
            "inspect tmux session '{}' for error output, \
             then: tmux kill-session -t {}",
            state.tmux_session,
            state.tmux_session,
        );
    }
    state.status = Status::Failed;
    if let Err(e) = state.save(state_path) {
        log::warn!("failed to save state: {e}");
    }
}

/// Ensures a seed directory exists for AFL++, creating a minimal corpus if needed.
///
/// When the user omits `seed_dir` from the config, AFL++ still requires `-i`
/// pointing to a non-empty directory.
fn ensure_seed_dir(config: &CampaignConfig) -> std::io::Result<PathBuf> {
    if let Some(dir) = &config.seed_dir {
        return Ok(dir.clone());
    }
    let seed_dir = config.output_dir.join(".seeds");
    fs::create_dir_all(&seed_dir)?;
    if seed_dir.read_dir()?.next().is_none() {
        fs::write(seed_dir.join("seed0"), b"\x00")?;
    }
    Ok(seed_dir)
}

/// Returns the path of the first runner `fuzzer_stats` already present under
/// `output_dir`, indicating a prior campaign's output.
///
/// `start` begins fresh campaigns only. A leftover `fuzzer_stats` would make
/// `verify_startup` read a stale PID and wrongly report a runner as started, so
/// its presence is rejected up front. Resuming an existing output dir is not yet
/// supported. AFL++ writes each runner's output to `output_dir/<id>` (see
/// `RunnerState::name`).
fn existing_campaign_runner(output_dir: &Path, runners: u16) -> Option<PathBuf> {
    (0..runners)
        .map(|id| output_dir.join(id.to_string()).join("fuzzer_stats"))
        .find(|p| p.exists())
}

/// Polls for `fuzzer_stats` files to confirm all runners have started,
/// extracting the `fuzzer_pid` from each.
///
/// `fuzzer_stats` is only written after AFL++ finishes calibrating every seed,
/// which under Nyx can take minutes for a large corpus. A runner whose window
/// dies before producing `fuzzer_stats` is reported as a failure immediately.
/// If `timeout` fires while windows are still alive, the campaign is marked
/// running anyway as the runners are calibrating a large corpus. `execute`
/// rejects a pre-populated `output_dir` up front (see `existing_campaign_runner`),
/// so a `fuzzer_stats` appearing here always belongs to this run.
fn verify_startup(
    session: &str,
    output_dir: &Path,
    runners: &mut [RunnerState],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;

    loop {
        let mut all_ready = true;
        for runner in runners.iter_mut() {
            if runner.pid.is_some() {
                continue;
            }
            let stats_path = output_dir.join(runner.name()).join("fuzzer_stats");
            if let Some(pid) = read_fuzzer_pid(&stats_path) {
                runner.pid = Some(pid);
            } else {
                all_ready = false;
            }
        }

        if all_ready {
            return true;
        }

        // A runner whose window exited before writing fuzzer_stats failed to
        // launch; report it now rather than waiting out the ceiling.
        match tmux::dead_windows(session) {
            Ok(dead) => {
                let mut failed = false;
                for runner in runners.iter().filter(|r| r.pid.is_none()) {
                    if dead.contains(&tmux::runner_window_name(runner.id)) {
                        log::error!(
                            "runner {} exited before producing fuzzer_stats; \
                             inspect window '{}' in tmux session '{session}'",
                            runner.id,
                            tmux::runner_window_name(runner.id),
                        );
                        failed = true;
                    }
                }
                if failed {
                    return false;
                }
            }
            Err(e) => log::debug!("could not query tmux window liveness: {e}"),
        }

        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(VERIFY_POLL_INTERVAL);
    }

    // Deadline reached. Check liveness one final time: alive_windows errors when
    // the session is gone, so an Ok result is authoritative. Runners still alive
    // are calibrating a large seed corpus; treat the campaign as running. PIDs
    // remain None and `smitebot stop` reads them from tmux pane PIDs at teardown.
    let alive = match tmux::alive_windows(session) {
        Ok(a) => a,
        Err(e) => {
            log::error!("could not confirm runners are alive: {e}");
            return false;
        }
    };
    let mut all_alive = true;
    for runner in runners.iter() {
        if runner.pid.is_none() {
            if alive.contains(&tmux::runner_window_name(runner.id)) {
                log::warn!(
                    "runner {} is still calibrating seeds; \
                     attach to session '{session}' to monitor",
                    runner.id
                );
            } else {
                log::error!(
                    "runner {} window is no longer alive; \
                     inspect session '{session}'",
                    runner.id
                );
                all_alive = false;
            }
        }
    }
    all_alive
}

/// Reads the `fuzzer_pid` field from a `fuzzer_stats` file.
fn read_fuzzer_pid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    contents
        .lines()
        .find(|l| l.trim_start().starts_with("fuzzer_pid"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
}

/// FNV-1a hash of `runner_id` followed by `name`, reduced to `0..100`.
///
/// Used to spread mutation modifiers across runners deterministically, so a
/// given runner always draws the same flags. std's `DefaultHasher` is
/// explicitly not stable across Rust releases (see `std::hash` docs), which
/// would break reproducibility, hence this fixed inline hash.
fn modifier_hash(runner_id: u16, name: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for byte in runner_id.to_le_bytes().iter().chain(name.as_bytes()) {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h % 100
}

/// Returns the strategy flags and env vars for a specific runner.
///
/// Distribution is deterministic by runner index. Runner 0 is primary and runs
/// the default (explore) schedule with no modifiers; the mutation modifiers
/// below apply only to secondaries. `has_custom_mutator` is true when an IR
/// scenario or the user's `afl_env` sets `AFL_CUSTOM_MUTATOR_LIBRARY`.
fn runner_strategy(
    runner_id: u16,
    runner_count: u16,
    testcache_mb: Option<u64>,
    has_custom_mutator: bool,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut flags = Vec::new();
    let mut envs = Vec::new();

    if runner_id == 0 {
        envs.push(("AFL_FINAL_SYNC".to_string(), "1".to_string()));
    } else {
        // Secondaries only. fuzzing_in_depth.md §c ("Using multiple cores") puts
        // the power schedule and the strategy knobs under "the other secondaries".
        let schedule = POWER_SCHEDULES[runner_id as usize % POWER_SCHEDULES.len()];
        flags.extend(["-p".to_string(), schedule.to_string()]);

        // Modifiers spread by modifier_hash (X < probability applies), so no two
        // modifiers correlate by runner index. Mutually-exclusive flags share one
        // hash mapped to disjoint ranges so a runner can never draw both values.

        // AFL_DISABLE_TRIM on ~60% of secondary runners.
        if modifier_hash(runner_id, "AFL_DISABLE_TRIM") < 60 {
            envs.push(("AFL_DISABLE_TRIM".to_string(), "1".to_string()));
        }

        // -a binary on ~70% of secondaries: wire messages are binary, so hinting
        // AFL++ to use binary mutation strategies (not text tokenization) fits the
        // target. See https://github.com/AFLplusplus/AFLplusplus/blob/e0b7cae5/src/afl-fuzz.c#L288
        if modifier_hash(runner_id, "-a") < 70 {
            flags.extend(["-a".to_string(), "binary".to_string()]);
        }

        // -P: fixed mutation strategy. explore 40% / exploit 20% / none.
        let p = modifier_hash(runner_id, "-P");
        if p < 40 {
            flags.extend(["-P".to_string(), "explore".to_string()]);
        } else if p < 60 {
            flags.extend(["-P".to_string(), "exploit".to_string()]);
        }

        // -L 0: MOpt mode, ~10%. Custom mutators are incompatible with MOpt —
        // https://github.com/AFLplusplus/AFLplusplus/blob/e0b7cae5/src/afl-fuzz.c#L2417
        // FATALs — so skip -L when one is set.
        if !has_custom_mutator && modifier_hash(runner_id, "-L") < 10 {
            flags.extend(["-L".to_string(), "0".to_string()]);
        }

        // -Z: sequential queue selection instead of weighted random, ~10%.
        if modifier_hash(runner_id, "-Z") < 10 {
            flags.push("-Z".to_string());
        }
    }

    // AFL_IMPORT_FIRST loads test cases from other fuzzers first, but the
    // AFL++ docs warn it "can slow down the start ... if you have many fuzzers."
    // 16 is a heuristic; AFL++ docs don't specify a threshold.
    if runner_count < 16 {
        envs.push(("AFL_IMPORT_FIRST".to_string(), "1".to_string()));
    }

    if let Some(size) = testcache_mb {
        envs.push(("AFL_TESTCACHE_SIZE".to_string(), size.to_string()));
    }

    (flags, envs)
}

/// Returns a suggested `AFL_TESTCACHE_SIZE` in MB based on available RAM.
fn testcache_size_mb() -> Option<u64> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    let free_mb = contents
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb / 1024)?;

    // AFL++ docs recommend 50–500 MB. Thresholds are conservative since
    // multiple runners share the same machine.
    Some(if free_mb > 32_000 {
        500
    } else if free_mb > 8_000 {
        250
    } else {
        50
    })
}

/// Builds the full shell command string for a single runner to be run by tmux.
fn build_runner_shell_cmd(
    config: &CampaignConfig,
    id: u16,
    seed_dir: &Path,
    testcache_mb: Option<u64>,
) -> String {
    let afl_fuzz = config.aflpp_path.join("afl-fuzz");
    // -L (MOpt) is incompatible with custom mutators; runner_strategy skips it
    // when an IR scenario or the user's afl_env supplies AFL_CUSTOM_MUTATOR_LIBRARY.
    let has_custom_mutator = config.scenario.starts_with("ir")
        || config.afl_env.contains_key("AFL_CUSTOM_MUTATOR_LIBRARY");
    let (strategy_flags, strategy_envs) =
        runner_strategy(id, config.runners, testcache_mb, has_custom_mutator);

    // Env precedence: strategy → IR mutator → user afl_env (last wins).
    let mut envs = strategy_envs;
    for (k, v) in ir_mutator_envs(config) {
        envs.push((k.to_string(), v));
    }
    for (k, v) in &config.afl_env {
        envs.push((k.clone(), v.clone()));
    }

    let mut parts: Vec<String> = envs
        .iter()
        .map(|(k, v)| format!("{}={}", k, shell_quote(v)))
        .collect();

    parts.push("exec".to_string());
    parts.push(shell_quote(&afl_fuzz.display().to_string()));
    parts.extend([
        "-Y".to_string(),
        "-i".to_string(),
        shell_quote(&seed_dir.display().to_string()),
        "-o".to_string(),
        shell_quote(&config.output_dir.display().to_string()),
        if id == 0 { "-M" } else { "-S" }.to_string(),
        id.to_string(),
    ]);

    for flag in &strategy_flags {
        parts.push(shell_quote(flag));
    }
    for flag in &config.afl_flags {
        parts.push(shell_quote(flag));
    }

    parts.push("--".to_string());
    parts.push(shell_quote(&config.sharedir.display().to_string()));

    parts.join(" ")
}

/// Returns the environment variables needed for the smite-ir custom mutator.
///
/// For IR scenarios, these set up AFL++ to use the custom mutator library and
/// disable built-in mutators. Returns an empty vec for non-IR scenarios.
fn ir_mutator_envs(config: &CampaignConfig) -> Vec<(&'static str, String)> {
    if !config.scenario.starts_with("ir") {
        return Vec::new();
    }
    // BOLT 2 makes the two channel establishment flows mutually exclusive on
    // one connection, so draw only from the generators this scenario's target
    // can act on. The other flow's programs would be rejected outright.
    let generators = if config.scenario == "ir_v2" {
        "v2"
    } else {
        "v1"
    };
    vec![
        (
            "AFL_CUSTOM_MUTATOR_LIBRARY",
            config.ir_mutator_path().to_string_lossy().into_owned(),
        ),
        ("AFL_CUSTOM_MUTATOR_ONLY", "1".to_string()),
        ("AFL_FRAMESHIFT_DISABLE", "1".to_string()),
        ("SMITE_IR_GENERATORS", generators.to_string()),
    ]
}

/// Builds the smite-ir-mutator shared library in release mode.
fn build_ir_mutator(smite_dir: &Path) -> bool {
    log::info!("building IR mutator library");
    let status = match Command::new("cargo")
        .args(["build", "--release", "-p", "smite-ir-mutator"])
        .current_dir(smite_dir)
        .status()
    {
        Ok(status) => status,
        Err(e) => {
            log::error!("failed to run cargo build: {e}");
            return false;
        }
    };

    if !status.success() {
        log::error!("cargo build for smite-ir-mutator failed with {status}");
        return false;
    }

    true
}

/// Runs a command and returns its trimmed stdout on success.
fn command_stdout(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns the smite repository git hash, or `None` if not a git repo.
fn smite_git_hash(smite_dir: &Path) -> Option<String> {
    command_stdout(
        Command::new("git")
            .arg("-C")
            .arg(smite_dir)
            .args(["rev-parse", "HEAD"]),
    )
}

/// Returns the Docker image ID hash for a locally built image.
fn docker_image_id(image: &str) -> Option<String> {
    command_stdout(
        Command::new("docker")
            .args(["inspect", "--format={{.Id}}"])
            .arg(image),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn read_fuzzer_pid_parses_pid() {
        let dir = tempfile::tempdir().unwrap();
        let stats = dir.path().join("fuzzer_stats");
        fs::write(
            &stats,
            "start_time        : 1718000000\nfuzzer_pid        : 12345\nexecs_per_sec     : 0.00\n",
        )
        .unwrap();
        assert_eq!(read_fuzzer_pid(&stats), Some(12345));
    }

    #[test]
    fn read_fuzzer_pid_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_fuzzer_pid(&dir.path().join("missing")), None);
    }

    #[test]
    fn verify_startup_reads_pids_from_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        let stats_content =
            "start_time        : 1718000000\nfuzzer_pid        : 42\nexecs_per_sec     : 0.00\n";

        let mut runners = vec![
            RunnerState { id: 0, pid: None },
            RunnerState { id: 1, pid: None },
        ];

        for runner in &runners {
            let runner_dir = dir.path().join(runner.name());
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(runner_dir.join("fuzzer_stats"), stats_content).unwrap();
        }

        // All stats are present on the first poll.
        assert!(verify_startup(
            "no-such-session",
            dir.path(),
            &mut runners,
            Duration::from_secs(5),
        ));
        assert_eq!(runners[0].pid, Some(42));
        assert_eq!(runners[1].pid, Some(42));
    }

    #[test]
    fn verify_startup_returns_false_when_stats_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut runners = vec![RunnerState { id: 0, pid: None }];

        // No fuzzer_stats and no live tmux session, alive_windows errors and
        // the runner is reported as failed. A near-zero timeout keeps the test fast.
        assert!(!verify_startup(
            "no-such-session",
            dir.path(),
            &mut runners,
            Duration::from_millis(1),
        ));
        assert!(runners[0].pid.is_none());
    }

    #[test]
    fn existing_campaign_runner_detects_leftover_fuzzer_stats() {
        let dir = tempfile::tempdir().unwrap();
        // A prior run of the secondary left fuzzer_stats behind.
        let runner_dir = dir.path().join("1");
        fs::create_dir_all(&runner_dir).unwrap();
        fs::write(runner_dir.join("fuzzer_stats"), "fuzzer_pid : 7\n").unwrap();

        assert_eq!(
            existing_campaign_runner(dir.path(), 2),
            Some(runner_dir.join("fuzzer_stats"))
        );
    }

    #[test]
    fn existing_campaign_runner_none_for_fresh_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Empty output dir (and one with only the synthesized .seeds) is fresh.
        assert_eq!(existing_campaign_runner(dir.path(), 4), None);
    }

    #[test]
    fn runner_strategy_primary_gets_final_sync() {
        let (_, envs) = runner_strategy(0, 8, None, false);
        assert!(envs.iter().any(|(k, v)| k == "AFL_FINAL_SYNC" && v == "1"));
    }

    #[test]
    fn runner_strategy_primary_gets_no_modifiers() {
        // Modifiers apply to secondaries only, never the primary.
        let (flags, envs) = runner_strategy(0, 10, None, false);
        for modifier in ["-p", "-a", "-P", "-L", "-Z"] {
            assert!(
                !flags.contains(&modifier.to_string()),
                "primary got {modifier}"
            );
        }
        assert!(!envs.iter().any(|(k, _)| k == "AFL_DISABLE_TRIM"));
    }

    #[test]
    fn runner_strategy_secondary_no_final_sync() {
        let (_, envs) = runner_strategy(1, 8, None, false);
        assert!(!envs.iter().any(|(k, _)| k == "AFL_FINAL_SYNC"));
    }

    #[test]
    fn runner_strategy_cycles_power_schedules() {
        // Secondaries (id 1..) index the array directly; explore (index 0) is
        // the primary's default, so the first secondary starts at fast.
        let schedules: Vec<String> = (1..8)
            .map(|id| {
                let (flags, _) = runner_strategy(id, 16, None, false);
                flags[1].clone()
            })
            .collect();
        assert_eq!(
            schedules,
            ["fast", "coe", "lin", "quad", "exploit", "rare", "explore"]
        );
    }

    #[test]
    fn runner_strategy_wraps_schedules_past_seven() {
        // id 7 wraps to index 0 = explore.
        let (flags, _) = runner_strategy(7, 16, None, false);
        assert_eq!(flags[1], "explore");
    }

    #[test]
    fn runner_strategy_input_format_binary_70_percent() {
        // 100 secondaries; expect ~70 with -a binary. Allow ±15 for hash spread.
        let binary_count = (1..=100u16)
            .filter(|&id| {
                let (flags, _) = runner_strategy(id, 101, None, false);
                flags.contains(&"binary".to_string())
            })
            .count();
        assert!(
            (55..=85).contains(&binary_count),
            "binary_count={binary_count}, expected ~70"
        );
    }

    #[test]
    fn runner_strategy_fixed_strategy_probabilities() {
        // 100 secondaries; -P explore ~40%, exploit ~20%. Allow ±15.
        let mut explore_count = 0usize;
        let mut exploit_count = 0usize;
        for id in 1..=100u16 {
            let (flags, _) = runner_strategy(id, 101, None, false);
            assert!(flags.iter().filter(|f| *f == "-P").count() <= 1);
            if let Some(pos) = flags.iter().position(|f| f == "-P") {
                match flags[pos + 1].as_str() {
                    "explore" => explore_count += 1,
                    "exploit" => exploit_count += 1,
                    other => panic!("unexpected -P value {other}"),
                }
            }
        }
        assert!(
            (25..=55).contains(&explore_count),
            "explore_count={explore_count}, expected ~40"
        );
        assert!(
            (8..=32).contains(&exploit_count),
            "exploit_count={exploit_count}, expected ~20"
        );
    }

    #[test]
    fn runner_strategy_skips_mopt_with_custom_mutator() {
        // -L (MOpt) FATALs with custom mutators (afl-fuzz.c#L2417): never emitted.
        for id in 1..=100u16 {
            let (flags, _) = runner_strategy(id, 101, None, true);
            assert!(
                !flags.contains(&"-L".to_string()),
                "id {id} got -L with custom mutator"
            );
        }
    }

    #[test]
    fn runner_strategy_mopt_probability() {
        // 100 secondaries; -L 0 ~10%. Allow ±10.
        let mopt_count = (1..=100u16)
            .filter(|&id| {
                let (flags, _) = runner_strategy(id, 101, None, false);
                flags.contains(&"-L".to_string())
            })
            .count();
        assert!(
            (2..=20).contains(&mopt_count),
            "mopt_count={mopt_count}, expected ~10"
        );
    }

    #[test]
    fn runner_strategy_sequential_queue_probability() {
        // 100 secondaries; -Z ~10%. Allow ±10.
        let z_count = (1..=100u16)
            .filter(|&id| {
                let (flags, _) = runner_strategy(id, 101, None, false);
                flags.contains(&"-Z".to_string())
            })
            .count();
        assert!(
            (2..=20).contains(&z_count),
            "z_count={z_count}, expected ~10"
        );
    }

    #[test]
    fn runner_strategy_deterministic() {
        // Same inputs always yield the same flags — reproducibility guarantee.
        assert_eq!(
            runner_strategy(5, 16, None, false),
            runner_strategy(5, 16, None, false)
        );
    }

    #[test]
    fn runner_strategy_disable_trim_60_percent() {
        // 100 secondaries; expect ~60 with AFL_DISABLE_TRIM. Allow ±15.
        let trim_count = (1..=100u16)
            .filter(|&id| {
                let (_, envs) = runner_strategy(id, 101, None, false);
                envs.iter().any(|(k, _)| k == "AFL_DISABLE_TRIM")
            })
            .count();
        assert!(
            (45..=75).contains(&trim_count),
            "trim_count={trim_count}, expected ~60"
        );
    }

    #[test]
    fn runner_strategy_import_first_under_16() {
        let (_, envs) = runner_strategy(0, 8, None, false);
        assert!(envs.iter().any(|(k, _)| k == "AFL_IMPORT_FIRST"));

        let (_, envs) = runner_strategy(0, 16, None, false);
        assert!(!envs.iter().any(|(k, _)| k == "AFL_IMPORT_FIRST"));
    }

    #[test]
    fn runner_strategy_includes_testcache() {
        let (_, envs) = runner_strategy(0, 8, Some(500), false);
        assert!(
            envs.iter()
                .any(|(k, v)| k == "AFL_TESTCACHE_SIZE" && v == "500")
        );
    }

    #[test]
    fn build_runner_shell_cmd_primary() {
        let dir = tempfile::tempdir().unwrap();
        let config = sample_config(dir.path());
        let seed_dir = dir.path().join("seeds");

        let cmd = build_runner_shell_cmd(&config, 0, &seed_dir, Some(500));

        assert!(cmd.contains("exec"));
        assert!(cmd.contains("afl-fuzz"));
        assert!(cmd.contains("-Y"));
        assert!(cmd.contains("-M"));
        assert!(cmd.contains("AFL_FINAL_SYNC='1'"));
        assert!(cmd.contains("AFL_TESTCACHE_SIZE='500'"));
        // Primary uses the default schedule: no -p flag.
        assert!(!cmd.contains("-p"));
    }

    #[test]
    fn build_runner_shell_cmd_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let config = sample_config(dir.path());
        let seed_dir = dir.path().join("seeds");

        let cmd = build_runner_shell_cmd(&config, 1, &seed_dir, None);

        assert!(cmd.contains("-S"));
        assert!(!cmd.contains("-M"));
        assert!(!cmd.contains("AFL_FINAL_SYNC"));
    }

    #[test]
    fn build_runner_shell_cmd_respects_env_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 2
output_dir = "{}"
sharedir = "{}"

[afl_env]
AFL_IMPORT_FIRST = "0"
"#,
                dir.path().display(),
                dir.path().display(),
                dir.path().join("out").display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();
        let seed_dir = dir.path().join("seeds");

        let cmd = build_runner_shell_cmd(&config, 1, &seed_dir, None);

        // Strategy sets AFL_IMPORT_FIRST='1' (runners < 16) first, user override
        // AFL_IMPORT_FIRST='0' last. Both appear; shell uses the last assignment.
        let first_pos = cmd.find("AFL_IMPORT_FIRST='1'").unwrap();
        let last_pos = cmd.find("AFL_IMPORT_FIRST='0'").unwrap();
        assert!(last_pos > first_pos);
    }

    #[test]
    fn ensure_seed_dir_returns_user_path_when_specified() {
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("my-seeds");
        fs::create_dir(&seed).unwrap();
        fs::write(seed.join("input0"), b"\x00").unwrap();

        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 1
seed_dir = "{}"
output_dir = "{}"
sharedir = "{}"
"#,
                dir.path().display(),
                dir.path().display(),
                seed.display(),
                dir.path().join("out").display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let result = ensure_seed_dir(&config).unwrap();
        assert_eq!(result, seed);
    }

    #[test]
    fn ensure_seed_dir_creates_minimal_corpus_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("out");
        fs::create_dir(&output_dir).unwrap();

        let config_path = dir.path().join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 1
output_dir = "{}"
sharedir = "{}"
"#,
                dir.path().display(),
                dir.path().display(),
                output_dir.display(),
                dir.path().join("nyx").display(),
            ),
        )
        .unwrap();
        let config = CampaignConfig::load(&config_path).unwrap();

        let result = ensure_seed_dir(&config).unwrap();
        assert_eq!(result, output_dir.join(".seeds"));
        assert!(result.join("seed0").exists());
    }

    /// A campaign config for the given IR scenario.
    fn ir_config(dir: &Path, scenario: &str) -> CampaignConfig {
        let config_path = dir.join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "{scenario}"
aflpp_path = "{aflpp}"
smite_dir = "{smite}"
runners = 1
output_dir = "{out}"
sharedir = "{sharedir}"
"#,
                aflpp = dir.display(),
                smite = dir.display(),
                out = dir.join("out").display(),
                sharedir = dir.join("nyx").display(),
            ),
        )
        .unwrap();
        CampaignConfig::load(&config_path).unwrap()
    }

    #[test]
    fn ir_mutator_envs_sets_vars_for_ir_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let config = ir_config(dir.path(), "ir_bytes");

        let envs = ir_mutator_envs(&config);

        assert_eq!(envs.len(), 4);
        assert_eq!(envs[0].0, "AFL_CUSTOM_MUTATOR_LIBRARY");
        assert!(envs[0].1.ends_with("libsmite_ir_mutator.so"));
        assert_eq!(envs[1], ("AFL_CUSTOM_MUTATOR_ONLY", "1".to_string()));
        assert_eq!(envs[2], ("AFL_FRAMESHIFT_DISABLE", "1".to_string()));
        // The `ir` scenario negotiates no dual funding, so it draws only the
        // single-funded generators.
        assert_eq!(envs[3], ("SMITE_IR_GENERATORS", "v1".to_string()));
    }

    #[test]
    fn ir_mutator_envs_selects_dual_funded_generators_for_ir_v2() {
        let dir = tempfile::tempdir().unwrap();
        let config = ir_config(dir.path(), "ir_v2");

        let envs = ir_mutator_envs(&config);

        assert_eq!(envs[3], ("SMITE_IR_GENERATORS", "v2".to_string()));
    }

    #[test]
    fn ir_mutator_envs_empty_for_non_ir_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let config = sample_config(dir.path());
        assert!(ir_mutator_envs(&config).is_empty());
    }

    fn sample_config(dir: &Path) -> CampaignConfig {
        let config_path = dir.join("campaign.toml");
        fs::write(
            &config_path,
            format!(
                r#"
target = "lnd"
scenario = "encrypted_bytes"
aflpp_path = "{}"
smite_dir = "{}"
runners = 8
output_dir = "{}"
sharedir = "{}"
"#,
                dir.display(),
                dir.display(),
                dir.join("out").display(),
                dir.join("nyx").display(),
            ),
        )
        .unwrap();
        CampaignConfig::load(&config_path).unwrap()
    }
}
