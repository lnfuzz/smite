//! Campaign status reporting: a one-shot text summary and a live tmux dashboard.
//!
//! `status` detects whether the campaign is still running by checking for its
//! tmux session. A dead campaign (or `--summary`) prints a static snapshot of
//! each runner's `fuzzer_stats`. A live campaign gets an extra tmux window that
//! re-runs the snapshot on an interval, then attaches so the user can flip
//! between the runner windows and the summary.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use clap::Args;

use crate::state::{CampaignState, RunnerState, Status};
use crate::tmux;
use crate::utils::{self, shell_quote};

/// Name of the tmux window hosting the reloading status view.
const STATUS_WINDOW: &str = "status";

/// Reload interval (seconds) for the live status window.
///
/// AFL++ rewrites `fuzzer_stats` at most every `STATS_UPDATE_SEC` (60, see
/// AFL++ `include/config.h`), so refreshing faster only redraws identical
/// numbers.
const RELOAD_SECS: u32 = 60;

/// Command handler for `smitebot status`.
pub struct StatusCommand;

/// CLI arguments for `smitebot status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Campaign ID to inspect (a directory name under `~/.smitebot/runs`).
    campaign_id: String,
    /// Print a one-shot text summary instead of attaching to the live dashboard.
    #[arg(long)]
    summary: bool,
}

impl StatusCommand {
    /// Reports the status of a campaign, either as a one-shot summary or by
    /// attaching to its live tmux dashboard.
    pub fn execute(args: &StatusArgs) -> bool {
        let (state, _) = match CampaignState::load_campaign(&args.campaign_id) {
            Ok(x) => x,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        // state.status is written only at start and by `stop`, so it can be
        // stale (e.g. still "running" for a campaign that has since crashed).
        // The live tmux session reconciles it against reality — both for the
        // snapshot-vs-dashboard choice below and for the reported status.
        let session_alive = tmux::session_exists(&state.tmux_session);

        if !session_alive || args.summary {
            let alive_runner_ids = match alive_runners(&state, session_alive) {
                Ok(ids) => ids,
                Err(e) => {
                    // A live session we can't query is anomalous (both this and
                    // the session check use tmux). Fail loudly rather than
                    // silently render every runner as dead.
                    log::error!(
                        "could not determine per-runner liveness in session '{}': {e}",
                        state.tmux_session
                    );
                    return false;
                }
            };
            print!(
                "{}",
                render_summary(&state, session_alive, &alive_runner_ids)
            );
            return true;
        }

        attach_dashboard(&state)
    }
}

/// Ensures a single reloading status window exists in the campaign session,
/// then attaches to it.
fn attach_dashboard(state: &CampaignState) -> bool {
    let session = &state.tmux_session;

    // Re-run guard: reuse the window if `status` was already run on this live
    // campaign, rather than stacking a second status window.
    match tmux::window_exists(session, STATUS_WINDOW) {
        Ok(true) => log::info!("status window already exists in session '{session}', attaching"),
        Ok(false) => {
            let cmd = dashboard_command(&state.id);
            if let Err(e) = tmux::add_window(session, STATUS_WINDOW, &cmd) {
                log::error!("failed to create status window in session '{session}': {e}");
                return false;
            }
        }
        Err(e) => {
            log::error!("failed to query tmux session '{session}': {e}");
            return false;
        }
    }

    // `attach`/`switch-client` land on whatever window is currently active. The
    // status window is active right after we create it, but if the user switched
    // to a runner window and detached, a later `status` run would otherwise
    // attach to that runner window — so select the status window explicitly.
    if let Err(e) = tmux::select_window(session, STATUS_WINDOW) {
        log::error!("failed to select status window in session '{session}': {e}");
        return false;
    }

    if let Err(e) = tmux::attach(session) {
        log::error!("failed to attach to tmux session '{session}': {e}");
        return false;
    }
    true
}

/// Builds the shell command for the reloading status window.
///
/// A bash loop re-runs `smitebot status <id> --summary` every [`RELOAD_SECS`]
/// seconds, clearing the terminal between frames with an ANSI home+erase escape
/// (`\033[H\033[2J`) so no `clear`/`watch` binary is required.
fn dashboard_command(campaign_id: &str) -> String {
    // Explicit path to this binary rather than a bare `smitebot`, so the window
    // runs the same binary the user invoked, not whatever is on PATH.
    let exe = std::env::current_exe()
        .map_or_else(|_| "smitebot".to_string(), |p| p.display().to_string());
    let exe = shell_quote(&exe);
    let id = shell_quote(campaign_id);
    format!(
        "while true; do printf '\\033[H\\033[2J'; {exe} status {id} --summary; sleep {RELOAD_SECS}; done"
    )
}

/// Returns the ids of runners whose tmux window is still alive.
///
/// A dead campaign (no session) has no live runners. For a live campaign, a
/// runner is alive only if its window still exists with a running pane (via
/// [`tmux::alive_windows`]). Keying off live panes rather than dead-but-open
/// ones means a runner whose pane was closed entirely — its window gone from
/// both lists — is correctly reported dead, not frozen-but-alive. A tmux query
/// failure propagates rather than being reported as "all runners dead".
fn alive_runners(state: &CampaignState, session_alive: bool) -> io::Result<Vec<u16>> {
    if !session_alive {
        return Ok(Vec::new());
    }
    let alive = tmux::alive_windows(&state.tmux_session)?;
    Ok(alive_ids(&state.runners, &alive))
}

/// Returns the ids of runners whose window is among `alive_windows`.
fn alive_ids(runners: &[RunnerState], alive_windows: &[String]) -> Vec<u16> {
    runners
        .iter()
        .filter(|runner| alive_windows.contains(&tmux::runner_window_name(runner.id)))
        .map(|runner| runner.id)
        .collect()
}

/// Renders a one-shot text summary of the campaign.
///
/// `session_alive` is the tmux-session liveness signal, used to reconcile the
/// displayed status (see [`display_status`]). `alive_runner_ids` holds the ids of
/// runners whose window is still alive, driving the per-runner `state` column.
fn render_summary(state: &CampaignState, session_alive: bool, alive_runner_ids: &[u16]) -> String {
    use std::fmt::Write;

    let now = utils::epoch_secs();
    let elapsed = state
        .stop_time
        .unwrap_or(now)
        .saturating_sub(state.start_time);

    let status = display_status(state, session_alive, !alive_runner_ids.is_empty());
    let mut out = render_header(state, status, &fmt_duration(elapsed));
    let _ = writeln!(out);
    out.push_str(&render_runner_table(state, alive_runner_ids, now));
    out
}

/// Renders the per-runner stats table: one row per runner plus a totals row,
/// each column right-aligned and boxed with border glyphs.
///
/// Column widths are derived from the actual cell contents (see
/// [`collect_rows`]) so values never overflow their column.
fn render_runner_table(state: &CampaignState, alive_runner_ids: &[u16], now: u64) -> String {
    use std::fmt::Write;

    let header = [
        "runner",
        "state",
        "execs/s",
        "execs",
        "corpus",
        "crashes",
        "hangs",
        "cov",
        "last find",
    ];
    let (rows, totals) = collect_rows(state, alive_runner_ids, now);

    let mut widths = header.map(str::len);
    for row in rows.iter().chain(std::iter::once(&totals)) {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "runners");
    let _ = writeln!(out, "{}", table_rule(&widths, '┌', '┬', '┐'));
    let _ = writeln!(out, "{}", table_row(&header, &widths));
    let _ = writeln!(out, "{}", table_rule(&widths, '├', '┼', '┤'));
    for row in &rows {
        let _ = writeln!(out, "{}", table_row(row, &widths));
    }
    let _ = writeln!(out, "{}", table_rule(&widths, '├', '┼', '┤'));
    let _ = writeln!(out, "{}", table_row(&totals, &widths));
    let _ = writeln!(out, "{}", table_rule(&widths, '└', '┴', '┘'));
    out
}

/// Parses a numeric `fuzzer_stats` field, returning `None` when it is absent.
///
/// AFL++ writes `fuzzer_stats` to `.fuzzer_stats_tmp` then `rename()`s it into
/// place (src/afl-fuzz-stats.c, v4.40c), so `status` never reads a partial file — a
/// present field is always a complete number. A parse failure would therefore
/// mean a smitebot bug (wrong key or corrupt file), not runtime variability, so
/// it panics rather than silently rendering "-".
fn stat_num<T>(stats: &HashMap<String, String>, key: &str) -> Option<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    stats.get(key).map(|v| {
        v.parse().unwrap_or_else(|e| {
            panic!(
                "{key} in fuzzer_stats is not a valid {}: {e:?}",
                std::any::type_name::<T>()
            )
        })
    })
}

/// Builds the per-runner rows and the totals row for the stats table.
///
/// Each numeric `fuzzer_stats` field is parsed once (via [`stat_num`], which
/// panics on a malformed value — see there), feeding both its cell and its
/// column total so they can't disagree. An absent field renders `-` and adds 0.
fn collect_rows(
    state: &CampaignState,
    alive_runner_ids: &[u16],
    now: u64,
) -> (Vec<[String; 9]>, [String; 9]) {
    let mut rows: Vec<[String; 9]> = Vec::new();
    let mut total_eps = 0.0f64;
    let mut total_execs = 0u64;
    let mut total_crashes = 0u64;
    let mut total_hangs = 0u64;

    // Renders an optional count column: the number, or "-" when the field was
    // absent from fuzzer_stats.
    let u64_or_dash = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |n| n.to_string());

    for runner in &state.runners {
        let liveness = if alive_runner_ids.contains(&runner.id) {
            "alive"
        } else {
            "dead"
        };
        // AFL++ writes fuzzer_stats only after calibrating every seed; until it
        // exists (or before any field lands) every stat cell renders as "-".
        let stats_path = state.output_dir.join(runner.name()).join("fuzzer_stats");
        let runner_stats = parse_stats(&stats_path).unwrap_or_default();

        let eps: Option<f64> = stat_num(&runner_stats, "execs_per_sec");
        let execs: Option<u64> = stat_num(&runner_stats, "execs_done");
        let crashes: Option<u64> = stat_num(&runner_stats, "saved_crashes");
        let hangs: Option<u64> = stat_num(&runner_stats, "saved_hangs");
        total_eps += eps.unwrap_or(0.0);
        total_execs += execs.unwrap_or(0);
        total_crashes += crashes.unwrap_or(0);
        total_hangs += hangs.unwrap_or(0);

        let last_find = stat_num::<u64>(&runner_stats, "last_find")
            .map_or_else(|| "-".to_string(), |t| fmt_ago(now, t));

        rows.push([
            runner.id.to_string(),
            liveness.to_string(),
            eps.map_or_else(|| "-".to_string(), |v| format!("{v:.2}")),
            u64_or_dash(execs),
            runner_stats
                .get("corpus_count")
                .map_or("-", String::as_str)
                .to_string(),
            u64_or_dash(crashes),
            u64_or_dash(hangs),
            runner_stats
                .get("bitmap_cvg")
                .map_or("-", String::as_str)
                .to_string(),
            last_find,
        ]);
    }

    // Totals sum only the additive columns: execs/s (aggregate throughput),
    // execs, crashes, hangs. corpus overlaps across runners (they share a synced
    // queue), and cov/last find are a percentage and a timestamp — not summable.
    let totals = [
        "totals".to_string(),
        String::new(),
        format!("{total_eps:.2}"),
        total_execs.to_string(),
        String::new(),
        total_crashes.to_string(),
        total_hangs.to_string(),
        String::new(),
        String::new(),
    ];

    (rows, totals)
}

/// Renders the campaign identity block: id, target, scenario, status, uptime.
fn render_header(state: &CampaignState, status: &str, uptime: &str) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(out, "campaign");
    let _ = writeln!(out, "  id         {}", state.id);
    let _ = writeln!(out, "  target     {}", state.target);
    let _ = writeln!(out, "  scenario   {}", state.scenario);
    let _ = writeln!(out, "  status     {status}");
    let _ = writeln!(out, "  uptime     {uptime}");
    out
}

/// Renders one runner-table row: each cell right-aligned in its column `widths`
/// and separated by `│` borders.
fn table_row<S: AsRef<str>>(cells: &[S], widths: &[usize]) -> String {
    use std::fmt::Write;

    let mut row = String::from("│");
    for (cell, width) in cells.iter().zip(widths) {
        let _ = write!(row, " {:>w$} │", cell.as_ref(), w = *width);
    }
    row
}

/// Renders a horizontal table border for the given column `widths` with the
/// given corner/junction glyphs (e.g. `┌ ┬ ┐` for the top edge, `├ ┼ ┤` for a
/// separator).
fn table_rule(widths: &[usize], left: char, junction: char, right: char) -> String {
    let mut rule = String::from(left);
    for (i, width) in widths.iter().enumerate() {
        rule.push_str(&"─".repeat(width + 2));
        rule.push(if i + 1 == widths.len() {
            right
        } else {
            junction
        });
    }
    rule
}

/// Reconciles the displayed campaign status against tmux liveness.
///
/// The persisted `state.status` is authoritative; tmux liveness only refines the
/// `Running` case. A verified-running campaign's session outlives its runners
/// (`remain-on-exit`), so it is only truly `running` while a runner is alive —
/// otherwise it crashed, or the host went away, and reads `dead`. `Starting`
/// covers the whole bring-up: the session may not exist yet (setup) or runners
/// may still be calibrating (minutes under Nyx), so it is never reported `dead`.
fn display_status(
    state: &CampaignState,
    session_alive: bool,
    any_runner_alive: bool,
) -> &'static str {
    match state.status {
        Status::Stopped => "stopped",
        Status::Failed => "failed",
        Status::Starting => "starting",
        Status::Running => {
            if session_alive && any_runner_alive {
                "running"
            } else {
                "dead"
            }
        }
    }
}

/// Parses an AFL++ `fuzzer_stats` file into key/value pairs.
///
/// Each line is `key : value`; both sides are trimmed and the split is on the
/// first colon (some values, e.g. `command_line`, contain colons). Returns
/// `None` if the file is absent or unreadable.
fn parse_stats(path: &Path) -> Option<HashMap<String, String>> {
    let contents = fs::read_to_string(path).ok()?;
    Some(
        contents
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
            .collect(),
    )
}

/// Formats a duration in seconds as a compact two-unit string (e.g. `2h 14m`).
fn fmt_duration(secs: u64) -> String {
    let (days, hours, mins, s) = (
        secs / 86_400,
        (secs % 86_400) / 3_600,
        (secs % 3_600) / 60,
        secs % 60,
    );
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Formats the age of an absolute epoch-seconds timestamp relative to `now`.
///
/// `then == 0` means AFL++ recorded no finds, rendered as `never`.
fn fmt_ago(now: u64, then: u64) -> String {
    if then == 0 {
        return "never".to_string();
    }
    format!("{} ago", fmt_duration(now.saturating_sub(then)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Target;
    use crate::state::RunnerState;
    use std::path::PathBuf;

    fn sample_stats(execs_per_sec: &str, crashes: u64, last_find: u64) -> String {
        format!(
            "start_time        : 1749465600\n\
             fuzzer_pid        : 1234\n\
             execs_done        : 5000000\n\
             execs_per_sec     : {execs_per_sec}\n\
             corpus_count      : 512\n\
             bitmap_cvg        : 12.34%\n\
             saved_crashes     : {crashes}\n\
             saved_hangs       : 1\n\
             last_find         : {last_find}\n"
        )
    }

    fn sample_state(output_dir: PathBuf, runners: u16) -> CampaignState {
        CampaignState {
            id: "lnd-encrypted_bytes-1749465600".to_string(),
            status: Status::Running,
            target: Target::Lnd,
            scenario: "encrypted_bytes".to_string(),
            image: "smite-lnd-encrypted_bytes".to_string(),
            image_digest: "sha256:abc123".to_string(),
            output_dir,
            sharedir: PathBuf::from("/tmp/nyx"),
            smite_git_hash: "deadbeef".to_string(),
            start_time: 1_749_465_600,
            stop_time: None,
            tmux_session: "lnd-encrypted_bytes-1749465600".to_string(),
            runners: (0..runners)
                .map(|id| RunnerState { id, pid: None })
                .collect(),
            aflpp_path: None,
        }
    }

    #[test]
    fn parse_stats_reads_key_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuzzer_stats");
        fs::write(&path, sample_stats("1234.50", 2, 1_749_465_900)).unwrap();

        let stats = parse_stats(&path).unwrap();
        assert_eq!(stats.get("execs_per_sec").unwrap(), "1234.50");
        assert_eq!(stats.get("bitmap_cvg").unwrap(), "12.34%");
        assert_eq!(stats.get("saved_crashes").unwrap(), "2");
    }

    #[test]
    fn parse_stats_returns_none_for_missing_file() {
        assert!(parse_stats(Path::new("/no/such/fuzzer_stats")).is_none());
    }

    #[test]
    fn render_summary_reports_runner_stats_and_totals() {
        let dir = tempfile::tempdir().unwrap();
        for (id, eps, crashes) in [(0u16, "1000.00", 2u64), (1, "500.00", 3)] {
            let runner_dir = dir.path().join(id.to_string());
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(
                runner_dir.join("fuzzer_stats"),
                sample_stats(eps, crashes, 1_749_465_900),
            )
            .unwrap();
        }
        let state = sample_state(dir.path().to_path_buf(), 2);

        let out = render_summary(&state, true, &[0, 1]);
        assert!(out.contains("running"));
        assert!(out.contains("1000.00"));
        assert!(out.contains("12.34%"));
        // totals: execs/s 1000 + 500 = 1500.00, crashes 2 + 3 = 5.
        assert!(out.contains("1500.00"));
        assert!(out.contains("totals"));
    }

    #[test]
    fn render_summary_marks_runner_without_stats() {
        let dir = tempfile::tempdir().unwrap();
        let state = sample_state(dir.path().to_path_buf(), 1);

        let out = render_summary(&state, true, &[0]);
        // A runner without fuzzer_stats still renders (alive here) and
        // contributes nothing, so the totals row reads zero throughput.
        assert!(out.contains("alive"));
        assert!(out.contains("0.00"));
    }

    #[test]
    fn render_summary_marks_dead_runner() {
        let dir = tempfile::tempdir().unwrap();
        for id in 0u16..2 {
            let runner_dir = dir.path().join(id.to_string());
            fs::create_dir_all(&runner_dir).unwrap();
            fs::write(
                runner_dir.join("fuzzer_stats"),
                sample_stats("100.00", 0, 0),
            )
            .unwrap();
        }
        let state = sample_state(dir.path().to_path_buf(), 2);

        // Only runner 0 is alive; runner 1's window has exited.
        let out = render_summary(&state, true, &[0]);
        assert!(out.contains("alive"));
        assert!(out.contains("dead"));
    }

    #[test]
    fn alive_ids_keeps_only_live_windows() {
        let runners: Vec<RunnerState> = (0u16..3).map(|id| RunnerState { id, pid: None }).collect();
        // runner-1's window is gone (pane closed) and runner-2's exited, so only
        // runner-0's window is still live.
        let alive_windows = vec!["runner-0".to_string()];

        let alive = alive_ids(&runners, &alive_windows);
        assert_eq!(alive, vec![0]);
    }

    #[test]
    fn display_status_reports_dead_when_session_gone_without_stop() {
        let dir = tempfile::tempdir().unwrap();
        let state = sample_state(dir.path().to_path_buf(), 1);
        // state.status is Running but the tmux session is gone.
        assert_eq!(display_status(&state, false, false), "dead");
    }

    #[test]
    fn display_status_reports_failed_when_session_gone_after_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = sample_state(dir.path().to_path_buf(), 1);
        state.status = Status::Failed;
        assert_eq!(display_status(&state, false, false), "failed");
    }

    #[test]
    fn display_status_reports_stopped_after_clean_stop() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = sample_state(dir.path().to_path_buf(), 1);
        state.status = Status::Stopped;
        assert_eq!(display_status(&state, false, false), "stopped");
    }

    #[test]
    fn display_status_reports_running_when_session_and_runner_alive() {
        let dir = tempfile::tempdir().unwrap();
        let state = sample_state(dir.path().to_path_buf(), 1);
        assert_eq!(display_status(&state, true, true), "running");
    }

    #[test]
    fn display_status_reports_dead_when_session_alive_but_runners_dead() {
        let dir = tempfile::tempdir().unwrap();
        let state = sample_state(dir.path().to_path_buf(), 1);
        // Session survives via remain-on-exit, but every runner has exited.
        assert_eq!(display_status(&state, true, false), "dead");
    }

    #[test]
    fn display_status_reports_starting_regardless_of_liveness() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = sample_state(dir.path().to_path_buf(), 1);
        state.status = Status::Starting;
        // Bring-up: no session yet during setup, or runners calibrating — both
        // read `starting`, never `dead`.
        assert_eq!(display_status(&state, false, false), "starting");
        assert_eq!(display_status(&state, true, true), "starting");
    }

    #[test]
    fn display_status_reports_failed_even_with_a_surviving_runner() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = sample_state(dir.path().to_path_buf(), 1);
        state.status = Status::Failed;
        // Startup failed overall; one runner surviving does not make it running.
        assert_eq!(display_status(&state, true, true), "failed");
    }

    #[test]
    fn fmt_duration_picks_two_largest_units() {
        assert_eq!(fmt_duration(0), "0s");
        assert_eq!(fmt_duration(45), "45s");
        assert_eq!(fmt_duration(3 * 60 + 5), "3m 5s");
        assert_eq!(fmt_duration(2 * 3600 + 14 * 60), "2h 14m");
        assert_eq!(fmt_duration(86_400 + 3600), "1d 1h");
    }

    #[test]
    fn fmt_ago_reports_never_for_zero() {
        assert_eq!(fmt_ago(1_000, 0), "never");
    }

    #[test]
    fn fmt_ago_reports_age_relative_to_now() {
        assert_eq!(fmt_ago(1_000 + 125, 1_000), "2m 5s ago");
    }

    #[test]
    fn dashboard_command_targets_summary_of_campaign() {
        let cmd = dashboard_command("lnd-encrypted_bytes-1749465600");
        assert!(cmd.contains("while true"));
        assert!(cmd.contains("status 'lnd-encrypted_bytes-1749465600' --summary"));
        assert!(cmd.contains("sleep 60"));
    }
}
