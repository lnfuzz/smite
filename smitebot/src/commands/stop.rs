//! Campaign teardown: stop a running campaign and reap all of its processes.
//!
//! Each afl-fuzz runner is a process-group leader, and its Nyx QEMU child shares
//! that group and keeps the group id even after it orphans. So a group-directed
//! kill (`pkill -g <pgid>`) reaps the QEMU too — which a plain `tmux kill-session`
//! does not (it leaks QEMU). Nyx QEMU did not exit on SIGTERM in testing, so the
//! kill escalates SIGTERM -> SIGKILL.

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use clap::Args;

use crate::state::{CampaignState, Status};
use crate::tmux;
use crate::utils;

/// How long to wait for a signalled group to exit before giving up on that
/// stage. Conservative headroom for afl-fuzz to finish `AFL_FINAL_SYNC` on a
/// large corpus and exit after SIGTERM; the poll returns as soon as every group
/// is gone, so this full duration is only spent when something ignores the
/// signal (SIGTERM, or SIGKILL against a process wedged in uninterruptible I/O).
const GRACEFUL_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for process groups to exit, and the delay before
/// the first poll: freshly-signalled runners won't have exited any sooner.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Command handler for `smitebot stop`.
pub struct StopCommand;

/// CLI arguments for `smitebot stop`.
#[derive(Debug, Args)]
pub struct StopArgs {
    /// Campaign ID to stop (a directory name under `~/.smitebot/runs`).
    campaign_id: String,
}

impl StopCommand {
    /// Stops a campaign: reaps its runner process groups, tears down the tmux
    /// session, and records the stop in state.json.
    pub fn execute(args: &StopArgs) -> bool {
        let (mut state, state_path) = match CampaignState::load_campaign(&args.campaign_id) {
            Ok(x) => x,
            Err(e) => {
                log::error!("{e}");
                return false;
            }
        };

        if state.status == Status::Stopped {
            log::info!("campaign {} is already stopped", state.id);
            return true;
        }

        let clean = terminate_runners(&state);

        if let Err(e) = tmux::kill_session(&state.tmux_session) {
            // The session may already be gone (e.g. killed manually); not fatal.
            log::debug!("kill-session '{}': {e}", state.tmux_session);
        }

        state.status = Status::Stopped;
        state.stop_time = Some(utils::epoch_secs());
        if let Err(e) = state.save(&state_path) {
            log::error!(
                "runners were reaped but recording the stop failed: {e}; \
                 campaign {} will still show as running in state.json",
                state.id
            );
            return false;
        }

        if clean {
            log::info!("campaign {} stopped", state.id);
        } else {
            log::error!(
                "campaign {} stopped, but some processes survived SIGKILL; \
                 inspect with `pgrep -a qemu` and kill them manually",
                state.id
            );
        }
        clean
    }
}

/// Terminates every runner process group for a campaign.
///
/// PIDs come only from the live tmux session, never from state.json: a recorded
/// PID whose session is gone (e.g. after a reboot) may have been recycled by the
/// OS, and group-killing it could hit an unrelated process. When the session is
/// alive, its pane PIDs are the afl-fuzz leaders, and each shares its process
/// group with its Nyx QEMU child, so the group kill reaps the QEMU too. Returns
/// `true` if no process survived.
fn terminate_runners(state: &CampaignState) -> bool {
    if !tmux::session_exists(&state.tmux_session) {
        log::warn!(
            "no live tmux session for campaign {}; nothing to reap \
             (if runners leaked — e.g. the session was killed manually — check `pgrep -a qemu`)",
            state.id,
        );
        return true;
    }

    let pgids = match tmux::list_pane_pids(&state.tmux_session) {
        Ok(pgids) => pgids,
        Err(e) => {
            log::error!(
                "could not read runner PIDs from tmux for campaign {}: {e}; \
                 not reaping — runners may still be alive, check `pgrep -a qemu`",
                state.id,
            );
            return false;
        }
    };
    if pgids.is_empty() {
        // Session exists but has no panes left; nothing to reap.
        return true;
    }

    kill_groups(&pgids)
}

/// Signals each process group, escalating SIGTERM -> SIGKILL, until all exit.
fn kill_groups(pgids: &[u32]) -> bool {
    if signal_and_wait(pgids, "TERM", GRACEFUL_TIMEOUT) {
        return true;
    }
    if signal_and_wait(pgids, "KILL", GRACEFUL_TIMEOUT) {
        return true;
    }

    // Report every survivor, not just the first, so the operator sees all the
    // pgids that still need a manual kill.
    let mut clean = true;
    for &pgid in pgids {
        if group_alive(pgid) {
            log::error!("process group {pgid} still alive after SIGKILL");
            clean = false;
        }
    }
    clean
}

/// Sends `signal` to every still-alive group, then polls at `POLL_INTERVAL`
/// until all exit or `timeout` elapses. Returns `true` if every group is gone.
///
/// The first poll is delayed one `POLL_INTERVAL`: the just-signalled runners
/// won't have exited any sooner, so checking immediately only wastes work.
fn signal_and_wait(pgids: &[u32], signal: &str, timeout: Duration) -> bool {
    for &pgid in pgids {
        if group_alive(pgid) {
            signal_group(pgid, signal);
        }
    }

    let deadline = Instant::now() + timeout;
    loop {
        thread::sleep(POLL_INTERVAL);
        if pgids.iter().all(|&pgid| !group_alive(pgid)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
    }
}

/// Sends `signal` to every process in the process group `pgid`.
///
/// Uses `pkill -g` (not `kill -<pgid>`: the `kill` *binary* silently ignores a
/// negative-PID group target, unlike the shell builtin). Errors are ignored:
/// the group may already be gone, which is the desired end state anyway.
fn signal_group(pgid: u32, signal: &str) {
    let _ = Command::new("pkill")
        .arg(format!("-{signal}"))
        .args(["-g", &pgid.to_string()])
        .status();
}

/// Returns `true` if any *live* (non-zombie) process remains in group `pgid`.
///
/// Zombies don't count: a killed afl-fuzz is parented to tmux (`remain-on-exit`),
/// so it lingers as a zombie until the tmux teardown reaps it — it is already
/// dead for our purposes. `pgrep -g` selects the process group; `ps` then filters
/// out zombie states (`Z`).
fn group_alive(pgid: u32) -> bool {
    let Ok(out) = Command::new("pgrep")
        .args(["-g", &pgid.to_string()])
        .output()
    else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pids: Vec<&str> = stdout.split_whitespace().collect();
    if pids.is_empty() {
        return false;
    }
    match Command::new("ps")
        .args(["-o", "stat=", "-p", &pids.join(",")])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|line| !line.trim_start().starts_with('Z')),
        Err(_) => true, // can't check — assume alive so we don't report a false "clean"
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;

    use super::*;

    /// Spawns a `sh` process-group leader running `shell_cmd`. The commands
    /// outlive the test unless killed, so a passing test proves the whole group
    /// was reaped. Caller must `wait()` the returned child.
    fn spawn_group(shell_cmd: &str) -> std::process::Child {
        let child = Command::new("sh")
            .args(["-c", shell_cmd])
            .process_group(0)
            .spawn()
            .expect("spawn test process group");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !group_alive(child.id()) {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(group_alive(child.id()), "test group never came up");
        child
    }

    #[test]
    fn kill_groups_reaps_whole_process_group() {
        let mut child = spawn_group("sleep 300 & sleep 300");
        let pgid = child.id();
        assert!(kill_groups(&[pgid]));
        assert!(!group_alive(pgid));
        let _ = child.wait(); // reap the leader zombie left by the group kill
    }

    #[test]
    fn kill_escalates_to_sigkill_when_sigterm_ignored() {
        // The leader ignores SIGTERM (inherited across the group), so only the
        // SIGKILL escalation can reap it.
        let mut child = spawn_group("trap '' TERM; sleep 300");
        let pgid = child.id();

        // SIGTERM is ignored -> the group is still alive when the wait expires.
        assert!(!signal_and_wait(&[pgid], "TERM", Duration::from_millis(1)));
        assert!(group_alive(pgid));

        // SIGKILL can't be caught -> the group is gone.
        assert!(signal_and_wait(&[pgid], "KILL", GRACEFUL_TIMEOUT));
        assert!(!group_alive(pgid));
        let _ = child.wait(); // reap the leader zombie left by the group kill
    }
}
