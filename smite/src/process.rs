//! Process management utilities for spawning and controlling subprocesses.
//!
//! Wraps [`std::process::Child`] with graceful shutdown support
//! and automatic cleanup on drop.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;

/// A managed subprocess with graceful shutdown support.
///
/// Wraps a [`Child`] process and provides utilities for graceful shutdown
/// (SIGTERM followed by SIGKILL after timeout).
///
/// Each managed child is placed into its own process group when spawned so
/// that shutdown can reliably clean up grandchildren as well.
pub struct ManagedProcess {
    child: Child,
    name: String,
}

impl ManagedProcess {
    /// Spawns a new managed process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process fails to spawn.
    pub fn spawn(cmd: &mut Command, name: impl Into<String>) -> io::Result<Self> {
        // Put the child in its own process group so shutdown can signal the
        // whole subtree rather than just the direct child process.
        cmd.process_group(0);

        let child = cmd.spawn()?;

        Ok(Self {
            child,
            name: name.into(),
        })
    }

    /// Returns the process ID.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns the process name (for logging).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Checks if the process is still running (non-blocking).
    ///
    /// Returns `true` if the process is running, `false` if it has exited
    /// or if the status cannot be determined (e.g., already reaped).
    pub fn is_running(&mut self) -> bool {
        // Ok(None) = still running
        // Ok(Some(_)) = exited
        // Err(_) = can't determine (e.g., ECHILD if already reaped) - treat as not running
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Attempts graceful shutdown: SIGTERM, wait for timeout, then SIGKILL.
    ///
    /// Returns the exit status of the process.
    ///
    /// # Errors
    ///
    /// Returns an error if sending signals or waiting fails.
    pub fn shutdown(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let process_group = i32::try_from(self.child.id())
            .map(Pid::from_raw)
            .map_err(|_| io::Error::other("pid exceeds i32::MAX"))?;

        // Check if already exited
        if let Some(status) = self.child.try_wait()? {
            log::debug!("{}: already exited with {status}", self.name);
            return Ok(status);
        }

        // Send SIGTERM to the entire process group so grandchildren are
        // cleaned up too.
        log::debug!(
            "{}: sending SIGTERM to process group {}",
            self.name,
            process_group
        );
        if let Err(e) = killpg(process_group, Signal::SIGTERM) {
            log::warn!(
                "{}: failed to send SIGTERM to process group: {e}",
                self.name
            );
        }

        // Wait for process to exit with timeout
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                log::debug!("{}: exited with {status}", self.name);
                return Ok(status);
            }

            if Instant::now() >= deadline {
                break;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        // Timeout expired, send SIGKILL
        log::warn!(
            "{}: did not exit within {}ms, sending SIGKILL to process group {}",
            self.name,
            timeout.as_millis(),
            process_group
        );
        if let Err(e) = killpg(process_group, Signal::SIGKILL) {
            log::warn!(
                "{}: failed to send SIGKILL to process group: {e}",
                self.name
            );
        }

        // Wait for process to exit after SIGKILL
        self.child.wait()
    }

    /// Returns a mutable reference to the underlying [`Child`].
    ///
    /// Use this for operations not covered by `ManagedProcess`, such as
    /// accessing stdin/stdout/stderr handles.
    pub fn inner(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if self.is_running() {
            log::debug!(
                "{}: dropping running process, attempting shutdown",
                self.name
            );
            if let Err(e) = self.shutdown(Duration::from_secs(5)) {
                log::error!("{}: failed to shutdown on drop: {e}", self.name);
            }
        }
    }
}

/// Sends SIGUSR1 to the process with the given `pid`.
///
/// # Errors
///
/// Returns an error if `pid` exceeds `i32::MAX` or if sending the signal fails.
pub fn send_sigusr1(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .map(Pid::from_raw)
        .map_err(|_| io::Error::other("pid exceeds i32::MAX"))?;

    kill(pid, Signal::SIGUSR1).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn process_exists(pid: i32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    #[test]
    fn shutdown_already_exited() {
        // Spawn a fast-exiting process and wait for it to finish
        let mut proc = ManagedProcess::spawn(Command::new("true").arg(""), "true").unwrap();
        assert!(proc.pid() > 0);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!proc.is_running());

        // shutdown should return the process's exit status
        let status = proc.shutdown(Duration::from_secs(1)).unwrap();
        assert!(status.success());
    }

    #[test]
    fn shutdown_running_process() {
        // Spawn a long-running process
        let mut proc = ManagedProcess::spawn(Command::new("sleep").arg("60"), "sleep").unwrap();
        assert!(proc.is_running());

        // shutdown should SIGTERM then SIGKILL after timeout
        let status = proc.shutdown(Duration::from_millis(100)).unwrap();
        assert!(!status.success()); // Killed by signal
        assert!(!proc.is_running());
    }

    #[test]
    fn shutdown_kills_process_group() {
        let temp_dir = TempDir::new().unwrap();
        let grandchild_pid_file = temp_dir.path().join("grandchild.pid");

        let script = format!(
            "sleep 60 & echo $! > '{}' && wait",
            grandchild_pid_file.display()
        );

        let mut proc =
            ManagedProcess::spawn(Command::new("sh").arg("-c").arg(script), "sh").unwrap();
        assert!(proc.is_running());

        let grandchild_pid = wait_for_pid_file(&grandchild_pid_file);
        assert!(process_exists(grandchild_pid));

        let status = proc.shutdown(Duration::from_secs(1)).unwrap();
        assert!(!status.success());
        assert!(!proc.is_running());

        let deadline = Instant::now() + Duration::from_secs(1);
        while process_exists(grandchild_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            !process_exists(grandchild_pid),
            "grandchild process {grandchild_pid} should have been terminated"
        );
    }

    fn wait_for_pid_file(path: &Path) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if let Ok(contents) = fs::read_to_string(path)
                && let Ok(pid) = contents.trim().parse()
            {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("timed out waiting for pid file at {}", path.display());
    }
}
