//! Scenario trait and the [`smite_run`] entry point.
//!
//! A [`Scenario`] defines how fuzz input is turned into protocol
//! interactions, from raw encrypted bytes to structured IR programs.
//! [`smite_run`] is the main function for all scenario binaries: it
//! initializes the runner, creates the scenario, delivers input and
//! reports results.

use crate::{bolt::BoltError, noise::ConnectionError};

/// `ScenarioResult` describes the outcomes of running a scenario
pub enum ScenarioResult {
    /// Scenario ran successfully
    Ok,
    /// Scenario indicated that the test case should be skipped
    Skip,
    /// Scenario indicated that the test case failed (i.e. the target node crashed)
    Fail(String),
}

/// Error from scenario operations.
#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    /// Target failed to start or crashed.
    #[error("target error: {0}")]
    Target(#[from] TargetError),

    /// Connection or handshake failed.
    #[error("connection failed: {0}")]
    Connection(#[from] ConnectionError),

    /// Failed to decode a BOLT message.
    #[error("decode error: {0}")]
    Decode(#[from] BoltError),

    /// Protocol error (e.g., unexpected message).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ScenarioError {
    /// Returns true if this error is a timeout (potential hang).
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        use std::io::ErrorKind;
        match self {
            Self::Connection(ConnectionError::Io(e)) | Self::Target(TargetError::Io(e)) => {
                matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
            }
            _ => false,
        }
    }
}

/// Error from target operations.
#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    /// Target failed to start.
    #[error("failed to start: {0}")]
    StartFailed(String),

    /// Target crashed.
    #[error("target crashed")]
    Crashed,

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// `Scenario` is the interface for test scenarios that can be run against a target node
pub trait Scenario: Sized {
    /// Create a new instance of the scenario, preparing the initial state of the test
    ///
    /// # Errors
    /// Returns an error if scenario initialization fails.
    fn new(args: &[String]) -> Result<Self, ScenarioError>;

    /// Run the test with the given fuzz input
    fn run(&mut self, input: &[u8]) -> ScenarioResult;
}

/// Installs the global `log` logger.
///
/// Defaults to `simple_logger`. When the `nyx` feature is enabled and both
/// `SMITE_NYX` and `SMITE_NYX_LOG` are set, `nyx_log` is installed instead.
fn init_logging() {
    #[cfg(feature = "nyx")]
    if std::env::var("SMITE_NYX").is_ok() && std::env::var("SMITE_NYX_LOG").is_ok() {
        crate::nyx_log::init();
        return;
    }
    simple_logger::init_with_env().expect("logger not already set");
}

/// Run a scenario with the standard runner.
///
/// This is the main entry point for smite scenario binaries. It initializes
/// the runner and scenario, then executes the fuzz input.
///
/// # Panics
///
/// Panics if the logger fails to initialize.
pub fn smite_run<S: Scenario>() -> std::process::ExitCode {
    use std::process::ExitCode;

    use crate::runners::{Runner, StdRunner};

    init_logging();

    // Install a panic hook so that panics in the scenario itself (e.g., failed
    // expect() calls) are reported as crashes rather than silent timeouts.
    #[cfg(feature = "nyx")]
    if std::env::var("SMITE_NYX").is_ok() {
        std::panic::set_hook(Box::new(|info| {
            let message = info.to_string();
            let c_message = std::ffi::CString::new(message).unwrap_or_default();
            // SAFETY: nyx_fail expects a null-terminated C string. We use
            // CString to ensure null-termination. The pointer is valid for the
            // duration of the call.
            unsafe {
                smite_nyx_sys::nyx_fail(c_message.as_ptr());
            }
        }));
    }

    // Initialize the runner before the scenario. This is important when
    // using Nyx to ensure nyx_init is called before spawning targets.
    let runner = StdRunner::new();

    let args: Vec<String> = std::env::args().collect();
    let mut scenario = match S::new(&args) {
        Ok(scenario) => scenario,
        Err(e) => {
            log::error!("Failed to initialize scenario: {e}");
            return ExitCode::FAILURE;
        }
    };

    log::info!("Scenario initialized! Executing input...");

    // In Nyx mode the snapshot is taken here and a new fuzz input is provided each reset.
    let input = runner.get_fuzz_input();

    match scenario.run(&input) {
        ScenarioResult::Ok => {}
        ScenarioResult::Skip => {
            runner.skip();
            return ExitCode::SUCCESS;
        }
        ScenarioResult::Fail(err) => {
            runner.fail(&format!("Test case failed: {err}"));
            return ExitCode::FAILURE;
        }
    }

    log::info!("Test case ran successfully!");

    // Drop runner before scenario. This provides a huge speedup in Nyx
    // mode since nyx_release() resets the VM before scenario cleanup
    // ever runs.
    #[allow(clippy::drop_non_drop)]
    drop(runner);

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::ScenarioError;
    use crate::{noise::ConnectionError, scenarios::TargetError};
    use std::io::{Error, ErrorKind};

    fn assert_is_timeout(kind: ErrorKind, expected: bool) {
        let actual =
            ScenarioError::Connection(ConnectionError::Io(Error::new(kind, "test"))).is_timeout();
        assert_eq!(actual, expected, "ConnectionError::Io with kind {kind:?}");
        let actual = ScenarioError::Target(TargetError::Io(Error::new(kind, "test"))).is_timeout();
        assert_eq!(actual, expected, "TargetError::Io with kind {kind:?}");
    }

    #[test]
    fn is_timeout() {
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            assert_is_timeout(kind, true);
        }
        // everything else should return false, but it's hard to test
        // "everything else", so we just test one other kind
        assert_is_timeout(ErrorKind::ConnectionRefused, false);
    }
}
