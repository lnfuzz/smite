//! The error type returned by every command handler.
//!
//! Each `execute` returns `Result<(), CliError>` and `main` logs the error once
//! at the top level, instead of every failure site calling `log::error!` and
//! returning `false` (issue #270). This keeps logging in one place and lets the
//! command bodies use `?`.

use crate::config::ConfigError;
use crate::state::StateError;

/// A failure from a command handler, logged once by `main`.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// A configuration file failed to load or validate.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Campaign state failed to load or save.
    #[error(transparent)]
    State(#[from] StateError),
    /// An operational failure described by a ready-to-log message.
    #[error("{0}")]
    Msg(String),
    /// The `config`/`doctor` report — whose printed output (including its JSON)
    /// is the artifact — came back negative. The command already printed the
    /// result, so `main` sets a non-zero exit code but logs nothing further.
    #[error("")]
    Reported,
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        CliError::Msg(message)
    }
}
