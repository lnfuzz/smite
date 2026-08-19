//! Target trait and implementations for Lightning nodes.

mod bitcoind;
mod cln;
mod eclair;
mod ldk;
mod lnd;

pub use bitcoind::INITIAL_BLOCKS;
pub use cln::{ClnCli, ClnConfig, ClnTarget};
pub use eclair::{EclairCli, EclairConfig, EclairTarget};
pub use ldk::{LdkConfig, LdkRpc, LdkTarget};
pub use lnd::{LndCli, LndConfig, LndTarget};
use smite::bitcoin::BitcoinCli;
use smite::scenarios::TargetError;

use bitcoin::secp256k1;
use std::net::SocketAddr;

/// Path where the crash handler writes crash data in local (non-Nyx) mode.
const CRASH_LOG_PATH: &str = "/tmp/smite-crash.log";

/// Checks if the crash handler was triggered in local mode.
///
/// In Nyx mode, crashes are reported directly via hypercall and we never get to
/// this point. In local mode, the crash handler writes crash data to a file.
///
/// Used by targets that have an external crash handler (CLN, Eclair).
///
/// # Errors
///
/// Returns [`TargetError::Crashed`] if the crash log file exists.
pub fn check_crash_log() -> Result<(), TargetError> {
    let crash_log = std::path::Path::new(CRASH_LOG_PATH);
    if crash_log.exists() {
        if let Ok(msg) = std::fs::read_to_string(crash_log) {
            log::error!("crash handler: {}", msg.trim());
        }
        let _ = std::fs::remove_file(crash_log);
        return Err(TargetError::Crashed);
    }
    Ok(())
}

/// Abstraction over target RPC operations for executing commands on a running
/// target, allowing target-specific implementations.
pub trait TargetRpc {
    /// Notifies the target of newly mined blocks so it updates its chain view.
    fn chain_sync(&mut self);
}

/// A Lightning implementation that can be fuzzed.
///
/// This trait abstracts over different Lightning implementations (LND, CLN, LDK, etc.),
/// allowing scenarios to be written once and run against any target.
pub trait Target: Sized {
    /// Configuration for this target.
    type Config: Default;

    /// RPC handle for this target.
    type Rpc: TargetRpc;

    /// Start the target and any dependencies (e.g., bitcoind).
    ///
    /// # Errors
    ///
    /// Returns an error if the target fails to start.
    fn start(config: Self::Config) -> Result<Self, TargetError>;

    /// Target's identity public key.
    fn pubkey(&self) -> &secp256k1::PublicKey;

    /// Target's P2P listen address.
    fn addr(&self) -> SocketAddr;

    /// Target's RPC handle for executing commands.
    fn rpc(&self) -> Self::Rpc;

    /// `bitcoin-cli` wrapper for the regtest `bitcoind` instance.
    fn bitcoin_cli(&self) -> &BitcoinCli;

    /// Check if target is still alive. Returns `Err(Crashed)` if dead.
    ///
    /// Implementation varies by target:
    /// - LND: Pipe-based coverage sync (Go can't write to AFL shm directly)
    /// - CLN/LDK: Process liveness check (C/Rust AFL instrumentation writes directly)
    /// - Eclair: Process liveness check (Java agent writes directly via JNI shmat)
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Crashed`] if the target has crashed.
    fn check_alive(&mut self) -> Result<(), TargetError>;

    /// Known protocol violations for this target that should be suppressed.
    ///
    /// Each entry is a sequence of patterns that must appear in the violation
    /// message in the specified order, without overlapping. Include stable
    /// context around variable parts to avoid suppressing unrelated violations.
    ///
    /// Every entry must describe the behavior justifying it, and be removed
    /// once the upstream fix lands.
    #[must_use]
    fn known_violations() -> &'static [&'static [&'static str]] {
        &[]
    }

    /// Check if a violation matches a known pattern for this target.
    #[must_use]
    fn is_violation_known(violation: &str) -> bool {
        Self::known_violations()
            .iter()
            .any(|pattern| Self::contains_in_order(violation, pattern))
    }

    /// Returns true if every fragment in a pattern appears in the violation
    /// message in the specified order, without overlapping.
    #[must_use]
    fn contains_in_order(violation: &str, pattern: &[&str]) -> bool {
        let mut pos = 0;
        for fragment in pattern {
            match violation[pos..].find(fragment) {
                Some(offset) => pos += offset + fragment.len(),
                None => return false,
            }
        }
        true
    }
}
