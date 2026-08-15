//! IR program scenario: deserialize a postcard `Program` from the fuzz input
//! and execute it against the target over an established encrypted connection.

use std::marker::PhantomData;

use smite::bitcoin::BitcoinCli;
use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};
use smite::violation::Violation;
use smite_ir::Program;

use super::{PingOutcome, SnapshotSetup, is_known_parked_error, ping_pong_checked};
use crate::executor::{ExecuteError, Executor};
use crate::targets::Target;

/// Scenario that executes IR programs against a target over an encrypted
/// connection established by `S`.
///
/// The program is expected to be well-formed and produced by `smite-ir`'s
/// mutators or generators; the executor panics on invariant violations
/// (out-of-bounds variable refs, type mismatches, `MineBlocks(0)`, etc.).
pub struct IrScenario<T: Target, S: SnapshotSetup<T>> {
    target: T,
    /// Executes IR programs and owns the connection, bitcoin-cli handle, and
    /// program context. Created once before the snapshot and reused across
    /// fuzzing runs.
    executor: Executor<NoiseConnection, BitcoinCli>,
    // S is only used for static dispatch on S::setup(), not stored.
    _phantom: PhantomData<S>,
}

impl<T: Target, S: SnapshotSetup<T>> Scenario for IrScenario<T, S> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let target = T::start(T::Config::default())?;
        let (conn, context) = S::setup(&target)?;
        let bitcoin_cli = target.bitcoin_cli().clone();
        let executor = Executor::new(conn, bitcoin_cli, context);
        Ok(Self {
            target,
            executor,
            _phantom: PhantomData,
        })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();

        let program = match postcard::from_bytes::<Program>(input) {
            Ok(p) => p,
            Err(e) => return ScenarioResult::Fail(format!("postcard decode: {e}")),
        };

        log::debug!(
            "[{:?}] Executing IR program ({} instructions, {} input bytes)",
            start.elapsed(),
            program.instructions.len(),
            input.len(),
        );

        // Set when the target has sent an error after which it is known to not
        // service this connection any further. See `is_known_parked_error`.
        let mut parked = false;

        match self.executor.execute(&program, start) {
            Ok(()) => {
                log::debug!("[{:?}] Program executed successfully", start.elapsed());
            }
            Err(ExecuteError::Connection(e)) => {
                // Target may have closed the connection in response to bad
                // input. check_alive below is the authority on whether that's a
                // crash.
                log::debug!("[{:?}] execute connection error: {e}", start.elapsed());
            }
            Err(e @ ExecuteError::UnexpectedMessage { .. }) => {
                // Target replied with an unexpected message type (often
                // Error/Warning when rejecting our input). Usually normal
                // protocol behavior.
                log::debug!("[{:?}] {e}", start.elapsed());
            }
            Err(ExecuteError::PeerError(e)) => {
                // Normal protocol behavior: the target rejected our input.
                parked = is_known_parked_error(&e);
                log::debug!(
                    "[{:?}] peer error (parked: {parked}): {}",
                    start.elapsed(),
                    e.message().unwrap_or("<non-utf8>"),
                );
            }
            Err(ExecuteError::Decode(e)) => {
                // Either our decoder is incomplete or the target sent something
                // the spec doesn't allow.
                return ScenarioResult::Fail(format!("decode error: {e}"));
            }
            Err(ExecuteError::InsufficientFunds(e)) => {
                // The mutator generated a funding amount/feerate combination
                // the available UTXOs can't cover. Not a bug in the target.
                log::debug!("[{:?}] insufficient funds: {e}", start.elapsed());
            }
            Err(ExecuteError::Commitment(e)) => {
                // The mutator generated a funding amount/push_msat combination
                // that can't form a valid initial commitment transaction. Not a
                // bug in the target.
                log::debug!("[{:?}] invalid commitment: {e}", start.elapsed());
            }
            Err(ExecuteError::Violation(v)) => {
                let violation = v.to_string();
                if T::is_violation_known(&violation) {
                    log::debug!(
                        "[{:?}] suppressed known violation: {violation}",
                        start.elapsed(),
                    );
                } else {
                    // The target broke a protocol invariant.
                    return ScenarioResult::Fail(violation);
                }
            }
        }

        // Ping-pong sync to ensure the target has at least done the initial
        // processing of all previous messages. Timeouts here signal a hang,
        // unless we know the connection has been parked by the target, in which
        // case we continue without requiring a pong.
        if parked {
            log::info!(
                "[{:?}] connection parked by target, skipping ping-pong",
                start.elapsed()
            );
        } else {
            match ping_pong_checked(self.executor.conn_mut()) {
                Ok(PingOutcome::Pong) => {
                    log::debug!("[{:?}] Target responded with pong", start.elapsed());
                }
                Ok(PingOutcome::ParkedConnection(msg)) => {
                    log::info!("[{:?}] connection parked by target: {msg}", start.elapsed());
                }
                Err(e) => {
                    log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
                    if e.is_timeout() {
                        return ScenarioResult::Fail(Violation::Hung.to_string());
                    }
                }
            }
        }

        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail(Violation::Crashed.to_string());
        }

        ScenarioResult::Ok
    }
}
