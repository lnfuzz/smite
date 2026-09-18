//! Raw bytes scenario - sends fuzz input directly as Lightning messages.

use std::time::Duration;

use smite::bolt::{Init, Message};
use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};
use smite::violation::Violation;

use super::{handshake_with_target, ping_pong};
use crate::targets::Target;

/// A scenario that sends raw fuzz input as Lightning messages.
///
/// This is the simplest fuzzing scenario - it takes arbitrary bytes and sends
/// them over an encrypted Lightning connection. This can find parsing bugs or
/// crashes from malformed messages.
pub struct EncryptedBytesScenario<T: Target> {
    /// Declared before `target` so the peer connection closes first and doesn't
    /// stall the target's shutdown.
    conn: NoiseConnection,
    target: T,
}

impl<T: Target> Scenario for EncryptedBytesScenario<T> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let config = T::Config::default();
        let target = T::start(config)?;
        let (mut conn, target_init) = handshake_with_target(&target, Duration::from_secs(5))?;
        let echo = Message::Init(Init::echo(&target_init)).encode();
        conn.send_message(&echo)?;

        // Warm up the target's message handling path before the Nyx snapshot.
        // For JVM-based targets (i.e. Eclair), this  causes the necessary
        // classes to load and be JIT compiled before we take the snapshot,
        // speeding up every subsequent iteration.
        ping_pong(&mut conn)?;

        Ok(Self { conn, target })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        let start = std::time::Instant::now();

        // Send raw fuzz input over the encrypted connection
        if self.conn.send_message(input).is_err() {
            return ScenarioResult::Skip;
        }
        log::debug!(
            "[{:?}] Sent fuzz input ({} bytes)",
            start.elapsed(),
            input.len()
        );

        // Synchronize to ensure the previous message was received and initial
        // processing has been done. The target node could still be doing
        // further async processing of the message, but we have no good way to
        // tell whether that is happening.
        if let Err(e) = ping_pong(&mut self.conn) {
            log::debug!("[{:?}] ping_pong: {e}", start.elapsed());
            if e.is_timeout() {
                return ScenarioResult::Fail(Violation::Hung.to_string());
            }
            // Non-timeout error likely means the target closed the connection.
            // This is expected when we send invalid messages, but it could also
            // mean the target crashed. Use check_alive below to distinguish.
        } else {
            log::debug!("[{:?}] Target responded with pong", start.elapsed());
        }

        // Check if target is still alive (and trigger coverage sync for LND)
        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail(Violation::Crashed.to_string());
        }

        ScenarioResult::Ok
    }
}
