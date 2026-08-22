//! Scenario implementations and helpers.

mod encrypted_bytes;
mod init;
mod ir;
mod noise;
mod setup;

pub use encrypted_bytes::EncryptedBytesScenario;
pub use init::InitScenario;
pub use ir::IrScenario;
pub use noise::NoiseScenario;
pub use setup::{EclairWarmupSetup, PostInitSetup, REGTEST_CHAIN_HASH, SnapshotSetup};
use smite::scenarios::ScenarioError;

use std::time::Duration;

use bitcoin::secp256k1::SecretKey;
use smite::bolt::{Error, Init, Message, Ping};
use smite::noise::NoiseConnection;

use crate::targets::Target;

/// Peer `error` messages after which a target is known to "park" the
/// connection, keeping it open but no longer servicing any messages on it.
/// When this happens the target will not respond to our pings.
///
/// Every entry must describe the behavior justifying it, and be removed once
/// the upstream fix lands.
///
/// - `"Wrong channel id"`: CLN permanently fails the channel without
///   disconnecting. If a follow-on message arrives while the channel's
///   subdaemon is still dying, lightningd fails to handle the message properly,
///   and connectd is left waiting for lightningd's response indefinitely. The
///   node stays alive and keeps serving other connections, but does not read
///   this one again until the connection is closed due to inactivity 80s later.
///   See <https://github.com/ElementsProject/lightning/issues/9369>.
const KNOWN_PARKED_CONNECTION_ERRORS: &[&str] = &["Wrong channel id"];

/// Returns true if `err` is one after which the target is known to leave the
/// connection open but unserviced. See [`KNOWN_PARKED_CONNECTION_ERRORS`].
#[must_use]
pub fn is_known_parked_error(err: &Error) -> bool {
    err.message().is_some_and(|msg| {
        KNOWN_PARKED_CONNECTION_ERRORS
            .iter()
            .any(|known| msg.contains(known))
    })
}

/// Static keys for Noise handshake. Using fixed keys ensures reproducibility
/// of fuzz failures across runs.
const STATIC_KEY: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const EPHEMERAL_KEY: [u8; 32] = [
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
];

/// Perform a Noise handshake with a target and receive its `Init` message.
///
/// Returns the encrypted connection and the target's `Init`. The caller is
/// responsible for sending its own `Init` response (e.g., via `Init::echo`).
///
/// # Errors
///
/// Returns an error if connection, handshake, or init receive fails.
#[allow(clippy::missing_panics_doc)] // Static keys are known-valid constants
pub fn handshake_with_target<T: Target>(
    target: &T,
    timeout: Duration,
) -> Result<(NoiseConnection, Init), ScenarioError> {
    let local_static = SecretKey::from_slice(&STATIC_KEY).expect("valid static key");
    let local_ephemeral = SecretKey::from_slice(&EPHEMERAL_KEY).expect("valid ephemeral key");

    let mut conn = NoiseConnection::connect(
        target.addr(),
        *target.pubkey(),
        local_static,
        local_ephemeral,
        timeout,
    )?;

    // Receive and validate target's init message
    let init_bytes = conn.recv_message()?;
    let Message::Init(init) = Message::decode(&init_bytes)? else {
        return Err(ScenarioError::Protocol("expected init message".into()));
    };

    log::debug!("Handshake complete, received target init");

    Ok((conn, init))
}

/// Outcome of a [`ping_pong_checked`] synchronization.
pub enum PingOutcome {
    /// The target responded with a pong.
    Pong,
    /// The target sent an error after which it is known to leave the connection
    /// unserviced, so no pong is coming. Carries the error message.
    ParkedConnection(String),
}

/// Send ping and wait for pong (for synchronization).
///
/// This ensures the target has done initial processing of any previously sent
/// message before we check if it's still alive.
///
/// # Errors
///
/// Returns an error if the connection is closed or times out.
pub fn ping_pong(conn: &mut NoiseConnection) -> Result<(), ScenarioError> {
    match ping_pong_inner(conn, false)? {
        PingOutcome::Pong => Ok(()),
        PingOutcome::ParkedConnection(_) => {
            unreachable!("stopping on known errors is disabled")
        }
    }
}

/// Like [`ping_pong`], but stops waiting when the target sends an error after
/// which it is known not to service the connection.
///
/// # Errors
///
/// Returns an error if the connection is closed or times out.
pub fn ping_pong_checked(conn: &mut NoiseConnection) -> Result<PingOutcome, ScenarioError> {
    ping_pong_inner(conn, true)
}

fn ping_pong_inner(
    conn: &mut NoiseConnection,
    stop_on_known_error: bool,
) -> Result<PingOutcome, ScenarioError> {
    conn.send_message(&Message::Ping(Ping::new(0)).encode())?;

    // Read messages until we get a pong
    loop {
        let msg_bytes = conn.recv_message()?;
        match Message::decode(&msg_bytes)? {
            Message::Pong(_) => return Ok(PingOutcome::Pong),
            Message::Error(e) if stop_on_known_error && is_known_parked_error(&e) => {
                let msg = e.message().unwrap_or("<non-utf8>").to_string();
                return Ok(PingOutcome::ParkedConnection(msg));
            }
            // Ignore other messages (warnings, errors, etc.)
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, is_known_parked_error};
    use smite::bolt::ChannelId;

    #[test]
    fn known_parked_error_matches_substring() {
        // CLN embeds the phrase in a longer, formatted message.
        let err = Error::for_channel(
            ChannelId::new([0x11; 32]),
            "channeld: sent ERROR Wrong channel id in channel_ready (expected 1111)",
        );
        assert!(is_known_parked_error(&err));
    }

    #[test]
    fn unrelated_error_is_not_parked() {
        let err = Error::all_channels("bad funding_signed signature");
        assert!(!is_known_parked_error(&err));
    }

    #[test]
    fn non_utf8_error_is_not_parked() {
        let err = Error {
            channel_id: ChannelId::ALL,
            data: vec![0xff, 0xfe],
        };
        assert!(!is_known_parked_error(&err));
    }
}
