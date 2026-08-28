//! Target-misbehavior findings.
//!
//! Each [`Violation`] variant names a buggy target behavior (e.g., crashing,
//! hanging, breaking a protocol invariant). This is how the fuzzer reports bugs
//! in the target.
//!
//! Conditions that are *not* the target's fault should be ordinary errors and
//! never a `Violation` (e.g., transport failures, insufficient wallet funds,
//! mutator-produced invalid commitments, undecodable harness input).

use crate::bolt::ChannelId;

/// A detected misbehavior of the target under test.
#[derive(Debug, thiserror::Error)]
pub enum Violation {
    /// The target process died during or after processing the input.
    #[error("target crashed")]
    Crashed,

    /// The target stopped responding to the post-input ping-pong sync.
    #[error("target hung (ping timeout)")]
    Hung,

    /// The target closed the connection during the post-input ping-pong sync
    /// instead of responding.
    #[error("target unexpectedly disconnected")]
    UnexpectedDisconnect,

    /// The target's `accept_channel` broke a BOLT 2 requirement, as judged by
    /// [`crate::oracles::AcceptChannelOracle`]. The reason names the breached
    /// requirement, one of:
    /// - it names a `temporary_channel_id` we sent no `open_channel` for,
    /// - it accepts an `open_channel` BOLT 2 required it to reject,
    /// - its own fields breach the `accept_channel` requirements, or
    /// - it reuses a `temporary_channel_id` still awaiting `funding_created`.
    #[error("invalid accept_channel for temporary_channel_id {0}: {1}")]
    InvalidAcceptChannel(ChannelId, String),

    /// The target sent a `funding_signed` or `channel_ready` for a `channel_id`
    /// we never opened, i.e. one for which no state was ever established.
    #[error("unknown channel: no tracked state for channel_id {0}")]
    UnknownChannel(ChannelId),

    /// The target's `funding_signed` signature failed to verify against the
    /// holder's initial commitment transaction.
    #[error("invalid counterparty signature for channel_id {0}")]
    InvalidCounterpartySignature(ChannelId),

    /// The target's `commitment_signed` for a channel establishment v2 open
    /// carried HTLC signatures. BOLT 2 requires the first commitment of a v2
    /// open to have no HTLCs, so there is nothing for them to sign.
    #[error("unexpected htlc signatures in commitment_signed for channel_id {0}")]
    UnexpectedHtlcSignatures(ChannelId),
}
