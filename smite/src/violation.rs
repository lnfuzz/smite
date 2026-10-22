//! Target-misbehavior findings.
//!
//! Each [`Violation`] variant names a buggy target behavior (e.g., crashing,
//! hanging, breaking a protocol invariant). This is how the fuzzer reports bugs
//! in the target.
//!
//! Conditions that are *not* the target's fault should be ordinary errors and
//! never a `Violation` (e.g., transport failures, insufficient wallet funds,
//! mutator-produced invalid commitments, undecodable harness input).

use crate::bolt::{ChannelId, TemporaryChannelId};

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
    /// - its own fields breach the `accept_channel` requirements,
    /// - it reuses a `temporary_channel_id` still awaiting `funding_created`, or
    /// - it reuses a pubkey whose private key we know or will learn.
    #[error("invalid accept_channel for temporary_channel_id {0}: {1}")]
    InvalidAcceptChannel(TemporaryChannelId, String),

    /// The target's `funding_signed` broke a BOLT 2 requirement, as judged by
    /// [`crate::oracles::FundingSignedOracle`]. The reason names the breached
    /// requirement, one of:
    /// - it names a `channel_id` we sent no `funding_created` for,
    /// - it names a `channel_id` that already received a `funding_signed`,
    /// - it answers a `funding_created` with an invalid signature, or
    /// - its signature is not valid for the holder's commitment transaction.
    #[error("invalid funding_signed for channel_id {0}: {1}")]
    InvalidFundingSigned(ChannelId, String),

    /// The target's `channel_ready` broke a BOLT 2 requirement, as judged by
    /// [`crate::oracles::ChannelReadyOracle`]. The reason names the breached
    /// requirement, one of:
    /// - it names a `channel_id` we have not funded,
    /// - its funding output does not match the negotiated funding script and
    ///   amount,
    /// - it arrives before the funding transaction reached `minimum_depth`,
    /// - it omits the `short_channel_id` alias `option_scid_alias` requires,
    /// - its alias reuses a `short_channel_id` revealed by another channel,
    /// - it resends with a different `second_per_commitment_point`, or
    /// - it reuses a per-commitment point from a previously revealed key.
    #[error("invalid channel_ready for channel_id {0}: {1}")]
    InvalidChannelReady(ChannelId, String),

    /// The target's `shutdown` broke a BOLT 2 requirement, as judged by
    /// [`crate::oracles::ShutdownOracle`]. The reason names the breached
    /// requirement, one of:
    /// - it names a `channel_id` we have not funded,
    /// - it replies on a channel we sent an invalid signature for, which the
    ///   target should have failed instead, or
    /// - its `scriptpubkey` is not a standard form for the negotiated features.
    #[error("invalid shutdown for channel_id {0}: {1}")]
    InvalidShutdown(ChannelId, String),
}
