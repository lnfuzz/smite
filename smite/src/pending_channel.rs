//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them. It also
//! tracks the origin of each pubkey sent on the wire, so pubkey reuse can be
//! reported.

use crate::bolt::{AcceptChannel, ChannelId, OpenChannel};
use crate::channel_tx::Side;
use std::fmt;

/// Negotiation parameters for a channel being established.
///
/// Contains the initiating peer's `open_channel` message, the corresponding
/// `accept_channel` once received, and whether a `funding_created` has already
/// been built from this negotiation.
pub struct PendingChannel {
    pub open_channel: OpenChannel,
    pub accept_channel: Option<AcceptChannel>,
    pub funding_built: bool,
}

/// The origin of a pubkey sent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyOrigin {
    /// The party that sent the pubkey.
    pub side: Side,
    /// The channel the pubkey belongs to: its `temporary_channel_id` before
    /// funding, its `channel_id` after.
    pub channel: ChannelId,
    /// The message field the pubkey was sent in, e.g. `"funding_pubkey"`.
    pub field: &'static str,
}

impl fmt::Display for KeyOrigin {
    /// Formats the origin as its field, side and channel.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} by {:?} on channel {}",
            self.field, self.side, self.channel
        )
    }
}
