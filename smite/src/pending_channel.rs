//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them.

use crate::bolt::{AcceptChannel, ChannelId, OpenChannel};

/// Negotiation parameters for a channel being established.
///
/// Contains the initiating peer's `open_channel` message, the corresponding
/// `accept_channel` once received, and the resulting channel ID once
/// `funding_created` has been built from the negotiation.
pub struct PendingChannel {
    pub open_channel: OpenChannel,
    pub accept_channel: Option<AcceptChannel>,
    /// The channel ID derived from the funding outpoint once `funding_created`
    /// has been built. `None` while the negotiation is still pre-funding.
    pub funded_channel_id: Option<ChannelId>,
}
