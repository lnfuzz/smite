//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them.

use crate::bolt::{AcceptChannel, AcceptChannel2, ChannelId, OpenChannel, OpenChannel2};

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

/// Negotiation parameters for a channel being established with the v2
/// (dual-funded) protocol.
///
/// Keyed by `temporary_channel_id` while the negotiation is in flight. Unlike
/// v1, the real `channel_id` does not depend on the funding transaction: it is
/// derived from both peers' revocation basepoints and so becomes known as soon
/// as `accept_channel2` arrives.
pub struct PendingChannelV2 {
    pub open_channel2: OpenChannel2,
    pub accept_channel2: Option<AcceptChannel2>,
    /// The v2 `channel_id`, known once `accept_channel2` reveals the peer's
    /// revocation basepoint.
    pub channel_id: Option<ChannelId>,
}
