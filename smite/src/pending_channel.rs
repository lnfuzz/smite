//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them.

use crate::bolt::{AcceptChannel, AcceptChannel2, ChannelId, OpenChannel, OpenChannel2};
use crate::channel_tx::SharedTransaction;

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
    /// The transaction being built by interactive construction, accumulating
    /// both peers' contributions.
    pub shared_tx: SharedTransaction,
    /// Progress through the interactive transaction exchange.
    pub tx_negotiation: TxNegotiation,
    /// Progress through the commitment and signature exchange that follows it.
    pub commitment_exchange: CommitmentExchange,
}

/// How far the interactive transaction exchange has progressed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxNegotiation {
    /// Whether we have sent `tx_complete` since our last contribution.
    pub sent_tx_complete: bool,
    /// Whether the peer's most recent message was `tx_complete`. The
    /// negotiation concludes only on two consecutive `tx_complete`s, so any
    /// other message from the peer clears this.
    pub peer_sent_tx_complete: bool,
    /// Whether either peer has aborted the negotiation.
    pub aborted: bool,
}

/// How far the commitment and signature exchange has progressed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitmentExchange {
    /// Whether we have sent `commitment_signed` for this funding transaction.
    pub sent_commitment_signed: bool,
    /// Whether the peer's `commitment_signed` has arrived and verified.
    pub received_commitment_signed: bool,
    /// Whether the peer's `tx_signatures` has arrived.
    pub received_tx_signatures: bool,
}

impl PendingChannelV2 {
    /// Starts a negotiation from the `open_channel2` we sent, taking the
    /// shared transaction's `nLockTime` from it.
    #[must_use]
    pub fn new(open_channel2: OpenChannel2) -> Self {
        let shared_tx = SharedTransaction::new(open_channel2.locktime);
        Self {
            open_channel2,
            accept_channel2: None,
            channel_id: None,
            shared_tx,
            tx_negotiation: TxNegotiation::default(),
            commitment_exchange: CommitmentExchange::default(),
        }
    }

    /// Whether both peers have sent `tx_complete` in succession, concluding
    /// the negotiation.
    #[must_use]
    pub fn tx_negotiation_complete(&self) -> bool {
        self.tx_negotiation.sent_tx_complete && self.tx_negotiation.peer_sent_tx_complete
    }

    /// Total funding output value: the sum of both peers' contributions, per
    /// BOLT 2. Saturates rather than overflowing on a mutated amount.
    #[must_use]
    pub fn total_funding_satoshis(&self) -> u64 {
        self.open_channel2.funding_satoshis.saturating_add(
            self.accept_channel2
                .as_ref()
                .map_or(0, |ac| ac.funding_satoshis),
        )
    }
}
