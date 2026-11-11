//! BOLT 2 state of a channel past negotiation.
//!
//! Tracks each channel once its funding is negotiated: its configuration,
//! commitments, and what each side has sent so far, against which the
//! target's later messages are checked.

use crate::channel_tx::{ChannelCommitments, ChannelConfig, CommitmentState, HolderIdentity, Side};
use bitcoin::secp256k1::PublicKey;

/// State of a single channel, including its static configuration, holder
/// identity, and the state of each side's commitment.
#[allow(clippy::struct_excessive_bools)] // Independent flags, not a state machine
pub struct ChannelState {
    /// Channel configuration established at channel creation and unchanged
    /// for the lifetime of the channel.
    pub config: ChannelConfig,
    /// Holder-specific identity data (channel side and funding secret) used to
    /// sign commitment transactions and verify the counterparty's signatures.
    pub holder: HolderIdentity,
    /// State of each side's commitment, updated as commitments are exchanged and
    /// revoked.
    pub commitments: ChannelCommitments,
    /// Opener's next per-commitment point used to build its next commitment,
    /// revealed by `channel_ready` and then each `revoke_and_ack`. `None` until
    /// known.
    pub opener_next_per_commitment_point: Option<PublicKey>,
    /// Acceptor's next per-commitment point used to build its next commitment,
    /// revealed by `channel_ready` and then each `revoke_and_ack`. `None` until
    /// known.
    pub acceptor_next_per_commitment_point: Option<PublicKey>,
    /// The `second_per_commitment_point` from the first received `channel_ready`,
    /// recorded so a resend can be checked to carry the same point. `None`
    /// until a `channel_ready` is received.
    pub received_channel_ready_point: Option<PublicKey>,
    /// Whether the on-chain output at the advertised funding outpoint matches
    /// the negotiated funding script and amount.
    pub is_funding_outpoint_valid: bool,
    /// Whether the funding transaction was already mined when we sent
    /// `funding_created`. Some targets only watch for the funding confirmation
    /// after the block height at which they receive `funding_created`, so they
    /// may never observe it and never send `channel_ready`.
    pub was_funding_mined_prematurely: bool,
    /// Whether we have ever sent a signature the peer was required to reject,
    /// such as a `funding_created`, `commitment_signed`, or HTLC signature etc.
    /// it cannot verify. Set on the first occurrence and never cleared, since
    /// BOLT 2 requires the peer to fail the channel or disconnect in response,
    /// any subsequent positive response is therefore a violation.
    pub sent_invalid_signature: bool,
    /// Whether a `funding_signed` has already been accepted for this channel.
    /// Any later one means the target re-signed a channel it already funded.
    pub funding_signed_received: bool,
    /// The `scriptpubkey` of the `shutdown` we sent, once we have sent one.
    /// Its presence is what makes a reply expected on this channel.
    pub our_shutdown_script: Option<Vec<u8>>,
    /// The `scriptpubkey` of the peer's `shutdown`, once it has sent one. A
    /// target may ignore any `shutdown` after the first, so a later
    /// `RecvShutdown` for this channel is a no-op that reports this script.
    pub counterparty_shutdown_script: Option<Vec<u8>>,
}

impl ChannelState {
    /// Constructs a channel state with both next per-commitment points unknown.
    #[must_use]
    pub fn new(
        config: ChannelConfig,
        holder: HolderIdentity,
        commitments: ChannelCommitments,
        is_funding_outpoint_valid: bool,
        was_funding_mined_prematurely: bool,
        sent_invalid_signature: bool,
    ) -> Self {
        Self {
            config,
            holder,
            commitments,
            opener_next_per_commitment_point: None,
            acceptor_next_per_commitment_point: None,
            received_channel_ready_point: None,
            is_funding_outpoint_valid,
            was_funding_mined_prematurely,
            sent_invalid_signature,
            funding_signed_received: false,
            our_shutdown_script: None,
            counterparty_shutdown_script: None,
        }
    }

    /// Returns the state of the holder's commitment.
    #[must_use]
    pub fn holder_commitment_state(&self) -> &CommitmentState {
        self.commitments.state(self.holder.side)
    }

    /// Returns the state of the counterparty's commitment.
    #[must_use]
    pub fn counterparty_commitment_state(&self) -> &CommitmentState {
        self.commitments.state(self.holder.counterparty_side())
    }

    /// Returns the holder's next per-commitment point.
    #[must_use]
    pub fn next_holder_per_commitment_point(&self) -> &Option<PublicKey> {
        match self.holder.side {
            Side::Opener => &self.opener_next_per_commitment_point,
            Side::Acceptor => &self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns a mutable reference to the holder's next per-commitment point.
    pub fn next_holder_per_commitment_point_mut(&mut self) -> &mut Option<PublicKey> {
        match self.holder.side {
            Side::Opener => &mut self.opener_next_per_commitment_point,
            Side::Acceptor => &mut self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns the counterparty's next per-commitment point.
    #[must_use]
    pub fn next_counterparty_per_commitment_point(&self) -> &Option<PublicKey> {
        match self.holder.counterparty_side() {
            Side::Opener => &self.opener_next_per_commitment_point,
            Side::Acceptor => &self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns a mutable reference to the counterparty's next per-commitment
    /// point.
    pub fn next_counterparty_per_commitment_point_mut(&mut self) -> &mut Option<PublicKey> {
        match self.holder.counterparty_side() {
            Side::Opener => &mut self.opener_next_per_commitment_point,
            Side::Acceptor => &mut self.acceptor_next_per_commitment_point,
        }
    }
}
