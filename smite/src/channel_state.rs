//! BOLT 2 state of a channel past negotiation.
//!
//! Tracks each channel once its funding is negotiated: its configuration,
//! commitments, and what each side has sent so far, against which the
//! target's later messages are checked.

use crate::channel_tx::{
    ChannelCommitments, ChannelConfig, CommitmentError, CommitmentState, HolderIdentity, Htlc, Side,
};
use bitcoin::secp256k1::PublicKey;

/// A commitment update sent by one side, applied to each side's commitment in
/// turn as commitments are signed and revoked.
#[derive(Clone, Copy)]
pub enum CommitmentUpdate {
    /// An HTLC added to the in-flight set.
    AddHtlc(Htlc),
    /// Fulfillment of the in-flight HTLC that `offerer` added with `id`.
    FulfillHtlc { id: u64, offerer: Side },
    /// Failure of the in-flight HTLC that `offerer` added with `id`.
    FailHtlc { id: u64, offerer: Side },
    /// New fee rate for the commitment transaction, sent only by the opener.
    UpdateFee { feerate_per_kw: u32 },
}

/// Commitment updates queued on one side's commitment.
#[derive(Default)]
pub struct CommitmentUpdateQueue {
    /// Updates to apply to this side's commitment on its next `commitment_signed`.
    pub pending_apply: Vec<CommitmentUpdate>,
    /// Updates sent by the other side and applied to this side's commitment,
    /// moved to the other side's `pending_apply` on this side's `revoke_and_ack`.
    pub pending_for_other: Vec<CommitmentUpdate>,
}

/// Update queues of both sides' commitments.
#[derive(Default)]
pub struct ChannelCommitmentUpdates {
    /// Update queue of the opener's commitment.
    opener: CommitmentUpdateQueue,
    /// Update queue of the acceptor's commitment.
    acceptor: CommitmentUpdateQueue,
}

/// State of a single channel, including its static configuration, holder
/// identity, the state of each side's commitment, and its pending commitment
/// updates.
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
    /// Commitment updates not yet applied to both sides' commitments, moved
    /// along as commitments are exchanged and revoked.
    pub commitment_updates: ChannelCommitmentUpdates,
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
}

impl CommitmentUpdate {
    /// Returns the side that sent this update.
    fn sender(&self) -> Side {
        match self {
            Self::AddHtlc(htlc) => htlc.offerer,
            Self::FulfillHtlc { offerer, .. } | Self::FailHtlc { offerer, .. } => offerer.other(),
            Self::UpdateFee { .. } => Side::Opener,
        }
    }

    /// Returns whether this update, once applied to `side`'s commitment, is
    /// pending for the other side's commitment until `side`'s `revoke_and_ack`.
    /// The sender's commitment is the last to include an update, so the
    /// sender's `revoke_and_ack` has nothing left to move.
    fn awaits_revoke_from(&self, side: Side) -> bool {
        self.sender() != side
    }
}

impl ChannelCommitmentUpdates {
    /// Returns the update queue of the given side's commitment.
    fn queue(&self, side: Side) -> &CommitmentUpdateQueue {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Returns a mutable reference to the update queue of the given side's commitment.
    fn queue_mut(&mut self, side: Side) -> &mut CommitmentUpdateQueue {
        match side {
            Side::Opener => &mut self.opener,
            Side::Acceptor => &mut self.acceptor,
        }
    }
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
            commitment_updates: ChannelCommitmentUpdates::default(),
            opener_next_per_commitment_point: None,
            acceptor_next_per_commitment_point: None,
            received_channel_ready_point: None,
            is_funding_outpoint_valid,
            was_funding_mined_prematurely,
            sent_invalid_signature,
            funding_signed_received: false,
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

    /// Returns the update queue of the holder's commitment.
    #[must_use]
    pub fn holder_commitment_updates(&self) -> &CommitmentUpdateQueue {
        self.commitment_updates.queue(self.holder.side)
    }

    /// Returns the update queue of the counterparty's commitment.
    #[must_use]
    pub fn counterparty_commitment_updates(&self) -> &CommitmentUpdateQueue {
        self.commitment_updates
            .queue(self.holder.counterparty_side())
    }

    /// Queues `update` on the receiving side's `pending_apply`.
    pub fn queue_commitment_update(&mut self, update: CommitmentUpdate) {
        self.commitment_updates
            .queue_mut(update.sender().other())
            .pending_apply
            .push(update);
    }

    /// Applies `side`'s `pending_apply` updates to its commitment, on
    /// `commitment_signed` for it, moving those sent by the other side to
    /// `side`'s `pending_for_other`.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcExceedsBalance`] or
    /// [`CommitmentError::HtlcNotFound`] if an update cannot be applied.
    pub fn apply_commitment_updates(&mut self, side: Side) -> Result<(), CommitmentError> {
        for update in std::mem::take(&mut self.commitment_updates.queue_mut(side).pending_apply) {
            match update {
                CommitmentUpdate::AddHtlc(htlc) => self.commitments.add_htlc(side, htlc)?,
                CommitmentUpdate::FulfillHtlc { id, offerer } => {
                    self.commitments.fulfill_htlc(side, id, offerer)?;
                }
                CommitmentUpdate::FailHtlc { id, offerer } => {
                    self.commitments.fail_htlc(side, id, offerer)?;
                }
                CommitmentUpdate::UpdateFee { feerate_per_kw } => {
                    self.commitments.update_fee(side, feerate_per_kw);
                }
            }
            if update.awaits_revoke_from(side) {
                self.commitment_updates
                    .queue_mut(side)
                    .pending_for_other
                    .push(update);
            }
        }
        Ok(())
    }

    /// Moves `side`'s `pending_for_other` updates to the other side's
    /// `pending_apply`, on `side`'s `revoke_and_ack`.
    pub fn revoke_commitment_updates(&mut self, side: Side) {
        let updates =
            std::mem::take(&mut self.commitment_updates.queue_mut(side).pending_for_other);
        self.commitment_updates
            .queue_mut(side.other())
            .pending_apply
            .extend(updates);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::Features;
    use crate::channel_tx::ChannelPartyConfig;
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn interleaved_updates_reach_both_commitments() {
        let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
        let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
        let party = || ChannelPartyConfig {
            funding_pubkey: pubkey,
            payment_basepoint: pubkey,
            revocation_basepoint: pubkey,
            delayed_payment_basepoint: pubkey,
            htlc_basepoint: pubkey,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };
        let config = ChannelConfig {
            funding_outpoint: OutPoint::null(),
            funding_satoshis: 10_000_000,
            channel_type: Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
            opener: party(),
            acceptor: party(),
            minimum_depth: 6,
            announce_channel: true,
        };
        let commitments = config
            .new_initial_commitments(3_000_000_000, 253, pubkey, pubkey)
            .expect("valid initial commitments");
        let holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret_key,
            htlc_basepoint_privkey: secret_key,
        };
        let mut state = ChannelState::new(config, holder, commitments, true, false, false);

        let htlc = |id, offerer, amount_msat| Htlc {
            id,
            offerer,
            amount_msat,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        // Asserts the number of updates in each of `side`'s queues.
        let assert_queues = |state: &ChannelState, side, pending_apply, pending_for_other| {
            let queue = state.commitment_updates.queue(side);
            assert_eq!(queue.pending_apply.len(), pending_apply);
            assert_eq!(queue.pending_for_other.len(), pending_for_other);
        };
        // Asserts `side`'s commitment balances, fee rate, and in-flight HTLCs.
        let assert_commitment = |state: &ChannelState,
                                 side,
                                 opener_balance_msat,
                                 acceptor_balance_msat,
                                 feerate_per_kw,
                                 htlc_count: usize| {
            let commitment = state.commitments.state(side);
            assert_eq!(commitment.opener_balance_msat, opener_balance_msat);
            assert_eq!(commitment.acceptor_balance_msat, acceptor_balance_msat);
            assert_eq!(commitment.feerate_per_kw, feerate_per_kw);
            assert_eq!(commitment.htlcs.len(), htlc_count);
        };

        // The opener sends HTLC #0 to the acceptor.
        state.queue_commitment_update(CommitmentUpdate::AddHtlc(htlc(
            0,
            Side::Opener,
            1_000_000_000,
        )));
        assert_queues(&state, Side::Acceptor, 1, 0);

        // The opener signs the acceptor's commitment, applying HTLC #0 there.
        state
            .apply_commitment_updates(Side::Acceptor)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Acceptor, 0, 1);
        assert_commitment(&state, Side::Acceptor, 6_000_000_000, 3_000_000_000, 253, 1);

        // The acceptor revokes, moving HTLC #0 to the opener's commitment.
        state.revoke_commitment_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, 0);
        assert_queues(&state, Side::Opener, 1, 0);

        // Before the acceptor signs the opener's commitment, the acceptor sends
        // its own HTLC #0 to the opener.
        state.queue_commitment_update(CommitmentUpdate::AddHtlc(htlc(
            0,
            Side::Acceptor,
            500_000_000,
        )));
        assert_queues(&state, Side::Opener, 2, 0);

        // The opener also changes the fee rate.
        state.queue_commitment_update(CommitmentUpdate::UpdateFee {
            feerate_per_kw: 1_000,
        });
        assert_queues(&state, Side::Acceptor, 1, 0);

        // The acceptor signs the opener's commitment, applying both HTLCs.
        state
            .apply_commitment_updates(Side::Opener)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Opener, 0, 1);
        assert_commitment(&state, Side::Opener, 6_000_000_000, 2_500_000_000, 253, 2);

        // The opener revokes, moving the acceptor's HTLC #0 to the acceptor's
        // commitment, behind the fee change.
        state.revoke_commitment_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 0, 0);
        assert_queues(&state, Side::Acceptor, 2, 0);

        // The opener signs the acceptor's commitment, applying the fee change
        // and the acceptor's HTLC #0.
        state
            .apply_commitment_updates(Side::Acceptor)
            .expect("balance covers HTLC and fee");
        assert_queues(&state, Side::Acceptor, 0, 1);
        assert_commitment(
            &state,
            Side::Acceptor,
            6_000_000_000,
            2_500_000_000,
            1_000,
            2,
        );

        // The acceptor revokes, moving the fee change to the opener's
        // commitment.
        state.revoke_commitment_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, 0);
        assert_queues(&state, Side::Opener, 1, 0);

        // The acceptor fulfills the opener's HTLC #0, queued behind the fee
        // change.
        state.queue_commitment_update(CommitmentUpdate::FulfillHtlc {
            id: 0,
            offerer: Side::Opener,
        });
        assert_queues(&state, Side::Opener, 2, 0);

        // The acceptor signs the opener's commitment, applying the fee change
        // and the fulfill.
        state
            .apply_commitment_updates(Side::Opener)
            .expect("state covers HTLC fulfillment and fees");
        assert_queues(&state, Side::Opener, 0, 1);
        assert_commitment(&state, Side::Opener, 6_000_000_000, 3_500_000_000, 1_000, 1);

        // The opener revokes, moving the fulfill to the acceptor's commitment.
        state.revoke_commitment_updates(Side::Opener);
        assert_queues(&state, Side::Acceptor, 1, 0);
        assert_queues(&state, Side::Opener, 0, 0);

        // The opener signs the acceptor's commitment, applying the fulfill.
        state
            .apply_commitment_updates(Side::Acceptor)
            .expect("state covers HTLC fulfillment");
        assert_queues(&state, Side::Acceptor, 0, 0);
        assert_commitment(
            &state,
            Side::Acceptor,
            6_000_000_000,
            3_500_000_000,
            1_000,
            1,
        );

        // The acceptor revokes with nothing left to move. Both commitments now
        // match and every queue is empty.
        state.revoke_commitment_updates(Side::Acceptor);
        assert_queues(&state, Side::Opener, 0, 0);
        assert_queues(&state, Side::Acceptor, 0, 0);
    }
}
