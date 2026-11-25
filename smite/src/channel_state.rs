//! BOLT 2 state of a channel past negotiation.
//!
//! Tracks each channel once its funding is negotiated: its configuration,
//! commitments, and what each side has sent so far, against which the
//! target's later messages are checked.

use crate::channel_tx::{
    ChannelCommitments, ChannelConfig, CommitmentError, CommitmentState, HolderIdentity, Htlc, Side,
};
use bitcoin::secp256k1::PublicKey;
use std::collections::VecDeque;

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
///
/// Each update is tracked until it is irrevocably committed on both sides. For
/// example, A adds HTLC `h` to B:
///
/// ```text
/// A -> update_add_htlc(h) -> B   queue_update                  h -> B.pending_commit
/// A -> commitment_signed -> B    commit_updates(B)             B.pending_commit -> B.pending_revoke
/// A <- revoke_and_ack <- B       revoke_updates(B)             B.pending_revoke -> A.pending_commit
/// A <- commitment_signed <- B    commit_updates(A)             A.pending_commit -> A.pending_revoke
/// A -> revoke_and_ack -> B       revoke_updates(A)             A.pending_revoke -> dropped
/// ```
#[derive(Default)]
pub struct CommitmentUpdateQueue {
    /// Updates waiting for the `commitment_signed` that adds them to this
    /// side's commitment.
    pub pending_commit: Vec<CommitmentUpdate>,
    /// Updates in this side's commitment(s), waiting for this side's `revoke_and_ack`.
    ///
    /// A side may sign again before its last commitment is revoked, so each
    /// `commitment_signed` adds its updates as one batch, possibly empty, and
    /// each `revoke_and_ack` removes the oldest.
    pub pending_revoke: VecDeque<Vec<CommitmentUpdate>>,
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
    /// Commitment updates not yet irrevocably committed on both sides'
    /// commitments, moved along as commitments are exchanged and revoked.
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
    /// The `scriptpubkey` of the `shutdown` we sent, once we have sent one.
    /// Its presence is what makes a reply expected on this channel.
    pub sent_shutdown_script: Option<Vec<u8>>,
    /// The `scriptpubkey` of the peer's `shutdown`, once it has sent one. A
    /// target may ignore any `shutdown` after the first, so its presence means
    /// no further reply is expected on this channel.
    pub received_shutdown_script: Option<Vec<u8>>,
}

impl CommitmentUpdate {
    /// Returns the side that sent this update.
    ///
    /// An `update_fee` is always attributed to the opener, since BOLT 2
    /// restricts it to the opener.
    fn sender(&self) -> Side {
        match self {
            Self::AddHtlc(htlc) => htlc.offerer,
            Self::FulfillHtlc { offerer, .. } | Self::FailHtlc { offerer, .. } => offerer.other(),
            Self::UpdateFee { .. } => Side::Opener,
        }
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
            sent_shutdown_script: None,
            received_shutdown_script: None,
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

    /// Records a sent `update`, to be committed in the receiver's next commitment.
    pub fn queue_update(&mut self, update: CommitmentUpdate) {
        self.commitment_updates
            .queue_mut(update.sender().other())
            .pending_commit
            .push(update);
    }

    /// Applies the updates pending for `side`'s commitment, on the
    /// `commitment_signed` that signs it, queuing them as one batch to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcExceedsBalance`] or
    /// [`CommitmentError::HtlcNotFound`] if an update cannot be applied. In
    /// either case, the channel state may be left with some updates in the batch
    /// applied and others lost. Callers should abort the channel rather than
    /// continuing from this state.
    pub fn commit_updates(&mut self, side: Side) -> Result<(), CommitmentError> {
        let updates = std::mem::take(&mut self.commitment_updates.queue_mut(side).pending_commit);
        for &update in &updates {
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
        }
        self.commitment_updates
            .queue_mut(side)
            .pending_revoke
            .push_back(updates);
        Ok(())
    }

    /// Forwards the oldest batch of updates applied to `side`'s commitment, if
    /// any, to the other side's, on `revoke_and_ack` sent by `side`. Updates
    /// sent by `side` are dropped, as they are now irrevocably committed.
    pub fn revoke_updates(&mut self, side: Side) {
        let updates = self
            .commitment_updates
            .queue_mut(side)
            .pending_revoke
            .pop_front()
            .unwrap_or_default();
        self.commitment_updates
            .queue_mut(side.other())
            .pending_commit
            .extend(updates.into_iter().filter(|u| u.sender() != side));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::Features;
    use crate::channel_tx::ChannelPartyConfig;
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn sample_channel_state() -> ChannelState {
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
        ChannelState::new(config, holder, commitments, true, false, false)
    }

    /// Asserts the number of updates in a side's commitment update queues,
    /// with `pending_revoke` giving the size of each batch, oldest first.
    #[track_caller]
    fn assert_queues(
        state: &ChannelState,
        side: Side,
        pending_commit: usize,
        pending_revoke: &[usize],
    ) {
        let queue = state.commitment_updates.queue(side);
        assert_eq!(queue.pending_commit.len(), pending_commit);
        let batches: Vec<usize> = queue.pending_revoke.iter().map(Vec::len).collect();
        assert_eq!(batches, pending_revoke);
    }

    /// Asserts a side's commitment balances, feerate, and in-flight HTLC count.
    #[track_caller]
    fn assert_commitment_state(
        state: &ChannelState,
        side: Side,
        opener_balance_msat: u64,
        acceptor_balance_msat: u64,
        feerate_per_kw: u32,
        htlc_count: usize,
    ) {
        let commitment = state.commitments.state(side);
        assert_eq!(commitment.opener_balance_msat, opener_balance_msat);
        assert_eq!(commitment.acceptor_balance_msat, acceptor_balance_msat);
        assert_eq!(commitment.feerate_per_kw, feerate_per_kw);
        assert_eq!(commitment.htlcs.len(), htlc_count);
    }

    #[test]
    fn interleaved_updates_reach_both_commitments() {
        let mut state = sample_channel_state();
        let htlc = |id, offerer, amount_msat| Htlc {
            id,
            offerer,
            amount_msat,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };

        // The opener sends HTLC #0 to the acceptor.
        state.queue_update(CommitmentUpdate::AddHtlc(htlc(
            0,
            Side::Opener,
            1_000_000_000,
        )));
        assert_queues(&state, Side::Acceptor, 1, &[]);

        // The opener signs the acceptor's commitment, applying HTLC #0 there.
        state
            .commit_updates(Side::Acceptor)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Acceptor, 0, &[1]);
        assert_commitment_state(&state, Side::Acceptor, 6_000_000_000, 3_000_000_000, 253, 1);

        // The acceptor revokes, moving HTLC #0 to the opener's commitment.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_queues(&state, Side::Opener, 1, &[]);

        // Before the acceptor signs the opener's commitment, the acceptor sends
        // its own HTLC #0 to the opener.
        state.queue_update(CommitmentUpdate::AddHtlc(htlc(
            0,
            Side::Acceptor,
            500_000_000,
        )));
        assert_queues(&state, Side::Opener, 2, &[]);

        // The opener also changes the fee rate.
        state.queue_update(CommitmentUpdate::UpdateFee {
            feerate_per_kw: 1_000,
        });
        assert_queues(&state, Side::Acceptor, 1, &[]);

        // The acceptor signs the opener's commitment, applying both HTLCs.
        state
            .commit_updates(Side::Opener)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Opener, 0, &[2]);
        assert_commitment_state(&state, Side::Opener, 6_000_000_000, 2_500_000_000, 253, 2);

        // The opener revokes, dropping its now irrevocably committed HTLC #0
        // and moving the acceptor's HTLC #0 to the acceptor's commitment,
        // behind the fee change.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 0, &[]);
        assert_queues(&state, Side::Acceptor, 2, &[]);

        // The opener signs the acceptor's commitment, applying the fee change
        // and the acceptor's HTLC #0.
        state
            .commit_updates(Side::Acceptor)
            .expect("balance covers HTLC and fee");
        assert_queues(&state, Side::Acceptor, 0, &[2]);
        assert_commitment_state(
            &state,
            Side::Acceptor,
            6_000_000_000,
            2_500_000_000,
            1_000,
            2,
        );

        // The acceptor revokes, dropping its now irrevocably committed HTLC #0
        // and moving the fee change to the opener's commitment.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_queues(&state, Side::Opener, 1, &[]);

        // The opener fails the acceptor's HTLC #0.
        state.queue_update(CommitmentUpdate::FailHtlc {
            id: 0,
            offerer: Side::Acceptor,
        });
        assert_queues(&state, Side::Acceptor, 1, &[]);

        // The acceptor fulfills the opener's HTLC #0, queued behind the fee
        // change.
        state.queue_update(CommitmentUpdate::FulfillHtlc {
            id: 0,
            offerer: Side::Opener,
        });
        assert_queues(&state, Side::Opener, 2, &[]);

        // The acceptor signs the opener's commitment, applying the fee change
        // and the fulfill.
        state
            .commit_updates(Side::Opener)
            .expect("state covers HTLC fulfillment and fees");
        assert_queues(&state, Side::Opener, 0, &[2]);
        assert_commitment_state(&state, Side::Opener, 6_000_000_000, 3_500_000_000, 1_000, 1);

        // The opener revokes, dropping the now irrevocably committed fee change
        // and moving the fulfill to the acceptor's commitment, behind the fail.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Acceptor, 2, &[]);
        assert_queues(&state, Side::Opener, 0, &[]);

        // The opener signs the acceptor's commitment, applying the fail and the
        // fulfill.
        state
            .commit_updates(Side::Acceptor)
            .expect("state covers HTLC failure and fulfillment");
        assert_queues(&state, Side::Acceptor, 0, &[2]);
        assert_commitment_state(
            &state,
            Side::Acceptor,
            6_000_000_000,
            4_000_000_000,
            1_000,
            0,
        );

        // The acceptor revokes, dropping the now irrevocably committed fulfill
        // and moving the fail to the opener's commitment.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_queues(&state, Side::Opener, 1, &[]);

        // The acceptor signs the opener's commitment, applying the fail.
        state
            .commit_updates(Side::Opener)
            .expect("state covers HTLC failure");
        assert_queues(&state, Side::Opener, 0, &[1]);
        assert_commitment_state(&state, Side::Opener, 6_000_000_000, 4_000_000_000, 1_000, 0);

        // The opener revokes, dropping the now irrevocably committed fail. Both
        // commitments now match with no HTLCs left and every queue is empty.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 0, &[]);
        assert_queues(&state, Side::Acceptor, 0, &[]);
    }

    #[test]
    fn last_fee_update_sent_is_committed() {
        let mut state = sample_channel_state();

        // The opener changes the fee rate twice before signing.
        state.queue_update(CommitmentUpdate::UpdateFee {
            feerate_per_kw: 2_000,
        });
        state.queue_update(CommitmentUpdate::UpdateFee {
            feerate_per_kw: 3_000,
        });
        assert_queues(&state, Side::Acceptor, 2, &[]);

        // The opener signs the acceptor's commitment, applying both fee changes
        // in order, so the second one wins.
        state
            .commit_updates(Side::Acceptor)
            .expect("state covers fees");
        assert_queues(&state, Side::Acceptor, 0, &[2]);
        assert_commitment_state(
            &state,
            Side::Acceptor,
            7_000_000_000,
            3_000_000_000,
            3_000,
            0,
        );

        // The acceptor revokes, moving both fee changes to the opener's
        // commitment.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_queues(&state, Side::Opener, 2, &[]);

        // The acceptor signs the opener's commitment, applying both fee changes
        // in order, so the second one wins there too.
        state
            .commit_updates(Side::Opener)
            .expect("state covers fees");
        assert_queues(&state, Side::Opener, 0, &[2]);
        assert_commitment_state(&state, Side::Opener, 7_000_000_000, 3_000_000_000, 3_000, 0);

        // The opener revokes, dropping both now irrevocably committed fee
        // changes. Both commitments end on the last fee rate sent.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 0, &[]);
        assert_queues(&state, Side::Acceptor, 0, &[]);
    }

    #[test]
    fn consecutive_commits_are_revoked_in_order() {
        let mut state = sample_channel_state();

        // The opener sends HTLC #0 and signs the acceptor's commitment.
        state.queue_update(CommitmentUpdate::AddHtlc(Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 1_000_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        }));
        state
            .commit_updates(Side::Acceptor)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Acceptor, 0, &[1]);

        // Before the acceptor revokes, the opener signs again with no new
        // updates, adding an empty batch.
        state
            .commit_updates(Side::Acceptor)
            .expect("no updates to apply");
        assert_queues(&state, Side::Acceptor, 0, &[1, 0]);
        assert_commitment_state(&state, Side::Acceptor, 6_000_000_000, 3_000_000_000, 253, 1);

        // The acceptor revokes its first commitment, moving only HTLC #0 to
        // the opener's commitment.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[0]);
        assert_queues(&state, Side::Opener, 1, &[]);

        // The acceptor signs the opener's commitment, applying HTLC #0.
        state
            .commit_updates(Side::Opener)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Opener, 0, &[1]);
        assert_commitment_state(&state, Side::Opener, 6_000_000_000, 3_000_000_000, 253, 1);

        // The opener revokes, dropping its now irrevocably committed HTLC #0.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 0, &[]);
        assert_queues(&state, Side::Acceptor, 0, &[0]);

        // The acceptor revokes its second commitment, forwarding the empty
        // batch.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_queues(&state, Side::Opener, 0, &[]);
    }

    #[test]
    fn consecutive_revokes_are_forwarded_in_order() {
        let mut state = sample_channel_state();
        let htlc = |id, amount_msat| Htlc {
            id,
            offerer: Side::Opener,
            amount_msat,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };

        // The opener sends HTLC #0 and signs the acceptor's commitment.
        state.queue_update(CommitmentUpdate::AddHtlc(htlc(0, 1_000_000_000)));
        state
            .commit_updates(Side::Acceptor)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Acceptor, 0, &[1]);

        // Before the acceptor revokes, the opener sends HTLC #1 and signs
        // again, adding a second batch.
        state.queue_update(CommitmentUpdate::AddHtlc(htlc(1, 500_000_000)));
        state
            .commit_updates(Side::Acceptor)
            .expect("balance covers HTLC");
        assert_queues(&state, Side::Acceptor, 0, &[1, 1]);
        assert_commitment_state(&state, Side::Acceptor, 5_500_000_000, 3_000_000_000, 253, 2);

        // The acceptor revokes its first commitment, moving only HTLC #0 to
        // the opener's commitment.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[1]);
        assert_queues(&state, Side::Opener, 1, &[]);

        // The acceptor revokes its second commitment right away, moving HTLC
        // #1 to the opener's commitment, behind HTLC #0.
        state.revoke_updates(Side::Acceptor);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_queues(&state, Side::Opener, 2, &[]);

        // The acceptor signs the opener's commitment, applying both HTLCs.
        state
            .commit_updates(Side::Opener)
            .expect("balance covers HTLCs");
        assert_queues(&state, Side::Opener, 0, &[2]);
        assert_commitment_state(&state, Side::Opener, 5_500_000_000, 3_000_000_000, 253, 2);

        // The opener revokes, dropping both now irrevocably committed HTLCs.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 0, &[]);
        assert_queues(&state, Side::Acceptor, 0, &[]);
    }

    #[test]
    fn revoke_without_commit_forwards_nothing() {
        let mut state = sample_channel_state();

        // The acceptor sends HTLC #0 but does not sign the opener's commitment.
        state.queue_update(CommitmentUpdate::AddHtlc(Htlc {
            id: 0,
            offerer: Side::Acceptor,
            amount_msat: 1_000_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        }));
        assert_queues(&state, Side::Opener, 1, &[]);

        // The opener revokes with no batch pending, leaving every queue and
        // commitment unchanged.
        state.revoke_updates(Side::Opener);
        assert_queues(&state, Side::Opener, 1, &[]);
        assert_queues(&state, Side::Acceptor, 0, &[]);
        assert_commitment_state(&state, Side::Opener, 7_000_000_000, 3_000_000_000, 253, 0);
        assert_commitment_state(&state, Side::Acceptor, 7_000_000_000, 3_000_000_000, 253, 0);
    }
}
