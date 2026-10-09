//! BOLT 3 commitment transaction construction and signing.

use super::funding::build_funding_witness_script;
use crate::bolt::Features;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};

/// Anchor output value in satoshis.
const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Weight of a non-anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR: u64 = 724;

/// Weight of an anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_ANCHOR: u64 = 1124;

/// Additional commitment weight per non-trimmed HTLC output.
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

/// Weight of an HTLC-timeout transaction on a non-anchor channel.
const HTLC_TIMEOUT_TX_WEIGHT_NON_ANCHOR: u64 = 663;

/// Weight of an HTLC-success transaction on a non-anchor channel.
const HTLC_SUCCESS_TX_WEIGHT_NON_ANCHOR: u64 = 703;

/// Errors that can occur when constructing or validating commitment transactions.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    /// Funding amount overflowed when converting to millisatoshis.
    #[error("funding_satoshis overflowed when converting to msat")]
    FundingMsatOverflow,

    /// Push amount exceeds the total funding amount.
    #[error("push_msat exceeds funding_msat")]
    PushExceedsFunding,

    /// Adding an HTLC would underflow the offerer's balance.
    #[error("htlc amount exceeds offerer's balance")]
    HtlcExceedsBalance,

    /// No in-flight HTLC matched the given id and offerer.
    #[error("htlc with the given id and offerer was not found")]
    HtlcNotFound,
}

/// Identifies the channel participant relative to the funding flow.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Opener,
    Acceptor,
}

/// Holder's identity and funding secret for the commitment.
pub struct HolderIdentity {
    /// Whether the holder is the channel opener or acceptor.
    pub side: Side,
    /// Holder's funding private key.
    pub funding_privkey: SecretKey,
    /// Holder's HTLC basepoint private key.
    pub htlc_basepoint_privkey: SecretKey,
}

/// Static public keys and channel parameters for one side of a channel (opener or acceptor).
pub struct ChannelPartyConfig {
    /// Funding pubkey used in the funding output.
    pub funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    pub payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive keys that allow punishment of old states.
    pub revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the time-locked `to_local` output key.
    pub delayed_payment_basepoint: PublicKey,
    /// HTLC basepoint used to derive HTLC keys.
    pub htlc_basepoint: PublicKey,
    /// Minimum output value below which outputs are trimmed as dust.
    pub dust_limit_satoshis: u64,
    /// CSV delay this party imposes on the other's `to_local` output.
    pub to_self_delay: u16,
}

/// Channel configuration including funding details and both parties configuration.
pub struct ChannelConfig {
    /// Funding transaction outpoint.
    pub funding_outpoint: OutPoint,
    /// Total channel funding amount in satoshis.
    pub funding_satoshis: u64,
    /// Channel type feature bits. The commitment format (anchor / legacy) is
    /// derived from the bits set here.
    pub channel_type: Features,
    /// Opener's static keys and parameters.
    pub opener: ChannelPartyConfig,
    /// Acceptor's static keys and parameters.
    pub acceptor: ChannelPartyConfig,
    /// Minimum funding confirmations required before `channel_ready` messages
    /// are exchanged and the channel becomes active.
    pub minimum_depth: u32,
}

/// An in-flight HTLC that appears (subject to dust trimming) as an output in
/// the commitment transaction.
#[derive(Clone, Copy)]
pub struct Htlc {
    /// HTLC ID, unique per channel and offering direction.
    pub id: u64,
    /// The party that offered this HTLC.
    ///
    /// Combined with the commitment owner, this determines whether the HTLC
    /// is treated as an "offered" or "received" output.
    pub offerer: Side,
    /// HTLC amount in millisatoshis.
    pub amount_msat: u64,
    /// The expiry height of the HTLC.
    pub cltv_expiry: u32,
    /// `SHA256` of the payment preimage.
    pub payment_hash: [u8; 32],
}

/// State of `local_side`'s commitment transaction.
///
/// Each side has its own commitment state, so the commitment number, fee rate,
/// and balances may differ until both sides have caught up.
pub struct CommitmentState {
    /// Side whose commitment transaction this state is for.
    pub local_side: Side,
    /// The commitment transaction number.
    pub commitment_number: u64,
    /// Fee rate for the commitment transaction.
    pub feerate_per_kw: u32,
    /// Per-commitment point of `local_side`, used to derive commitment-specific
    /// keys.
    pub per_commitment_point: PublicKey,
    /// Amount allocated to the opener in millisatoshis. Represents the balance
    /// before subtraction of fees, and anchors outputs. In-flight HTLCs are
    /// represented as separate outputs in the commitment transaction, so those
    /// values are already deducted from these balance values.
    pub opener_balance_msat: u64,
    /// Amount allocated to the acceptor in millisatoshis. In-flight HTLCs are
    /// represented as separate outputs in the commitment transaction, so those
    /// values are already deducted from these balance values.
    pub acceptor_balance_msat: u64,
    /// In-flight HTLCs offered in either direction.
    pub htlcs: Vec<Htlc>,
}

impl CommitmentState {
    /// Returns a mutable reference to the given side's balance.
    fn balance_msat_mut(&mut self, side: Side) -> &mut u64 {
        match side {
            Side::Opener => &mut self.opener_balance_msat,
            Side::Acceptor => &mut self.acceptor_balance_msat,
        }
    }
}

/// State of both sides' commitments.
pub struct ChannelCommitments {
    /// State of the opener's commitment.
    opener: CommitmentState,
    /// State of the acceptor's commitment.
    acceptor: CommitmentState,
}

/// Costs associated with a commitment transaction, including transaction fee
/// and anchor outputs.
pub struct CommitmentCost {
    /// Commitment transaction fee in satoshis.
    pub fee_sat: u64,
    /// Total cost of anchor outputs in satoshis.
    pub anchor_cost_sat: u64,
}

/// An HTLC output included in a commitment transaction after dust trimming and
/// output ordering have been finalized.
#[derive(Clone, Copy)]
struct HtlcOutputInCommitment {
    /// Whether this is an offered or received HTLC output from the commitment
    /// owner's perspective.
    offered: bool,
    /// The HTLC that this output corresponds to.
    htlc: Htlc,
    /// The output index of the HTLC in the commitment transaction.
    vout: u32,
}

/// Per-commitment keys used when constructing and signing a commitment
/// transaction.
struct TxCreationKeys {
    /// The per-commitment point used to derive the commitment-specific keys.
    per_commitment_point: PublicKey,
    /// Local delayed payment pubkey.
    local_delayedpubkey: PublicKey,
    /// Revocation pubkey for this commitment.
    revocationpubkey: PublicKey,
    /// Local per-commitment HTLC pubkey.
    local_htlcpubkey: PublicKey,
    /// Remote per-commitment HTLC pubkey.
    remote_htlcpubkey: PublicKey,
}

/// A fully built commitment transaction with the metadata needed to construct
/// and sign its second-stage HTLC transactions.
struct BuiltCommitmentTx {
    /// Side whose commitment transaction this is.
    local_side: Side,
    /// Fee rate of the commitment transaction, also used to compute the fees
    /// of its second-stage HTLC transactions.
    feerate_per_kw: u32,
    /// Per-commitment keys for the local side.
    keys: TxCreationKeys,
    /// The set of non-dust HTLCs included in the commitment. They must be sorted
    /// in increasing output index order.
    nondust_htlcs: Vec<HtlcOutputInCommitment>,
    /// The assembled commitment transaction.
    tx: Transaction,
}

/// A second-stage HTLC transaction spending an HTLC output from a commitment
/// transaction.
struct BuiltHtlcTx {
    /// The commitment transaction HTLC output being spent.
    nondust_htlc: HtlcOutputInCommitment,
    /// The HTLC-success or HTLC-timeout transaction.
    tx: Transaction,
}

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

impl Side {
    /// Returns the counterparty side.
    fn other(self) -> Self {
        match self {
            Self::Opener => Self::Acceptor,
            Self::Acceptor => Self::Opener,
        }
    }
}

impl HolderIdentity {
    /// Returns the counterparty side.
    #[must_use]
    fn counterparty_side(&self) -> Side {
        self.side.other()
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
            opener_next_per_commitment_point: None,
            acceptor_next_per_commitment_point: None,
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
}

impl ChannelConfig {
    /// Returns the config for the given channel side.
    fn party(&self, side: Side) -> &ChannelPartyConfig {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Constructs the initial commitment states for both sides after channel
    /// funding. Both sides start with the same commitment state, except for the
    /// per-commitment point and `local_side`.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`CommitmentError::FundingMsatOverflow`] if `funding_satoshis` overflows when
    ///   converting to millisatoshis.
    /// - [`CommitmentError::PushExceedsFunding`] if `push_msat` exceeds the total
    ///   funding amount in millisatoshis.
    pub fn new_initial_commitments(
        &self,
        push_msat: u64,
        feerate_per_kw: u32,
        opener_per_commitment_point: PublicKey,
        acceptor_per_commitment_point: PublicKey,
    ) -> Result<ChannelCommitments, CommitmentError> {
        let funding_msat = self
            .funding_satoshis
            .checked_mul(1000)
            .ok_or(CommitmentError::FundingMsatOverflow)?;
        let to_opener_balance_msat = funding_msat
            .checked_sub(push_msat)
            .ok_or(CommitmentError::PushExceedsFunding)?;
        let to_acceptor_balance_msat = push_msat;

        let new_state = |local_side, per_commitment_point| CommitmentState {
            local_side,
            commitment_number: 0,
            feerate_per_kw,
            per_commitment_point,
            opener_balance_msat: to_opener_balance_msat,
            acceptor_balance_msat: to_acceptor_balance_msat,
            htlcs: Vec::new(),
        };

        Ok(ChannelCommitments {
            opener: new_state(Side::Opener, opener_per_commitment_point),
            acceptor: new_state(Side::Acceptor, acceptor_per_commitment_point),
        })
    }

    /// Counts the non-dust HTLCs for the given commitment side.
    #[must_use]
    pub fn count_nondust_htlcs(&self, state: &CommitmentState, local_side: Side) -> usize {
        state
            .htlcs
            .iter()
            .filter(|htlc| {
                !htlc.is_dust(
                    self.party(local_side).dust_limit_satoshis,
                    state.feerate_per_kw,
                    &self.channel_type,
                    local_side,
                )
            })
            .count()
    }

    /// Builds the signatures for the counterparty's commitment transaction:
    /// the funding-input signature plus one signature per non-dust HTLC
    /// output, in commitment-output order.
    #[must_use]
    pub fn sign_counterparty_commitment(
        &self,
        commitments: &ChannelCommitments,
        holder: &HolderIdentity,
    ) -> (Signature, Vec<Signature>) {
        let state = commitments.state(holder.counterparty_side());
        let commitment = self.build_commitment_tx(state);
        let htlc_txs = self.build_htlc_txs(&commitment);
        let commitment_sig = self.sign_commitment_tx(&commitment, &holder.funding_privkey);
        let htlc_sigs = self.sign_htlc_txs(&commitment, &htlc_txs, holder);

        (commitment_sig, htlc_sigs)
    }

    /// Verifies the counterparty's signatures on the holder's commitment
    /// transaction and all of its non-dust HTLC outputs.
    #[must_use]
    pub fn verify_counterparty_signature(
        &self,
        commitments: &ChannelCommitments,
        holder: &HolderIdentity,
        commitment_sig: &Signature,
        htlc_sigs: &[Signature],
    ) -> bool {
        let state = commitments.state(holder.side);
        let commitment = self.build_commitment_tx(state);
        if !self.verify_commitment_sig(
            &commitment,
            &self.party(holder.counterparty_side()).funding_pubkey,
            commitment_sig,
        ) {
            return false;
        }

        let htlc_txs = self.build_htlc_txs(&commitment);
        self.verify_htlc_sigs(&commitment, &htlc_txs, htlc_sigs)
    }

    /// Builds the signatures for the holder's own commitment transaction and
    /// its HTLC outputs. Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn sign_holder_commitment(
        &self,
        commitments: &ChannelCommitments,
        holder: &HolderIdentity,
    ) -> (Signature, Vec<Signature>) {
        let state = commitments.state(holder.side);
        let commitment = self.build_commitment_tx(state);
        let htlc_txs = self.build_htlc_txs(&commitment);
        let commitment_sig = self.sign_commitment_tx(&commitment, &holder.funding_privkey);
        let htlc_sigs = self.sign_htlc_txs(&commitment, &htlc_txs, holder);

        (commitment_sig, htlc_sigs)
    }

    /// Builds the commitment transaction. The commitment format (legacy or
    /// anchor) is determined by the `channel_type`.
    fn build_commitment_tx(&self, state: &CommitmentState) -> BuiltCommitmentTx {
        // Obscured commitment number.
        let obscuring_factor = compute_obscuring_factor(
            &self.opener.payment_basepoint,
            &self.acceptor.payment_basepoint,
        );
        let obscured_commitment_number = state.commitment_number ^ obscuring_factor;

        // Upper 8 bits of sequence are 0x80 and lower 24 bits are the upper 24 bits
        // of the obscured commitment number.
        let sequence = (0x80u32 << (8 * 3))
            | u32::try_from(obscured_commitment_number >> 24)
                .expect("commitment_number cannot be more than 48 bits");

        // Upper 8 bits of locktime are 0x20 and lower 24 bits are the lower 24 bits
        // of the obscured commitment number.
        let locktime = (0x20u32 << (8 * 3))
            | u32::try_from(obscured_commitment_number & 0x00ff_ffff_u64)
                .expect("commitment_number cannot be more than 48 bits");

        // Build the commitment transaction
        let keys = TxCreationKeys::derive(self, state);
        let (outputs, nondust_htlcs) = self.build_commitment_outputs(state, &keys);

        // Witness is not included in the BIP 143 sighash, so we leave it empty.
        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(locktime),
            input: vec![input],
            output: outputs,
        };

        BuiltCommitmentTx {
            local_side: state.local_side,
            feerate_per_kw: state.feerate_per_kw,
            keys,
            nondust_htlcs,
            tx,
        }
    }

    /// Builds the sighash for the given commitment transaction.
    fn build_commitment_sighash(&self, tx: &Transaction) -> [u8; 32] {
        // Funding output witness script.
        let funding_witness_script = build_funding_witness_script(
            &self.opener.funding_pubkey,
            &self.acceptor.funding_pubkey,
        );

        // Compute the BIP143 sighash
        let sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(
                0,
                &funding_witness_script,
                Amount::from_sat(self.funding_satoshis),
                EcdsaSighashType::All,
            )
            .expect("input index 0 is always in bounds for a single input transaction");

        sighash.to_byte_array()
    }

    /// Builds the lexicographically sorted commitment outputs together with
    /// the mapping from each non-dust HTLC to its output index.
    ///
    /// Outputs are built for the commitment side specified by `state`:
    /// the opener or the acceptor.
    fn build_commitment_outputs(
        &self,
        state: &CommitmentState,
        keys: &TxCreationKeys,
    ) -> (Vec<TxOut>, Vec<HtlcOutputInCommitment>) {
        let local_side = state.local_side;
        let anchor = self.channel_type.supports_feature(Features::OPTION_ANCHORS);
        let mut outputs: Vec<TxOut> = Vec::new();

        // Insert non-dust HTLC outputs, recording each one's output index.
        let nondust_htlc_outputs = self.build_sorted_nondust_htlc_outputs(state, keys);
        let nondust_htlc_count = nondust_htlc_outputs.len();
        let mut nondust_htlcs: Vec<HtlcOutputInCommitment> = Vec::with_capacity(nondust_htlc_count);
        for (vout, (txout, htlc)) in nondust_htlc_outputs.into_iter().enumerate() {
            nondust_htlcs.push(HtlcOutputInCommitment {
                offered: htlc.is_offered(local_side),
                htlc,
                vout: u32::try_from(vout)
                    .expect("commitment cannot have more than u32::MAX outputs"),
            });
            outputs.push(txout);
        }

        // Insert the non-HTLC outputs, ordered by value, then by script pubkey.
        let mut insert_non_htlc_output = |non_htlc_output: TxOut| {
            let idx = outputs
                .binary_search_by(|output| {
                    output
                        .value
                        .cmp(&non_htlc_output.value)
                        .then(output.script_pubkey.cmp(&non_htlc_output.script_pubkey))
                })
                .unwrap_or_else(|i| i);

            outputs.insert(idx, non_htlc_output);

            // Increment the transaction output indices of all the HTLCs that
            // come after the output we just inserted.
            nondust_htlcs
                .iter_mut()
                .rev()
                .take_while(|nondust_htlc| {
                    nondust_htlc.vout
                        >= u32::try_from(idx)
                            .expect("commitment cannot have more than u32::MAX outputs")
                })
                .for_each(|nondust_htlc| nondust_htlc.vout += 1);
        };

        // Fee and balances.
        let commitment_cost =
            CommitmentCost::new(state.feerate_per_kw, &self.channel_type, nondust_htlc_count);
        let opener_balance =
            (state.opener_balance_msat / 1000).saturating_sub(commitment_cost.total_sat());
        let acceptor_balance = state.acceptor_balance_msat / 1000;

        // Map opener/acceptor to local/remote for this commitment side.
        let (to_local_value, to_remote_value) = match local_side {
            Side::Opener => (opener_balance, acceptor_balance),
            Side::Acceptor => (acceptor_balance, opener_balance),
        };
        let local = self.party(local_side);
        let remote = self.party(local_side.other());
        let has_to_local = to_local_value >= local.dust_limit_satoshis;
        let has_to_remote = to_remote_value >= local.dust_limit_satoshis;

        if has_to_local {
            let to_local_spk = build_revocable_scriptpubkey(
                &keys.local_delayedpubkey,
                &keys.revocationpubkey,
                remote.to_self_delay,
            );

            insert_non_htlc_output(TxOut {
                value: Amount::from_sat(to_local_value),
                script_pubkey: to_local_spk,
            });
        }
        if has_to_remote {
            let to_remote_spk = build_to_remote_scriptpubkey(&remote.payment_basepoint, anchor);

            insert_non_htlc_output(TxOut {
                value: Amount::from_sat(to_remote_value),
                script_pubkey: to_remote_spk,
            });
        }

        if anchor {
            if has_to_local || nondust_htlc_count > 0 {
                insert_non_htlc_output(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&local.funding_pubkey),
                });
            }

            if has_to_remote || nondust_htlc_count > 0 {
                insert_non_htlc_output(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&remote.funding_pubkey),
                });
            }
        }

        (outputs, nondust_htlcs)
    }

    /// Builds the non-dust HTLC outputs for the commitment transaction, tagging
    /// each output with its corresponding [`Htlc`] and returning them in BOLT 3
    /// commitment output order.
    fn build_sorted_nondust_htlc_outputs(
        &self,
        state: &CommitmentState,
        keys: &TxCreationKeys,
    ) -> Vec<(TxOut, Htlc)> {
        let local_side = state.local_side;
        let anchor = self.channel_type.supports_feature(Features::OPTION_ANCHORS);
        let dust_limit = self.party(local_side).dust_limit_satoshis;

        // Add non-dust HTLCs as commitment transaction outputs.
        let mut outputs = Vec::new();
        for htlc in &state.htlcs {
            if htlc.is_dust(
                dust_limit,
                state.feerate_per_kw,
                &self.channel_type,
                local_side,
            ) {
                continue;
            }

            let htlc_witness_script =
                build_htlc_witness_script(htlc, keys, htlc.is_offered(local_side), anchor);
            let output = TxOut {
                script_pubkey: htlc_witness_script.to_p2wsh(),
                value: htlc.amount(),
            };

            outputs.push((output, *htlc));
        }

        // Sort into BOLT 3 transaction output order: by value, then by
        // `scriptPubKey` bytes, then by `cltv_expiry` for HTLC outputs.
        outputs.sort_by(|(a_txout, a_htlc), (b_txout, b_htlc)| {
            a_txout
                .value
                .cmp(&b_txout.value)
                .then_with(|| {
                    a_txout
                        .script_pubkey
                        .as_bytes()
                        .cmp(b_txout.script_pubkey.as_bytes())
                })
                .then_with(|| a_htlc.cltv_expiry.cmp(&b_htlc.cltv_expiry))
        });

        outputs
    }

    /// Signs the commitment transaction with the holder's funding private key.
    fn sign_commitment_tx(
        &self,
        commitment: &BuiltCommitmentTx,
        funding_privkey: &SecretKey,
    ) -> Signature {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        sign(&sighash, funding_privkey)
    }

    /// Verifies the commitment signature against the counterparty's funding
    /// public key.
    fn verify_commitment_sig(
        &self,
        commitment: &BuiltCommitmentTx,
        funding_pubkey: &PublicKey,
        commitment_sig: &Signature,
    ) -> bool {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        verify(&sighash, commitment_sig, funding_pubkey)
    }

    /// Builds the second-stage HTLC transactions that spend the non-dust HTLC
    /// outputs of `commitment`, in commitment-output order.
    fn build_htlc_txs(&self, commitment: &BuiltCommitmentTx) -> Vec<BuiltHtlcTx> {
        let local_side = commitment.local_side;
        let anchor = self.channel_type.supports_feature(Features::OPTION_ANCHORS);
        let mut htlc_txs = Vec::new();

        for &nondust_htlc in &commitment.nondust_htlcs {
            // Spend the HTLC output of the commitment transaction.
            let input = TxIn {
                previous_output: OutPoint {
                    txid: commitment.tx.compute_txid(),
                    vout: nondust_htlc.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(u32::from(anchor)),
                // Witness is not included in the BIP 143 sighash, so we leave
                // it empty.
                witness: Witness::new(),
            };

            let second_stage_fee_sat = htlc_tx_fee_sat(
                &self.channel_type,
                commitment.feerate_per_kw,
                nondust_htlc.offered,
            );

            // Spend the HTLC output to a revocable output identical to `to_local`.
            let output = TxOut {
                script_pubkey: build_revocable_scriptpubkey(
                    &commitment.keys.local_delayedpubkey,
                    &commitment.keys.revocationpubkey,
                    self.party(local_side.other()).to_self_delay,
                ),
                value: nondust_htlc.htlc.amount() - Amount::from_sat(second_stage_fee_sat),
            };

            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::from_consensus(if nondust_htlc.offered {
                    nondust_htlc.htlc.cltv_expiry
                } else {
                    0
                }),
                input: vec![input],
                output: vec![output],
            };

            htlc_txs.push(BuiltHtlcTx { nondust_htlc, tx });
        }

        htlc_txs
    }

    /// Builds the sighash for a second-stage HTLC transaction of `commitment`
    /// signed by `signer`.
    fn build_htlc_sighash(
        &self,
        htlc_tx: &BuiltHtlcTx,
        commitment: &BuiltCommitmentTx,
        signer: Side,
    ) -> [u8; 32] {
        // HTLC output witness script.
        let anchor = self.channel_type.supports_feature(Features::OPTION_ANCHORS);
        let htlc_witness_script = build_htlc_witness_script(
            &htlc_tx.nondust_htlc.htlc,
            &commitment.keys,
            htlc_tx.nondust_htlc.offered,
            anchor,
        );

        let sighash_type = if anchor && signer != commitment.local_side {
            EcdsaSighashType::SinglePlusAnyoneCanPay
        } else {
            EcdsaSighashType::All
        };

        // Compute the BIP143 sighash
        let sighash = SighashCache::new(&htlc_tx.tx)
            .p2wsh_signature_hash(
                0,
                &htlc_witness_script,
                htlc_tx.nondust_htlc.htlc.amount(),
                sighash_type,
            )
            .expect("input index 0 is always in bounds for a single input transaction");

        sighash.to_byte_array()
    }

    /// Signs each second-stage HTLC transaction of `commitment` with the
    /// holder's per-commitment HTLC private key.
    fn sign_htlc_txs(
        &self,
        commitment: &BuiltCommitmentTx,
        htlc_txs: &[BuiltHtlcTx],
        holder: &HolderIdentity,
    ) -> Vec<Signature> {
        let htlc_privkey = derive_privkey(
            &holder.htlc_basepoint_privkey,
            &commitment.keys.per_commitment_point,
        );

        htlc_txs
            .iter()
            .map(|htlc_tx| {
                let sighash = self.build_htlc_sighash(htlc_tx, commitment, holder.side);
                sign(&sighash, &htlc_privkey)
            })
            .collect()
    }

    /// Verifies the counterparty's signatures on each second-stage HTLC
    /// transaction of `commitment` against its per-commitment HTLC public key.
    fn verify_htlc_sigs(
        &self,
        commitment: &BuiltCommitmentTx,
        htlc_txs: &[BuiltHtlcTx],
        htlc_sigs: &[Signature],
    ) -> bool {
        if htlc_sigs.len() != htlc_txs.len() {
            return false;
        }

        let signer = commitment.local_side.other();
        htlc_txs.iter().zip(htlc_sigs.iter()).all(|(htlc_tx, sig)| {
            let sighash = self.build_htlc_sighash(htlc_tx, commitment, signer);
            verify(&sighash, sig, &commitment.keys.remote_htlcpubkey)
        })
    }
}

impl ChannelCommitments {
    /// Returns the state of the given side's commitment.
    fn state(&self, side: Side) -> &CommitmentState {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Returns a mutable reference to the state of the given side's commitment.
    fn state_mut(&mut self, side: Side) -> &mut CommitmentState {
        match side {
            Side::Opener => &mut self.opener,
            Side::Acceptor => &mut self.acceptor,
        }
    }

    /// Adds `htlc` to the in-flight set of `side`'s commitment, debiting
    /// its amount from the offerer's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcExceedsBalance`] if the HTLC amount
    /// would underflow the offerer's balance.
    pub fn add_htlc(&mut self, side: Side, htlc: Htlc) -> Result<(), CommitmentError> {
        let state = self.state_mut(side);
        let offerer_balance = state.balance_msat_mut(htlc.offerer);
        // According to the spec, the target should reject an `update_add_htlc`
        // if it exceeds the offerer's balance, leaves the offerer below its
        // channel reserve, or leaves the funder unable to cover the commitment
        // fee. We only guard the balance here: if the HTLC exceeds it, the
        // balance would underflow below zero, so we error out rather than build
        // a commitment from a broken balance that would otherwise be masked as
        // an invalid signature.
        *offerer_balance = offerer_balance
            .checked_sub(htlc.amount_msat)
            .ok_or(CommitmentError::HtlcExceedsBalance)?;
        state.htlcs.push(htlc);
        Ok(())
    }

    /// Settles the in-flight HTLC that `offerer` added with the given `id` on
    /// `side`'s commitment, removing it from the in-flight set and crediting
    /// its amount to the receiver's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    pub fn fulfill_htlc(
        &mut self,
        side: Side,
        id: u64,
        offerer: Side,
    ) -> Result<(), CommitmentError> {
        let state = self.state_mut(side);
        // The target is currently the only side that sends HTLC resolutions, so
        // a resolution for an unknown HTLC means the target is misbehaving; we
        // surface it as `HtlcNotFound`. Once we send our own resolutions, we
        // should skip this error for those, since we cannot shift the balance
        // and the resulting broken commitment would otherwise be masked as an
        // invalid signature.
        let pos = state
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        let htlc = state.htlcs.remove(pos);
        *state.balance_msat_mut(htlc.offerer.other()) += htlc.amount_msat;
        Ok(())
    }

    /// Fails the in-flight HTLC that `offerer` added with the given `id` on
    /// `side`'s commitment, removing it from the in-flight set and refunding
    /// its amount to the offerer's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    pub fn fail_htlc(&mut self, side: Side, id: u64, offerer: Side) -> Result<(), CommitmentError> {
        let state = self.state_mut(side);
        // The target is currently the only side that sends HTLC resolutions, so
        // a resolution for an unknown HTLC means the target is misbehaving; we
        // surface it as `HtlcNotFound`. Once we send our own resolutions, we
        // should skip this error for those, since we cannot shift the balance
        // and the resulting broken commitment would otherwise be masked as an
        // invalid signature.
        let pos = state
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        let htlc = state.htlcs.remove(pos);
        *state.balance_msat_mut(htlc.offerer) += htlc.amount_msat;
        Ok(())
    }

    /// Updates the fee rate for `side`'s commitment transaction.
    pub fn update_fee(&mut self, side: Side, feerate_per_kw: u32) {
        self.state_mut(side).feerate_per_kw = feerate_per_kw;
    }

    /// Updates the per-commitment point for `side`'s commitment.
    pub fn update_per_commitment_point(&mut self, side: Side, per_commitment_point: PublicKey) {
        self.state_mut(side).per_commitment_point = per_commitment_point;
    }

    /// Advances `side`'s commitment transaction number by one.
    pub fn advance_commitment_number(&mut self, side: Side) {
        self.state_mut(side).commitment_number += 1;
    }
}

impl Htlc {
    /// Returns whether this HTLC is offered on the commitment owned by
    /// `local_side` (otherwise it is received).
    fn is_offered(&self, local_side: Side) -> bool {
        self.offerer == local_side
    }

    /// Returns whether this HTLC would be trimmed from the commitment
    /// transaction due to dust limits.
    fn is_dust(
        &self,
        dust_limit_satoshis: u64,
        feerate_per_kw: u32,
        channel_type: &Features,
        local_side: Side,
    ) -> bool {
        let stage_fee = htlc_tx_fee_sat(channel_type, feerate_per_kw, self.is_offered(local_side));
        let amount_sat = self.amount_msat / 1000;
        amount_sat < dust_limit_satoshis.saturating_add(stage_fee)
    }

    /// Converts the HTLC amount from millisatoshis to satoshis.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        Amount::from_sat(self.amount_msat / 1000)
    }
}

impl CommitmentCost {
    /// Calculates the total cost of a commitment transaction with non-dust HTLCs.
    #[must_use]
    pub fn new(
        feerate_per_kw: u32,
        channel_type: &Features,
        nondust_htlc_count: usize,
    ) -> CommitmentCost {
        CommitmentCost {
            fee_sat: commit_tx_fee_sat(feerate_per_kw, nondust_htlc_count, channel_type),
            anchor_cost_sat: total_anchors_sat(channel_type),
        }
    }

    /// Returns the total cost (fee + anchor outputs) in satoshis.
    #[must_use]
    pub fn total_sat(&self) -> u64 {
        self.fee_sat + self.anchor_cost_sat
    }
}

impl TxCreationKeys {
    /// Derives the per-commitment keys for the given commitment state.
    fn derive(config: &ChannelConfig, state: &CommitmentState) -> Self {
        let local_side = state.local_side;
        let per_commitment_point = state.per_commitment_point;
        let local = config.party(local_side);
        let remote = config.party(local_side.other());

        Self {
            per_commitment_point,
            local_delayedpubkey: derive_pubkey(
                &local.delayed_payment_basepoint,
                &per_commitment_point,
            ),
            revocationpubkey: derive_revocation_pubkey(
                &remote.revocation_basepoint,
                &per_commitment_point,
            ),
            local_htlcpubkey: derive_pubkey(&local.htlc_basepoint, &per_commitment_point),
            remote_htlcpubkey: derive_pubkey(&remote.htlc_basepoint, &per_commitment_point),
        }
    }
}

/// Get the fee cost of a commitment tx with a given number of HTLC outputs in
/// satoshis.
/// Note that `num_htlcs` should not include dust HTLCs.
fn commit_tx_fee_sat(feerate_per_kw: u32, num_htlcs: usize, channel_type: &Features) -> u64 {
    let commitment_base_weight = if channel_type.supports_feature(Features::OPTION_ANCHORS) {
        COMMITMENT_TX_BASE_WEIGHT_ANCHOR
    } else {
        COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR
    };

    let commitment_weight =
        commitment_base_weight + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC;
    u64::from(feerate_per_kw) * commitment_weight / 1000
}

/// Get the anchor cost of a commitment tx in satoshis.
fn total_anchors_sat(channel_type: &Features) -> u64 {
    if channel_type.supports_feature(Features::OPTION_ANCHORS) {
        ANCHOR_OUTPUT_VALUE * 2
    } else {
        0
    }
}

/// Get the fee cost of a second-stage HTLC transaction in satoshis.
/// `is_offered` selects between the HTLC-timeout and HTLC-success weights.
fn htlc_tx_fee_sat(channel_type: &Features, feerate_per_kw: u32, is_offered: bool) -> u64 {
    if channel_type.supports_feature(Features::OPTION_ANCHORS) {
        return 0;
    }

    if is_offered {
        u64::from(feerate_per_kw) * HTLC_TIMEOUT_TX_WEIGHT_NON_ANCHOR / 1000
    } else {
        u64::from(feerate_per_kw) * HTLC_SUCCESS_TX_WEIGHT_NON_ANCHOR / 1000
    }
}

/// Returns `SHA256(pubkey1 || pubkey2)`.
///
/// Both public keys are serialized in compressed form before hashing.
fn hash_pubkeys(pubkey1: &PublicKey, pubkey2: &PublicKey) -> [u8; 32] {
    let mut sha = Sha256::engine();
    sha.input(&pubkey1.serialize());
    sha.input(&pubkey2.serialize());

    Sha256::from_engine(sha).to_byte_array()
}

/// Computes the commitment number obscuring factor per BOLT 3.
fn compute_obscuring_factor(
    opener_payment_basepoint: &PublicKey,
    acceptor_payment_basepoint: &PublicKey,
) -> u64 {
    let hash = hash_pubkeys(opener_payment_basepoint, acceptor_payment_basepoint);

    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(&hash[26..32]);
    u64::from_be_bytes(buf)
}

/// Derives a public key from a basepoint and per-commitment point per BOLT 3.
fn derive_pubkey(basepoint: &PublicKey, per_commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let tweak = hash_pubkeys(per_commitment_point, basepoint);
    let hashkey = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&tweak).expect("SHA256 output is a valid secret key"),
    );

    basepoint
        .combine(&hashkey)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Derives a private key from a basepoint secret and a per-commitment point per
/// BOLT 3.
fn derive_privkey(basepoint_secret: &SecretKey, per_commitment_point: &PublicKey) -> SecretKey {
    let secp = Secp256k1::new();
    let basepoint = basepoint_secret.public_key(&secp);
    let tweak = hash_pubkeys(per_commitment_point, &basepoint);
    let scalar = Scalar::from_be_bytes(tweak).expect("SHA256 output is a valid scalar");
    basepoint_secret
        .add_tweak(&scalar)
        .expect("derived HTLC privkey tweak must be valid")
}

/// Derives the `revocationpubkey` per BOLT 3.
fn derive_revocation_pubkey(
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let rev_append_commit_hash_key = hash_pubkeys(revocation_basepoint, per_commitment_point);
    let commit_append_rev_hash_key = hash_pubkeys(per_commitment_point, revocation_basepoint);

    let revocation_contrib = revocation_basepoint
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(rev_append_commit_hash_key)
                .expect("SHA256 output is a valid scalar"),
        )
        .expect("scalar multiplication of a valid pubkey cannot fail");

    let commitment_contrib = per_commitment_point
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(commit_append_rev_hash_key)
                .expect("SHA256 output is a valid scalar"),
        )
        .expect("scalar multiplication of a valid pubkey cannot fail");

    revocation_contrib
        .combine(&commitment_contrib)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Builds the revocable P2WSH `script_pubkey` per BOLT 3.
/// Used by the `to_local` commitment output and by 2nd-stage HTLC outputs.
fn build_revocable_scriptpubkey(
    local_delayedpubkey: &PublicKey,
    revocationpubkey: &PublicKey,
    to_self_delay: u16,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::OP_IF)
        .push_slice(revocationpubkey.serialize())
        .push_opcode(opcodes::OP_ELSE)
        .push_int(i64::from(to_self_delay))
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_DROP)
        .push_slice(local_delayedpubkey.serialize())
        .push_opcode(opcodes::OP_ENDIF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
        .to_p2wsh()
}

/// Builds the `to_remote` output `script_pubkey` per BOLT 3.
///
/// With `option_anchors`, the output is P2WSH with a 1-block CSV lock.
/// Without anchors, it is a simple P2WPKH to the remote payment basepoint.
fn build_to_remote_scriptpubkey(payment_basepoint: &PublicKey, anchor: bool) -> ScriptBuf {
    if anchor {
        Builder::new()
            .push_slice(payment_basepoint.serialize())
            .push_opcode(opcodes::OP_CHECKSIGVERIFY)
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_CSV)
            .into_script()
            .to_p2wsh()
    } else {
        ScriptBuf::new_p2wpkh(&CompressedPublicKey(*payment_basepoint).wpubkey_hash())
    }
}

/// Builds the anchor output P2WSH `script_pubkey` per BOLT 3.
fn build_anchor_scriptpubkey(funding_pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(funding_pubkey.serialize())
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_IFDUP)
        .push_opcode(opcodes::OP_NOTIF)
        .push_opcode(opcodes::OP_PUSHNUM_16)
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_ENDIF)
        .into_script()
        .to_p2wsh()
}

/// Builds the HTLC output witness script per BOLT 3.
///
/// `is_offered` selects between the offered and received HTLC scripts.
fn build_htlc_witness_script(
    htlc: &Htlc,
    keys: &TxCreationKeys,
    is_offered: bool,
    anchor: bool,
) -> ScriptBuf {
    let payment_hash160 = Ripemd160::hash(&htlc.payment_hash[..]).to_byte_array();

    let mut bldr = Builder::new()
        .push_opcode(opcodes::OP_DUP)
        .push_opcode(opcodes::OP_HASH160)
        .push_slice(PubkeyHash::hash(&keys.revocationpubkey.serialize()))
        .push_opcode(opcodes::OP_EQUAL)
        .push_opcode(opcodes::OP_IF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_ELSE)
        .push_slice(keys.remote_htlcpubkey.serialize())
        .push_opcode(opcodes::OP_SWAP)
        .push_opcode(opcodes::OP_SIZE)
        .push_int(32)
        .push_opcode(opcodes::OP_EQUAL);

    bldr = if is_offered {
        bldr.push_opcode(opcodes::OP_NOTIF)
            .push_opcode(opcodes::OP_DROP)
            .push_int(2)
            .push_opcode(opcodes::OP_SWAP)
            .push_slice(keys.local_htlcpubkey.serialize())
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .push_opcode(opcodes::OP_ELSE)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(payment_hash160)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_opcode(opcodes::OP_CHECKSIG)
            .push_opcode(opcodes::OP_ENDIF)
    } else {
        bldr.push_opcode(opcodes::OP_IF)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(payment_hash160)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(opcodes::OP_SWAP)
            .push_slice(keys.local_htlcpubkey.serialize())
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .push_opcode(opcodes::OP_ELSE)
            .push_opcode(opcodes::OP_DROP)
            .push_int(i64::from(htlc.cltv_expiry))
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(opcodes::OP_DROP)
            .push_opcode(opcodes::OP_CHECKSIG)
            .push_opcode(opcodes::OP_ENDIF)
    };

    if anchor {
        bldr = bldr
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_CSV)
            .push_opcode(opcodes::OP_DROP);
    }
    bldr.push_opcode(opcodes::OP_ENDIF).into_script()
}

/// Signs a sighash with the given private key.
fn sign(sighash: &[u8; 32], privkey: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa(&msg, privkey)
}

/// Verifies that `sig` is a valid signature for `sighash` under `pubkey`.
fn verify(sighash: &[u8; 32], sig: &Signature, pubkey: &PublicKey) -> bool {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.verify_ecdsa(&msg, sig, pubkey).is_ok()
}

#[cfg(test)]
mod tests;
