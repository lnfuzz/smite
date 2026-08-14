//! BOLT 3 commitment transaction construction and signing.

use super::funding::build_funding_witness_script;

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

/// `option_anchors` feature bits (BOLT 9, bits 22/23).
const OPTION_ANCHORS_FEATURE_BITS: &[usize] = &[22, 23];

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
    pub channel_type: Vec<u8>,
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
    id: u64,
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

/// Per-party parameters used in a commitment transaction.
pub struct CommitmentPartyState {
    /// Per-commitment point used to derive all commitment-specific keys.
    pub per_commitment_point: PublicKey,

    /// Amount allocated to this party in millisatoshis.
    /// Represents the balance before subtraction of fees, and anchors outputs.
    /// In-flight HTLCs are represented as separate outputs in the commitment
    /// transaction, so those values are already deducted from these balance values.
    pub balance_msat: u64,
}

/// Parameters for building a commitment transaction.
pub struct CommitmentState {
    /// The commitment transaction number.
    pub commitment_number: u64,
    /// Fee rate for the commitment transaction.
    pub feerate_per_kw: u32,
    /// Parameters for the channel opener.
    pub opener: CommitmentPartyState,
    /// Parameters for the channel acceptor.
    pub acceptor: CommitmentPartyState,
    /// In-flight HTLCs offered in either direction.
    pub htlcs: Vec<Htlc>,
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
/// transaction from the local party's perspective.
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
/// identity, and current commitment state.
pub struct ChannelState {
    /// Channel configuration established at channel creation and unchanged
    /// for the lifetime of the channel.
    pub config: ChannelConfig,
    /// Holder-specific identity data (channel side and funding secret) used to
    /// sign commitment transactions and verify the counterparty's signatures.
    pub holder: HolderIdentity,
    /// Current commitment state, updated as commitments are exchanged and
    /// revoked.
    pub commitment: CommitmentState,
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
        commitment: CommitmentState,
        is_funding_outpoint_valid: bool,
        was_funding_mined_prematurely: bool,
    ) -> Self {
        Self {
            config,
            holder,
            commitment,
            opener_next_per_commitment_point: None,
            acceptor_next_per_commitment_point: None,
            is_funding_outpoint_valid,
            was_funding_mined_prematurely,
        }
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
        match self.holder.side.other() {
            Side::Opener => &self.opener_next_per_commitment_point,
            Side::Acceptor => &self.acceptor_next_per_commitment_point,
        }
    }

    /// Returns a mutable reference to the counterparty's next per-commitment
    /// point.
    pub fn next_counterparty_per_commitment_point_mut(&mut self) -> &mut Option<PublicKey> {
        match self.holder.side.other() {
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

    /// Constructs the initial commitment state after channel funding.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`CommitmentError::FundingMsatOverflow`] if `funding_satoshis` overflows when
    ///   converting to millisatoshis.
    /// - [`CommitmentError::PushExceedsFunding`] if `push_msat` exceeds the total
    ///   funding amount in millisatoshis.
    pub fn new_initial_commitment(
        &self,
        push_msat: u64,
        feerate_per_kw: u32,
        opener_per_commitment_point: PublicKey,
        acceptor_per_commitment_point: PublicKey,
    ) -> Result<CommitmentState, CommitmentError> {
        let funding_msat = self
            .funding_satoshis
            .checked_mul(1000)
            .ok_or(CommitmentError::FundingMsatOverflow)?;
        let to_opener_balance_msat = funding_msat
            .checked_sub(push_msat)
            .ok_or(CommitmentError::PushExceedsFunding)?;
        let to_acceptor_balance_msat = push_msat;

        Ok(CommitmentState {
            commitment_number: 0,
            feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: opener_per_commitment_point,
                balance_msat: to_opener_balance_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: acceptor_per_commitment_point,
                balance_msat: to_acceptor_balance_msat,
            },
            htlcs: Vec::new(),
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
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> (Signature, Vec<Signature>) {
        let commitment = self.build_commitment_tx(state, holder.counterparty_side());
        let htlc_txs = self.build_htlc_txs(state, &commitment, holder.counterparty_side());

        (
            self.sign_commitment_tx(&commitment, &holder.funding_privkey),
            self.sign_htlc_txs(
                &commitment,
                &htlc_txs,
                &holder.htlc_basepoint_privkey,
                peer_htlc_sighash_type(&self.channel_type),
            ),
        )
    }

    /// Verifies the counterparty's signatures on the holder's commitment
    /// transaction and all of its non-dust HTLC outputs.
    #[must_use]
    pub fn verify_counterparty_signature(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
        commit_sig: &Signature,
        htlc_sigs: &[Signature],
    ) -> bool {
        let commitment = self.build_commitment_tx(state, holder.side);
        let htlc_txs = self.build_htlc_txs(state, &commitment, holder.side);

        self.verify_commit_sig(&commitment, holder, commit_sig)
            && self.verify_htlc_sigs(&commitment, &htlc_txs, htlc_sigs)
    }

    /// Builds the signatures for the holder's own commitment transaction and
    /// its HTLC outputs. Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn sign_holder_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> (Signature, Vec<Signature>) {
        let commitment = self.build_commitment_tx(state, holder.side);
        let htlc_txs = self.build_htlc_txs(state, &commitment, holder.side);

        (
            self.sign_commitment_tx(&commitment, &holder.funding_privkey),
            self.sign_htlc_txs(
                &commitment,
                &htlc_txs,
                &holder.htlc_basepoint_privkey,
                EcdsaSighashType::All,
            ),
        )
    }

    /// Builds the commitment transaction. The commitment format (legacy or
    /// anchor) is determined by the `channel_type`.
    ///
    /// `local_side` selects whose commitment is built: the opener's or
    /// the acceptor's.
    fn build_commitment_tx(&self, state: &CommitmentState, local_side: Side) -> BuiltCommitmentTx {
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
        let keys = self.derive_commitment_keys(state, local_side);
        let (outputs, nondust_htlcs) = self.build_commitment_outputs(state, &keys, local_side);

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
    /// `local_side` selects whose commitment outputs are built: the
    /// opener's or the acceptor's.
    fn build_commitment_outputs(
        &self,
        state: &CommitmentState,
        keys: &TxCreationKeys,
        local_side: Side,
    ) -> (Vec<TxOut>, Vec<HtlcOutputInCommitment>) {
        let anchor = supports_option_anchors(&self.channel_type);
        let mut outputs: Vec<TxOut> = Vec::new();

        // Insert non-dust HTLC outputs, recording each one's output index.
        let nondust_htlc_outputs = self.build_sorted_nondust_htlc_outputs(state, keys, local_side);
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
            (state.opener.balance_msat / 1000).saturating_sub(commitment_cost.total_sat());
        let acceptor_balance = state.acceptor.balance_msat / 1000;

        // Map opener/acceptor to local/remote for this commitment side.
        let (to_local_value, to_remote_value) = match local_side {
            Side::Opener => (opener_balance, acceptor_balance),
            Side::Acceptor => (acceptor_balance, opener_balance),
        };
        let local = self.party(local_side);
        let remote = self.party(local_side.other());

        if to_local_value >= local.dust_limit_satoshis {
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
        if to_remote_value >= local.dust_limit_satoshis {
            let to_remote_spk = build_to_remote_scriptpubkey(&remote.payment_basepoint, anchor);

            insert_non_htlc_output(TxOut {
                value: Amount::from_sat(to_remote_value),
                script_pubkey: to_remote_spk,
            });
        }

        if anchor {
            if to_local_value >= local.dust_limit_satoshis || nondust_htlc_count > 0 {
                insert_non_htlc_output(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&local.funding_pubkey),
                });
            }

            if to_remote_value >= local.dust_limit_satoshis || nondust_htlc_count > 0 {
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
        local_side: Side,
    ) -> Vec<(TxOut, Htlc)> {
        let anchor = supports_option_anchors(&self.channel_type);
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

    /// Signs the commitment transaction using the local party's funding private
    /// key.
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
    fn verify_commit_sig(
        &self,
        commitment: &BuiltCommitmentTx,
        holder: &HolderIdentity,
        commit_sig: &Signature,
    ) -> bool {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        let counterparty = self.party(holder.counterparty_side());
        verify(&sighash, commit_sig, &counterparty.funding_pubkey)
    }

    /// Builds the second-stage HTLC transactions that spend the non-dust HTLC
    /// outputs of `commitment`, in commitment-output order.
    fn build_htlc_txs(
        &self,
        state: &CommitmentState,
        commitment: &BuiltCommitmentTx,
        local_side: Side,
    ) -> Vec<BuiltHtlcTx> {
        let anchor = supports_option_anchors(&self.channel_type);
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
                state.feerate_per_kw,
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

    /// Builds the sighash for the HTLC's second-stage transaction.
    fn build_htlc_sighash(
        &self,
        htlc_tx: &BuiltHtlcTx,
        keys: &TxCreationKeys,
        sighash_type: EcdsaSighashType,
    ) -> [u8; 32] {
        // HTLC output witness script.
        let anchor = supports_option_anchors(&self.channel_type);
        let htlc_witness_script = build_htlc_witness_script(
            &htlc_tx.nondust_htlc.htlc,
            keys,
            htlc_tx.nondust_htlc.offered,
            anchor,
        );

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

    /// Signs each HTLC second-stage transaction using the local party's
    /// per-commitment HTLC private key.
    fn sign_htlc_txs(
        &self,
        commitment: &BuiltCommitmentTx,
        htlc_txs: &[BuiltHtlcTx],
        htlc_basepoint_privkey: &SecretKey,
        sighash_type: EcdsaSighashType,
    ) -> Vec<Signature> {
        let htlc_privkey = derive_privkey(
            htlc_basepoint_privkey,
            &commitment.keys.per_commitment_point,
        );

        htlc_txs
            .iter()
            .map(|htlc_tx| {
                let sighash = self.build_htlc_sighash(htlc_tx, &commitment.keys, sighash_type);
                sign(&sighash, &htlc_privkey)
            })
            .collect()
    }

    /// Verifies the HTLC signatures against the counterparty's per-commitment
    /// HTLC public key.
    fn verify_htlc_sigs(
        &self,
        commitment: &BuiltCommitmentTx,
        htlc_txs: &[BuiltHtlcTx],
        htlc_sigs: &[Signature],
    ) -> bool {
        if htlc_sigs.len() != htlc_txs.len() {
            return false;
        }

        htlc_txs.iter().zip(htlc_sigs.iter()).all(|(htlc_tx, sig)| {
            let sighash = self.build_htlc_sighash(
                htlc_tx,
                &commitment.keys,
                peer_htlc_sighash_type(&self.channel_type),
            );
            verify(&sighash, sig, &commitment.keys.remote_htlcpubkey)
        })
    }

    /// Derives the per-commitment keys for the `local_side`.
    fn derive_commitment_keys(&self, state: &CommitmentState, local_side: Side) -> TxCreationKeys {
        let local = self.party(local_side);
        let remote = self.party(local_side.other());
        let per_commitment_point = state.party(local_side).per_commitment_point;

        TxCreationKeys {
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

impl CommitmentState {
    /// Returns the parameters for the given commitment side.
    fn party(&self, side: Side) -> &CommitmentPartyState {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Returns a mutable reference to the parameters for the given commitment side.
    fn party_mut(&mut self, side: Side) -> &mut CommitmentPartyState {
        match side {
            Side::Opener => &mut self.opener,
            Side::Acceptor => &mut self.acceptor,
        }
    }

    /// Adds `htlc` to the in-flight set, debiting its amount from the offerer's
    /// balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcExceedsBalance`] if the HTLC amount
    /// would underflow the offerer's balance.
    pub fn add_htlc(&mut self, htlc: Htlc) -> Result<(), CommitmentError> {
        let offerer_balance = &mut self.party_mut(htlc.offerer).balance_msat;
        *offerer_balance = offerer_balance
            .checked_sub(htlc.amount_msat)
            .ok_or(CommitmentError::HtlcExceedsBalance)?;
        self.htlcs.push(htlc);
        Ok(())
    }

    /// Settles the in-flight HTLC that `offerer` added with the given `id`,
    /// removing it from the in-flight set and crediting its amount to the
    /// receiver's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    pub fn fulfill_htlc(&mut self, id: u64, offerer: Side) -> Result<(), CommitmentError> {
        let pos = self
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        let htlc = self.htlcs.remove(pos);
        self.party_mut(htlc.offerer.other()).balance_msat += htlc.amount_msat;
        Ok(())
    }

    /// Fails the in-flight HTLC that `offerer` added with the given `id`,
    /// removing it from the in-flight set and refunding its amount to the
    /// offerer's balance.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    pub fn fail_htlc(&mut self, id: u64, offerer: Side) -> Result<(), CommitmentError> {
        let pos = self
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        let htlc = self.htlcs.remove(pos);
        self.party_mut(htlc.offerer).balance_msat += htlc.amount_msat;
        Ok(())
    }

    /// Updates the fee rate for the commitment transaction.
    pub fn update_fee(&mut self, feerate_per_kw: u32) {
        self.feerate_per_kw = feerate_per_kw;
    }

    /// Updates the per-commitment point for the given commitment side.
    pub fn update_per_commitment_point(&mut self, side: Side, per_commitment_point: PublicKey) {
        self.party_mut(side).per_commitment_point = per_commitment_point;
    }

    /// Advances the commitment transaction number by one.
    pub fn advance_commitment_number(&mut self) {
        self.commitment_number += 1;
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
        channel_type: &[u8],
        local_side: Side,
    ) -> bool {
        let stage_fee = htlc_tx_fee_sat(channel_type, feerate_per_kw, self.is_offered(local_side));
        let amount_sat = self.amount_msat / 1000;
        amount_sat < dust_limit_satoshis.saturating_add(stage_fee)
    }

    /// Converts the HTLC amount from millisatoshis to satoshis.
    pub const fn amount(&self) -> Amount {
        Amount::from_sat(self.amount_msat / 1000)
    }
}

impl CommitmentCost {
    /// Calculates the total cost of a commitment transaction with non-dust HTLCs.
    #[must_use]
    pub fn new(
        feerate_per_kw: u32,
        channel_type: &[u8],
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

/// Get the fee cost of a commitment tx with a given number of HTLC outputs in
/// satoshis.
/// Note that `num_htlcs` should not include dust HTLCs.
fn commit_tx_fee_sat(feerate_per_kw: u32, num_htlcs: usize, channel_type: &[u8]) -> u64 {
    let commitment_base_weight = if supports_option_anchors(channel_type) {
        COMMITMENT_TX_BASE_WEIGHT_ANCHOR
    } else {
        COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR
    };

    let commitment_weight =
        commitment_base_weight + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC;
    u64::from(feerate_per_kw) * commitment_weight / 1000
}

/// Get the anchor cost of a commitment tx in satoshis.
fn total_anchors_sat(channel_type: &[u8]) -> u64 {
    if supports_option_anchors(channel_type) {
        ANCHOR_OUTPUT_VALUE * 2
    } else {
        0
    }
}

/// Get the fee cost of a second-stage HTLC transaction in satoshis.
/// `is_offered` selects between the HTLC-timeout and HTLC-success weights.
fn htlc_tx_fee_sat(channel_type: &[u8], feerate_per_kw: u32, is_offered: bool) -> u64 {
    if supports_option_anchors(channel_type) {
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

/// Checks whether `option_anchors` (BOLT 9, bits 22/23) is set in a
/// big-endian `channel_type` feature bitfield.
///
/// Per BOLT 9, even bit (22) = required, odd bit (23) = optional.
/// Either bit indicates anchor support.
fn supports_option_anchors(channel_type: &[u8]) -> bool {
    let byte_offset = OPTION_ANCHORS_FEATURE_BITS[0] / 8;
    let len = channel_type.len();
    if len <= byte_offset {
        return false;
    }

    let required_mask = 1 << (OPTION_ANCHORS_FEATURE_BITS[0] % 8);
    let optional_mask = 1 << (OPTION_ANCHORS_FEATURE_BITS[1] % 8);

    channel_type[len - 1 - byte_offset] & (required_mask | optional_mask) != 0
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

/// Returns the sighash type used for the HTLC signatures exchanged with the
/// peer.
fn peer_htlc_sighash_type(channel_type: &[u8]) -> EcdsaSighashType {
    if supports_option_anchors(channel_type) {
        EcdsaSighashType::SinglePlusAnyoneCanPay
    } else {
        EcdsaSighashType::All
    }
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
mod tests {
    use super::*;

    fn pubkey(hex_str: &str) -> PublicKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        PublicKey::from_slice(&bytes).expect("valid pubkey")
    }

    fn secret(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        SecretKey::from_slice(&bytes).expect("valid secret key")
    }

    fn der_sig(hex_str: &str) -> Signature {
        let bytes = hex::decode(hex_str).expect("valid hex");
        Signature::from_der(&bytes).expect("valid DER signature")
    }

    fn payment_hash(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("valid hex");
        Sha256::hash(&bytes).to_byte_array()
    }

    /// BOLT 3 Appendix C opener (local) funding private key.
    const OPENER_FUNDING_PRIVKEY: &str =
        "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749";

    /// BOLT 3 Appendix C acceptor (remote) funding private key.
    const ACCEPTOR_FUNDING_PRIVKEY: &str =
        "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13";

    #[test]
    fn obscuring_factor() {
        let opener_payment_basepoint =
            pubkey("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        let acceptor_payment_basepoint =
            pubkey("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
        let factor =
            compute_obscuring_factor(&opener_payment_basepoint, &acceptor_payment_basepoint);
        assert_eq!(factor, 0x2bb0_3852_1914);
    }

    #[test]
    fn supports_option_anchors_detection() {
        // Required (bit 22), optional (bit 23).
        assert!(supports_option_anchors(&[0x40, 0x00, 0x00]));
        assert!(supports_option_anchors(&[0x80, 0x00, 0x00]));
        // No support.
        assert!(!supports_option_anchors(&[0x00, 0x00, 0x40]));
        assert!(!supports_option_anchors(&[0x00, 0x00, 0x80]));
        assert!(!supports_option_anchors(&[]));
        assert!(!supports_option_anchors(&[0xff, 0xff]));
        assert!(!supports_option_anchors(&[0x00, 0x10]));
    }

    fn bolt3_commitment_params(
        feerate_per_kw: u32,
        to_opener_msat: u64,
        to_acceptor_msat: u64,
        dust_limit_satoshis: u64,
        channel_type: Vec<u8>,
    ) -> (
        ChannelConfig,
        CommitmentState,
        HolderIdentity,
        HolderIdentity,
    ) {
        let chan_config = ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid funding txid hex"),
                vout: 0,
            },
            funding_satoshis: 10_000_000,
            channel_type,
            opener: ChannelPartyConfig {
                funding_pubkey: pubkey(
                    "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
                ),
                payment_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                revocation_basepoint: pubkey(
                    "02c6047f9441ed7d6d3045406e95c07cd85a0f5f0f3b9b3f3d5f9b1e5e4a7c4f09",
                ),
                delayed_payment_basepoint: pubkey(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                ),
                htlc_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                dust_limit_satoshis,
                to_self_delay: 144,
            },
            acceptor: ChannelPartyConfig {
                funding_pubkey: pubkey(
                    "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1",
                ),
                payment_basepoint: pubkey(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                ),
                revocation_basepoint: pubkey(
                    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                ),
                delayed_payment_basepoint: pubkey(
                    "02a1633caf7bf0b7d9e5c4b8a1d6f2e3c4b5a6978877665544332211ffeeddccbb",
                ),
                htlc_basepoint: pubkey(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                ),
                dust_limit_satoshis,
                to_self_delay: 144,
            },
            minimum_depth: 8,
        };

        let state = CommitmentState {
            commitment_number: 42,
            feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: pubkey(
                    "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
                ),
                balance_msat: to_opener_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: pubkey(
                    "03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
                ),
                balance_msat: to_acceptor_msat,
            },
            htlcs: vec![],
        };

        let opener_holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret(OPENER_FUNDING_PRIVKEY),
            htlc_basepoint_privkey: secret(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        };

        let acceptor_holder = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            htlc_basepoint_privkey: secret(
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        };

        (chan_config, state, opener_holder, acceptor_holder)
    }

    fn bolt3_htlc_list() -> Vec<Htlc> {
        let htlc0 = Htlc {
            id: 0,
            offerer: Side::Acceptor,
            amount_msat: 1_000_000,
            cltv_expiry: 500,
            payment_hash: payment_hash(
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        };
        let htlc1 = Htlc {
            id: 1,
            offerer: Side::Acceptor,
            amount_msat: 2_000_000,
            cltv_expiry: 501,
            payment_hash: payment_hash(
                "0101010101010101010101010101010101010101010101010101010101010101",
            ),
        };
        let htlc2 = Htlc {
            id: 2,
            offerer: Side::Opener,
            amount_msat: 2_000_000,
            cltv_expiry: 502,
            payment_hash: payment_hash(
                "0202020202020202020202020202020202020202020202020202020202020202",
            ),
        };
        let htlc3 = Htlc {
            id: 3,
            offerer: Side::Opener,
            amount_msat: 3_000_000,
            cltv_expiry: 503,
            payment_hash: payment_hash(
                "0303030303030303030303030303030303030303030303030303030303030303",
            ),
        };
        let htlc4 = Htlc {
            id: 4,
            offerer: Side::Acceptor,
            amount_msat: 4_000_000,
            cltv_expiry: 504,
            payment_hash: payment_hash(
                "0404040404040404040404040404040404040404040404040404040404040404",
            ),
        };
        let htlc5 = Htlc {
            id: 5,
            offerer: Side::Opener,
            amount_msat: 5_000_000,
            cltv_expiry: 506,
            payment_hash: payment_hash(
                "0505050505050505050505050505050505050505050505050505050505050505",
            ),
        };
        let htlc6 = Htlc {
            id: 6,
            offerer: Side::Opener,
            amount_msat: 5_000_001,
            cltv_expiry: 505,
            payment_hash: payment_hash(
                "0505050505050505050505050505050505050505050505050505050505050505",
            ),
        };

        vec![htlc0, htlc1, htlc2, htlc3, htlc4, htlc5, htlc6]
    }

    // BOLT 3 Appendix C: Commitment and HTLC Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors

    // name: simple commitment tx with no HTLCs (BOLT 3 Appendix C)
    #[test]
    fn simple_commitment_tx_with_no_htlcs_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 7_000_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b0",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with all five HTLCs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_all_five_htlcs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(0, 6_993_000_000, 3_007_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[0]).unwrap();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402206fc2d1f10ea59951eefac0b4b7c396a3c3d87b71ff0b019796ef4535beaf36f902201765b0181e514d04f4c8ad75659d7037be26cdb3f8bb6f78fe61decef484c3ea",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "30440220636de5682ef0c5b61f124ec74e8aa2461a69777521d6998295dcea36bc3338110220165285594b23c50b28b82df200234566628a27bcd17f7f14404bd865354eb3ce",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100803159dee7935dba4a1d36a61055ce8fd62caa528573cc221ae288515405a252022029c59e7cffce374fe860100a4a63787e105c3cf5156d40b12dd53ff55ac8cf3f",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "3045022100a437cc2ce77400ecde441b3398fea3c3ad8bdad8132be818227fe3c5b8345989022069d45e7fa0ae551ec37240845e2c561ceb2567eacf3076a6a43a502d05865faa",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[3].serialize_der()),
            "304402203121d9b9c055f354304b016a36662ee99e1110d9501cb271b087ddb6f382c2c80220549882f3f3b78d9c492de47543cb9a697cecc493174726146536c5954dac7487",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[4].serialize_der()),
            "3045022100d9080f103cc92bac15ec42464a95f070c7fb6925014e673ee2ea1374d36a7f7502200c65294d22eb20d48564954d5afe04a385551919d8b2ddb4ae2459daaeee1d95",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3044022009b048187705a8cbc9ad73adbe5af148c3d012e1f067961486c822c7af08158c022006d66f3704cfab3eb2dc49dae24e4aa22a6910fc9b424007583204e3621af2e5",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100d9e29616b8f3959f1d3d7f7ce893ffedcdc407717d0de8e37d808c91d3a7c50d022078c3033f6d00095c8720a4bc943c1b45727818c082e4e3ddbc6d3116435b624b",
            ),
            der_sig(
                "30440220649fe8b20e67e46cbb0d09b4acea87dbec001b39b08dee7bdd0b1f03922a8640022037c462dff79df501cecfdb12ea7f4de91f99230bb544726f6e04527b1f896004",
            ),
            der_sig(
                "30440220770fc321e97a19f38985f2e7732dd9fe08d16a2efa4bcbc0429400a447faf49102204d40b417f3113e1b0944ae0986f517564ab4acd3d190503faf97a6e420d43352",
            ),
            der_sig(
                "304402207bcbf4f60a9829b05d2dbab84ed593e0291836be715dc7db6b72a64caf646af802201e489a5a84f7c5cc130398b841d138d031a5137ac8f4c49c770a4959dc3c1363",
            ),
            der_sig(
                "3044022076dca5cb81ba7e466e349b7128cdba216d4d01659e29b96025b9524aaf0d1899022060de85697b88b21c749702b7d2cfa7dfeaa1f472c8f1d7d9c23f2bf968464b87",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with seven outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_seven_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(647, 6_993_000_000, 3_007_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[0]).unwrap();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "30450221009ec15c687898bb4da8b3a833e5ab8bfc51ec6e9202aaa8e66611edfd4a85ed1102203d7183e45078b9735c93450bc3415d3e5a8c576141a711ec6ddcb4a893926bb7",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "30440220344b0deb055230d01703e6c7acd45853c4af2328b49b5d8af4f88a060733406602202ea64f2a43d5751edfe75503cbc35a62e3141b5ed032fa03360faf4ca66f670b",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "30450221009e5e3822b0185c6799a95288c597b671d6cc69ab80f43740f00c6c3d0752bdda02206da947a74bd98f3175324dc56fdba86cc783703a120a6f0297537e60632f4c7f",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "3045022100fcfc47e36b712624677626cef3dc1d67f6583bd46926a6398fe6b00b0c9a37760220525788257b187fc775c6370d04eadf34d06f3650a63f8df851cee0ecb47a1673",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[3].serialize_der()),
            "3045022100e78211b8409afb7255ffe37337da87f38646f1faebbdd61bc1920d69e3ead67a02201a626305adfcd16bfb7e9340928d9b6305464eab4aa4c4a3af6646e9b9f69dee",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[4].serialize_der()),
            "3044022048762cf546bbfe474f1536365ea7c416e3c0389d60558bc9412cb148fb6ab68202207215d7083b75c96ff9d2b08c59c34e287b66820f530b486a9aa4cdd9c347d5b9",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100a135f9e8a5ed25f7277446c67956b00ce6f610ead2bdec2c2f686155b7814772022059f1f6e1a8b336a68efcc1af3fe4d422d4827332b5b067501b099c47b7b5b5ee",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "30450221008437627f9ad84ac67052e2a414a4367b8556fd1f94d8b02590f89f50525cd33502205b9c21ff6e7fc864f2352746ad8ba59182510819acb644e25b8a12fc37bbf24f",
            ),
            der_sig(
                "304402205a67f92bf6845cf2892b48d874ac1daf88a36495cf8a06f93d83180d930a6f75022031da1621d95c3f335cc06a3056cf960199dae600b7cf89088f65fc53cdbef28c",
            ),
            der_sig(
                "30440220437e21766054a3eef7f65690c5bcfa9920babbc5af92b819f772f6ea96df6c7402207173622024bd97328cfb26c6665e25c2f5d67c319443ccdc60c903217005d8c8",
            ),
            der_sig(
                "304402207436e10737e4df499fc051686d3e11a5bb2310e4d1f1e691d287cef66514791202207cb58e71a6b7a42dd001b7e3ae672ea4f71ea3e1cd412b742e9124abb0739c64",
            ),
            der_sig(
                "30450221009acd6a827a76bfee50806178dfe0495cd4e1d9c58279c194c7b01520fe68cb8d022024d439047c368883e570997a7d40f0b430cb5a742f507965e7d3063ae3feccca",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with six outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_six_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(648, 6_993_000_000, 3_006_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100b15f72908ba3382a34ca5b32519240a22300cc6015b6f9418635fb41f3d01d8802207adb331b9ed1575383dca0f2355e86c173802feecf8298fbea53b9d4610583e9",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304502210097e1873b57267730154595187a34949d3744f52933070c74757005e61ce2112e02204ecfba2aa42d4f14bdf8bad4206bb97217b702e6c433e0e1b0ce6587e6d46ec6",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3044022019de73b00f1d818fb388e83b2c8c31f6bce35ac624e215bc12f88f9dc33edf48022006ff814bb9f700ee6abc3294e146fac3efd4f13f0005236b41c0a946ee00c9ae",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "3045022100bd0be6100c4fd8f102ec220e1b053e4c4e2ecca25615490150007b40d314dc3902201a1e0ea266965b43164d9e6576f58fa6726d42883dd1c3996d2925c2e2260796",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[3].serialize_der()),
            "3045022100bbfb9d0a946d420807c86e985d636cceb16e71c3694ed186316251a00cbd807202207773223f9a337e145f64673825be9b30d07ef1542c82188b264bedcf7cda78c6",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402203948f900a5506b8de36a4d8502f94f21dd84fd9c2314ab427d52feaa7a0a19f2022059b6a37a4adaa2c5419dc8aea63c6e2a2ec4c4bde46207f6dc1fcd22152fc6e5",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100a031202f3be94678f0e998622ee95ebb6ada8da1e9a5110228b5e04a747351e4022010ca6a21e18314ed53cfaae3b1f51998552a61a468e596368829a50ce40110e0",
            ),
            der_sig(
                "304402202361012a634aee7835c5ecdd6413dcffa8f404b7e77364c792cff984e4ee71e90220715c5e90baa08daa45a7439b1ee4fa4843ed77b19c058240b69406606d384124",
            ),
            der_sig(
                "304402207e8e82cd71ed4febeb593732c260456836e97d81896153ecd2b3cf320ca6861702202dd4a30f68f98ced7cc56a36369ac1fdd978248c5ff4ed204fc00cc625532989",
            ),
            der_sig(
                "3044022024cd52e4198c8ae0e414a86d86b5a65ea7450f2eb4e783096736d93395eca5ce022078f0094745b45be4d4b2b04dd5978c9e66ba49109e5704403e84aaf5f387d6be",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with six outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_six_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(2069, 6_993_000_000, 3_006_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100ad9a9bbbb75d506ca3b716b336ee3cf975dd7834fcf129d7dd188146eb58a8b4022061a759ee417339f7fe2ea1e8deb83abb6a74db31a09b7648a932a639cda23e33",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100a637902a5d4c9ba9e7c472a225337d5aac9e2e3f6744f76e237132e7619ba0400220035c60d784a031c0d9f6df66b7eab8726a5c25397399ee4aa960842059eb3f9d",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100e57e46234f8782d3ff7aa593b4f7446fb5316c842e693dc63ee324fd49f6a1c302204a2f7b44c48bd26e1554422afae13153eb94b29d3687b733d18930615fb2db61",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "3044022068613fb1b98eb3aec7f44c5b115b12343c2f066c4277c82b5f873dfe68f37f50022028109b4650f3f528ca4bfe9a467aff2e3e43893b61b5159157119d5d95cf1c18",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[3].serialize_der()),
            "3045022100d315522e09e7d53d2a659a79cb67fef56d6c4bddf3f46df6772d0d20a7beb7c8022070bcc17e288607b6a72be0bd83368bb6d53488db266c1cdb4d72214e4f02ac33",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304502210090b96a2498ce0c0f2fadbec2aab278fed54c1a7838df793ec4d2c78d96ec096202204fdd439c50f90d483baa7b68feeef4bd33bc277695405447bcd0bfb2ca34d7bc",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100f33513ee38abf1c582876f921f8fddc06acff48e04515532a32d3938de938ffd02203aa308a2c1863b7d6fdf53159a1465bf2e115c13152546cc5d74483ceaa7f699",
            ),
            der_sig(
                "3045022100ce07682cf4b90093c22dc2d9ab2a77ad6803526b655ef857221cc96af5c9e0bf02200f501cee22e7a268af40b555d15a8237c9f36ad67ef1841daf9f6a0267b1e6df",
            ),
            der_sig(
                "3045022100e3e35492e55f82ec0bc2f317ffd7a486d1f7024330fe9743c3559fc39f32ef0c02203d1d4db651fc388a91d5ad8ecdd8e83673063bc8eefe27cfd8c189090e3a23e0",
            ),
            der_sig(
                "304402207475aeb0212ef9bf5130b60937817ad88c9a87976988ef1f323f026148cc4a850220739fea17ad3257dcad72e509c73eebe86bee30b178467b9fdab213d631b109df",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with five outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_five_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(2070, 6_993_000_000, 3_004_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3044022001014419b5ba00e083ac4e0a85f19afc848aacac2d483b4b525d15e2ae5adbfe022015ebddad6ee1e72b47cb09f3e78459da5be01ccccd95dceca0e056a00cc773c1",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "30440220150b11069454da70caf2492ded9e0065c9a57f25ac2a4c52657b1d15b6c6ed85022068a38833b603c8892717206383611bad210f1cbb4b1f87ea29c6c65b9e1cb3e5",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "30450221009a6ed18e6873bc3644332a6ee21c152a5b102821865350df7a8c74451a51f9f2022050d801fb4895d7d7fbf452824c0168347f5c0cbe821cf6a97a63af5b8b2563c6",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "30440220408ad3009827a8fccf774cb285587686bfb2ed041f89a89453c311ce9c8ee0f902203c7392d9f8306d3a46522a66bd2723a7eb2628cb2d9b34d4c104f1766bf37502",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402204ca1ba260dee913d318271d86e10ca0f5883026fb5653155cff600fb40895223022037b145204b7054a40e08bb1fefbd826f827b40838d3e501423bcc57924bcb50c",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "304402205f6b6d12d8d2529fb24f4445630566cf4abbd0f9330ab6c2bdb94222d6a2a0c502202f556258ae6f05b193749e4c541dfcc13b525a5422f6291f073f15617ba8579b",
            ),
            der_sig(
                "3045022100f960dfb1c9aee7ce1437efa65b523e399383e8149790e05d8fed27ff6e42fe0002202fe8613e062ffe0b0c518cc4101fba1c6de70f64a5bcc7ae663f2efae43b8546",
            ),
            der_sig(
                "3045022100ae5fc7717ae684bc1fcf9020854e5dbe9842c9e7472879ac06ff95ac2bb10e4e022057728ada4c00083a3e65493fb5d50a232165948a1a0f530ef63185c2c8c56504",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with five outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_five_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(2194, 6_993_000_000, 3_004_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3044022072c2e2b1c899b2242656a537dde2892fa3801be0d6df0a87836c550137acde8302201654aa1974d37a829083c3ba15088689f30b56d6a4f6cb14c7bad0ee3116d398",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304502210099c98c2edeeee6ec0fb5f3bea8b79bb016a2717afa9b5072370f34382de281d302206f5e2980a995e045cf90a547f0752a7ee99d48547bc135258fe7bc07e0154301",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100fd85bd7697b89c08ec12acc8ba89b23090637d83abd26ca37e01ae93e67c367302202b551fe69386116c47f984aab9c8dfd25d864dcde5d3389cfbef2447a85c4b77",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "30450221008a9f2ea24cd455c2b64c1472a5fa83865b0a5f49a62b661801e884cf2849af8302204d44180e50bf6adfcf1c1e581d75af91aba4e28681ce4a5ee5f3cbf65eca10f3",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402204bb3d6e279d71d9da414c82de42f1f954267c762b2e2eb8b76bc3be4ea07d4b0022014febc009c5edc8c3fc5d94015de163200f780046f1c293bfed8568f08b70fb3",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100939726680351a7856c1bc386d4a1f422c7d29bd7b56afc139570f508474e6c40022023175a799ccf44c017fbaadb924c40b2a12115a5b7d0dfd3228df803a2de8450",
            ),
            der_sig(
                "3044022021bb883bf324553d085ba2e821cad80c28ef8b303dbead8f98e548783c02d1600220638f9ef2a9bba25869afc923f4b5dc38be3bb459f9efa5d869392d5f7779a4a0",
            ),
            der_sig(
                "3045022100c9e6f0454aa598b905a35e641a70cc9f67b5f38cc4b00843a041238c4a9f1c4a0220260a2822a62da97e44583e837245995ca2e36781769c52f19e498efbdcca262b",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with four outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_four_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(2195, 6_991_000_000, 3_004_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3044022044d592025b610c0d678f65032e87035cdfe89d1598c522cc32524ae8172417c30220749fef9d5b2ae8cdd91ece442ba8809bc891efedae2291e578475f97715d1767",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100ecc8c6529d0b2316d046f0f0757c1e1c25a636db168ec4f3aa1b9278df685dc0022067ae6b65e936f1337091f7b18a15935b608c5f2cdddb2f892ed0babfdd376d76",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3044022014d66f11f9cacf923807eba49542076c5fe5cccf252fb08fe98c78ef3ca6ab5402201b290dbe043cc512d9d78de074a5a129b8759bc6a6c546b190d120b690bd6e82",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402201a8c1b1f9671cd9e46c7323a104d7047cc48d3ee80d40d4512e0c72b8dc65666022066d7f9a2ce18c9eb22d2739ffcce05721c767f9b607622a31b6ea5793ddce403",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100e57b845066a06ee7c2cbfc29eabffe52daa9bf6f6de760066d04df9f9b250e0002202ffb197f0e6e0a77a75a9aff27014bd3de83b7f748d7efef986abe655e1dd50e",
            ),
            der_sig(
                "3045022100d193b7ecccad8057571620a0b1ffa6c48e9483311723b59cf536043b20bc51550220546d4bd37b3b101ecda14f6c907af46ec391abce1cd9c7ce22b1a62b534f2f2a",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with four outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_four_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(3702, 6_991_000_000, 3_004_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100e5efb73c32d32da2d79702299b6317de6fb24a60476e3855926d78484dd1b3c802203557cb66a42c944ef06e00bcc4da35a5bcb2f185aab0f8e403e519e1d66aaf75",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304402206e36c683ebf2cb16bcef3d5439cf8b53cd97280a365ed8acd7abb85a8ba5f21c02206e8621edfc2a5766cbc96eb67fd501127ff163eb6b85518a39f7d4974aef126f",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "304402207faad26678c8850e01b4a0696d60841f7305e1832b786110ee9075cb92ed14a30220516ef8ee5dfa80824ea28cbcec0dd95f8b847146257c16960db98507db15ffdc",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304502210092a587aeb777f869e7ff0d7898ea619ee26a3dacd1f3672b945eea600be431100220077ee9eae3528d15251f2a52b607b189820e57a6ccfac8d1af502b132ee40169",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "304402206fa54c11f98c3bae1e93df43fc7affeb05b476bf8060c03e29c377c69bc08e8b0220672701cce50d5c379ff45a5d2cfe48ac44973adb066ac32608e21221d869bb89",
            ),
            der_sig(
                "3044022057649739b0eb74d541ead0dfdb3d4b2c15aa192720031044c3434c67812e5ca902201e5ede42d960ae551707f4a6b34b09393cf4dee2418507daa022e3550dbb5817",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with three outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_three_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(3703, 6_988_000_000, 3_004_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402201b736d1773a124c745586217a75bed5f66c05716fbe8c7db4fdb3c3069741cdd02205083f39c321c1bcadfc8d97e3c791a66273d936abac0c6a2fde2ed46019508e1",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100988c143e2110067117d2321bdd4bd16ca1734c98b29290d129384af0962b634e02206c1b02478878c5f547018b833986578f90c3e9be669fe5788ad0072a55acbb05",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100b495d239772a237ff2cf354b1b11be152fd852704cb184e7356d13f2fb1e5e430220723db5cdb9cbd6ead7bfd3deb419cf41053a932418cbb22a67b581f40bc1f13e",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100c34c61735f93f2e324cc873c3b248111ccf8f6db15d5969583757010d4ad2b4602207867bb919b2ddd6387873e425345c9b7fd18d1d66aba41f3607bc2896ef3c30a",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with three outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_three_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(4914, 6_988_000_000, 3_004_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100d72638bc6308b88bb6d45861aae83e5b9ff6e10986546e13bce769c70036e2620220320be7c6d66d22f30b9fcd52af66531505b1310ca3b848c19285b38d8a1a8c19",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "30440220585dee80fafa264beac535c3c0bb5838ac348b156fdc982f86adc08dfc9bfd250220130abb82f9f295cc9ef423dcfef772fde2acd85d9df48cc538981d26a10a9c10",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100b4b16d5f8cc9fc4c1aff48831e832a0d8990e133978a66e302c133550954a44d022073573ce127e2200d316f6b612803a5c0c97b8d20e1e44dbe2ac0dd2fb8c95244",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100f43591c156038ba217756006bb3c55f7d113a325cdd7d9303c82115372858d68022016355b5aadf222bc8d12e426c75f4a03423917b2443a103eb2a498a3a2234374",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with two outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(4_915, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf5",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a720",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with two outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_180, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd3",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with one output untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_one_output_untrimmed_minimum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_181, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with fee greater than funder amount (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_fee_greater_than_funder_amount_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_936, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with 3 htlc outputs, 2 offered having the same amount and preimage (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_3_htlc_outputs_2_offered_having_the_same_amount_and_preimage_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(253, 6_998_000_000, 3_002_000_000, 546, vec![]);
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[5]).unwrap();
        commitment_params.add_htlc(htlcs[6]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402200d10bf5bc5397fc59d7188ae438d80c77575595a2d488e41bd6363a810cc8d72022012b57e714fbbfdf7a28c47d5b370cb8ac37c8545f596216e5b21e9b236ef457c",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3044022017b90c65207522a907fb6a137f9dd528b3389465a8ae72308d9e1d564f512cf402204fc917b4f0e88604a3e994f85bfae7c7c1f9d9e9f78e8cd112e0889720d9405b",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100ee2e16b90930a479b13f8823a7f14b600198c838161160b9436ed086d3fc57e002202a66fa2324f342a17129949c640bfe934cbc73a869ba7c06aa25c5a3d0bfb53d",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "304402207157f452f2506d73c315192311893800cfb3cc235cc1185b1cfcc136b55230db022014be242dbc6c5da141fec4034e7f387f74d6ff1899453d72ba957467540e1ecb",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402207d0870964530f97b62497b11153c551dca0a1e226815ef0a336651158da0f82402200f5378beee0e77759147b8a0a284decd11bfd2bc55c8fafa41c134fe996d43c8",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100b470fe12e5b7fea9eccb8cbff1972cea4f96758041898982a02bcc7f9d56d50b0220338a75b2afaab4ec00cdd2d9273c68c7581ff5a28bcbb40c4d138b81f1d45ce5",
            ),
            der_sig(
                "3045022100b575379f6d8743cb0087648f81cfd82d17a97fbf8f67e058c65ce8b9d25df9500220554a210d65b02d9f36c6adf0f639430ca8293196ba5089bf67cc3a9813b7b00a",
            ),
            der_sig(
                "30440220471c9f3ad92e49b13b7b8059f43ecf8f7887b0dccbb9fdb54bfe23d62a8ae332022024bd22fae0740e86a44228c35330da9526fd7306dffb2b9dc362d5e78abef7cc",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the edge case where `push_msat % 1000 != 0` to ensure there is
    /// no off-by-one error in opener balance calculation.
    #[test]
    fn commitment_tx_with_balance_msat_not_multiple_of_1000_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 6_999_999_000, 3_000_000_123, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3045022100a41609df3e71b939046d6dfface892aa6161ef8fb61898e142aeffc0ce1462df02201d1ca13eb145436593b0cb1a201c48bf2fdd6fc0c754784240d5f407c06ab4cf",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402202c85c0eb44ff3c5133e0a1e9f120a1af215b43d73da69b994e04c545b6cf7b600220331d81cacccfd7ae71eb3a1407bd767fc39a30776638e1048531441c95889bc2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Covers the case where commitment outputs have equal values,
    /// ensuring outputs are ordered by `script_pubkey`.
    #[test]
    fn commitment_tx_with_equal_output_values_orders_by_script_pubkey_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 5_005_430_000, 4_994_570_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3045022100a51021a83202743cb336edad88ee08bd14f434779bff21351c8f39d78d035f9602200d889a4a98332aff37f02938157cd3d7cf336313e5663848ac18bcd09ad5ff13",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402206ad05e8243d8fa04953cf14fff140fbf00999c3b6ffe63670d8edbf2eccf82c502201ca99860981ee1df1d93a02129f5b54f5c18e2ff047e8d8864a017eca48f94c9",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where HTLC `amount_msat % 1000 != 0` to ensure there is no
    /// off-by-one error in HTLC amount calculation.
    #[test]
    fn commitment_tx_with_htlc_amount_msat_not_multiple_of_1000_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(647, 7_000_000_000, 3_000_000_000, 546, vec![]);
        let htlc = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 2_000_999,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "30440220071d58afa4022249b2cc5e6bd1a82ebc73f6711a92802cd5ebd5428042883d4a02200766bf95b4537841ca209033c8f8c6d6d5d49a867db7298ce6d26e294573c4cb",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100c1eb6f0ab1b6461d1318e7f0d04c939c7d9b19d5f4f29b5fbacdd235d2348bfc02203dc02106596520a3189b1672c9b38610e447aa08662d4db90f93f6e7c3400351",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402207e966b48a4e5fda2223a87045b90e7ee2f111acd4c7fe0c9f297fe866b754b6102202e31f94429bdb06c42d60bc706b11ee420a89f48e8574b1d67c51ce6f23962d3",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100df9e9b4f2ba34b38c39e031557b3172e0ae5e7d82bf1d204ec1cef2d734f9ac702203c48988e280548a5a84b85492f78b66112930a4df64b60e5c41437fb3efb4acb",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where an HTLC output has the same value as the non-htlc
    /// output, ensuring outputs with equal values are ordered by `script_pubkey`
    /// and the HTLC output index accounts for outputs inserted before it.
    #[test]
    fn commitment_tx_with_htlc_value_equals_non_htlc_value_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 8_000_000_000, 2_000_000_000, 546, vec![]);
        let htlc = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 2_000_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100c6683d74adb5a359652cefc627f5cecc2a18844caeb2a722341d438d576855c202205821ee5aee49254b66be18b19dba6981c4829ed15c0f497cde4efc0faa155710",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3044022012d206a85befa450cee5358a234f5268aa0298e7b0a2c93cac72377ae19e0d6802203aaedd781aeee4c5f300060ba091a31f56895e2a0210ffb30667361bc41b3db0",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100f1835e03879680566ae1b32ef6e3a90b5e2ca5f738b70fdbdb0fc3bbffd1a21f0220406a0833b9ff7a81b6520d12c110c41ad873a18dcb7cdf7196da00a06aa621dc",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100e535e1b519dfb35cafac9ae192e127ee9c944edaa3ef647c513f93990e4d898c0220357d03c72ff115213a3276a95c5d0d3d3112f9d7ddaa81ad96540ef7051c10cc",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where the non-htlc outputs sort between two HTLC outputs,
    /// so only the HTLC outputs after each insertion point are shifted to later
    /// output indices.
    #[test]
    fn commitment_tx_with_non_htlc_outputs_between_htlc_outputs_legacy() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 7_000_000_000, 3_000_000_000, 546, vec![]);
        let htlc1 = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 2_000_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        let htlc2 = Htlc {
            id: 1,
            offerer: Side::Opener,
            amount_msat: 4_000_000_000,
            cltv_expiry: 501,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc1).unwrap();
        commitment_params.add_htlc(htlc2).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402200b657ece96eb1067b4ea9164f3c0cf4262ac3d6c3729fbd62bea6959b9c1ca5d02204b74bf808ac1d098629ae50d601b390c73918f9efe8c267665a7b3052e6214d8",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100b496172824cfe29ac87061da7a60c31911bb2f3ec9ae56b1a92c4376b818c969022065d6d2d828e7824fb9ad75133ae4f288b468824d588fea9214e204510cb286ad",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100e00c5207da69a769aef80d4e10dbf52dfced157c7ce25db68e56e4186ded68d70220262c52906309c5f40ab1d762161b376c0b458e4e766fedaad20e2dc96e134c67",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100eb66a11ca2bd46e9f85c4388b0db6449fd67c0935795849325e0c47bdb0c4e10022053fedb53271bd3dc730a6529fffab33c03500a2705efb6a0b004b641ea290b05",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "304402202d8004bf8054f8d2073d1c04cff430e7322a4b166c7eb6b99330fe6f4efee46002205ed9dacfc0c74bbe07696b4c2c8ae2afa14d3e939d01ad7013777c10bf3f9a36",
            ),
            der_sig(
                "3045022100fe8e2b4cc39a40b0921b6725c6b9c5fb645497d3d358f139ee58d0941e78ea2a0220305cea8be49c56b4e439112725dd45f49026a9250f6789888c3e9712c0cf205d",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where two sides have asymmetric dust limits, so the same
    /// HTLC is an output on one commitment and trimmed on the other.
    #[test]
    fn commitment_tx_with_asymmetric_dust_limits_legacy() {
        let (mut chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 7_000_000_000, 3_000_000_000, 546, vec![]);
        chan_config.acceptor.dust_limit_satoshis = 20_000;
        let htlc = Htlc {
            id: 0,
            offerer: Side::Acceptor,
            amount_msat: 20_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(local_htlc_signsignature.len(), 1);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402204b0e3b07abc81b1b718a8b89598f35a7cb78255509d3b70d564adf6c0caea44d02207effe6e5f73aac72d0e87397e904d05e56c77d3f760904eeadc532af72d20ea3",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304402204ce093917fa0fcf089e437a83b66ef27fef9ca7a1983c989bc1b58633b835e5202202c37ab9f215689964c7f38b6cbab179ae20046ce0d536de66a35245f158083ee",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30440220287cfea68d2ead0ae509b500ee1c31ab066a40567578e57689a9f27a0ee4fdaa0220452e3e202f60689e0a3f9a635e9b0580c793026a86c83f7f4c3c943dc7022133",
        );
        let remote_htlc_signature = vec![der_sig(
            "3044022002028f6f216f9a83620ff5b4619dee6407ae3424bebcb788807f6eb9a29a6566022070af8304a250a2db51f98963ea8e8d743b116bbc612753cf53da0f0e93e90559",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(acceptor_htlc_sigs.is_empty());
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // BOLT 3 Appendix F: Commitment and HTLC Transaction Test Vectors (anchors)
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-f-commitment-and-htlc-transaction-test-vectors-anchors

    // name: simple commitment tx with no HTLCs (BOLT 3 Appendix F)
    #[test]
    fn simple_commitment_tx_with_no_htlcs_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                7_000_000_000,
                3_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f7",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f3",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: simple commitment tx with no HTLCs and single anchor (BOLT 3 Appendix F)
    #[test]
    fn simple_commitment_tx_with_no_htlc_and_single_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 10_000_000_000, 0, 546, vec![0x40, 0x00, 0x00]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3044022007cf6b405e9c9b4f527b0ecad9d8bb661fabb8b12abf7d1c0b3ad1855db3ed490220616d5c1eeadccc63bd775a131149455d62d95a42c2a1b01cc7821fc42dce7778",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30440220655bf909fb6fa81d086f1336ac72c97906dce29d1b166e305c99152d810e26e1022051f577faa46412c46707aaac46b65d50053550a66334e00a44af2706f27a8658",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with seven outputs untrimmed (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_seven_outputs_untrimmed_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                644,
                6_993_000_000,
                3_007_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[0]).unwrap();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100ef82a405364bfc4007e63a7cc82925a513d79065bdbc216d60b6a4223a323f8a02200716730b8561f3c6d362eaf47f202e99fb30d0557b61b92b5f9134f8e2de3681",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3044022036f77f88b49bd03dc16d3a015efcc7acffc2a93b213324035d77a716f79013ff02203c218eb882a40402a8bb05dbb751a442345a4e56307be76b214b6d4db9ed3c92",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3044022026739b1adbfa34c485bf0e5a19e0cf7532f64545bcc5c95b95643ccc2d351e1902201743bb1b34f00e031cc15f6eff0f8ab764508d2681ff965ba62e76e540bca1e8",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "30440220191ba44e57b1601a59d99f85971d4801b286d428de275487c87ceeb8df1a4811022002215875d92833df0c9615c9096cf97152f87139ed9f82718bbb5b8b3d312524",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[3].serialize_der()),
            "3045022100f03047e38bc0aae2d80d53424b8c1d1b8139120e2bf09ad31a2803978745e6e102205b74c0eef0b472710b98c77e619ee9d0cc47a9dd786f4f214a564f44d79f9b9a",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[4].serialize_der()),
            "3044022022604660234aef9bd21284598ec50f070ac82a3a0152e0af5e98a02cd6e8976f022042b0b9112ee00806b856dff6de52a82c98b036a4fe14bb5fd2926725e2fc8191",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100e0106830467a558c07544a3de7715610c1147062e7d091deeebe8b5c661cda9402202ad049c1a6d04834317a78483f723c205c9f638d17222aafc620800cc1b6ae35",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "30440220746dc89a593e1b50915db63359b50c3c404f8324f78075c87708c866ccefda2502202a11062012dc8607b17e8c46ea4eefdfcc6b89a35440de99432ba12788d7bb17",
            ),
            der_sig(
                "3045022100a847bc3b8cf2441013725ae32dc589c419835d069afd6d7f3d9834d8be7cea6e02204ce9d35ec7f0788da80e4d62e810c4ccd13617e58fa10832e38fb7ae87bdf338",
            ),
            der_sig(
                "3044022035977f2aa6d6ae12f1dae3366440faa17558e9c88c3188bfc8df7e276c6c65410220659f1f9070c725d9d46e43b99a36fc6d711d36069704add2d57fc1fa2818cf12",
            ),
            der_sig(
                "3044022002f3ff9a31270092c214d3d5b8b4f826599404bba64b87f7536ef6324d41551b022079dc4cb25f7ecd84b49f5cce03eae7e2655b59f39d543765daef0d4f11c93fa2",
            ),
            der_sig(
                "30440220547937564288f64fb3e3c945a1348b912471f0c1c4cc7dc8ceca15a4cbd299b6022053c4f8e30832b13dfbe31e4091e313428625e0b5ac61eecba93f8f11c1e26225",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with six outputs untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_six_outputs_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                645,
                6_993_000_000,
                3_007_000_000,
                1001,
                vec![0x40, 0x00, 0x00],
            );
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[0]).unwrap();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100d57697c707b6f6d053febf24b98e8989f186eea42e37e9e91663ec2c70bb8f70022079b0715a472118f262f43016a674f59c015d9cafccec885968e76d9d9c5d0051",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100b7c49846466b13b190ff739bbe3005c105482fc55539e55b1c561f76b6982b6c02200e5c35808619cf543c8405cff9fedd25f333a4a2f6f6d5e8af8150090c40ef09",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100d29330f24db213b262068706099b39c15fa7e070c3fcdf8836c09723fc4d365602203ce57d01e9f28601e461a0b5c4a50119b270bde8b70148d133a6849c70b115ac",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "304402202d4ce515cd9000ec37575972d70b8d24f73909fb7012e8ebd8c2066ef6fe187902202830b53e64ea565fecd0f398100691da6bb2a5cf9bb0d1926f1d71d05828a11e",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[3].serialize_der()),
            "3045022100b20cd63e0587d1711beaebda4730775c4ac8b8b2ec78fe18a0c44c3f168c25230220079abb7fc4924e2fca5950842e5b9e416735585026914570078c4ef62f286226",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3044022025d97466c8049e955a5afce28e322f4b34d2561118e52332fb400f9b908cc0a402205dc6fba3a0d67ee142c428c535580cd1f2ff42e2f89b47e0c8a01847caffc312",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "3045022100e04d160a326432659fe9fb127304c1d348dfeaba840081bdc57d8efd902a48d8022008a824e7cf5492b97e4d9e03c06a09f822775a44f6b5b2533a2088904abfc282",
            ),
            der_sig(
                "3045022100fbdc3c367ce3bf30796025cc590ee1f2ce0e72ae1ac19f5986d6d0a4fc76211f02207e45ae9267e8e820d188569604f71d1abd11bd385d58853dd7dc034cdb3e9a6e",
            ),
            der_sig(
                "3044022066c5ef625cee3ddd2bc7b6bfb354b5834cf1cc6d52dd972fb41b7b225437ae4a022066cb85647df65c6b87a54e416dcdcca778a776c36a9643d2b5dc793c9b29f4c1",
            ),
            der_sig(
                "3044022022c7e11595c53ee89a57ca76baf0aed730da035952d6ab3fe6459f5eff3b337a022075e10cc5f5fd724a35ce4087a5d03cd616698626c69814032132b50bb97dc615",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with four outputs untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_four_outputs_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                2185,
                6_993_000_000,
                3_007_000_000,
                2001,
                vec![0x40, 0x00, 0x00],
            );
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[0]).unwrap();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100cd8479cfe1edb1e5a1d487391e0451a469c7171e51e680183f19eb4321f20e9b02204eab7d5a6384b1b08e03baa6e4d9748dfd2b5ab2bae7e39604a0d0055bbffdd5",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "30440220669de9ca7910eff65a7773ebd14a9fc371fe88cde5b8e2a81609d85c87ac939b02201ac29472fa4067322e92d75b624942d60be5050139b20bb363db75be79eb946f",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "3045022100e3104ed8b239f8019e5f0a1a73d7782a94a8c36e7984f476c3a0b3cb0e62e27902207e3d52884600985f8a2098e53a5c30dd6a5e857733acfaa07ab2162421ed2688",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3044022040f63a16148cf35c8d3d41827f5ae7f7c3746885bb64d4d1b895892a83812b3e02202fcf95c2bf02c466163b3fa3ced6a24926fbb4035095a96842ef516e86ba54c0",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "304402206870514a72ad6e723ff7f1e0370d7a33c1cd2a0b9272674143ebaf6a1d02dee102205bd953c34faf5e7322e9a1c0103581cb090280fda4f1039ee8552668afa90ebb",
            ),
            der_sig(
                "3045022100949e8dd938da56445b1cdfdebe1b7efea086edd05d89910d205a1e2e033ce47102202cbd68b5262ab144d9ec12653f87dfb0bb6bd05d1f58ae1e523f028eaefd7271",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with three outputs untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_three_outputs_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                3687,
                6_993_000_000,
                3_007_000_000,
                3001,
                vec![0x40, 0x00, 0x00],
            );
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[0]).unwrap();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[2]).unwrap();
        commitment_params.add_htlc(htlcs[3]).unwrap();
        commitment_params.add_htlc(htlcs[4]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100c970799bcb33f43179eb43b3378a0a61991cf2923f69b36ef12548c3df0e6d500220413dc27d2e39ee583093adfcb7799be680141738babb31cc7b0669a777a31f5d",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100af7a8b7c7ff2080c68995254cb66d64d9954edcc5baac3bb4f27ed2d29aaa6120220421c27da7a60574a9263f271e0f3bd34594ec6011095190022b3b54596ea03de",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100ad6c71569856b2d7ff42e838b4abe74a713426b37f22fa667a195a4c88908c6902202b37272b02a42dc6d9f4f82cab3eaf84ac882d9ed762859e1e75455c2c228377",
        );
        let remote_htlc_signature = vec![der_sig(
            "3044022017b558a3cf5f0cb94269e2e927b29ed22bd2416abb8a7ce6de4d1256f359b93602202e9ca2b1a23ea3e69f433c704e327739e219804b8c188b1d52f74fd5a9de954c",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with two outputs untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                4_894,
                6_988_000_000,
                3_000_000_000,
                4_001,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221009f16ac85d232e4eddb3fcd750a68ebf0b58e3356eaada45d3513ede7e817bf4c02207c2b043b4e5f971261975406cb955219fa56bffe5d834a833694b5abc1ce4cfd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b95",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with one output untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_one_output_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                6_216_010,
                6_988_000_000,
                3_000_000_000,
                4_001,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221009ad80792e3038fe6968d12ff23e6888a565c3ddd065037f357445f01675d63f3022018384915e5f1f4ae157e15debf4f49b61c8d9d2b073c7d6f97c4a68caa3ed4c1",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30450221008fd5dbff02e4b59020d4cd23a3c30d3e287065fda75a0a09b402980adf68ccda022001e0b8b620cd915ddff11f1de32addf23d81d51b90e6841b2cb8dcaf3faa5ecf",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with 3 htlc outputs, 2 offered having the same amount and preimage (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_3_htlc_outputs_2_offered_having_the_same_amount_and_preimage_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                253,
                6_998_000_000,
                3_002_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );
        let htlcs = bolt3_htlc_list();
        commitment_params.add_htlc(htlcs[1]).unwrap();
        commitment_params.add_htlc(htlcs[5]).unwrap();
        commitment_params.add_htlc(htlcs[6]).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100b4014970d9d7962853f3f85196144671d7d5d87426250f0a5fdaf9a55292e92502205360910c9abb397467e19dbd63d081deb4a3240903114c98cec0a23591b79b76",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304402205df665e2908c7690d2d33eb70e6e119958c28febe141a94ed0dd9a55ce7c8cfc0220364d02663a5d019af35c5cd5fda9465d985d85bbd12db207738d61163449a424",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "304402203f99ec05cdd89558a23683b471c1dcce8f6a92295f1fff3b0b5d21be4d4f97ea022019d29070690fc2c126fe27cc4ab2f503f289d362721b2efa7418e7fddb939a5b",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[2].serialize_der()),
            "3045022100f2cd35e385b9b7e15b92a5d78d120b6b2c5af4e974bc01e884c5facb3bb5966c0220706e0506477ce809a40022d6de8e041e9ef13136c45abee9c36f58a01fdb188b",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3044022027b38dfb654c34032ffb70bb43022981652fce923cbbe3cbe7394e2ade8b34230220584195b78da6e25c2e8da6b4308d9db25b65b64975db9266163ef592abb7c725",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "30440220078fe5343dab88c348a3a8a9c1a9293259dbf35507ae971702cc39dd623ea9af022011ed0c0f35243cd0bb4d9ca3c772379b2b5f4af93140e9fdc5600dfec1cdb0c2",
            ),
            der_sig(
                "304402202df6bf0f98a42cfd0172a16bded7d1b16c14f5f42ba23f5c54648c14b647531302200fe1508626817f23925bb56951d5e4b2654c751743ab6db48a6cce7dda17c01c",
            ),
            der_sig(
                "3045022100bd206b420c495f3aa714d3ea4766cbe95441deacb5d2f737f1913349aee7c2ae02200249d2c950dd3b15326bf378ae5d2b871d33d6737f5d70735f3de8383140f2a1",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the edge case where `push_msat % 1000 != 0` to ensure there is
    /// no off-by-one error in opener balance calculation.
    #[test]
    fn commitment_tx_with_balance_msat_not_multiple_of_1000_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                6_999_999_000,
                3_000_000_123,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "304402202573a6da7fffc40fffb98d106dc4c83a5c94266118b3b0b44ea03100e20dab1e022038d9e65b3b84096ccebc91f9b56117d30c1cc249e21426d2d3dbf3e4617935fd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "3044022036e0e75ab8bd15f1232da3974db1a4cfca2491912b1fb06bfe2fbfca4f416e29022035c5a4f4b09f344a595ffdfb73aebf5982d41f1fcf5e90b141d8141c857e9aed",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Covers the case where commitment outputs have equal values,
    /// ensuring outputs are ordered by `script_pubkey`.
    #[test]
    fn commitment_tx_with_equal_output_values_orders_by_script_pubkey_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                5_008_760_000,
                4_991_240_000,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30440220156f857fc1cfaa0e13dadc5a07553244971a91d99a3f53bf87305189864043a402200bd512ace372ac10c54a3745ae123e69d99305c564bd0420ade72ebcac994bd8",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "3044022035fd44caf320fdca9f2a866fe88e27f186a4a93ecf390549c3ed9950a9042c2f0220237525890e37617749e1eae4c2cce10e19d1a796acea1937c29cb888ee992d19",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where HTLC `amount_msat % 1000 != 0` to ensure there is no
    /// off-by-one error in HTLC amount calculation.
    #[test]
    fn commitment_tx_with_htlc_amount_msat_not_multiple_of_1000_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                647,
                7_000_000_000,
                3_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );
        let htlc = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 2_000_999,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402206e7365edbeeab65e2d652070cf6836d5da2a13c17f5366427e2c5d24ea97f0e202207ec990ea4b1e0d4d7902522cc7dc3c37ca771aa7f2da6a83c166f3f906f541b9",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3045022100cf2585a9a423f20a897fd78612e2c407f786e5194b632221cd6b31056c54624d02206215236fc36cacb2e90dc6df9485c6c662919fa819ba34793267828a9db224fd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30440220509de9833bddefdbfc68c5618b28344598e600011476d750729227228c7cd03002204e18f7bc12f7e73e4a1a5523a1a77d20b05d7a08deee8b6eb641646e0577b5e2",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100cce5b9738f0233766886815c8716dd72997756f2428e1d81a2ab3bc30e3e458a022024d80702719b758a618bab07774ef3f0a2745266473488dfcde8265658c631d1",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where an HTLC output has the same value as the non-htlc
    /// output, ensuring outputs with equal values are ordered by `script_pubkey`
    /// and the HTLC output index accounts for outputs inserted before it.
    #[test]
    fn commitment_tx_with_htlc_value_equals_non_htlc_value_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                8_000_000_000,
                2_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );
        let htlc = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 2_000_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402200dec768812a74dff68dfb5cf4c69ceaabb5cb983784f937f804f6d0f23ae08e902206be6c6a073bfa225beb34fd768e97d1976a0824be7d86600a311284d34e9d11f",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304402204046207472175337796f45aae19af6a2d4178dc1b716ab2c821ac8c0e8c0163b0220353ddce7c7aad1446d6145fbc92ef2222ddbe3b2ad37a103d73a6506986b6cce",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402204657f701066d94fc6a46b9581503eb87c81cd7fb2523f8d6e99c5f5fec3b810802204208d3d0e882ca7db6856a46fe3b06be4c68f1f4a3b6e743374aaaf0270fb160",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100e8646cb7d334f3fbb46cfb028a6a5bddcd02495631c9debca395272d55a8f491022067f511cfc2b3a7a139b774e4f4767f3552d8f18a8654e054f88341b6c935221e",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where the non-htlc outputs sort between two HTLC outputs,
    /// so only the HTLC outputs after each insertion point are shifted to later
    /// output indices.
    #[test]
    fn commitment_tx_with_non_htlc_outputs_between_htlc_outputs_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                7_000_000_000,
                3_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );
        let htlc1 = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 2_000_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        let htlc2 = Htlc {
            id: 1,
            offerer: Side::Opener,
            amount_msat: 4_000_000_000,
            cltv_expiry: 501,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc1).unwrap();
        commitment_params.add_htlc(htlc2).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "304402205089ec3e39ec7ae4d13e2dbf6fe968a1d9b254faf38eb8a2bc66722b8fc05ccb022020f1b80237b8d41b843897774e664147b3ea69ca8c4ada3fdf75e86fe11410ec",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3044022005fda3445684d34f33cf4ae625acf5039c772919fe6a2c69d120ad202f1d3101022071a9481a2748726093f00c0ed4536478389b6e95541dc65a95c7048cd4a728d6",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[1].serialize_der()),
            "304402206fecae256ecc8d031ba9740b76adaecf5390e7c1e0a6e8ce368a9cca8e62e87002201ec9821c0396c1b34200d54d8a40c4957f25984d4e41a021a126ed38ef154423",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100bbb32f1b07e16ad3e4ae0ed0a59297dbd8502385996d2f0cbf3b2a66d9d2949702200fc0444198a3d7168eb72adb3172bba53219b17e79ec26e346c638ea9a09d073",
        );
        let remote_htlc_signature = vec![
            der_sig(
                "304402204dbcc299bb4f4d6c639ca75fdafdcf223d919bba06a95b947f321ca0b459a0fb02204d1e468b852fba37c69bb31d76c04b727a2793ea5ed389452fcdf93e93dbfcba",
            ),
            der_sig(
                "304502210098d77f27cdbdf2b9223b4e98a58d9a8dcb8bac0daae9fa9ebab4a03ec74429f80220421c43b913e6ade19085af521f69b209ff2f6a0b70b7fbc583dc96a911571760",
            ),
        ];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where two sides have asymmetric dust limits, so the same
    /// HTLC is an output on one commitment and trimmed on the other.
    #[test]
    fn commitment_tx_with_asymmetric_dust_limits_anchor() {
        let (mut chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                7_000_000_000,
                3_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );
        chan_config.acceptor.dust_limit_satoshis = 20_000;
        let htlc = Htlc {
            id: 0,
            offerer: Side::Acceptor,
            amount_msat: 15_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(local_htlc_signsignature.len(), 1);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3044022037e9c8d6a877b3ef02fb7f41f2f24746ba0ae11f868b3756ec3b88f1c60cf4f502204e9006f0c1748184bcdbd66c739dbbf4f219d0bb3524bf2bb7a09f29a2116a30",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "304402203f734f41a30faa7a88c56e145d01eafde90302936958d0f6821032685e5d8496022062834eaa224c50d93281aceffca52df0de211c6468fa15066b05d8d598f5baa8",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402201c8c18214e67c0f9f5ec6a5960c5c4ba758197631ccadc1370f760c67f541eb502204d45a5d2c0e906e0cb6f7c9936b55522d5cebe06366ee4687ae4d548f9e3bdcd",
        );
        let remote_htlc_signature = vec![der_sig(
            "3045022100dcbd66f962a33cd8b9c03df38b1f90d140db5cd1296ec9f5d2416914dda74d090220014774c67e8c7274e59f684b0616c1fa92476ca691fce56d5cce8560a80a01ff",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(acceptor_htlc_sigs.is_empty());
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors; the expected signatures were generated
    /// by `eclair` as the source of truth.
    /// Tests the case where a party's main output is trimmed but the commitment
    /// still carries a non-dust HTLC, so both anchor outputs must be present.
    #[test]
    fn commitment_tx_with_main_output_trimmed_but_htlcs_present_anchor() {
        let (chan_config, mut commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 10_000_000_000, 0, 546, vec![0x40, 0x00, 0x00]);
        let htlc = Htlc {
            id: 0,
            offerer: Side::Opener,
            amount_msat: 5_000_000,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        commitment_params.add_htlc(htlc).unwrap();

        // Opener signs own commitment.
        let (local_signature, local_htlc_signsignature) =
            chan_config.sign_holder_commitment(&commitment_params, &opener_holder);
        assert_eq!(
            hex::encode(local_signature.serialize_der()),
            "3045022100effa83adb5b8878580b470d3a6d3fe922ffc8e05b576de8b2084326cbe7a5b64022062f42e170abb83924b6e7c32229534de60290b3a6b325e7ebb30f3f663d4517b",
        );
        assert_eq!(
            hex::encode(local_htlc_signsignature[0].serialize_der()),
            "3044022019117ef6efd57c43db551f800cd100488521b462ab0daadceee7f1172eecf11f022064e7c452d3c5ca7e2ff029109394800a7c09b1b10a609fe548182f6daa2c8680",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100f74c249e12c692454317bfeb868fc6cc04249a0cc84bf1cbfdd4177963fc045702202c40d41c1fbac3eb582201dda0c3faf3317a530fffa4016a1afc456405503c21",
        );
        let remote_htlc_signature = vec![der_sig(
            "30440220717a09ec2d7ca248756e87bc3b28d2bf914ac66eabc6f9d91c245118eddd468c0220346cac86050ce10df472b0a7194c2d12376ca882052870cf67489a3956f55a86",
        )];
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &remote_htlc_signature,
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // BOLT 3 Appendix E: Key Derivation Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-e-key-derivation-test-vectors

    #[test]
    fn derive_pubkey_from_basepoint() {
        let basepoint =
            pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point =
            pubkey("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let localpubkey = derive_pubkey(&basepoint, &per_commitment_point);
        assert_eq!(
            localpubkey,
            pubkey("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"),
        );
    }

    #[test]
    fn derive_revocation_pubkey_from_basepoint() {
        let revocation_basepoint =
            pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point =
            pubkey("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let revocationpubkey =
            derive_revocation_pubkey(&revocation_basepoint, &per_commitment_point);
        assert_eq!(
            revocationpubkey,
            pubkey("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"),
        );
    }

    fn sample_chan_config(funding_satoshis: u64, channel_type: Vec<u8>) -> ChannelConfig {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let sample_party = || ChannelPartyConfig {
            funding_pubkey: sample_key,
            payment_basepoint: sample_key,
            revocation_basepoint: sample_key,
            delayed_payment_basepoint: sample_key,
            htlc_basepoint: sample_key,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };

        ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid txid hex"),
                vout: 0,
            },
            funding_satoshis,
            channel_type,
            opener: sample_party(),
            acceptor: sample_party(),
            minimum_depth: 8,
        }
    }

    #[test]
    fn new_initial_from_funding_msat_overflow() {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let chan_config = sample_chan_config(u64::MAX, vec![]);
        let result = chan_config.new_initial_commitment(0, 15_000, sample_key, sample_key);
        assert!(matches!(result, Err(CommitmentError::FundingMsatOverflow)));
    }

    #[test]
    fn new_initial_from_funding_push_exceeds_funding() {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let chan_config = sample_chan_config(1_000, vec![]);
        let result = chan_config.new_initial_commitment(2_000_000, 15_000, sample_key, sample_key);
        assert!(matches!(result, Err(CommitmentError::PushExceedsFunding)));
    }

    #[test]
    fn opener_balance_after_commitment_cost_total_sat_checks() {
        let feerate_per_kw: u32 = 15_000;
        let anchor_channel_type = [0x40, 0x00, 0x00];
        // Legacy fee: 15000 * 724 / 1000 = 10_860 sat
        // Anchor fee: 15000 * 1124 / 1000 = 16_860 sat; anchor_cost = 660 sat

        // Comfortably affordable
        let opener_balance_sat: u64 = 20_000;
        assert_eq!(
            opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &[], 0).total_sat()),
            Some(9_140),
        );

        // Exact zero opener balance
        let opener_balance_sat: u64 = 10_860;
        assert_eq!(
            opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &[], 0).total_sat()),
            Some(0),
        );

        // Balance does not cover the fee
        let opener_balance_sat: u64 = 10_000;
        assert_eq!(
            opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &[], 0).total_sat()),
            None
        );

        // Balance covers the fee but not the anchor outputs
        let opener_balance_sat: u64 = 17_500;
        assert_eq!(
            opener_balance_sat.checked_sub(
                CommitmentCost::new(feerate_per_kw, &anchor_channel_type, 0).total_sat()
            ),
            None,
        );
    }

    #[test]
    fn opener_balance_after_commitment_cost_total_sat_with_htlc_checks() {
        let feerate_per_kw: u32 = 15_000;
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let htlc = |id: u64, offerer: Side, amount_msat: u64| Htlc {
            id,
            offerer,
            amount_msat,
            cltv_expiry: 500,
            payment_hash: [0; 32],
        };
        let state_with = |config: &ChannelConfig, push_msat: u64, htlcs: &[Htlc]| {
            let mut state = config
                .new_initial_commitment(push_msat, feerate_per_kw, sample_key, sample_key)
                .expect("valid commitment");
            for h in htlcs {
                state.add_htlc(*h).unwrap();
            }
            state
        };
        // Returns opener balance after deducting the commitment cost.
        let opener_balance = |config: &ChannelConfig, state: &CommitmentState, local_side: Side| {
            let opener_balance_sat = state.opener.balance_msat / 1000;
            let cost = CommitmentCost::new(
                state.feerate_per_kw,
                &config.channel_type,
                config.count_nondust_htlcs(state, local_side),
            );
            opener_balance_sat.checked_sub(cost.total_sat())
        };
        // Legacy fee: 15000 * (724 + 172 per non-dust HTLC) / 1000
        //   = 10_860 / 13_440 / 16_020 sat for 0 / 1 / 2 HTLCs
        // Legacy dust thresholds: 546 + 15000 * 663 / 1000 = 10_491 sat (offered);
        //   546 + 15000 * 703 / 1000 = 11_091 sat (received)
        // Anchor fee: 15000 * (1124 + 172) / 1000 = 19_440 sat for 1 HTLC; anchor_cost = 660 sat

        // Opener balance exactly covers the one-HTLC fee
        let config = sample_chan_config(50_000, vec![]);
        let offered = htlc(0, Side::Opener, 12_000_000);
        let state = state_with(&config, 24_560_000, &[offered]);
        assert_eq!(opener_balance(&config, &state, Side::Opener), Some(0));
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), Some(0));

        // One msat short of the one-HTLC fee
        let state = state_with(&config, 24_560_001, &[offered]);
        assert_eq!(opener_balance(&config, &state, Side::Opener), None);
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), None);

        // Dust HTLC is trimmed and adds no fee
        let state = state_with(
            &config,
            24_560_000,
            &[offered, htlc(1, Side::Acceptor, 1_000_000)],
        );
        assert_eq!(opener_balance(&config, &state, Side::Opener), Some(0));
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), Some(0));

        // Second non-dust HTLC pushes the fee out of reach
        let state = state_with(
            &config,
            24_560_000,
            &[offered, htlc(1, Side::Acceptor, 12_000_000)],
        );
        assert_eq!(opener_balance(&config, &state, Side::Opener), None);
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), None);

        // Exactly at the offered dust threshold: kept on the opener's
        // commitment, trimmed as received on the acceptor's
        let state = state_with(&config, 27_509_000, &[htlc(0, Side::Opener, 10_491_000)]);
        assert_eq!(opener_balance(&config, &state, Side::Opener), None);
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), Some(1_140));

        // Dust limit of the evaluated side decides trimming
        let mut config = sample_chan_config(50_000, vec![]);
        config.acceptor.dust_limit_satoshis = 20_000;
        let state = state_with(&config, 26_000_000, &[offered]);
        assert_eq!(opener_balance(&config, &state, Side::Opener), None);
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), Some(1_140));

        // Anchor dust threshold is the dust limit alone
        let config = sample_chan_config(50_000, vec![0x40, 0x00, 0x00]);
        let htlcs = [
            htlc(0, Side::Opener, 546_000),
            htlc(1, Side::Opener, 545_000),
        ];
        let state = state_with(&config, 28_809_000, &htlcs);
        assert_eq!(opener_balance(&config, &state, Side::Opener), Some(0));
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), Some(0));

        // One msat short of the anchor one-HTLC fee plus anchor cost
        let state = state_with(&config, 28_809_001, &htlcs);
        assert_eq!(opener_balance(&config, &state, Side::Opener), None);
        assert_eq!(opener_balance(&config, &state, Side::Acceptor), None);
    }
}
