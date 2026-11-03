//! BOLT 3 commitment transaction construction and signing.

use super::funding::build_funding_witness_script;
use crate::bolt::{AcceptChannel, Features, OpenChannel, SHA256_HASH_SIZE};

use bitcoin::absolute::LockTime;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Anchor output value in satoshis.
const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Weight of a non-anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR: u64 = 724;

/// Weight of an anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_ANCHOR: u64 = 1124;

/// Additional commitment weight per non-trimmed HTLC output.
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Opener,
    Acceptor,
}

/// Holder's identity and funding/HTLC secrets for the commitment.
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
    /// Whether the opener requested a public channel in `open_channel`.
    pub announce_channel: bool,
}

/// An in-flight HTLC that appears (subject to dust trimming) as an output in
/// the commitment transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub payment_hash: [u8; SHA256_HASH_SIZE],
}

/// State of `local_side`'s commitment transaction.
///
/// Each side has its own commitment state, so the commitment number, fee rate,
/// balances, and in-flight HTLCs may differ until both sides have caught up.
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

/// Per-commitment keys used when constructing a commitment transaction.
struct TxCreationKeys {
    /// Local delayed payment pubkey.
    local_delayedpubkey: PublicKey,
    /// Revocation pubkey for this commitment.
    revocationpubkey: PublicKey,
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
    pub fn counterparty_side(&self) -> Side {
        self.side.other()
    }
}

impl ChannelConfig {
    /// Returns the channel `open_channel` and `accept_channel` negotiate, funded at
    /// `funding_outpoint`, with its initial commitments.
    ///
    /// # Errors
    ///
    /// Returns the [`CommitmentError`] of [`Self::new_initial_commitments`] if
    /// the negotiated amounts cannot form the initial commitments.
    pub fn from_negotiation(
        open_channel: &OpenChannel,
        accept_channel: &AcceptChannel,
        funding_outpoint: OutPoint,
    ) -> Result<(Self, ChannelCommitments), CommitmentError> {
        let config = Self {
            funding_outpoint,
            funding_satoshis: open_channel.funding_satoshis,
            channel_type: Features::from(
                open_channel.tlvs.channel_type.clone().unwrap_or_default(),
            ),
            opener: ChannelPartyConfig {
                funding_pubkey: open_channel.funding_pubkey,
                payment_basepoint: open_channel.payment_basepoint,
                revocation_basepoint: open_channel.revocation_basepoint,
                delayed_payment_basepoint: open_channel.delayed_payment_basepoint,
                htlc_basepoint: open_channel.htlc_basepoint,
                dust_limit_satoshis: open_channel.dust_limit_satoshis,
                to_self_delay: open_channel.to_self_delay,
            },
            acceptor: ChannelPartyConfig {
                funding_pubkey: accept_channel.funding_pubkey,
                payment_basepoint: accept_channel.payment_basepoint,
                revocation_basepoint: accept_channel.revocation_basepoint,
                delayed_payment_basepoint: accept_channel.delayed_payment_basepoint,
                htlc_basepoint: accept_channel.htlc_basepoint,
                dust_limit_satoshis: accept_channel.dust_limit_satoshis,
                to_self_delay: accept_channel.to_self_delay,
            },
            minimum_depth: accept_channel.minimum_depth,
            announce_channel: open_channel.announce_channel(),
        };
        let commitments = config.new_initial_commitments(
            open_channel.push_msat,
            open_channel.feerate_per_kw,
            open_channel.first_per_commitment_point,
            accept_channel.first_per_commitment_point,
        )?;

        Ok((config, commitments))
    }

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

    /// Builds the signature for the counterparty's commitment transaction.
    #[must_use]
    pub fn sign_counterparty_commitment(
        &self,
        commitments: &ChannelCommitments,
        holder: &HolderIdentity,
    ) -> Signature {
        let state = commitments.state(holder.counterparty_side());
        let commitment = self.build_commitment_tx(state);
        self.sign_commitment_tx(&commitment, &holder.funding_privkey)
    }

    /// Verifies the counterparty's signature on the holder's commitment
    /// transaction. Returns `true` if the signature is valid.
    #[must_use]
    pub fn verify_counterparty_signature(
        &self,
        commitments: &ChannelCommitments,
        holder: &HolderIdentity,
        commitment_sig: &Signature,
    ) -> bool {
        let state = commitments.state(holder.side);
        let commitment = self.build_commitment_tx(state);
        self.verify_commitment_sig(
            &commitment,
            &self.party(holder.counterparty_side()).funding_pubkey,
            commitment_sig,
        )
    }

    /// Builds the signature for the holder's commitment transaction.
    /// Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn sign_holder_commitment(
        &self,
        commitments: &ChannelCommitments,
        holder: &HolderIdentity,
    ) -> Signature {
        let state = commitments.state(holder.side);
        let commitment = self.build_commitment_tx(state);
        self.sign_commitment_tx(&commitment, &holder.funding_privkey)
    }

    /// Builds the commitment transaction. The commitment format (legacy or
    /// anchor) is determined by the `channel_type`.
    fn build_commitment_tx(&self, state: &CommitmentState) -> Transaction {
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
        let outputs = self.build_commitment_outputs(state, &keys);

        // Witness is not included in the BIP 143 sighash, so we leave it empty.
        let input = TxIn {
            previous_output: self.funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        };

        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(locktime),
            input: vec![input],
            output: outputs,
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

    /// Builds the lexicographically sorted commitment outputs.
    ///
    /// Outputs are built for the commitment side specified by `state`:
    /// the opener or the acceptor.
    fn build_commitment_outputs(
        &self,
        state: &CommitmentState,
        keys: &TxCreationKeys,
    ) -> Vec<TxOut> {
        let local_side = state.local_side;
        let anchor = self.channel_type.supports_feature(Features::OPTION_ANCHORS);
        let mut outputs: Vec<TxOut> = Vec::new();

        // Fee and balances.
        let commitment_cost = CommitmentCost::new(state.feerate_per_kw, &self.channel_type);
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

            outputs.push(TxOut {
                value: Amount::from_sat(to_local_value),
                script_pubkey: to_local_spk,
            });
        }
        if has_to_remote {
            let to_remote_spk = build_to_remote_scriptpubkey(&remote.payment_basepoint, anchor);

            outputs.push(TxOut {
                value: Amount::from_sat(to_remote_value),
                script_pubkey: to_remote_spk,
            });
        }

        if anchor {
            if has_to_local {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&local.funding_pubkey),
                });
            }

            if has_to_remote {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&remote.funding_pubkey),
                });
            }
        }

        // BOLT 3 output ordering: sort by (value, script_pubkey).
        outputs.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()))
        });

        outputs
    }

    /// Signs the commitment transaction using the local party's funding private
    /// key.
    fn sign_commitment_tx(
        &self,
        commitment: &Transaction,
        funding_privkey: &SecretKey,
    ) -> Signature {
        let sighash = self.build_commitment_sighash(commitment);
        sign(&sighash, funding_privkey)
    }

    /// Verifies the commitment signature against the counterparty's funding
    /// public key.
    fn verify_commitment_sig(
        &self,
        commitment: &Transaction,
        funding_pubkey: &PublicKey,
        commitment_sig: &Signature,
    ) -> bool {
        let sighash = self.build_commitment_sighash(commitment);
        verify(&sighash, commitment_sig, funding_pubkey)
    }
}

impl Htlc {
    /// Converts the HTLC amount from millisatoshis to satoshis.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        Amount::from_sat(self.amount_msat / 1000)
    }
}

impl CommitmentState {
    /// Returns a mutable reference to the given side's balance.
    fn balance_msat_mut(&mut self, side: Side) -> &mut u64 {
        match side {
            Side::Opener => &mut self.opener_balance_msat,
            Side::Acceptor => &mut self.acceptor_balance_msat,
        }
    }

    /// Removes the in-flight HTLC that `offerer` added with the given `id`,
    /// returning it.
    ///
    /// # Errors
    ///
    /// Returns [`CommitmentError::HtlcNotFound`] if no in-flight HTLC matches
    /// `id` and `offerer`.
    fn remove_htlc(&mut self, id: u64, offerer: Side) -> Result<Htlc, CommitmentError> {
        // The target is currently the only side that sends HTLC resolutions, so
        // a resolution for an unknown HTLC means the target is misbehaving; we
        // surface it as `HtlcNotFound`. Once we send our own resolutions, we
        // should skip this error for those, since we cannot shift the balance
        // and the resulting broken commitment would otherwise be masked as an
        // invalid signature.
        let pos = self
            .htlcs
            .iter()
            .position(|h| h.id == id && h.offerer == offerer)
            .ok_or(CommitmentError::HtlcNotFound)?;
        Ok(self.htlcs.remove(pos))
    }
}

impl ChannelCommitments {
    /// Returns the state of the given side's commitment.
    #[must_use]
    pub fn state(&self, side: Side) -> &CommitmentState {
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
        let htlc = state.remove_htlc(id, offerer)?;
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
        let htlc = state.remove_htlc(id, offerer)?;
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

impl CommitmentCost {
    /// Calculates the total cost of a commitment transaction.
    #[must_use]
    pub fn new(feerate_per_kw: u32, channel_type: &Features) -> CommitmentCost {
        CommitmentCost {
            fee_sat: commit_tx_fee_sat(feerate_per_kw, 0, channel_type),
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
            local_delayedpubkey: derive_pubkey(
                &local.delayed_payment_basepoint,
                &per_commitment_point,
            ),
            revocationpubkey: derive_revocation_pubkey(
                &remote.revocation_basepoint,
                &per_commitment_point,
            ),
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
/// Used by the `to_local` commitment output.
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
