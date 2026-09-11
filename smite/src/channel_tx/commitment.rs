//! BOLT 3 commitment transaction construction and signing.

use super::funding::build_funding_witness_script;
use crate::bolt::Features;

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

/// Errors that can occur when constructing or validating commitment transactions.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    /// Funding amount overflowed when converting to millisatoshis.
    #[error("funding_satoshis overflowed when converting to msat")]
    FundingMsatOverflow,

    /// Push amount exceeds the total funding amount.
    #[error("push_msat exceeds funding_msat")]
    PushExceedsFunding,
}

/// Identifies the channel participant relative to the funding flow.
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
    // TODO: When adding HTLC support, store pending HTLCs (offered/received) for both sides
    // to correctly compute balances and construct HTLC outputs in the commitment transaction.
}

/// Costs associated with a commitment transaction, including transaction fee
/// and anchor outputs.
pub struct CommitmentCost {
    /// Commitment transaction fee in satoshis.
    pub fee_sat: u64,
    /// Total cost of anchor outputs in satoshis.
    pub anchor_cost_sat: u64,
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
    fn other(&self) -> &Self {
        match self {
            Self::Opener => &Self::Acceptor,
            Self::Acceptor => &Self::Opener,
        }
    }
}

impl HolderIdentity {
    /// Returns the counterparty side.
    #[must_use]
    fn counterparty_side(&self) -> &Side {
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
    fn party(&self, side: &Side) -> &ChannelPartyConfig {
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
        })
    }

    /// Builds the signature for the counterparty's commitment transaction.
    #[must_use]
    pub fn sign_counterparty_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> Signature {
        let sighash = self.build_commitment_sighash(state, holder.counterparty_side());
        sign(&sighash, &holder.funding_privkey)
    }

    /// Verifies a signature received from the counterparty for the holder's
    /// commitment transaction. Returns `true` if the signature is valid.
    #[must_use]
    pub fn verify_counterparty_signature(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
        signature: &Signature,
    ) -> bool {
        let sighash = self.build_commitment_sighash(state, &holder.side);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash);
        let counterparty = self.party(holder.counterparty_side());

        secp.verify_ecdsa(&msg, signature, &counterparty.funding_pubkey)
            .is_ok()
    }

    /// Builds the signature for the holder's commitment transaction.
    /// Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn sign_holder_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> Signature {
        let sighash = self.build_commitment_sighash(state, &holder.side);
        sign(&sighash, &holder.funding_privkey)
    }

    /// Builds the sighash for the commitment transaction. The commitment
    /// format (legacy or anchor) is determined by the `channel_type`.
    ///
    /// `local_side` selects whose commitment is built: the opener's or
    /// the acceptor's.
    fn build_commitment_sighash(&self, state: &CommitmentState, local_side: &Side) -> [u8; 32] {
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
        let outputs = self.build_commitment_outputs(state, local_side);

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

        // Funding output witness script.
        let funding_witness_script = build_funding_witness_script(
            &self.opener.funding_pubkey,
            &self.acceptor.funding_pubkey,
        );

        // Compute the BIP143 sighash
        let sighash = SighashCache::new(&tx)
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
    /// `local_side` selects whose commitment outputs are built: the
    /// opener's or the acceptor's.
    fn build_commitment_outputs(&self, state: &CommitmentState, local_side: &Side) -> Vec<TxOut> {
        let anchor = self.channel_type.supports_feature(Features::OPTION_ANCHORS);

        // Fee and balances.
        let commitment_cost = CommitmentCost::new(state.feerate_per_kw, &self.channel_type);
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
        let local_per_commitment_point = state.party(local_side).per_commitment_point;

        let mut outputs: Vec<TxOut> = Vec::new();

        if to_local_value >= local.dust_limit_satoshis {
            let local_delayedpubkey = derive_pubkey(
                &local.delayed_payment_basepoint,
                &local_per_commitment_point,
            );
            let revocationpubkey =
                derive_revocation_pubkey(&remote.revocation_basepoint, &local_per_commitment_point);

            let to_local_spk = build_to_local_scriptpubkey(
                &local_delayedpubkey,
                &revocationpubkey,
                remote.to_self_delay,
            );

            outputs.push(TxOut {
                value: Amount::from_sat(to_local_value),
                script_pubkey: to_local_spk,
            });

            if anchor {
                outputs.push(TxOut {
                    value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                    script_pubkey: build_anchor_scriptpubkey(&local.funding_pubkey),
                });
            }
        }
        if to_remote_value >= local.dust_limit_satoshis {
            let to_remote_spk = build_to_remote_scriptpubkey(&remote.payment_basepoint, anchor);

            outputs.push(TxOut {
                value: Amount::from_sat(to_remote_value),
                script_pubkey: to_remote_spk,
            });

            if anchor {
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
}

impl CommitmentState {
    /// Returns the parameters for the given commitment side.
    fn party(&self, side: &Side) -> &CommitmentPartyState {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    // TODO: When adding HTLC support, add `get_next_commitment_state` to build the next
    // commitment state based on the previous state and the HTLCs claimed by both sides.
}

impl CommitmentCost {
    /// Calculates the total cost of a commitment transaction.
    #[must_use]
    pub fn new(feerate_per_kw: u32, channel_type: &Features) -> CommitmentCost {
        CommitmentCost {
            fee_sat: commit_tx_fee_sat(feerate_per_kw, channel_type),
            anchor_cost_sat: total_anchors_sat(channel_type),
        }
    }

    /// Returns the total cost (fee + anchor outputs) in satoshis.
    #[must_use]
    pub fn total_sat(&self) -> u64 {
        self.fee_sat + self.anchor_cost_sat
    }
}

/// Get the fee cost of a commitment tx in satoshis.
fn commit_tx_fee_sat(feerate_per_kw: u32, channel_type: &Features) -> u64 {
    let commitment_weight = if channel_type.supports_feature(Features::OPTION_ANCHORS) {
        COMMITMENT_TX_BASE_WEIGHT_ANCHOR
    } else {
        COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR
    };

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

/// Builds the `to_local` P2WSH `script_pubkey` per BOLT 3.
fn build_to_local_scriptpubkey(
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

/// Signs a commitment sighash with the given funding private key.
fn sign(sighash: &[u8; 32], funding_privkey: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa(&msg, funding_privkey)
}

#[cfg(test)]
mod tests;
