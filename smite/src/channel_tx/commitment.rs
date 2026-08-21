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
            channel_type: Features::from(channel_type),
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
        };

        let opener_holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret(OPENER_FUNDING_PRIVKEY),
        };

        let acceptor_holder = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
        };

        (chan_config, state, opener_holder, acceptor_holder)
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
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
            channel_type: Features::from(channel_type),
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
        let legacy = Features::new();
        let anchor = Features::from_bits(&[Features::OPTION_ANCHORS]);
        // Legacy fee: 15000 * 724 / 1000 = 10_860 sat
        // Anchor fee: 15000 * 1124 / 1000 = 16_860 sat; anchor_cost = 660 sat

        // Comfortably affordable
        let opener_balance_sat: u64 = 20_000;
        assert_eq!(
            opener_balance_sat
                .checked_sub(CommitmentCost::new(feerate_per_kw, &legacy).total_sat()),
            Some(9_140),
        );

        // Exact zero opener balance
        let opener_balance_sat: u64 = 10_860;
        assert_eq!(
            opener_balance_sat
                .checked_sub(CommitmentCost::new(feerate_per_kw, &legacy).total_sat()),
            Some(0),
        );

        // Balance does not cover the fee
        let opener_balance_sat: u64 = 10_000;
        assert_eq!(
            opener_balance_sat
                .checked_sub(CommitmentCost::new(feerate_per_kw, &legacy).total_sat()),
            None
        );

        // Balance covers the fee but not the anchor outputs
        let opener_balance_sat: u64 = 17_500;
        assert_eq!(
            opener_balance_sat
                .checked_sub(CommitmentCost::new(feerate_per_kw, &anchor).total_sat()),
            None,
        );
    }
}
