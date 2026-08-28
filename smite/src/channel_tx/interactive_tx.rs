//! BOLT 2 interactive transaction construction.
//!
//! Two peers collaboratively build one transaction by exchanging `tx_add_input`
//! / `tx_add_output` / `tx_remove_input` / `tx_remove_output` messages, each
//! carrying a `serial_id`. [`SharedTransaction`] accumulates those
//! contributions and assembles the transaction both peers must agree on.

use std::collections::BTreeMap;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use bitcoin::{Witness, secp256k1::PublicKey};

use super::funding::FundingTransaction;

/// Maximum inputs in the constructed transaction (BOLT 2). The cap keeps the
/// input count to a single `CompactSize` byte.
pub const MAX_INPUTS: usize = 252;

/// Weight of the transaction fields the initiator alone pays for (BOLT 2):
/// `(input_count + output_count + version + locktime) * 4 + segwit marker and
/// flag`.
const COMMON_FIELDS_WEIGHT: u64 = (1 + 1 + 4 + 4) * 4 + 2;

/// Weight of one input's non-witness fields: `txid + vout + scriptSig length +
/// sequence`, all outside the witness and so multiplied by four.
const INPUT_WEIGHT: u64 = (32 + 4 + 1 + 4) * 4;

/// Weight of one output's fixed fields: `value + script length`.
const OUTPUT_BASE_WEIGHT: u64 = (8 + 1) * 4;

/// Witness weight charged per input we contribute.
///
/// BOLT 3 Appendix G charges `max(num_inputs * 107, actual witness weight)`,
/// where 107 is the minimum witness weight. Our wallet inputs are P2WPKH,
/// whose witness is `1` element count `+ 1 + 72` signature `+ 1 + 33` pubkey =
/// 108 weight units, so the maximum is always the actual weight. Using it
/// directly keeps the estimate on the paying side of the requirement: the peer
/// fails the negotiation when our feerate falls short, never when it exceeds.
const WITNESS_WEIGHT_PER_INPUT: u64 = 108;

/// Maximum outputs in the constructed transaction (BOLT 2).
pub const MAX_OUTPUTS: usize = 252;

/// Largest `sequence` a `tx_add_input` may carry (BOLT 2): every input must
/// signal replaceability.
pub const MAX_SEQUENCE: u32 = 0xffff_fffd;

/// Which peer contributed an input or output to the shared transaction.
///
/// Only [`Contributor::Local`] contributions are ours to sign and to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contributor {
    /// We contributed it.
    Local,
    /// The peer contributed it.
    Remote,
}

/// An input contributed to the shared transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedInput {
    /// The outpoint being spent.
    pub outpoint: OutPoint,
    /// `nSequence` for this input.
    pub sequence: u32,
    /// Which peer contributed it.
    pub contributor: Contributor,
    /// The output being spent, when known. Always known for our own inputs;
    /// known for the peer's only when its `prevtx` parsed and `prevtx_vout` was
    /// within range.
    pub prevout: Option<TxOut>,
}

impl SharedInput {
    /// Builds an input from a `tx_add_input`'s serialized previous transaction.
    ///
    /// A `prevtx` that does not parse, or a `prevtx_vout` past the end of it,
    /// yields an all-zero txid and an unknown `prevout` rather than an error:
    /// the peer is free to send nonsense, and it is the peer that must then
    /// fail the negotiation.
    #[must_use]
    pub fn from_prevtx(
        prevtx: &[u8],
        prevtx_vout: u32,
        sequence: u32,
        contributor: Contributor,
    ) -> Self {
        let prev: Option<Transaction> = deserialize(prevtx).ok();
        let prevout = prev
            .as_ref()
            .and_then(|tx| tx.output.get(prevtx_vout as usize))
            .cloned();
        let txid = prev.as_ref().map_or_else(
            || Txid::from_byte_array([0u8; 32]),
            Transaction::compute_txid,
        );

        Self {
            outpoint: OutPoint {
                txid,
                vout: prevtx_vout,
            },
            sequence,
            contributor,
            prevout,
        }
    }

    /// Value of the output being spent, or `0` when it is unknown.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.prevout.as_ref().map_or(0, |o| o.value.to_sat())
    }
}

/// An output contributed to the shared transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedOutput {
    /// Output value in satoshis.
    pub value: u64,
    /// Output `scriptPubKey`.
    pub script_pubkey: ScriptBuf,
    /// Which peer contributed it.
    pub contributor: Contributor,
}

/// The transaction being built by an interactive construction session.
///
/// Contributions are keyed by `serial_id`, so iteration is already in the
/// ascending order BOLT 2 requires for the assembled transaction. A repeated
/// `serial_id` replaces the previous entry, mirroring what a peer that failed
/// to enforce uniqueness would end up with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedTransaction {
    /// `nLockTime` of the transaction, from `open_channel2`.
    pub locktime: u32,
    inputs: BTreeMap<u64, SharedInput>,
    outputs: BTreeMap<u64, SharedOutput>,
}

impl SharedTransaction {
    /// Creates an empty session for a transaction with the given `nLockTime`.
    #[must_use]
    pub fn new(locktime: u32) -> Self {
        Self {
            locktime,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }
    }

    /// Adds or replaces the input with `serial_id`.
    ///
    /// Returns `false` when the transaction already holds [`MAX_INPUTS`]
    /// distinct serial ids and the input was dropped.
    pub fn add_input(&mut self, serial_id: u64, input: SharedInput) -> bool {
        if !self.inputs.contains_key(&serial_id) && self.inputs.len() >= MAX_INPUTS {
            return false;
        }
        self.inputs.insert(serial_id, input);
        true
    }

    /// Adds or replaces the output with `serial_id`.
    ///
    /// Returns `false` when the transaction already holds [`MAX_OUTPUTS`]
    /// distinct serial ids and the output was dropped.
    pub fn add_output(&mut self, serial_id: u64, output: SharedOutput) -> bool {
        if !self.outputs.contains_key(&serial_id) && self.outputs.len() >= MAX_OUTPUTS {
            return false;
        }
        self.outputs.insert(serial_id, output);
        true
    }

    /// Removes the input with `serial_id`, returning it when it was present.
    pub fn remove_input(&mut self, serial_id: u64) -> Option<SharedInput> {
        self.inputs.remove(&serial_id)
    }

    /// Removes the output with `serial_id`, returning it when it was present.
    pub fn remove_output(&mut self, serial_id: u64) -> Option<SharedOutput> {
        self.outputs.remove(&serial_id)
    }

    /// Inputs in ascending `serial_id` order.
    pub fn inputs(&self) -> impl Iterator<Item = (u64, &SharedInput)> {
        self.inputs.iter().map(|(id, input)| (*id, input))
    }

    /// Outputs in ascending `serial_id` order.
    pub fn outputs(&self) -> impl Iterator<Item = (u64, &SharedOutput)> {
        self.outputs.iter().map(|(id, output)| (*id, output))
    }

    /// Total value of the inputs contributed by `contributor`, saturating.
    ///
    /// Inputs whose `prevout` is unknown count as zero.
    #[must_use]
    pub fn contributed_input_value(&self, contributor: Contributor) -> u64 {
        self.inputs
            .values()
            .filter(|i| i.contributor == contributor)
            .fold(0u64, |acc, i| acc.saturating_add(i.value()))
    }

    /// Fee we are responsible for at `feerate_per_kw`, in satoshis.
    ///
    /// BOLT 2 splits fee responsibility: the initiator pays for the common
    /// transaction fields, and each peer pays for the inputs and outputs it
    /// contributed. `pending_output_script_lens` covers outputs we are about to
    /// add but have not added yet, which is what makes a change output's value
    /// computable before it exists.
    ///
    /// Rounds up. BOLT 3 Appendix G's worked example has weight 609 at 253
    /// sat/kw and states a fee of 155, not the 154 that truncating would give;
    /// underpaying by a single satoshi makes the peer fail the negotiation.
    #[must_use]
    pub fn local_fee_sat(&self, feerate_per_kw: u32, pending_output_script_lens: &[usize]) -> u64 {
        let local_inputs = self
            .inputs
            .values()
            .filter(|i| i.contributor == Contributor::Local)
            .count() as u64;

        let output_weight = self
            .outputs
            .values()
            .filter(|o| o.contributor == Contributor::Local)
            .map(|o| o.script_pubkey.len() as u64)
            .chain(pending_output_script_lens.iter().map(|len| *len as u64))
            .map(|script_len| OUTPUT_BASE_WEIGHT + script_len * 4)
            .sum::<u64>();

        let weight = COMMON_FIELDS_WEIGHT
            + local_inputs * INPUT_WEIGHT
            + output_weight
            + local_inputs * WITNESS_WEIGHT_PER_INPUT;

        weight
            .saturating_mul(u64::from(feerate_per_kw))
            .div_ceil(1000)
    }

    /// Assembles the transaction both peers must agree on.
    ///
    /// Per BOLT 2 the inputs and outputs are sorted by ascending `serial_id`;
    /// `nVersion` is 2 and `nLockTime` comes from `open_channel2`. Witnesses are
    /// left empty, so the txid is final: it does not change once
    /// `tx_signatures` are applied.
    #[must_use]
    pub fn build(&self) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(self.locktime),
            input: self
                .inputs
                .values()
                .map(|i| TxIn {
                    previous_output: i.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(i.sequence),
                    witness: Witness::new(),
                })
                .collect(),
            output: self
                .outputs
                .values()
                .map(|o| TxOut {
                    value: Amount::from_sat(o.value),
                    script_pubkey: o.script_pubkey.clone(),
                })
                .collect(),
        }
    }

    /// Index of the channel funding output, identified by its script and value.
    ///
    /// Returns `None` when no output matches, which happens when a mutated
    /// program never added the funding output or gave it the wrong value.
    #[must_use]
    pub fn funding_vout(&self, funding_script: &Script, funding_satoshis: u64) -> Option<u32> {
        let index = self
            .outputs
            .values()
            .position(|o| o.script_pubkey == *funding_script && o.value == funding_satoshis)?;
        u32::try_from(index).ok()
    }

    /// Assembles the transaction and locates its funding output.
    ///
    /// When no output matches the funding script and value, `vout` falls back
    /// to `0`. That keeps the result well-typed, and
    /// [`FundingTransaction::matches_funding_output`] then correctly reports the
    /// channel as invalid rather than the caller having to special-case it.
    #[must_use]
    pub fn build_funding(
        &self,
        funding_script: &Script,
        funding_satoshis: u64,
    ) -> FundingTransaction {
        FundingTransaction {
            tx: self.build(),
            vout: self
                .funding_vout(funding_script, funding_satoshis)
                .unwrap_or(0),
        }
    }
}

/// Returns whether we must send `tx_signatures` first.
///
/// Per BOLT 2 the peer contributing the lowest total input value signs first,
/// with the lexicographically lower `node_id` breaking a tie. The strict
/// ordering is what stops both peers waiting on each other.
#[must_use]
pub fn signs_first(
    local_input_value: u64,
    remote_input_value: u64,
    local_node_id: &PublicKey,
    remote_node_id: &PublicKey,
) -> bool {
    match local_input_value.cmp(&remote_input_value) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => local_node_id.serialize() < remote_node_id.serialize(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The transaction whose outputs both peers spend in the BOLT 3
    /// "Appendix G: Dual Funded Transaction Test Vectors".
    const APPENDIX_G_PREVTX: &str = "02000000000101f86fd1d0db3ac5a72df968622f31e6b5e6566a09e2920\
6d7c7a55df90e181de800000000171600141fb9623ffd0d422eacc450fd1e967efc477b83ccffffffff0580b2e60e0000\
0000220020fd89acf65485df89797d9ba7ba7a33624ac4452f00db08107f34257d33e5b94680b2e60e0000000017a9146\
a235d064786b49e7043e4a042d4cc429f7eb6948780b2e60e00000000160014fbb4db9d85fba5e301f4399e3038928e44\
e37d3280b2e60e0000000017a9147ecd1b519326bc13b0ec716e469b58ed02b112a087f0006bee0000000017a914f856a\
70093da3a5b5c4302ade033d4c2171705d387024730440220696f6cee2929f1feb3fd6adf024ca0f9aa2f4920ed6d35fb\
9ec5b78c8408475302201641afae11242160101c6f9932aeb4fcd1f13a9c6df5d1386def000ea259a35001210381d7d5b\
1bc0d7600565d827242576d9cb793bfe0754334af82289ee8b65d137600000000";

    /// The `Unsigned Funding Transaction` of BOLT 3 Appendix G.
    const APPENDIX_G_UNSIGNED_TX: &str = "0200000002b932b0669cd0394d0d5bcc27e01ab8c511f1662a679992\
5b346c0cf18fca03430200000000fdffffffb932b0669cd0394d0d5bcc27e01ab8c511f1662a6799925b346c0cf18fca0\
3430000000000fdffffff03e5effa02000000001600141ca1cca8855bad6bc1ea5436edd8cff10b7e448b1cf0fa020000\
000016001444cb0c39f93ecc372b5851725bd29d865d333b100084d71700000000220020297b92c238163e820b8248608\
4634b4846b86a3c658d87b9384192e6bea98ec578000000";

    /// The 2-of-2 funding `scriptPubKey` of Appendix G.
    const APPENDIX_G_FUNDING_SPK: &str =
        "0020297b92c238163e820b82486084634b4846b86a3c658d87b9384192e6bea98ec5";
    /// Appendix G's opener change `scriptPubKey`.
    const APPENDIX_G_OPENER_CHANGE_SPK: &str = "00141ca1cca8855bad6bc1ea5436edd8cff10b7e448b";
    /// Appendix G's accepter change `scriptPubKey`.
    const APPENDIX_G_ACCEPTER_CHANGE_SPK: &str = "001444cb0c39f93ecc372b5851725bd29d865d333b10";

    /// Appendix G's `nLockTime`.
    const APPENDIX_G_LOCKTIME: u32 = 120;
    /// Appendix G's funding output value: 2 x 2,000,000,000 sat.
    const APPENDIX_G_FUNDING_SATS: u64 = 400_000_000;

    fn script(hex_str: &str) -> ScriptBuf {
        ScriptBuf::from(hex::decode(hex_str).expect("valid hex"))
    }

    fn pubkey(hex_str: &str) -> PublicKey {
        PublicKey::from_slice(&hex::decode(hex_str).expect("valid hex")).expect("valid pubkey")
    }

    /// Rebuilds Appendix G's funding transaction from the `tx_add_input` and
    /// `tx_add_output` messages the appendix says each peer sends. Note that
    /// the contributions are added out of serial order on purpose.
    fn appendix_g() -> SharedTransaction {
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");
        let mut shared = SharedTransaction::new(APPENDIX_G_LOCKTIME);

        // Opener's input, serial_id 20, spending the parent's output 0.
        assert!(shared.add_input(
            20,
            SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Local),
        ));
        // Accepter's input, serial_id 11, spending the parent's output 2.
        assert!(shared.add_input(
            11,
            SharedInput::from_prevtx(&prevtx, 2, MAX_SEQUENCE, Contributor::Remote),
        ));

        // Opener's change, serial_id 30.
        assert!(shared.add_output(
            30,
            SharedOutput {
                value: 49_999_845,
                script_pubkey: script(APPENDIX_G_OPENER_CHANGE_SPK),
                contributor: Contributor::Local,
            },
        ));
        // Opener's funding output, serial_id 44.
        assert!(shared.add_output(
            44,
            SharedOutput {
                value: APPENDIX_G_FUNDING_SATS,
                script_pubkey: script(APPENDIX_G_FUNDING_SPK),
                contributor: Contributor::Local,
            },
        ));
        // Accepter's change, serial_id 33.
        assert!(shared.add_output(
            33,
            SharedOutput {
                value: 49_999_900,
                script_pubkey: script(APPENDIX_G_ACCEPTER_CHANGE_SPK),
                contributor: Contributor::Remote,
            },
        ));

        shared
    }

    #[test]
    fn build_matches_bolt3_appendix_g() {
        let tx = appendix_g().build();

        assert_eq!(
            bitcoin::consensus::encode::serialize_hex(&tx),
            APPENDIX_G_UNSIGNED_TX,
        );
    }

    #[test]
    fn build_sorts_by_serial_id_not_insertion_order() {
        let tx = appendix_g().build();

        // Inputs: serial 11 (parent vout 2) before serial 20 (parent vout 0),
        // even though serial 20 was added first.
        assert_eq!(
            tx.input
                .iter()
                .map(|i| i.previous_output.vout)
                .collect::<Vec<_>>(),
            vec![2, 0],
        );
        // Outputs: serials 30, 33, 44, even though 44 was added before 33.
        assert_eq!(
            tx.output
                .iter()
                .map(|o| o.value.to_sat())
                .collect::<Vec<_>>(),
            vec![49_999_845, 49_999_900, APPENDIX_G_FUNDING_SATS],
        );
    }

    #[test]
    fn build_uses_version_two_and_negotiated_locktime() {
        let tx = appendix_g().build();

        assert_eq!(tx.version, Version::TWO);
        assert_eq!(tx.lock_time, LockTime::from_consensus(APPENDIX_G_LOCKTIME));
        assert!(
            tx.input
                .iter()
                .all(|i| i.sequence == Sequence(MAX_SEQUENCE))
        );
    }

    #[test]
    fn funding_vout_locates_the_two_of_two_output() {
        let shared = appendix_g();

        assert_eq!(
            shared.funding_vout(&script(APPENDIX_G_FUNDING_SPK), APPENDIX_G_FUNDING_SATS),
            Some(2),
        );
        assert_eq!(
            shared
                .build_funding(&script(APPENDIX_G_FUNDING_SPK), APPENDIX_G_FUNDING_SATS)
                .vout,
            2,
        );
    }

    #[test]
    fn funding_vout_rejects_a_wrong_value_or_script() {
        let shared = appendix_g();

        assert_eq!(
            shared.funding_vout(&script(APPENDIX_G_FUNDING_SPK), APPENDIX_G_FUNDING_SATS - 1),
            None,
        );
        assert_eq!(
            shared.funding_vout(
                &script(APPENDIX_G_OPENER_CHANGE_SPK),
                APPENDIX_G_FUNDING_SATS
            ),
            None,
        );
    }

    #[test]
    fn build_funding_falls_back_to_vout_zero_without_a_funding_output() {
        let mut shared = appendix_g();
        shared.remove_output(44);

        let funding =
            shared.build_funding(&script(APPENDIX_G_FUNDING_SPK), APPENDIX_G_FUNDING_SATS);

        assert_eq!(funding.vout, 0);
    }

    #[test]
    fn contributed_input_value_splits_by_contributor() {
        let shared = appendix_g();

        // Each peer spends one 2.5 BTC output of the parent transaction.
        assert_eq!(
            shared.contributed_input_value(Contributor::Local),
            250_000_000
        );
        assert_eq!(
            shared.contributed_input_value(Contributor::Remote),
            250_000_000
        );
    }

    #[test]
    fn from_prevtx_with_unparsable_prevtx_is_not_an_error() {
        let input = SharedInput::from_prevtx(&[0xde, 0xad], 0, MAX_SEQUENCE, Contributor::Remote);

        assert_eq!(input.outpoint.txid, Txid::from_byte_array([0u8; 32]));
        assert_eq!(input.prevout, None);
        assert_eq!(input.value(), 0);
    }

    #[test]
    fn from_prevtx_with_out_of_range_vout_has_no_prevout() {
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");

        let input = SharedInput::from_prevtx(&prevtx, 99, MAX_SEQUENCE, Contributor::Remote);

        // The txid is still known, so the outpoint is well-formed and the peer
        // is the one that must fail the negotiation.
        assert_ne!(input.outpoint.txid, Txid::from_byte_array([0u8; 32]));
        assert_eq!(input.outpoint.vout, 99);
        assert_eq!(input.prevout, None);
        assert_eq!(input.value(), 0);
    }

    #[test]
    fn add_replaces_a_duplicate_serial_id() {
        let mut shared = appendix_g();
        let outputs_before = shared.outputs().count();

        assert!(shared.add_output(
            30,
            SharedOutput {
                value: 1,
                script_pubkey: script(APPENDIX_G_ACCEPTER_CHANGE_SPK),
                contributor: Contributor::Remote,
            },
        ));

        assert_eq!(shared.outputs().count(), outputs_before);
        assert_eq!(shared.build().output[0].value.to_sat(), 1);
    }

    #[test]
    fn add_input_stops_at_the_maximum() {
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");
        let mut shared = SharedTransaction::new(0);
        for serial_id in 0..MAX_INPUTS as u64 {
            assert!(shared.add_input(
                serial_id,
                SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Remote),
            ));
        }

        // A new serial id is dropped, but replacing an existing one still works.
        assert!(!shared.add_input(
            MAX_INPUTS as u64,
            SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Remote),
        ));
        assert!(shared.add_input(
            0,
            SharedInput::from_prevtx(&prevtx, 1, MAX_SEQUENCE, Contributor::Remote),
        ));
        assert_eq!(shared.inputs().count(), MAX_INPUTS);
    }

    #[test]
    fn add_output_stops_at_the_maximum() {
        let mut shared = SharedTransaction::new(0);
        let output = SharedOutput {
            value: 1000,
            script_pubkey: script(APPENDIX_G_ACCEPTER_CHANGE_SPK),
            contributor: Contributor::Remote,
        };
        for serial_id in 0..MAX_OUTPUTS as u64 {
            assert!(shared.add_output(serial_id, output.clone()));
        }

        assert!(!shared.add_output(MAX_OUTPUTS as u64, output.clone()));
        assert!(shared.add_output(0, output));
        assert_eq!(shared.outputs().count(), MAX_OUTPUTS);
    }

    #[test]
    fn remove_reports_whether_the_serial_id_was_present() {
        let mut shared = appendix_g();

        assert!(shared.remove_input(20).is_some());
        assert!(shared.remove_input(20).is_none());
        assert!(shared.remove_output(44).is_some());
        assert!(shared.remove_output(9999).is_none());
    }

    // -- Fee responsibility --

    #[test]
    fn local_fee_matches_bolt3_appendix_g_opener() {
        // Appendix G's opener contributes one input, the funding output and a
        // change output, at 253 sat/kw, and owes 155 sat.
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");
        let mut shared = SharedTransaction::new(APPENDIX_G_LOCKTIME);
        shared.add_input(
            20,
            SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Local),
        );
        shared.add_output(
            44,
            SharedOutput {
                value: APPENDIX_G_FUNDING_SATS,
                script_pubkey: script(APPENDIX_G_FUNDING_SPK),
                contributor: Contributor::Local,
            },
        );

        // The change output is not added yet; its script length is what makes
        // its own value computable.
        let change_script = script(APPENDIX_G_OPENER_CHANGE_SPK);
        assert_eq!(shared.local_fee_sat(253, &[change_script.len()]), 155);
    }

    #[test]
    fn local_fee_rounds_up() {
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");
        let mut shared = SharedTransaction::new(0);
        shared.add_input(
            0,
            SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Local),
        );

        // Weight 42 + 164 + 108 = 314. At 1 sat/kw that is 0.314 sat, which
        // must round up to 1 rather than down to 0.
        assert_eq!(shared.local_fee_sat(1, &[]), 1);
        // And 314 * 1000 / 1000 divides exactly.
        assert_eq!(shared.local_fee_sat(1000, &[]), 314);
    }

    #[test]
    fn local_fee_ignores_the_peers_contributions() {
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");
        let mut shared = SharedTransaction::new(0);
        shared.add_input(
            0,
            SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Local),
        );
        let ours = shared.local_fee_sat(253, &[]);

        // Each peer pays for what it contributed, so adding theirs must not
        // change what we owe.
        shared.add_input(
            1,
            SharedInput::from_prevtx(&prevtx, 1, MAX_SEQUENCE, Contributor::Remote),
        );
        shared.add_output(
            3,
            SharedOutput {
                value: 10_000,
                script_pubkey: script(APPENDIX_G_ACCEPTER_CHANGE_SPK),
                contributor: Contributor::Remote,
            },
        );

        assert_eq!(shared.local_fee_sat(253, &[]), ours);
    }

    #[test]
    fn local_fee_covers_the_common_fields_with_no_contributions() {
        // The initiator pays for version, locktime and the two counts even
        // when it contributes nothing else: weight 42 at 1000 sat/kw.
        assert_eq!(SharedTransaction::new(0).local_fee_sat(1000, &[]), 42);
    }

    #[test]
    fn local_fee_grows_with_each_input_and_output() {
        let prevtx = hex::decode(APPENDIX_G_PREVTX).expect("valid hex");
        let mut shared = SharedTransaction::new(0);
        let base = shared.local_fee_sat(1000, &[]);

        shared.add_input(
            0,
            SharedInput::from_prevtx(&prevtx, 0, MAX_SEQUENCE, Contributor::Local),
        );
        let with_input = shared.local_fee_sat(1000, &[]);
        assert_eq!(with_input - base, INPUT_WEIGHT + WITNESS_WEIGHT_PER_INPUT);

        let change_script = script(APPENDIX_G_OPENER_CHANGE_SPK);
        let with_output = shared.local_fee_sat(1000, &[change_script.len()]);
        assert_eq!(
            with_output - with_input,
            OUTPUT_BASE_WEIGHT + change_script.len() as u64 * 4,
        );
    }

    // -- tx_signatures ordering --

    /// Two valid compressed points, ordered so that `LOW` sorts first.
    const NODE_ID_LOW: &str = "0292edb5f7bbf9e900f7e024be1c1339c6d149c11930e613af3a983d2565f4e41e";
    const NODE_ID_HIGH: &str = "02e16172a41e928cbd78f761bd1c657c4afc7495a1244f7f30166b654fbf7661e3";

    #[test]
    fn signs_first_follows_the_lowest_contribution() {
        let low = pubkey(NODE_ID_LOW);
        let high = pubkey(NODE_ID_HIGH);

        // We contributed less, so we sign first regardless of node id.
        assert!(signs_first(1, 2, &high, &low));
        // We contributed more, so the peer signs first.
        assert!(!signs_first(2, 1, &low, &high));
    }

    #[test]
    fn signs_first_breaks_an_equal_contribution_by_node_id() {
        let low = pubkey(NODE_ID_LOW);
        let high = pubkey(NODE_ID_HIGH);

        assert!(signs_first(5, 5, &low, &high));
        assert!(!signs_first(5, 5, &high, &low));
    }

    #[test]
    fn signs_first_when_the_peer_contributes_nothing_is_the_peer() {
        let low = pubkey(NODE_ID_LOW);
        let high = pubkey(NODE_ID_HIGH);

        // The opener-funds-everything case: the peer's total is 0, so the peer
        // signs first and we must receive tx_signatures before sending ours.
        assert!(!signs_first(250_000_000, 0, &low, &high));
    }
}
