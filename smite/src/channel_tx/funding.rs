//! BOLT 3 funding transaction construction.

use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::PublicKey;
use bitcoin::transaction::{InputWeightPrediction, Version, predict_weight};
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use super::taproot;
use crate::bitcoin::Utxo;
use crate::bolt::Features;
use crate::musig::{FundingKeys, MusigError};

/// Error returned when available UTXOs cannot cover the funding amount plus
/// estimated miner fee.
#[derive(Debug, thiserror::Error)]
#[error(
    "insufficient funds to cover funding amount and fee: required {required}, available {available}"
)]
pub struct InsufficientFunds {
    /// Total amount required, including fees.
    pub required: Amount,
    /// Total spendable amount available from the selected UTXOs.
    pub available: Amount,
}

/// Errors that can occur while building a funding transaction.
#[derive(Debug, thiserror::Error)]
pub enum FundingError {
    /// The selected UTXOs cannot cover the funding amount and fees.
    #[error(transparent)]
    InsufficientFunds(#[from] InsufficientFunds),

    /// The taproot funding key could not be derived from the two
    /// `funding_pubkey`s.
    #[error("taproot funding output: {0}")]
    Musig(#[from] MusigError),
}

/// A constructed funding transaction along with the index of the 2-of-2
/// funding output within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingTransaction {
    /// The Bitcoin transaction containing the funding output.
    pub tx: Transaction,
    /// Index of the funding output.
    pub vout: u32,
}

/// Builds a funding transaction paying to the channel's funding output.
///
/// The output is a 2-of-2 P2WSH, or a single-key P2TR when `channel_type`
/// negotiates `option_simple_taproot`.
///
/// Coins are selected for spending in the order the `utxos` are provided.
///
/// # Errors
///
/// Returns [`FundingError::InsufficientFunds`] if the provided inputs do not
/// contain enough value to cover `funding_satoshis` and the required
/// transaction fees, or [`FundingError::Musig`] if a taproot funding key
/// cannot be derived from the two `funding_pubkey`s.
///
/// # Panics
///
/// Panics if an input has an unsupported script pubkey type, since fee
/// estimation currently only supports P2PKH and P2WPKH inputs.
pub fn build_funding_transaction(
    opener_funding_pubkey: &PublicKey,
    acceptor_funding_pubkey: &PublicKey,
    funding_satoshis: u64,
    feerate_per_kw: u32,
    channel_type: &Features,
    utxos: Vec<Utxo>,
    change_spk: ScriptBuf,
) -> Result<FundingTransaction, FundingError> {
    // Amounts exceeding Bitcoin's maximum supply can never be funded. The
    // error's `available` field reports Bitcoin's total supply cap.
    let funding_amt = Amount::from_sat(funding_satoshis);
    if funding_amt > Amount::MAX_MONEY {
        return Err(InsufficientFunds {
            required: funding_amt,
            available: Amount::MAX_MONEY,
        }
        .into());
    }

    // Return early if no UTXOs are available, since the funding transaction
    // cannot be funded.
    if utxos.is_empty() {
        return Err(InsufficientFunds {
            required: funding_amt,
            available: Amount::ZERO,
        }
        .into());
    }

    let funding_spk =
        build_funding_scriptpubkey(opener_funding_pubkey, acceptor_funding_pubkey, channel_type)?;

    let mut inputs = Vec::new();
    let mut input_weights = Vec::new();
    let mut outputs = vec![TxOut {
        value: funding_amt,
        script_pubkey: funding_spk.clone(),
    }];
    let mut total = Amount::ZERO;
    let mut expected_fee_no_change =
        predict_tx_fee(feerate_per_kw, &input_weights, &[funding_spk.len()]);

    for utxo in utxos {
        total += utxo.amount;

        inputs.push(TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });

        // By default, the address bitcoind generates coins to is always a P2WPKH
        // address, but to support the BOLT 3 test vectors, we also include P2PKH.
        let input_weight = if utxo.script_pubkey.is_p2pkh() {
            InputWeightPrediction::P2PKH_COMPRESSED_MAX
        } else {
            // Assert this so fee estimation breaks loudly if the default ever changes.
            assert!(
                utxo.script_pubkey.is_p2wpkh(),
                "unsupported input script pubkey; fee estimation only handles P2PKH and P2WPKH"
            );
            InputWeightPrediction::P2WPKH_MAX
        };
        input_weights.push(input_weight);

        // Check whether the selected inputs can cover the funding amount and fees.
        expected_fee_no_change =
            predict_tx_fee(feerate_per_kw, &input_weights, &[funding_spk.len()]);
        if total >= funding_amt + expected_fee_no_change {
            break;
        }
    }

    // Verify that the selected inputs can cover the funding amount and fees.
    if total < funding_amt + expected_fee_no_change {
        return Err(InsufficientFunds {
            required: funding_amt + expected_fee_no_change,
            available: total,
        }
        .into());
    }

    // Add remaining funds after accounting for fees as a change output,
    // unless the resulting change would be dust.
    let expected_fee_with_change = predict_tx_fee(
        feerate_per_kw,
        &input_weights,
        &[funding_spk.len(), change_spk.len()],
    );
    let dust = change_spk.minimal_non_dust();
    if let Some(change) = total
        .checked_sub(funding_amt + expected_fee_with_change)
        .filter(|c| *c >= dust)
    {
        outputs.push(TxOut {
            value: change,
            script_pubkey: change_spk,
        });
    }

    Ok(FundingTransaction {
        tx: Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        },
        vout: 0,
    })
}

/// Returns the predicted fee cost of a transaction.
fn predict_tx_fee(
    feerate_per_kw: u32,
    input_weights: &[InputWeightPrediction],
    output_scriptlens: &[usize],
) -> Amount {
    let weight = predict_weight(
        input_weights.iter().copied(),
        output_scriptlens.iter().copied(),
    );
    Amount::from_sat((u64::from(feerate_per_kw) * weight.to_wu()) / 1000)
}

impl FundingTransaction {
    /// Returns whether the referenced funding output matches the negotiated
    /// output script and amount.
    ///
    /// A mismatch is not an error here: mutators can make the transaction
    /// disagree with the negotiation, and the caller records that so it knows
    /// the target will never see the channel confirm.
    #[must_use]
    pub fn matches_funding_output(
        &self,
        opener_funding_pubkey: &PublicKey,
        acceptor_funding_pubkey: &PublicKey,
        funding_satoshis: u64,
        channel_type: &Features,
    ) -> bool {
        let Ok(expected_spk) = build_funding_scriptpubkey(
            opener_funding_pubkey,
            acceptor_funding_pubkey,
            channel_type,
        ) else {
            return false;
        };
        self.tx.output.get(self.vout as usize).is_some_and(|out| {
            out.script_pubkey == expected_spk && out.value.to_sat() == funding_satoshis
        })
    }
}

/// Builds the funding output `script_pubkey` for the negotiated channel type.
///
/// Simple taproot channels pay to a single P2TR key aggregated from both
/// `funding_pubkey`s; every other channel type pays to a 2-of-2 P2WSH.
///
/// # Errors
///
/// Returns [`MusigError`] if the taproot funding key cannot be derived, which
/// cannot happen for two valid public keys.
pub fn build_funding_scriptpubkey(
    opener_funding_pubkey: &PublicKey,
    acceptor_funding_pubkey: &PublicKey,
    channel_type: &Features,
) -> Result<ScriptBuf, MusigError> {
    if channel_type.supports_feature(Features::OPTION_SIMPLE_TAPROOT) {
        let keys = FundingKeys::new(opener_funding_pubkey, acceptor_funding_pubkey)?;
        Ok(taproot::funding_scriptpubkey(keys.aggregate_pubkey()))
    } else {
        Ok(build_funding_witness_script(opener_funding_pubkey, acceptor_funding_pubkey).to_p2wsh())
    }
}

/// Builds the funding output witness script per BOLT 3.
pub fn build_funding_witness_script(pubkey1: &PublicKey, pubkey2: &PublicKey) -> ScriptBuf {
    let key1_bytes = pubkey1.serialize();
    let key2_bytes = pubkey2.serialize();
    let (lesser, greater) = if key1_bytes < key2_bytes {
        (&key1_bytes, &key2_bytes)
    } else {
        (&key2_bytes, &key1_bytes)
    };
    Builder::new()
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_slice(lesser)
        .push_slice(greater)
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::ecdsa::Signature;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    /// Unwraps the [`FundingError::InsufficientFunds`] variant, failing the
    /// test on any other error.
    fn expect_insufficient_funds(err: FundingError) -> InsufficientFunds {
        match err {
            FundingError::InsufficientFunds(e) => e,
            other @ FundingError::Musig(_) => {
                panic!("expected InsufficientFunds, got {other:?}")
            }
        }
    }

    /// A `channel_type` negotiating `option_simple_taproot`.
    fn simple_taproot_channel_type() -> Features {
        Features::from_bits(&[Features::OPTION_SIMPLE_TAPROOT])
    }

    fn pubkey(hex_str: &str) -> PublicKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        PublicKey::from_slice(&bytes).expect("valid pubkey")
    }

    fn secret(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        SecretKey::from_slice(&bytes).expect("valid secret key")
    }

    // Signs a P2PKH input (input 0) of the funding transaction, producing the
    // script_sig with signature and public key.
    fn sign_p2pkh_input(funding: &mut FundingTransaction, utxo: &Utxo, input_privkey: &SecretKey) {
        let input_pubkey = PublicKey::from_secret_key(&Secp256k1::signing_only(), input_privkey);
        let sighash = SighashCache::new(&funding.tx)
            .legacy_signature_hash(0, &utxo.script_pubkey, EcdsaSighashType::All.to_u32())
            .expect("valid sighash");
        let sig = Signature::sighash_all(
            Secp256k1::signing_only().sign_ecdsa(&sighash.into(), input_privkey),
        );

        funding.tx.input[0].script_sig = Builder::new()
            .push_slice(sig.serialize())
            .push_slice(input_pubkey.serialize())
            .into_script();
    }

    // Signs P2WPKH inputs of the funding transaction, producing the witness
    // with signature and public key.
    fn sign_p2wpkh_input(
        funding: &mut FundingTransaction,
        utxos: &[Utxo],
        input_privkeys: &[SecretKey],
    ) {
        assert_eq!(utxos.len(), input_privkeys.len());

        let secp = Secp256k1::signing_only();

        for (i, (utxo, input_privkey)) in utxos.iter().zip(input_privkeys).enumerate() {
            let amount = utxo.amount;
            let input_spk = &utxo.script_pubkey;

            let input_pubkey = PublicKey::from_secret_key(&secp, input_privkey);
            let sighash = SighashCache::new(&funding.tx)
                .p2wpkh_signature_hash(i, input_spk, amount, EcdsaSighashType::All)
                .expect("valid sighash");
            let sig = Signature::sighash_all(secp.sign_ecdsa_low_r(&sighash.into(), input_privkey));

            funding.tx.input[i].witness =
                Witness::from_slice(&[sig.serialize().as_ref(), &input_pubkey.serialize()[..]]);
        }
    }

    // BOLT 3 Appendix B: Funding Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-b-funding-transaction-test-vectors

    #[test]
    fn valid_funding_tx_with_p2pkh_input_and_p2wpkh_change() {
        let utxos = vec![Utxo {
            amount: Amount::from_sat(5_000_000_000),
            outpoint: OutPoint {
                txid: "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            // P2PKH scriptpubkey of the block 1 coinbase output being spent.
            script_pubkey: ScriptBuf::from(
                hex::decode("76a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac")
                    .expect("valid P2PKH scriptpubkey hex"),
            ),
        }];

        // P2WPKH scriptpubkey for the change destination.
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let mut funding = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            10_000_000,
            15_000,
            &Features::new(),
            utxos.clone(),
            change_spk,
        )
        .expect("inputs should cover funding amount and fees");

        assert_eq!(funding.vout, 0);
        assert_eq!(funding.tx.output.len(), 2);
        assert_eq!(
            funding.tx.output[funding.vout as usize].value,
            Amount::from_sat(10_000_000)
        );

        // The BOLT 3 test vectors assume that the sequence used in the inputs
        // disables absolute locktime and replace-by-fee. However, our funding
        // transaction construction enables replace-by-fee, so we override the
        // sequence here to validate against the BOLT 3 test vectors.
        funding.tx.input[0].sequence = Sequence::MAX;

        // Sign the P2PKH input with the block 1 coinbase privkey to verify the
        // BOLT 3 txid.
        sign_p2pkh_input(
            &mut funding,
            &utxos[0],
            &secret("6bd078650fcee8444e4e09825227b801a1ca928debb750eb36e6d56124bb20e8"),
        );

        assert_eq!(
            serialize_hex(&funding.tx),
            "0200000001adbb20ea41a8423ea937e76e8151636bf6093b70eaff942930d20576600521fd000000006b48304502210090587b6201e166ad6af0227d3036a9454223d49a1f11839c1a362184340ef0240220577f7cd5cca78719405cbf1de7414ac027f0239ef6e214c90fcaab0454d84b3b012103535b32d5eb0a6ed0982a0479bbadc9868d9836f6ba94dd5a63be16d875069184ffffffff028096980000000000220020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd20256d29010000001600143ca33c2e4446f4a305f23c80df8ad1afdcf652f900000000"
        );
        assert_eq!(
            funding.tx.compute_txid().to_string(),
            "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
        );
    }

    /// Not from BOLT 3 test vectors; expected serialized tx and txid were
    /// generated by `bdk_wallet`.
    /// Tests the case where the spendable UTXOs are only sufficient to cover
    /// the funding amount and fees, but not the change output.
    #[test]
    fn valid_funding_tx_with_p2wpkh_input_and_no_change() {
        let utxos = vec![Utxo {
            amount: Amount::from_sat(10_008_942),
            outpoint: OutPoint {
                txid: "a1f7b953dc8c3db0222d931d3e2613f9971af75a09a005b31af057f8414cc5d7"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                    .expect("valid P2WPKH scriptpubkey hex"),
            ),
        }];

        // P2WPKH scriptPubKey for the change output (will be dropped).
        let change_spk = ScriptBuf::from(
            hex::decode("00142e532c12351a5c81e23c8a76d19345ca7b6de57a")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let mut funding = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            10_000_000,
            15_000,
            &Features::new(),
            utxos.clone(),
            change_spk,
        )
        .expect("inputs should cover funding amount and fees");

        assert_eq!(funding.vout, 0);
        assert_eq!(funding.tx.output.len(), 1);
        assert_eq!(
            funding.tx.output[funding.vout as usize].value,
            Amount::from_sat(10_000_000)
        );

        sign_p2wpkh_input(
            &mut funding,
            &utxos,
            &[secret(
                "6c856f454ca42dc1df9cb154270ba11f7a9cc17392097101d92685ea81345b88",
            )],
        );

        assert_eq!(
            serialize_hex(&funding.tx),
            "02000000000101d7c54c41f857f01ab305a0095af71a97f913263e1d932d22b03d8cdc53b9f7a10000000000fdffffff018096980000000000220020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd02473044022037f8b8e50c6e12a270a8856ceaecbdfe40132d744985c3fd690b0820b97e368c0220294d38ed56053f25be89ed48d06d5fabe8ab900ce6597d70e4e957e0d324fa24012102ceb69e22333f83556c5d1efba75a03346bf3d52cfbd39fc5d24ded034ef7d9f400000000"
        );
        assert_eq!(
            funding.tx.compute_txid().to_string(),
            "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
        );
    }

    /// Not from BOLT 3 test vectors; expected serialized tx and txid were
    /// generated by `bdk_wallet`.
    /// Tests the case where the spendable UTXOs are sufficient to cover the
    /// funding amount and fees, and the resulting change output equals the
    /// dust limit.
    #[test]
    fn valid_funding_tx_with_p2wpkh_input_and_change_at_dust_limit() {
        let utxos = vec![Utxo {
            amount: Amount::from_sat(10_009_444),
            outpoint: OutPoint {
                txid: "7e7cd7f911a0e095105cbcd72290482c34369beceb6b14f0965dba35fce2c474"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                    .expect("valid P2WPKH scriptpubkey hex"),
            ),
        }];

        // P2WPKH scriptPubKey for the change output.
        let change_spk = ScriptBuf::from(
            hex::decode("0014dbe223abef0f0dc3d41a01d0a8e3e0f7eea7f61f")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let mut funding = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            10_000_000,
            15_000,
            &Features::new(),
            utxos.clone(),
            change_spk,
        )
        .expect("inputs should cover funding amount and fees");

        assert_eq!(funding.vout, 0);
        assert_eq!(funding.tx.output.len(), 2);
        assert_eq!(funding.tx.output[0].value, Amount::from_sat(10_000_000));

        // Bitcoin Core considers P2WPKH outputs worth less than 294 satoshis
        // to be dust at the default dust relay fee of 3000 sat/kB.
        assert_eq!(funding.tx.output[1].value, Amount::from_sat(294));

        sign_p2wpkh_input(
            &mut funding,
            &utxos,
            &[secret(
                "6c856f454ca42dc1df9cb154270ba11f7a9cc17392097101d92685ea81345b88",
            )],
        );

        assert_eq!(
            serialize_hex(&funding.tx),
            "0200000000010174c4e2fc35ba5d96f0146bebec9b36342c489022d7bc5c1095e0a011f9d77c7e0000000000fdffffff028096980000000000220020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd2601000000000000160014dbe223abef0f0dc3d41a01d0a8e3e0f7eea7f61f0247304402207ab0a59f970733752f9e1e91fab3681003e9d5733bfe6a53bf484b415b8b611602206737ffd43bd3450ee53e67b7c489f52e16a8777ab9f7a7f59d7aed5e7d7a3bdb012102ceb69e22333f83556c5d1efba75a03346bf3d52cfbd39fc5d24ded034ef7d9f400000000"
        );
        assert_eq!(
            funding.tx.compute_txid().to_string(),
            "7066ff548b215f084e1ed166fec587b83f1e211dc8eb7b13b2b8e0440f81cd59"
        );
    }

    /// Not from BOLT 3 test vectors; expected serialized tx and txid were
    /// generated by `bdk_wallet`.
    /// Tests the case where multiple UTXO inputs are available, but only a
    /// subset of them are used.
    #[test]
    fn valid_funding_tx_with_multiple_inputs() {
        let utxos = vec![
            Utxo {
                amount: Amount::from_sat(10_011_000),
                outpoint: OutPoint {
                    txid: "fe4e8d394f82812a85cbcea9dbee1a1cdfa56a7416ee764b15a100303b6e6d6a"
                        .parse()
                        .expect("valid txid"),
                    vout: 0,
                },
                script_pubkey: ScriptBuf::from(
                    hex::decode("0014255bdf13fe8864b038f90ed40251d8ba4efc005e")
                        .expect("valid P2WPKH scriptpubkey hex"),
                ),
            },
            Utxo {
                amount: Amount::from_sat(10_010_000),
                outpoint: OutPoint {
                    txid: "0eabe9a1a0e3332abf1137a688ef11afa7e626abb96c1e76c7e892b3065291bc"
                        .parse()
                        .expect("valid txid"),
                    vout: 0,
                },
                script_pubkey: ScriptBuf::from(
                    hex::decode("0014f31409f93323c31054ed14d6efe5ac32e05a5abc")
                        .expect("valid P2WPKH scriptpubkey hex"),
                ),
            },
            Utxo {
                amount: Amount::from_sat(10_000_000),
                outpoint: OutPoint {
                    txid: "8bc86cceeac83860cae4fb2ff389304fdecac68b49574afe802a5a606012f295"
                        .parse()
                        .expect("valid txid"),
                    vout: 0,
                },
                script_pubkey: ScriptBuf::from(
                    hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                        .expect("valid P2WPKH scriptpubkey hex"),
                ),
            },
        ];

        // P2WPKH scriptPubKey for the change output.
        let change_spk = ScriptBuf::from(
            hex::decode("0014dbe223abef0f0dc3d41a01d0a8e3e0f7eea7f61f")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let mut funding = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            15_000_000,
            15_000,
            &Features::new(),
            utxos.clone(),
            change_spk,
        )
        .expect("inputs should cover funding amount and fees");

        assert_eq!(funding.vout, 0);
        assert_eq!(funding.tx.input.len(), 2);
        assert_eq!(funding.tx.output.len(), 2);
        assert_eq!(
            funding.tx.output[funding.vout as usize].value,
            Amount::from_sat(15_000_000)
        );

        sign_p2wpkh_input(
            &mut funding,
            &utxos[..2],
            &[
                secret("213375f0a88d2519baf76c80f51f546fac9974e60ce8d416dbadeff41b88837c"),
                secret("ad97abe5507fff5748c5d59885548b4f9cc8dfe06b795c5b5dd9e2fbf28f6674"),
            ],
        );

        assert_eq!(
            serialize_hex(&funding.tx),
            "020000000001026a6d6e3b3000a1154b76ee16746aa5df1c1aeedba9cecb852a81824f398d4efe0000000000fdffffffbc915206b392e8c7761e6cb9ab26e6a7af11ef88a63711bf2a33e3a0a1e9ab0e0000000000fdffffff02c0e1e40000000000220020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd9a694c0000000000160014dbe223abef0f0dc3d41a01d0a8e3e0f7eea7f61f024730440220241b86d533920bf831b0f293f33a235f88058192ec43dae4d487198652f634b302202a40f65d398eb7c01d580d23d6da4b9a911e1f4fc202b24c981452b3595bfb600121027c0cd74ffa26b13782539ce945f945d386606fb08490a2778089dad0ad29a2b402473044022054db9ac7982c3d78643883f69638b01c0d01d0363336ef001232a8348065e7d6022069846cbdda1202633548535529dbcb71fb3051091ad6c5e3e13a03fa755268d8012102d466308945a80e73cb65d35e30adcfaacfd8e4fb657edbe15537d770cf9021a900000000"
        );
        assert_eq!(
            funding.tx.compute_txid().to_string(),
            "e737c301bcdcd305c52995f56c4cf6c9234bd4e99b16a38ff9a7cc897f5cf28d"
        );
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the case where no spendable UTXOs are provided to cover the
    /// funding amount and fees.
    #[test]
    fn funding_tx_with_empty_utxos() {
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let err = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            10_000_000,
            15_000,
            &Features::new(),
            vec![],
            change_spk,
        )
        .unwrap_err();
        let err = expect_insufficient_funds(err);
        assert_eq!(err.required, Amount::from_sat(10_000_000));
        assert_eq!(err.available, Amount::from_sat(0));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests that building a funding transaction fails when the funding amount,
    /// feerate, and available UTXOs are all zero.
    #[test]
    fn funding_tx_with_zero_funding_amt_feerate_and_utxos() {
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let err = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            0,
            0,
            &Features::new(),
            vec![],
            change_spk,
        )
        .unwrap_err();
        let err = expect_insufficient_funds(err);
        assert_eq!(err.required, Amount::from_sat(0));
        assert_eq!(err.available, Amount::from_sat(0));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the case where the spendable UTXOs are insufficient to cover the
    /// funding amount and fees.
    #[test]
    fn funding_tx_with_insufficient_funds() {
        let utxos = vec![Utxo {
            amount: Amount::from_sat(1_000),
            outpoint: OutPoint {
                txid: "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("76a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac")
                    .expect("valid P2PKH scriptpubkey hex"),
            ),
        }];
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let err = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            10_000_000,
            15_000,
            &Features::new(),
            utxos,
            change_spk,
        )
        .unwrap_err();
        let err = expect_insufficient_funds(err);
        assert_eq!(err.required, Amount::from_sat(10_012_060));
        assert_eq!(err.available, Amount::from_sat(1_000));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the case where the `funding_satoshis` value exceeds Bitcoin's
    /// maximum supply. This exercises the case where `funding_satoshis` is near
    /// `u64::MAX` and adding fees would overflow the required amount
    /// calculation. We should return `InsufficientFunds` instead of panicking.
    #[test]
    fn funding_tx_funding_amount_plus_fee_does_not_overflow() {
        let utxos = vec![Utxo {
            amount: Amount::from_sat(1_000),
            outpoint: OutPoint {
                txid: "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("76a9143ca33c2e4446f4a305f23c80df8ad1afdcf652f988ac")
                    .expect("valid P2PKH scriptpubkey hex"),
            ),
        }];
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let err = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            u64::MAX,
            15_000,
            &Features::new(),
            utxos,
            change_spk,
        )
        .unwrap_err();
        let err = expect_insufficient_funds(err);
        assert_eq!(err.required, Amount::from_sat(u64::MAX));
        assert_eq!(err.available, Amount::MAX_MONEY);
    }

    /// Not from BOLT 3 test vectors.
    /// Tests that fee estimation panics when an input has an unsupported script
    /// pubkey type (here P2TR), guarding against bitcoind's default address
    /// type silently shifting away from P2WPKH.
    #[test]
    #[should_panic(expected = "unsupported input script pubkey")]
    fn funding_tx_panics_on_unsupported_input_script() {
        let utxos = vec![Utxo {
            amount: Amount::from_sat(10_008_942),
            outpoint: OutPoint {
                txid: "a1f7b953dc8c3db0222d931d3e2613f9971af75a09a005b31af057f8414cc5d7"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("51201baeaaf9047cc42055a37a3ac981bdf7f5ab96fad0d2d07c54608e8a181b9477")
                    .expect("valid P2TR scriptpubkey hex"),
            ),
        }];

        let change_spk = ScriptBuf::from(
            hex::decode("00142e532c12351a5c81e23c8a76d19345ca7b6de57a")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let _ = build_funding_transaction(
            &pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"),
            &pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"),
            10_000_000,
            15_000,
            &Features::new(),
            utxos,
            change_spk,
        );
    }

    /// Not from BOLT 3 test vectors.
    #[test]
    fn funding_witness_script_is_key_order_independent() {
        let local_funding_pubkey =
            pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
        let remote_funding_pubkey =
            pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");

        let funding_witness_script_1 =
            build_funding_witness_script(&local_funding_pubkey, &remote_funding_pubkey);
        let funding_witness_script_2 =
            build_funding_witness_script(&remote_funding_pubkey, &local_funding_pubkey);

        // Argument order must not matter as keys are sorted lexicographically.
        assert_eq!(funding_witness_script_1, funding_witness_script_2);

        assert_eq!(
            hex::encode(funding_witness_script_1.as_bytes()),
            "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"
        );
    }

    #[test]
    fn funding_output_matches_detects_matching_and_mismatched_outputs() {
        let opener_funding_pubkey =
            pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
        let acceptor_funding_pubkey =
            pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");
        let funding_satoshis = 10_000_000;

        let utxos = vec![Utxo {
            amount: Amount::from_sat(5_000_000_000),
            outpoint: OutPoint {
                txid: "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                    .expect("valid P2WPKH scriptpubkey hex"),
            ),
        }];
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );
        let funding = build_funding_transaction(
            &opener_funding_pubkey,
            &acceptor_funding_pubkey,
            funding_satoshis,
            15_000,
            &Features::new(),
            utxos,
            change_spk,
        )
        .expect("inputs should cover funding amount and fees");

        // The referenced funding output matches the negotiated output script
        // and amount.
        assert!(funding.matches_funding_output(
            &opener_funding_pubkey,
            &acceptor_funding_pubkey,
            funding_satoshis,
            &Features::new(),
        ));

        // A different funding pubkey yields a different script and does not match.
        let other_pubkey =
            pubkey("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        assert!(!funding.matches_funding_output(
            &opener_funding_pubkey,
            &other_pubkey,
            funding_satoshis,
            &Features::new(),
        ));

        // A mismatched funding amount does not match.
        let other_amount = 10_000;
        assert!(!funding.matches_funding_output(
            &opener_funding_pubkey,
            &acceptor_funding_pubkey,
            other_amount,
            &Features::new(),
        ));
    }

    /// The spec's funding test vector: a simple taproot channel funds a P2TR
    /// output keyed on the `MuSig2` aggregate of both `funding_pubkey`s, not a
    /// 2-of-2 P2WSH.
    #[test]
    fn taproot_channel_type_funds_a_p2tr_output() {
        let local = pubkey("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");
        let remote = pubkey("02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb");

        // `option_simple_taproot` alone: BOLT 9 bit 80.
        let taproot_type = simple_taproot_channel_type();
        let spk = build_funding_scriptpubkey(&local, &remote, &taproot_type)
            .expect("valid funding pubkeys");

        assert!(spk.is_p2tr());
        assert_eq!(
            hex::encode(spk.as_bytes()),
            "5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e"
        );

        // Without the taproot bit the output stays a 2-of-2 P2WSH.
        assert!(
            build_funding_scriptpubkey(&local, &remote, &Features::new())
                .expect("valid funding pubkeys")
                .is_p2wsh()
        );
    }

    /// The funding transaction pays to the taproot script, and
    /// `matches_funding_output` only agrees when given the same channel type.
    #[test]
    fn taproot_funding_output_matches_only_its_own_channel_type() {
        let local = pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
        let remote = pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");
        let taproot_type = simple_taproot_channel_type();

        let utxos = vec![Utxo {
            amount: Amount::from_sat(5_000_000_000),
            outpoint: OutPoint {
                txid: "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
                    .parse()
                    .expect("valid txid"),
                vout: 0,
            },
            script_pubkey: ScriptBuf::from(
                hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                    .expect("valid P2WPKH scriptpubkey hex"),
            ),
        }];
        let change_spk = ScriptBuf::from(
            hex::decode("00143ca33c2e4446f4a305f23c80df8ad1afdcf652f9")
                .expect("valid P2WPKH scriptpubkey hex"),
        );

        let funding = build_funding_transaction(
            &local,
            &remote,
            10_000_000,
            15_000,
            &taproot_type,
            utxos,
            change_spk,
        )
        .expect("inputs should cover funding amount and fees");

        assert!(
            funding.tx.output[funding.vout as usize]
                .script_pubkey
                .is_p2tr()
        );
        assert!(funding.matches_funding_output(&local, &remote, 10_000_000, &taproot_type));
        // The same transaction does not satisfy a non-taproot negotiation.
        assert!(!funding.matches_funding_output(&local, &remote, 10_000_000, &Features::new()));
    }
}
