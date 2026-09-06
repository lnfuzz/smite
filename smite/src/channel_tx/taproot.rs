//! Simple taproot channel output scripts.
//!
//! Every commitment output of a simple taproot channel is a P2TR output whose
//! key commits to a tapscript tree. This module builds those `script_pubkey`s.
//! The forms here are the ones negotiated by the `option_simple_taproot`
//! channel type (BOLT 9 bit 80), which is what lnd calls its "final" taproot
//! commitment and what the spec's test vectors encode.

use bitcoin::ScriptBuf;
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};

/// The "Nothing Up My Sleeve" point used as the internal key of the `to_local`
/// and `to_remote` outputs, so that the script path must always be taken and
/// the keys inside it are revealed on chain.
///
/// Generated with the seed phrase "Lightning Simple Taproot".
const NUMS_POINT: [u8; 33] = [
    0x02, 0xdc, 0xa0, 0x94, 0x75, 0x11, 0x09, 0xd0, 0xbd, 0x05, 0x5d, 0x03, 0x56, 0x58, 0x74, 0xe8,
    0x27, 0x6d, 0xd5, 0x3e, 0x92, 0x6b, 0x44, 0xe3, 0xbd, 0x1b, 0xb6, 0xbf, 0x4b, 0xc1, 0x30, 0xa2,
    0x79,
];

/// Returns the NUMS internal key.
fn nums_point() -> XOnlyPublicKey {
    PublicKey::from_slice(&NUMS_POINT)
        .expect("the NUMS constant is a valid compressed pubkey")
        .x_only_public_key()
        .0
}

/// Builds the funding output `script_pubkey` for a simple taproot channel.
///
/// `aggregate_funding_key` is the `MuSig2` aggregate of both `funding_pubkey`s
/// with the BIP 86 tweak already applied, so the output commits to no script
/// path and is spent with a single aggregated Schnorr signature.
#[must_use]
pub fn funding_scriptpubkey(aggregate_funding_key: XOnlyPublicKey) -> ScriptBuf {
    // `dangerous_assume_tweaked` is correct here: the `MuSig2` key aggregation
    // already applied the BIP 86 taptweak, so tweaking again would produce a
    // key neither peer can sign for.
    ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
        aggregate_funding_key,
    ))
}

/// Builds the `to_local` output `script_pubkey`.
///
/// The tree has two leaves: the owner sweeps after `to_self_delay` blocks, or
/// the counterparty sweeps immediately with the revocation key. The revocation
/// leaf pushes the delayed key and drops it, which reveals that key on chain so
/// the anchor output stays spendable.
#[must_use]
pub fn to_local_scriptpubkey(
    local_delayedpubkey: &PublicKey,
    revocationpubkey: &PublicKey,
    to_self_delay: u16,
) -> ScriptBuf {
    let delay_script = to_local_delay_script(local_delayedpubkey, to_self_delay);
    let revoke_script = to_local_revoke_script(local_delayedpubkey, revocationpubkey);

    let spend_info = TaprootBuilder::new()
        .add_leaf(1, delay_script)
        .and_then(|builder| builder.add_leaf(1, revoke_script))
        .expect("a two-leaf tree at depth 1 is always valid")
        .finalize(&Secp256k1::verification_only(), nums_point())
        .expect("a complete two-leaf tree always finalizes");

    p2tr(&spend_info)
}

/// Builds the `to_remote` output `script_pubkey`.
///
/// A single leaf letting the counterparty sweep after a 1-block delay. The
/// internal key is the NUMS point so the delay cannot be bypassed, and because
/// it is a constant the counterparty can scan the chain for this output.
#[must_use]
pub fn to_remote_scriptpubkey(remotepubkey: &PublicKey) -> ScriptBuf {
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, to_remote_script(remotepubkey))
        .expect("a single-leaf tree is always valid")
        .finalize(&Secp256k1::verification_only(), nums_point())
        .expect("a complete single-leaf tree always finalizes");

    p2tr(&spend_info)
}

/// Builds an anchor output `script_pubkey`.
///
/// The owner spends it via the key path; anyone may sweep it via the script
/// path after 16 blocks. Unlike the segwit v0 anchors, the internal key is the
/// owner's main output key (`local_delayedpubkey` or `remotepubkey`) rather
/// than the funding key, which `MuSig2` no longer reveals.
#[must_use]
pub fn anchor_scriptpubkey(anchor_internal_key: &PublicKey) -> ScriptBuf {
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, anchor_script())
        .expect("a single-leaf tree is always valid")
        .finalize(
            &Secp256k1::verification_only(),
            anchor_internal_key.x_only_public_key().0,
        )
        .expect("a complete single-leaf tree always finalizes");

    p2tr(&spend_info)
}

/// `<local_delayedpubkey> OP_CHECKSIGVERIFY <to_self_delay> OP_CHECKSEQUENCEVERIFY`
fn to_local_delay_script(local_delayedpubkey: &PublicKey, to_self_delay: u16) -> ScriptBuf {
    Builder::new()
        .push_slice(local_delayedpubkey.x_only_public_key().0.serialize())
        .push_opcode(opcodes::OP_CHECKSIGVERIFY)
        .push_int(i64::from(to_self_delay))
        .push_opcode(opcodes::OP_CSV)
        .into_script()
}

/// `<local_delayedpubkey> OP_DROP <revocationpubkey> OP_CHECKSIG`
fn to_local_revoke_script(
    local_delayedpubkey: &PublicKey,
    revocationpubkey: &PublicKey,
) -> ScriptBuf {
    Builder::new()
        .push_slice(local_delayedpubkey.x_only_public_key().0.serialize())
        .push_opcode(opcodes::OP_DROP)
        .push_slice(revocationpubkey.x_only_public_key().0.serialize())
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
}

/// `<remotepubkey> OP_CHECKSIGVERIFY OP_1 OP_CHECKSEQUENCEVERIFY`
fn to_remote_script(remotepubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(remotepubkey.x_only_public_key().0.serialize())
        .push_opcode(opcodes::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::OP_PUSHNUM_1)
        .push_opcode(opcodes::OP_CSV)
        .into_script()
}

/// `OP_16 OP_CHECKSEQUENCEVERIFY`
fn anchor_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::OP_PUSHNUM_16)
        .push_opcode(opcodes::OP_CSV)
        .into_script()
}

/// Returns the P2TR `script_pubkey` for a finalized tapscript tree.
fn p2tr(spend_info: &TaprootSpendInfo) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(spend_info.output_key())
}

/// Returns the tapscript merkle root of a `to_local` output, exposed so tests
/// can check it against the spec vectors.
#[cfg(test)]
fn to_local_merkle_root(
    local_delayedpubkey: &PublicKey,
    revocationpubkey: &PublicKey,
    to_self_delay: u16,
) -> bitcoin::TapNodeHash {
    TaprootBuilder::new()
        .add_leaf(1, to_local_delay_script(local_delayedpubkey, to_self_delay))
        .and_then(|builder| {
            builder.add_leaf(
                1,
                to_local_revoke_script(local_delayedpubkey, revocationpubkey),
            )
        })
        .expect("a two-leaf tree at depth 1 is always valid")
        .finalize(&Secp256k1::verification_only(), nums_point())
        .expect("a complete two-leaf tree always finalizes")
        .merkle_root()
        .expect("a tree with leaves has a merkle root")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn pubkey(hex_str: &str) -> PublicKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        PublicKey::from_slice(&bytes).expect("valid pubkey")
    }

    // Test vectors from the simple taproot channels spec:
    //   bolt-simple-taproot.md, "Test Vectors" appendix.
    //
    // `csv_delay` is 144 throughout.

    const DELAYED_PUBKEY: &str =
        "0315ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05";
    const REVOCATION_PUBKEY: &str =
        "03d4c77088d346bce67c13bbbf82ca112588f4b1c9595a1f8af3be9b2f95a109a0";
    const REMOTE_PAYMENT_PUBKEY: &str =
        "03595f2ef2a51d2250a21077dbea4a7fc3ce550f10676996bf63719e2a71d1f4c9";
    const CSV_DELAY: u16 = 144;

    #[test]
    fn nums_point_matches_spec_vector() {
        assert_eq!(
            hex::encode(nums_point().serialize()),
            "dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279"
        );
    }

    #[test]
    fn to_local_leaf_scripts_match_spec_vectors() {
        let delayed = pubkey(DELAYED_PUBKEY);
        let revocation = pubkey(REVOCATION_PUBKEY);

        assert_eq!(
            hex::encode(to_local_delay_script(&delayed, CSV_DELAY).as_bytes()),
            "2015ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05ad029000b2"
        );
        assert_eq!(
            hex::encode(to_local_revoke_script(&delayed, &revocation).as_bytes()),
            "2015ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c057520d4c77088d346bce67c13bbbf82ca112588f4b1c9595a1f8af3be9b2f95a109a0ac"
        );
    }

    /// BIP 341 sorts each `TapBranch`'s children, so the root is independent of
    /// the order the leaves were added in. This pins the root against the spec
    /// so a change in tree assembly cannot go unnoticed.
    #[test]
    fn to_local_merkle_root_matches_spec_vector() {
        assert_eq!(
            hex::encode(
                to_local_merkle_root(
                    &pubkey(DELAYED_PUBKEY),
                    &pubkey(REVOCATION_PUBKEY),
                    CSV_DELAY
                )
                .to_byte_array()
            ),
            "b8b76c2e893ca785072f0d7393e35d5bd72adf8b7ff2a53538aa664378a38a36"
        );
    }

    #[test]
    fn to_local_scriptpubkey_matches_spec_vector() {
        assert_eq!(
            hex::encode(
                to_local_scriptpubkey(
                    &pubkey(DELAYED_PUBKEY),
                    &pubkey(REVOCATION_PUBKEY),
                    CSV_DELAY
                )
                .as_bytes()
            ),
            "51203e1fcbbd06c8a7414704612c72be9834a75d86ed85b29f0ef0c52e1950afaff3"
        );
    }

    #[test]
    fn to_remote_script_matches_spec_vector() {
        assert_eq!(
            hex::encode(to_remote_script(&pubkey(REMOTE_PAYMENT_PUBKEY)).as_bytes()),
            "20595f2ef2a51d2250a21077dbea4a7fc3ce550f10676996bf63719e2a71d1f4c9ad51b2"
        );
    }

    #[test]
    fn to_remote_scriptpubkey_matches_spec_vector() {
        assert_eq!(
            hex::encode(to_remote_scriptpubkey(&pubkey(REMOTE_PAYMENT_PUBKEY)).as_bytes()),
            "51203609bb705034e5629aa6ec05c5ca906ac89ac08b34c4583c259521ec30174408"
        );
    }

    #[test]
    fn anchor_script_matches_spec_vector() {
        assert_eq!(hex::encode(anchor_script().as_bytes()), "60b2");
    }

    /// The local anchor's internal key is the delayed payment key, and the
    /// remote anchor's is the remote payment key: both are revealed on chain
    /// when the commitment is spent.
    #[test]
    fn anchor_scriptpubkeys_match_spec_vectors() {
        assert_eq!(
            hex::encode(anchor_scriptpubkey(&pubkey(DELAYED_PUBKEY)).as_bytes()),
            "5120f67ab012701705f3203d132f909a6810ef18c5da4c11d986cb50818803b8344e"
        );
        assert_eq!(
            hex::encode(anchor_scriptpubkey(&pubkey(REMOTE_PAYMENT_PUBKEY)).as_bytes()),
            "51201249c50576fdf914caa14f9221370b986df520bdbc73f57d5056a86ee03e5ac4"
        );
    }

    #[test]
    fn funding_scriptpubkey_matches_spec_vector() {
        let aggregate = XOnlyPublicKey::from_slice(
            &hex::decode("d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e")
                .expect("valid hex"),
        )
        .expect("valid x-only pubkey");

        assert_eq!(
            hex::encode(funding_scriptpubkey(aggregate).as_bytes()),
            "5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e"
        );
    }
}
