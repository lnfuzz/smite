//! BOLT 3 commitment transaction tests.

mod harness;

use super::*;
use harness::run_commitment_vectors;

fn pubkey(hex_str: &str) -> PublicKey {
    let bytes = hex::decode(hex_str).expect("valid hex");
    PublicKey::from_slice(&bytes).expect("valid pubkey")
}

#[test]
fn obscuring_factor() {
    let opener_payment_basepoint =
        pubkey("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    let acceptor_payment_basepoint =
        pubkey("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
    let factor = compute_obscuring_factor(&opener_payment_basepoint, &acceptor_payment_basepoint);
    assert_eq!(factor, 0x2bb0_3852_1914);
}

// BOLT 3 Appendix C: Commitment and HTLC Transaction Test Vectors
//    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors
#[test]
fn bolt3_appendix_c_legacy_vectors() {
    run_commitment_vectors(include_str!("test_vectors/bolt3_appendix_c_legacy.json"));
}

// BOLT 3 Appendix F: Commitment and HTLC Transaction Test Vectors (anchors)
//    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-f-commitment-and-htlc-transaction-test-vectors-anchors
#[test]
fn bolt3_appendix_f_anchor_vectors() {
    run_commitment_vectors(include_str!("test_vectors/bolt3_appendix_f_anchor.json"));
}

// Vectors not from BOLT 3, covering edge cases the appendices do not.
#[test]
fn custom_legacy_vectors() {
    run_commitment_vectors(include_str!("test_vectors/custom_legacy.json"));
}

// Vectors not from BOLT 3, covering edge cases the appendices do not.
#[test]
fn custom_anchor_vectors() {
    run_commitment_vectors(include_str!("test_vectors/custom_anchor.json"));
}

// BOLT 3 Appendix E: Key Derivation Test Vectors
//    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-e-key-derivation-test-vectors

#[test]
fn derive_pubkey_from_basepoint() {
    let basepoint = pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
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
    let revocationpubkey = derive_revocation_pubkey(&revocation_basepoint, &per_commitment_point);
    assert_eq!(
        revocationpubkey,
        pubkey("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"),
    );
}

fn sample_chan_config(funding_satoshis: u64, channel_type: Features) -> ChannelConfig {
    let sample_key = pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
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
        channel_type,
        opener: sample_party(),
        acceptor: sample_party(),
        minimum_depth: 8,
    }
}

#[test]
fn new_initial_from_funding_msat_overflow() {
    let sample_key = pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
    let chan_config = sample_chan_config(
        u64::MAX,
        Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
    );
    let result = chan_config.new_initial_commitment(0, 15_000, sample_key, sample_key);
    assert!(matches!(result, Err(CommitmentError::FundingMsatOverflow)));
}

#[test]
fn new_initial_from_funding_push_exceeds_funding() {
    let sample_key = pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
    let chan_config = sample_chan_config(
        1_000,
        Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
    );
    let result = chan_config.new_initial_commitment(2_000_000, 15_000, sample_key, sample_key);
    assert!(matches!(result, Err(CommitmentError::PushExceedsFunding)));
}

#[test]
fn opener_balance_after_commitment_cost_total_sat_checks() {
    let feerate_per_kw: u32 = 15_000;
    let legacy = Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]);
    let anchor = Features::from_bits(&[Features::OPTION_ANCHORS]);
    // Legacy fee: 15000 * 724 / 1000 = 10_860 sat
    // Anchor fee: 15000 * 1124 / 1000 = 16_860 sat; anchor_cost = 660 sat

    // Comfortably affordable
    let opener_balance_sat: u64 = 20_000;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &legacy).total_sat()),
        Some(9_140),
    );

    // Exact zero opener balance
    let opener_balance_sat: u64 = 10_860;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &legacy).total_sat()),
        Some(0),
    );

    // Balance does not cover the fee
    let opener_balance_sat: u64 = 10_000;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &legacy).total_sat()),
        None
    );

    // Balance covers the fee but not the anchor outputs
    let opener_balance_sat: u64 = 17_500;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &anchor).total_sat()),
        None,
    );
}
