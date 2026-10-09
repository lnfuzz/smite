//! BOLT 3 commitment transaction tests.

mod harness;

use std::str::FromStr;

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
    let opener_pubkey =
        pubkey("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
    let acceptor_pubkey =
        pubkey("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");

    let sample_party = |sample_key: PublicKey| ChannelPartyConfig {
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
        opener: sample_party(opener_pubkey),
        acceptor: sample_party(acceptor_pubkey),
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
    let result = chan_config.new_initial_commitments(0, 15_000, sample_key, sample_key);
    assert!(matches!(result, Err(CommitmentError::FundingMsatOverflow)));
}

#[test]
fn new_initial_from_funding_push_exceeds_funding() {
    let sample_key = pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
    let chan_config = sample_chan_config(
        1_000,
        Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
    );
    let result = chan_config.new_initial_commitments(2_000_000, 15_000, sample_key, sample_key);
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
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &legacy, 0).total_sat()),
        Some(9_140),
    );

    // Exact zero opener balance
    let opener_balance_sat: u64 = 10_860;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &legacy, 0).total_sat()),
        Some(0),
    );

    // Balance does not cover the fee
    let opener_balance_sat: u64 = 10_000;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &legacy, 0).total_sat()),
        None
    );

    // Balance covers the fee but not the anchor outputs
    let opener_balance_sat: u64 = 17_500;
    assert_eq!(
        opener_balance_sat.checked_sub(CommitmentCost::new(feerate_per_kw, &anchor, 0).total_sat()),
        None,
    );
}

#[test]
fn opener_balance_after_commitment_cost_total_sat_with_htlc_checks() {
    let feerate_per_kw: u32 = 15_000;
    let legacy = Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]);
    let anchor = Features::from_bits(&[Features::OPTION_ANCHORS]);
    let sample_key = pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
    let htlc = |id: u64, offerer: Side, amount_msat: u64| Htlc {
        id,
        offerer,
        amount_msat,
        cltv_expiry: 500,
        payment_hash: [0; 32],
    };
    let state_with = |config: &ChannelConfig, push_msat: u64, htlcs: &[Htlc]| {
        let mut commitments = config
            .new_initial_commitments(push_msat, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        for h in htlcs {
            commitments.add_htlc(Side::Opener, *h).unwrap();
            commitments.add_htlc(Side::Acceptor, *h).unwrap();
        }

        // Since both sides are built identically, we can use either side's state
        // to verify the opener's balance after deducting the commitment cost.
        commitments.opener
    };
    // Returns opener balance after deducting the commitment cost.
    let opener_balance = |config: &ChannelConfig, state: &CommitmentState, local_side: Side| {
        let opener_balance_sat = state.opener_balance_msat / 1000;
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
    let config = sample_chan_config(50_000, legacy.clone());
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
    let mut config = sample_chan_config(50_000, legacy);
    config.acceptor.dust_limit_satoshis = 20_000;
    let state = state_with(&config, 26_000_000, &[offered]);
    assert_eq!(opener_balance(&config, &state, Side::Opener), None);
    assert_eq!(opener_balance(&config, &state, Side::Acceptor), Some(1_140));

    // Anchor dust threshold is the dust limit alone
    let config = sample_chan_config(50_000, anchor);
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

#[test]
#[allow(clippy::too_many_lines)]
fn commitment_dance_adds_and_resolves_htlc() {
    let secp = Secp256k1::new();
    let privkey1 =
        SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
            .expect("valid secret key");
    let privkey2 =
        SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
            .expect("valid secret key");
    let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);
    let pubkey2 = PublicKey::from_secret_key(&secp, &privkey2);

    // Set up the channel configuration, initial commitments, and holder
    // identities for the HTLC commitment dance.
    let config = sample_chan_config(
        10_000_000,
        Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
    );
    let mut commitments = config
        .new_initial_commitments(3_000_000_000, 253, pubkey1, pubkey2)
        .expect("valid commitment");
    let opener_holder = HolderIdentity {
        side: Side::Opener,
        funding_privkey: privkey1,
        htlc_basepoint_privkey: privkey1,
    };
    let acceptor_holder = HolderIdentity {
        side: Side::Acceptor,
        funding_privkey: privkey2,
        htlc_basepoint_privkey: privkey2,
    };

    let htlc = |id: u64, offerer: Side, amount_msat: u64| Htlc {
        id,
        offerer,
        amount_msat,
        cltv_expiry: 500,
        payment_hash: [0; 32],
    };
    // A `commitment_signed` creates the counterparty's next commitment: `signer`
    // advances it (updates number and per-commitment point) and signs it, then
    // `verifier` (that counterparty) verifies.
    let commitment_signed = |commitments: &mut ChannelCommitments,
                             signer: &HolderIdentity,
                             verifier: &HolderIdentity,
                             next_per_commitment_point: PublicKey| {
        commitments.update_per_commitment_point(verifier.side, next_per_commitment_point);
        commitments.advance_commitment_number(verifier.side);
        assert_eq!(
            commitments.state(verifier.side).per_commitment_point,
            next_per_commitment_point,
        );
        let (commitment_sig, htlc_sigs) = config.sign_counterparty_commitment(commitments, signer);
        assert!(config.verify_counterparty_signature(
            commitments,
            verifier,
            &commitment_sig,
            &htlc_sigs,
        ));
    };

    // Asserts a side's commitment balances, feerate, and in-flight HTLC count.
    let assert_state = |commitments: &ChannelCommitments,
                        side: Side,
                        opener_balance_msat: u64,
                        acceptor_balance_msat: u64,
                        feerate_per_kw: u32,
                        htlc_count: usize| {
        let state = commitments.state(side);
        assert_eq!(state.opener_balance_msat, opener_balance_msat);
        assert_eq!(state.acceptor_balance_msat, acceptor_balance_msat);
        assert_eq!(state.feerate_per_kw, feerate_per_kw);
        assert_eq!(state.htlcs.len(), htlc_count);
    };

    // Opener sends two `update_add_htlc`, an `update_fee`, and
    // `commitment_signed`, committing the HTLCs and the new feerate to the
    // acceptor's commitment #1.
    commitments
        .add_htlc(Side::Acceptor, htlc(0, Side::Opener, 2_000_000_000))
        .expect("balance covers HTLC");
    commitments
        .add_htlc(Side::Acceptor, htlc(1, Side::Opener, 1_000_000_000))
        .expect("balance covers HTLC");
    commitments.update_fee(Side::Acceptor, 500);
    assert_state(
        &commitments,
        Side::Acceptor,
        4_000_000_000,
        3_000_000_000,
        500,
        2,
    );
    commitment_signed(
        &mut commitments,
        &opener_holder,
        &acceptor_holder,
        pubkey1, // Rotate the pubkeys to verify that PCP is updated.
    );

    // Acceptor replies with `commitment_signed`, committing the same to the
    // opener's commitment #1.
    commitments
        .add_htlc(Side::Opener, htlc(0, Side::Opener, 2_000_000_000))
        .expect("balance covers HTLC");
    commitments
        .add_htlc(Side::Opener, htlc(1, Side::Opener, 1_000_000_000))
        .expect("balance covers HTLC");
    commitments.update_fee(Side::Opener, 500);
    assert_state(
        &commitments,
        Side::Opener,
        4_000_000_000,
        3_000_000_000,
        500,
        2,
    );
    commitment_signed(
        &mut commitments,
        &acceptor_holder,
        &opener_holder,
        pubkey2, // Rotate the pubkeys to verify that PCP is updated.
    );

    // The acceptor received both of the opener's HTLCs: it fulfills HTLC 0
    // (crediting itself) and fails HTLC 1 (refunding the opener). Its
    // `commitment_signed` resolves both on the opener's commitment #2.
    commitments
        .fulfill_htlc(Side::Opener, 0, Side::Opener)
        .expect("HTLC 0 is in-flight");
    commitments
        .fail_htlc(Side::Opener, 1, Side::Opener)
        .expect("HTLC 1 is in-flight");
    assert_state(
        &commitments,
        Side::Opener,
        5_000_000_000,
        5_000_000_000,
        500,
        0,
    );
    commitment_signed(
        &mut commitments,
        &acceptor_holder,
        &opener_holder,
        pubkey1, // Rotate the pubkeys to verify that PCP is updated.
    );

    // Opener's reply resolves both on the acceptor's commitment #2.
    commitments
        .fulfill_htlc(Side::Acceptor, 0, Side::Opener)
        .expect("HTLC 0 is in-flight");
    commitments
        .fail_htlc(Side::Acceptor, 1, Side::Opener)
        .expect("HTLC 1 is in-flight");
    assert_state(
        &commitments,
        Side::Acceptor,
        5_000_000_000,
        5_000_000_000,
        500,
        0,
    );
    commitment_signed(
        &mut commitments,
        &opener_holder,
        &acceptor_holder,
        pubkey2, // Rotate the pubkeys to verify that PCP is updated.
    );
}
