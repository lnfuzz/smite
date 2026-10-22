mod harness;
mod programs;

use super::*;
use bitcoin::Amount;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use harness::*;
use programs::*;
use smite::bolt::{
    AcceptChannelTlvs, ChannelReadyTlvs, GossipTimestampFilter, Init, Ping, QueryShortChannelIds,
    QueryShortChannelIdsTlvs, ReplyShortChannelIdsEnd, Warning,
};
use smite_ir::Instruction;
use smite_ir::builder::ProgramBuilder;
use smite_ir::operation::ShutdownScriptVariant;

// -- execute() tests --

// All fields of the sent `open_channel` must match what we expected.
#[test]
fn execute_load_build_send() {
    let oc = announced_open_channel();

    let mut fx = Fixture::new();
    fx.run(&send_open_channel_program(&oc));

    assert_eq!(fx.sent_len(), 1);
    assert_eq!(fx.sent::<OpenChannel>(0), oc.message);
}

#[test]
fn execute_build_channel_announcement() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features_bytes = vec![0x01, 0x02];

    let mut b = ProgramBuilder::new();
    let features = b.append(Operation::LoadFeatures(features_bytes.clone()), &[]);
    let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
    let short_channel_id = b.append(Operation::LoadShortChannelId(scid.as_u64()), &[]);
    let node_sk_1 = b.append(Operation::LoadPrivateKey(node_sk_1_bytes), &[]);
    let node_sk_2 = b.append(Operation::LoadPrivateKey(node_sk_2_bytes), &[]);
    let bitcoin_sk_1 = b.append(Operation::LoadPrivateKey(bitcoin_sk_1_bytes), &[]);
    let bitcoin_sk_2 = b.append(Operation::LoadPrivateKey(bitcoin_sk_2_bytes), &[]);
    let announcement = b.append(
        Operation::BuildChannelAnnouncement,
        &[
            features,
            chain_hash,
            short_channel_id,
            node_sk_1,
            node_sk_2,
            bitcoin_sk_1,
            bitcoin_sk_2,
        ],
    );
    b.append(Operation::SendMessage, &[announcement]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let ca: ChannelAnnouncement = fx.sent(0);

    let secp = Secp256k1::new();
    let pk = |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
    assert_eq!(ca.features, features_bytes);
    assert_eq!(ca.chain_hash, sample_context().chain_hash);
    assert_eq!(ca.short_channel_id, scid);
    assert_eq!(ca.node_id_1, pk(&node_sk_1_bytes));
    assert_eq!(ca.node_id_2, pk(&node_sk_2_bytes));
    assert_eq!(ca.bitcoin_key_1, pk(&bitcoin_sk_1_bytes));
    assert_eq!(ca.bitcoin_key_2, pk(&bitcoin_sk_2_bytes));
    assert_eq!(ca.extra, b"");
    assert!(ca.verify());
}

#[test]
fn execute_build_node_announcement() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let rgb_color = [0x11, 0x22, 0x33];
    let mut alias = [0u8; 32];
    alias[..5].copy_from_slice(b"smite");
    let addresses_bytes = vec![0xaa, 0xbb, 0xcc];

    let mut b = ProgramBuilder::new();
    let node_sk = b.append(Operation::LoadPrivateKey(sk_bytes), &[]);
    let features = b.append(Operation::LoadFeatures(vec![0x01, 0x02]), &[]);
    let timestamp = b.append(Operation::LoadTimestamp(1_700_000_000), &[]);
    let addresses = b.append(Operation::LoadBytes(addresses_bytes.clone()), &[]);
    let announcement = b.append(
        Operation::BuildNodeAnnouncement { rgb_color, alias },
        &[node_sk, features, timestamp, addresses],
    );
    b.append(Operation::SendMessage, &[announcement]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let na: NodeAnnouncement = fx.sent(0);

    let secp = Secp256k1::new();
    let expected_node_id =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
    assert_eq!(na.node_id, expected_node_id);
    assert_eq!(na.features, vec![0x01, 0x02]);
    assert_eq!(na.timestamp, 1_700_000_000);
    assert_eq!(na.rgb_color, rgb_color);
    assert_eq!(na.alias, alias);
    assert_eq!(na.addresses, addresses_bytes);
    assert_eq!(na.extra, b"");
    assert!(na.verify());
}

#[test]
fn execute_build_channel_update() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let scid = ShortChannelId::new(538_532, 845, 1);

    let mut b = ProgramBuilder::new();
    let node_sk = b.append(Operation::LoadPrivateKey(sk_bytes), &[]);
    let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
    let short_channel_id = b.append(Operation::LoadShortChannelId(scid.as_u64()), &[]);
    let timestamp = b.append(Operation::LoadTimestamp(1_715_000_000), &[]);
    let message_flags = b.append(Operation::LoadU8(0x01), &[]); // must_be_one
    let channel_flags = b.append(Operation::LoadU8(0x00), &[]);
    let cltv_expiry_delta = b.append(Operation::LoadU16(144), &[]);
    let htlc_minimum_msat = b.append(Operation::LoadAmount(1_000), &[]);
    let fee_base_msat = b.append(Operation::LoadForwardingFee(1_000), &[]);
    let fee_proportional_millionths = b.append(Operation::LoadForwardingFee(100), &[]);
    let htlc_maximum_msat = b.append(Operation::LoadAmount(99_000_000), &[]);
    let update = b.append(
        Operation::BuildChannelUpdate,
        &[
            node_sk,
            chain_hash,
            short_channel_id,
            timestamp,
            message_flags,
            channel_flags,
            cltv_expiry_delta,
            htlc_minimum_msat,
            fee_base_msat,
            fee_proportional_millionths,
            htlc_maximum_msat,
        ],
    );
    b.append(Operation::SendMessage, &[update]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let cu: ChannelUpdate = fx.sent(0);

    assert_eq!(cu.chain_hash, sample_context().chain_hash);
    assert_eq!(cu.short_channel_id, scid);
    assert_eq!(cu.timestamp, 1_715_000_000);
    assert_eq!(cu.message_flags, 0x01);
    assert_eq!(cu.channel_flags, 0x00);
    assert_eq!(cu.cltv_expiry_delta, 144);
    assert_eq!(cu.htlc_minimum_msat, 1_000);
    assert_eq!(cu.fee_base_msat, 1_000);
    assert_eq!(cu.fee_proportional_millionths, 100);
    assert_eq!(cu.htlc_maximum_msat, 99_000_000);
    assert_eq!(cu.extra, b"");

    let secp = Secp256k1::new();
    let expected_node_id =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
    assert!(cu.verify(&expected_node_id));
}

#[test]
fn execute_build_announcement_signatures() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let channel_id_bytes = [0xbb; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features_bytes = vec![0x01, 0x02];

    // We sign with our own keys and carry the target's as points, so the
    // target's keys are loaded only to derive them.
    let program = {
        let mut b = ProgramBuilder::new();
        let channel_id = b.append(Operation::LoadChannelId(channel_id_bytes), &[]);
        let features = b.append(Operation::LoadFeatures(features_bytes.clone()), &[]);
        let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
        let short_channel_id = b.append(Operation::LoadShortChannelId(scid.as_u64()), &[]);
        let node_sk_1 = b.append(Operation::LoadPrivateKey(node_sk_1_bytes), &[]);
        let node_sk_2 = b.append(Operation::LoadPrivateKey(node_sk_2_bytes), &[]);
        let node_id_2 = b.append(Operation::DerivePoint, &[node_sk_2]);
        let bitcoin_sk_1 = b.append(Operation::LoadPrivateKey(bitcoin_sk_1_bytes), &[]);
        let bitcoin_sk_2 = b.append(Operation::LoadPrivateKey(bitcoin_sk_2_bytes), &[]);
        let bitcoin_key_2 = b.append(Operation::DerivePoint, &[bitcoin_sk_2]);
        let ann_sigs = b.append(
            Operation::BuildAnnouncementSignatures,
            &[
                channel_id,
                features,
                chain_hash,
                short_channel_id,
                node_sk_1,
                node_id_2,
                bitcoin_sk_1,
                bitcoin_key_2,
            ],
        );
        b.append(Operation::SendMessage, &[ann_sigs]);

        b.build()
    };

    let mut fx = Fixture::new();
    fx.run(&program);

    assert_eq!(fx.sent_len(), 1);
    let ann_sigs: AnnouncementSignatures = fx.sent(0);

    assert_eq!(ann_sigs.channel_id, ChannelId::new(channel_id_bytes));
    assert_eq!(ann_sigs.short_channel_id, scid);

    // Verify the signatures in announcement_signatures directly against
    // the channel_announcement body digest.
    let secp = Secp256k1::new();
    let node_sk_1 = SecretKey::from_slice(&node_sk_1_bytes).unwrap();
    let node_sk_2 = SecretKey::from_slice(&node_sk_2_bytes).unwrap();
    let bitcoin_sk_1 = SecretKey::from_slice(&bitcoin_sk_1_bytes).unwrap();
    let bitcoin_sk_2 = SecretKey::from_slice(&bitcoin_sk_2_bytes).unwrap();
    let node_id_ours = PublicKey::from_secret_key(&secp, &node_sk_1);
    let node_id_theirs = PublicKey::from_secret_key(&secp, &node_sk_2);
    let bitcoin_key_ours = PublicKey::from_secret_key(&secp, &bitcoin_sk_1);
    let bitcoin_key_theirs = PublicKey::from_secret_key(&secp, &bitcoin_sk_2);
    let (n1, n2, bk1, bk2) = if node_id_ours.serialize() <= node_id_theirs.serialize() {
        (
            node_id_ours,
            node_id_theirs,
            bitcoin_key_ours,
            bitcoin_key_theirs,
        )
    } else {
        (
            node_id_theirs,
            node_id_ours,
            bitcoin_key_theirs,
            bitcoin_key_ours,
        )
    };
    let placeholder = Signature::from_compact(&[0u8; 64]).unwrap();
    let ca = ChannelAnnouncement {
        node_signature_1: placeholder,
        node_signature_2: placeholder,
        bitcoin_signature_1: placeholder,
        bitcoin_signature_2: placeholder,
        features: features_bytes,
        chain_hash: sample_context().chain_hash,
        short_channel_id: scid,
        node_id_1: n1,
        node_id_2: n2,
        bitcoin_key_1: bk1,
        bitcoin_key_2: bk2,
        extra: Vec::new(),
    };
    let digest = ca.signing_digest();
    assert!(
        secp.verify_ecdsa(&digest, &ann_sigs.node_signature, &node_id_ours)
            .is_ok()
    );
    assert!(
        secp.verify_ecdsa(&digest, &ann_sigs.bitcoin_signature, &bitcoin_key_ours)
            .is_ok()
    );
}

#[test]
fn execute_build_open_channel_with_tlvs() {
    let mut oc = announced_open_channel();
    oc.message.tlvs = OpenChannelTlvs {
        upfront_shutdown_script: Some(vec![0x00, 0x14, 0xab]),
        channel_type: Some(vec![0x01, 0x02]),
    };

    let mut fx = Fixture::new();
    fx.run(&send_open_channel_program(&oc));

    assert_eq!(fx.sent::<OpenChannel>(0), oc.message);
}

// Every pubkey of the `open_channel` is derived from one private key, so the
// message arriving with the expected pubkeys means `DerivePoint` produced the
// correct Point variable.
#[test]
fn execute_derive_point() {
    let oc = SampleOpenChannel::new(PointSource::Secret([0x11; 32]));

    let mut fx = Fixture::new();
    fx.run(&send_open_channel_program(&oc));

    assert_eq!(fx.sent::<OpenChannel>(0), oc.message);
}

#[test]
fn execute_recv_and_extract_all_fields() {
    // Receive accept_channel (v0), then extract all 16 fields (v1..v16).
    let fields = [
        AcceptChannelField::TemporaryChannelId,
        AcceptChannelField::DustLimitSatoshis,
        AcceptChannelField::MaxHtlcValueInFlightMsat,
        AcceptChannelField::ChannelReserveSatoshis,
        AcceptChannelField::HtlcMinimumMsat,
        AcceptChannelField::MinimumDepth,
        AcceptChannelField::ToSelfDelay,
        AcceptChannelField::MaxAcceptedHtlcs,
        AcceptChannelField::FundingPubkey,
        AcceptChannelField::RevocationBasepoint,
        AcceptChannelField::PaymentBasepoint,
        AcceptChannelField::DelayedPaymentBasepoint,
        AcceptChannelField::HtlcBasepoint,
        AcceptChannelField::FirstPerCommitmentPoint,
        AcceptChannelField::UpfrontShutdownScript,
        AcceptChannelField::ChannelType,
    ];

    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel(&mut b, &announced_open_channel());
    for field in fields {
        b.append(
            Operation::ExtractAcceptChannel(field),
            &[negotiated.accept_channel],
        );
    }

    // TODO: Once we add IR support for building accept_channel messages,
    // rebuild a message from the extracted fields and verify it matches the
    // original.

    Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run(&b.build());
}

#[test]
fn execute_recv_unexpected_message() {
    let err = Fixture::new()
        .queue(&Message::Init(Init::empty()))
        .run_err(&negotiate_channel_program(&announced_open_channel()));
    assert!(matches!(
        err,
        ExecuteError::UnexpectedMessage {
            expected: MessageType::ACCEPT_CHANNEL,
            got: MessageType::INIT,
        }
    ));
}

#[test]
fn execute_recv_peer_error() {
    let peer_error = smite::bolt::Error::all_channels("Wrong channel id in channel_ready");

    let err = Fixture::new()
        .queue(&Message::Error(peer_error.clone()))
        .run_err(&negotiate_channel_program(&announced_open_channel()));
    assert!(matches!(err, ExecuteError::PeerError(e) if e == peer_error));
}

#[test]
#[allow(clippy::similar_names)] // ping and pong are the canonical names
fn execute_recv_auto_pong() {
    let ping = Ping {
        num_pong_bytes: 4,
        ignored: vec![0xaa],
    };

    let mut fx = Fixture::new()
        .queue(&Message::Ping(ping))
        .queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&negotiate_channel_program(&announced_open_channel()));

    // Verify exactly two messages were sent: `open_channel` and `pong`.
    assert_eq!(fx.sent_len(), 2);
    fx.sent::<OpenChannel>(0);
    let pong: Pong = fx.sent(1);
    assert_eq!(pong.ignored.len(), 4);
}

#[test]
fn execute_recv_skips_gossip() {
    let gossip = GossipTimestampFilter::new([0u8; 32], 0, 86400);
    let query = QueryShortChannelIds {
        chain_hash: [0u8; 32],
        // encoding type 0, then one 8-byte short_channel_id
        encoded_short_ids: vec![0x00, 0x00, 0x08, 0x3b, 0x04, 0x00, 0x03, 0x4d, 0x00],
        tlvs: QueryShortChannelIdsTlvs::default(),
    };
    let reply_end = ReplyShortChannelIdsEnd {
        chain_hash: [0u8; 32],
        full_information: 1,
    };

    let mut fx = Fixture::new()
        .queue(&Message::GossipTimestampFilter(gossip))
        .queue(&Message::QueryShortChannelIds(query))
        .queue(&Message::ReplyShortChannelIdsEnd(reply_end))
        .queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&negotiate_channel_program(&announced_open_channel()));

    let accept_channel = fx
        .negotiation(&TEMPORARY_CHANNEL_ID)
        .accept_channel
        .as_ref()
        .expect("accept_channel recorded");
    assert_eq!(accept_channel.clone(), sample_accept_channel());
}

#[test]
fn execute_records_negotiation_for_open_and_accept() {
    let mut fx = Fixture::new().queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&negotiate_channel_program(&announced_open_channel()));

    let pending = fx.negotiation(&TEMPORARY_CHANNEL_ID);
    assert_eq!(
        pending.open_channel.temporary_channel_id,
        TEMPORARY_CHANNEL_ID
    );
    let accept_channel = pending.accept_channel.as_ref().unwrap();
    assert_eq!(accept_channel.clone(), sample_accept_channel());
    assert!(!pending.funding_built);
}

#[test]
fn execute_recv_accept_channel_unknown_channel() {
    let unknown_id = TemporaryChannelId::new([0xcc; 32]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(AcceptChannel {
            temporary_channel_id: unknown_id,
            ..sample_accept_channel()
        }))
        .run_err(&negotiate_channel_program(&announced_open_channel()));

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, unknown_id);
    assert!(
        reason.contains(
            "unknown temporary_channel_id: no open_channel was sent for this negotiation"
        )
    );
}

#[test]
fn execute_recv_accept_channel_opener_cannot_afford_fee() {
    // Set `push_msat` so the opener cannot afford the commitment fee
    // requiring the peer to reject the `open_channel` per BOLT 2.
    let mut oc = announced_open_channel();
    oc.message.push_msat = 99_900_000;

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&negotiate_channel_program(&oc));

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, TEMPORARY_CHANNEL_ID);
    assert!(
        reason.contains(
            "invalid open_channel: opener balance 100 sat cannot cover the commitment fee"
        )
    );
}

#[test]
fn execute_recv_accept_channel_rejects_reuse_before_funding() {
    // Send the same `open_channel` a second time and receive another
    // `accept_channel` for it.
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel(&mut b, &announced_open_channel());
    let resent = b.append(
        Operation::SendOpenChannel,
        &[negotiated.open_channel.vars.built],
    );
    b.append(Operation::RecvAcceptChannel, &[resent]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, TEMPORARY_CHANNEL_ID);
    assert!(reason.contains(
        "temporary_channel_id reuse: previous negotiation has not reached funding_created"
    ));
}

#[test]
fn execute_recv_accept_channel_rejects_reused_our_pubkey() {
    // Echo back the opener's (our) `funding_pubkey` in the `accept_channel`.
    let oc = SampleOpenChannel::new(PointSource::Secret([0x11; 32]));
    let reused = oc.message.funding_pubkey;

    let mut b = ProgramBuilder::new();
    let open_channel = send_open_channel(&mut b, &oc);
    b.append(Operation::RecvAcceptChannel, &[open_channel.sent]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(AcceptChannel {
            first_per_commitment_point: reused,
            ..sample_accept_channel()
        }))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, TEMPORARY_CHANNEL_ID);
    assert!(reason.contains(&format!(
        "pubkey reuse: first_per_commitment_point {reused} reuses our key from instruction {}",
        open_channel.sent,
    )));
}

#[test]
fn execute_recv_accept_channel_rejects_reused_target_node_pubkey() {
    let oc = SampleOpenChannel::new(PointSource::Secret([0x11; 32]));
    let reused = sample_context().target_pubkey;

    let mut b = ProgramBuilder::new();
    let open_channel = send_open_channel(&mut b, &oc);
    b.append(Operation::RecvAcceptChannel, &[open_channel.sent]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(AcceptChannel {
            first_per_commitment_point: reused,
            ..sample_accept_channel()
        }))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, TEMPORARY_CHANNEL_ID);
    assert!(reason.contains(&format!(
        "pubkey reuse: first_per_commitment_point {reused} reuses target's node_pubkey on channel {}",
        TemporaryChannelId::ALL
    )));
}

#[test]
fn execute_recv_accept_channel_allows_reused_static_pubkeys() {
    let accept_channel = sample_accept_channel();

    // Run two negotiations with different temporary channel IDs. The second
    // `accept_channel` reuses the first's static pubkeys, but uses a fresh
    // `first_per_commitment_point`
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &announced_open_channel());
    let mut second_open = announced_open_channel();
    second_open.message.temporary_channel_id = SECOND_TEMPORARY_CHANNEL_ID;
    negotiate_channel(&mut b, &second_open);

    let mut fx = Fixture::new()
        .queue(&Message::AcceptChannel(accept_channel.clone()))
        .queue(&Message::AcceptChannel(AcceptChannel {
            temporary_channel_id: SECOND_TEMPORARY_CHANNEL_ID,
            first_per_commitment_point: sample_pubkey(8),
            ..accept_channel
        }));
    fx.run(&b.build());

    assert_eq!(fx.queued_len(), 0);
    for id in [TEMPORARY_CHANNEL_ID, SECOND_TEMPORARY_CHANNEL_ID] {
        assert!(
            fx.negotiation(&id).accept_channel.is_some(),
            "no accept_channel recorded for {id}"
        );
    }
}

#[test]
fn execute_recv_accept_channel_rejects_reused_target_pcp() {
    let accept_channel = sample_accept_channel();

    // Run two negotiations with different temporary channel IDs but the same
    // pubkeys.
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &announced_open_channel());
    let mut second_open = announced_open_channel();
    second_open.message.temporary_channel_id = SECOND_TEMPORARY_CHANNEL_ID;
    negotiate_channel(&mut b, &second_open);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(accept_channel.clone()))
        .queue(&Message::AcceptChannel(AcceptChannel {
            temporary_channel_id: SECOND_TEMPORARY_CHANNEL_ID,
            ..accept_channel
        }))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, SECOND_TEMPORARY_CHANNEL_ID);
    assert!(reason.contains(&format!(
        "pubkey reuse: first_per_commitment_point {} reuses target's per-commitment point on channel {TEMPORARY_CHANNEL_ID} at commitment number 0",
        accept_channel.first_per_commitment_point,
    )));
}

#[test]
fn execute_recv_accept_channel_rejects_reused_our_channel_ready_pubkey() {
    let our_sk = SecretKey::from_slice(&[0x42; 32]).expect("valid secret key");

    // Send a `channel_ready` revealing a point we hold the secret for, then
    // negotiate a channel.
    let mut b = ProgramBuilder::new();
    let channel_id = b.append(Operation::LoadChannelId([0xaa; 32]), &[]);
    let sk = b.append(Operation::LoadPrivateKey(our_sk.secret_bytes()), &[]);
    let our_point = b.append(Operation::DerivePoint, &[sk]);
    let alias = b.append(Operation::LoadShortChannelId(0), &[]);
    let sent_channel_ready = b.append(
        Operation::SendChannelReady {
            include_alias: true,
        },
        &[channel_id, our_point, alias],
    );
    negotiate_channel(&mut b, &announced_open_channel());

    // The target reuses our point as its `htlc_basepoint`.
    let accept_channel = AcceptChannel {
        htlc_basepoint: PublicKey::from_secret_key(&Secp256k1::new(), &our_sk),
        ..sample_accept_channel()
    };
    let err = Fixture::new()
        .queue(&Message::AcceptChannel(accept_channel.clone()))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, accept_channel.temporary_channel_id);
    assert!(reason.contains(&format!(
        "pubkey reuse: htlc_basepoint {} reuses our key from instruction {sent_channel_ready}",
        accept_channel.htlc_basepoint,
    )));
}

#[test]
fn execute_recv_accept_channel_rejects_reused_target_channel_ready_pubkey() {
    let (fx, target_pcp) = recv_channel_ready_fixture();
    let accept_channel = AcceptChannel {
        revocation_basepoint: target_pcp,
        ..sample_accept_channel()
    };

    let mut b = ProgramBuilder::new();
    fund_channel(&mut b);
    b.append(Operation::MineBlocks(6), &[]);
    b.append(Operation::RecvChannelReady, &[]);
    negotiate_channel(&mut b, &announced_open_channel());

    let err = fx
        .queue(&Message::AcceptChannel(accept_channel.clone()))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, accept_channel.temporary_channel_id);
    assert!(reason.contains(&format!(
        "pubkey reuse: revocation_basepoint {} reuses target's per-commitment point on channel {} at commitment number 1",
        accept_channel.revocation_basepoint,
        funding_channel_id()
    )));
}

#[test]
fn execute_records_only_first_open_channel_for_duplicate_id_before_funding() {
    // First open_channel: funding_satoshis = 100_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 200_000.
    let mut b = ProgramBuilder::new();
    let first = send_open_channel(&mut b, &announced_open_channel());

    // Override only funding_satoshis; reuse the first open_channel's other 19 inputs.
    let mut second = first.vars;
    second.funding_satoshis = b.append(Operation::LoadAmount(200_000), &[]);
    second.built = b.append(Operation::BuildOpenChannel, &second.build_inputs());
    b.append(Operation::SendOpenChannel, &[second.built]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // Both open_channel messages went out on the wire, but only the first
    // negotiation is recorded for the shared id.
    assert_eq!(fx.sent_len(), 2);
    assert_eq!(fx.sent::<OpenChannel>(0).funding_satoshis, 100_000);
    assert_eq!(fx.sent::<OpenChannel>(1).funding_satoshis, 200_000);
    let pending = fx.negotiation(&TEMPORARY_CHANNEL_ID);
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
}

#[test]
fn execute_records_open_channel_for_duplicate_id_after_funding() {
    // Negotiated open_channel: funding_satoshis = 10_000_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 100_000.
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    send_funding_created(&mut b);
    send_open_channel(&mut b, &announced_open_channel());

    let mut fx = Fixture::new().queue(&Message::AcceptChannel(funded_accept_channel()));
    fx.run(&b.build());

    let pending = fx.negotiation(&TEMPORARY_CHANNEL_ID);
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
    assert!(pending.accept_channel.is_none());
    assert!(!pending.funding_built);
}

// -- Panic path tests --

#[test]
#[should_panic(expected = "expected 1 inputs, got 0")]
fn execute_wrong_input_count_panics() {
    // `DerivePoint` expects one input.
    Fixture::new().run(&raw_program(&[(Operation::DerivePoint, &[])]));
}

#[test]
#[should_panic(expected = "expected PrivateKey, got Amount")]
fn execute_type_mismatch_panics() {
    // v0 is an Amount; `DerivePoint` wants a PrivateKey.
    Fixture::new().run(&raw_program(&[
        (Operation::LoadAmount(42), &[]),
        (Operation::DerivePoint, &[0]),
    ]));
}

#[test]
#[should_panic(expected = "out of bounds")]
fn execute_variable_out_of_bounds_panics() {
    Fixture::new().run(&raw_program(&[(Operation::SendMessage, &[99])]));
}

#[test]
#[should_panic(expected = "out of bounds")]
fn execute_forward_variable_reference_panics() {
    // v0 refers forward to v1.
    Fixture::new().run(&raw_program(&[
        (Operation::DerivePoint, &[1]),
        (Operation::LoadPrivateKey([0x11; 32]), &[]),
    ]));
}

#[test]
#[should_panic(expected = "is void")]
fn execute_void_variable_reference_panics() {
    // `MineBlocks` produces no variable, so v0 is void.
    Fixture::new().run(&raw_program(&[
        (Operation::MineBlocks(1), &[]),
        (Operation::SendMessage, &[0]),
    ]));
}

#[test]
#[should_panic(expected = "valid private key")]
fn execute_invalid_private_key_panics() {
    let mut b = ProgramBuilder::new();
    let sk = b.append(Operation::LoadPrivateKey([0; 32]), &[]);
    b.append(Operation::DerivePoint, &[sk]);

    Fixture::new().run(&b.build());
}

#[test]
#[should_panic(expected = "expected OpenChannelMessage, got Amount")]
fn execute_send_open_channel_wrong_type_panics() {
    Fixture::new().run(&raw_program(&[
        (Operation::LoadAmount(42), &[]),
        (Operation::SendOpenChannel, &[0]),
    ]));
}

#[test]
#[should_panic(expected = "is void")]
fn execute_affine_overuse_panics() {
    let mut b = ProgramBuilder::new();
    let negotiated = negotiate_channel(&mut b, &announced_open_channel());
    let mut program = b.build();

    // `ProgramBuilder` rejects the reuse itself, so we manually append the
    // second receive instruction.
    program.instructions.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![negotiated.open_channel.sent],
    });

    Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run(&program);
}

// MineBlocks should track calls to mine_blocks
#[test]
fn execute_mine_blocks_invokes_cli() {
    let mut b = ProgramBuilder::new();
    b.append(Operation::MineBlocks(6), &[]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // Verify that mine_blocks was called with the correct number
    assert_eq!(fx.bitcoin().mine_blocks_calls, vec![6]);
    assert_eq!(fx.bitcoin().mined_private_mempool, Vec::<String>::new());
    assert_eq!(fx.rpc().chain_syncs, 1);
}

#[test]
#[should_panic(expected = "expected 0 inputs, got 1")]
fn execute_mine_blocks_wrong_input() {
    // `MineBlocks` takes no inputs.
    Fixture::new().run(&raw_program(&[
        (Operation::LoadAmount(1), &[]),
        (Operation::MineBlocks(6), &[0]),
    ]));
}

#[test]
fn execute_create_and_broadcast_tx() {
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.bitcoin().broadcast_calls.len(), 1);
    let broadcast_tx = &fx.bitcoin().broadcast_calls[0];
    assert_eq!(broadcast_tx.compute_txid(), funding_outpoint().txid);
    assert_eq!(fx.rpc().chain_syncs, 0);
}

// LookupShortChannelId should combine the confirmed block position with
// the funding output's vout to produce the correct SCID, which we verify
// by feeding it into a channel_announcement and decoding the sent message.
#[test]
fn execute_lookup_short_channel_id_confirmed() {
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    b.append(Operation::MineBlocks(6), &[]);
    let scid = b.append(Operation::LookupShortChannelId, &[funding.tx]);
    send_channel_announcement(&mut b, scid);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.bitcoin().mine_blocks_calls, vec![6]);
    // The executor must have queried the mock with the broadcast
    // transaction's txid.
    assert_eq!(fx.bitcoin().block_position_lookups.len(), 1);
    let broadcast_txid = fx.bitcoin().broadcast_calls[0].compute_txid();
    assert_eq!(fx.bitcoin().block_position_lookups[0], broadcast_txid);

    let ca: ChannelAnnouncement = fx.sent(0);
    assert_eq!(ca.short_channel_id, FUNDING_SCID);
}

// LookupShortChannelId should produce the sentinel SCID (0/0/0) when the
// funding transaction is unknown to the node (e.g. never broadcast or
// never confirmed), rather than panicking. We verify the sentinel value
// via the SCID carried in a channel_announcement.
#[test]
fn execute_lookup_short_channel_id_unconfirmed_returns_sentinel() {
    // No BroadcastTransaction and no MineBlocks: the mock reports zero
    // confirmations and get_transaction_block_position returns None.
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx(&mut b);
    let scid = b.append(Operation::LookupShortChannelId, &[funding.tx]);
    send_channel_announcement(&mut b, scid);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    // The mock was queried but returned None (zero confirmations), so the
    // executor took the sentinel path without panicking.
    assert_eq!(fx.bitcoin().mine_blocks_calls, Vec::<u8>::new());
    assert_eq!(fx.bitcoin().block_position_lookups.len(), 1);

    let ca: ChannelAnnouncement = fx.sent(0);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(0, 0, 0));
}

#[test]
fn execute_broadcast_dedupes_rejected_tx_in_private_mempool() {
    // Fund with a dust amount so the built funding tx carries a below-dust
    // output, and broadcast it twice.
    let mut b = ProgramBuilder::new();
    let funding = create_funding_tx_with(&mut b, 200, 15_000);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    b.append(Operation::MineBlocks(1), &[]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.bitcoin().broadcast_calls.len(), 2);
    assert_eq!(
        fx.bitcoin().broadcast_calls[0].compute_txid(),
        fx.bitcoin().broadcast_calls[1].compute_txid(),
    );

    let rejected_hex = bitcoin::consensus::encode::serialize_hex(&fx.bitcoin().broadcast_calls[0]);
    assert_eq!(fx.private_mempool(), []);
    assert_eq!(fx.bitcoin().mined_private_mempool, vec![rejected_hex]);
}

#[test]
fn execute_create_funding_transaction_insufficient_funds() {
    // UTXO too small to cover the funding amount and fees.
    let small_utxo = Utxo {
        amount: Amount::from_sat(1_000),
        ..sample_utxo()
    };
    let mut b = ProgramBuilder::new();
    create_funding_tx(&mut b);

    let err = Fixture::new()
        .with_utxos(vec![small_utxo])
        .run_err(&b.build());
    let ExecuteError::InsufficientFunds(funds_err) = err else {
        panic!("expected InsufficientFunds, got {err:?}");
    };
    assert_eq!(funds_err.available, Amount::from_sat(1_000));
    assert_eq!(funds_err.required, Amount::from_sat(10_007_290));
}

#[test]
fn execute_send_funding_created_and_recv_funding_signed() {
    // The acceptor replies with funding_signed carrying its signature over
    // the opener's commitment.
    let mut fx = recv_funding_signed_fixture();
    fx.run(&fund_channel_program());

    assert_eq!(fx.sent_len(), 2);
    let fc: FundingCreated = fx.sent(1);

    assert_eq!(fc.temporary_channel_id, TEMPORARY_CHANNEL_ID);
    assert_eq!(fc.funding_txid, funding_outpoint().txid);
    assert_eq!(fc.funding_output_index, 0);

    // Verify the signature sent by the opener on the acceptor side.
    let state = fx.channel_state(&funding_channel_id());
    let holder = HolderIdentity {
        side: Side::Acceptor,
        funding_privkey: acceptor_funding_sk(),
        htlc_basepoint_privkey: acceptor_funding_sk(),
    };

    assert!(
        state
            .config
            .verify_counterparty_signature(&state.commitments, &holder, &fc.signature)
    );

    let pending = fx.negotiation(&TEMPORARY_CHANNEL_ID);
    assert!(pending.funding_built);
    assert_eq!(fx.rpc().chain_syncs, 0);
}

#[test]
fn execute_send_funding_created_uses_wire_funding_pubkey() {
    // Swap out the SendFundingCreated privkey. This should not affect the
    // constructed channel config, which uses the negotiated pubkeys. It
    // should only change the signature sent to the target.
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    send_funding_created_with(&mut b, funding, funding.acceptor_privkey);

    // Signing with a key the peer did not negotiate marks the channel as
    // having sent an invalid signature, so receiving a `funding_signed` would
    // be a violation. We therefore stop after sending `funding_created`.
    let mut fx = Fixture::new().queue(&Message::AcceptChannel(funded_accept_channel()));
    fx.run(&b.build());

    let secp = Secp256k1::new();
    let opener_pk = PublicKey::from_secret_key(&secp, &opener_funding_sk());
    // The funding pubkey matches what was negotiated.
    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(state.config.opener.funding_pubkey, opener_pk);
    // But the swapped privkey used for signing is the acceptor's, which
    // does not match what was negotiated.
    assert_eq!(state.holder.funding_privkey, acceptor_funding_sk());
    assert_ne!(
        state.config.opener.funding_pubkey,
        PublicKey::from_secret_key(&secp, &state.holder.funding_privkey)
    );
}

#[test]
fn execute_send_funding_created_after_funding_built_does_not_track_channel() {
    // A second UTXO so the program can build a second funding transaction.
    let second_utxo = Utxo {
        outpoint: OutPoint {
            vout: 1,
            ..sample_utxo().outpoint
        },
        ..sample_utxo()
    };

    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    let first = send_funding_created(&mut b);

    // The opener's pubkey is used on both sides of the funding script, creating
    // a different outpoint than the first funding transaction's.
    let funding = first.tx;
    let second_tx = b.append(
        Operation::CreateFundingTransaction,
        &[
            funding.opener_pubkey,
            funding.opener_pubkey,
            funding.funding_satoshis,
            funding.feerate_per_kw,
        ],
    );
    b.append(
        Operation::SendFundingCreated,
        &[
            second_tx,
            funding.opener_privkey,
            funding.opener_privkey,
            first.temporary_channel_id,
        ],
    );

    let mut fx = Fixture::new()
        .with_utxos(vec![sample_utxo(), second_utxo])
        .queue(&Message::AcceptChannel(funded_accept_channel()));
    fx.run(&b.build());

    // The message still goes out, only the state tracking is suppressed.
    assert_eq!(fx.sent_len(), 3);
    assert_eq!(fx.channel_states().len(), 1);
    // The tracked channel id derives from the first funding transaction's
    // outpoint.
    assert!(fx.channel_states().contains_key(&funding_channel_id()));
}

#[test]
fn execute_send_funding_created_no_open_channel() {
    // No negotiation exists for this temporary_channel_id, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut fx = Fixture::new();
    fx.run(&send_funding_created_program());

    let fc: FundingCreated = fx.sent(0);
    assert_eq!(fc.temporary_channel_id, TEMPORARY_CHANNEL_ID);
    assert_eq!(fc.funding_txid, funding_outpoint().txid);
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(fx.channel_states().is_empty());
}

#[test]
fn execute_send_funding_created_no_accept_channel() {
    // The `accept_channel` has not been received yet, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut b = ProgramBuilder::new();
    send_open_channel(&mut b, &funded_open_channel());
    send_funding_created(&mut b);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    let fc: FundingCreated = fx.sent(1);
    assert_eq!(fc.temporary_channel_id, TEMPORARY_CHANNEL_ID);
    assert_eq!(fc.funding_txid, funding_outpoint().txid);
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(fx.channel_states().is_empty());
}

#[test]
fn execute_recv_funding_signed_unknown_channel() {
    let channel_id = ChannelId::new([0xbb; 32]);

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(funded_accept_channel()))
        .queue(&funding_signed_reply(channel_id))
        .run_err(&fund_channel_program());
    let ExecuteError::Violation(Violation::InvalidFundingSigned(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, channel_id);
    assert!(reason.contains("unknown channel_id: no funding_created was sent for this channel"));
}

#[test]
fn execute_recv_funding_signed_invalid_signature() {
    let channel_id = funding_channel_id();
    let err = Fixture::new()
        .queue(&Message::AcceptChannel(funded_accept_channel()))
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: Signature::from_compact(&[0u8; 64])
                .expect("zero bytes parse as a signature"),
        }))
        .run_err(&fund_channel_program());
    let ExecuteError::Violation(Violation::InvalidFundingSigned(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, channel_id);
    assert!(reason.contains("invalid funding_signed: signature is not valid"));
}

#[test]
fn execute_recv_funding_signed_after_invalid_funding_created() {
    let channel_id = funding_channel_id();

    // Sign the commitment with the acceptor's private key instead of the
    // opener's, so the signature does not match the `funding_pubkey` negotiated
    // in `open_channel`.
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    let funding = create_funding_tx(&mut b);
    let funding_created = send_funding_created_with(&mut b, funding, funding.acceptor_privkey);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);

    let err = recv_funding_signed_fixture().run_err(&b.build());
    let ExecuteError::Violation(Violation::InvalidFundingSigned(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, channel_id);
    assert!(reason.contains("accepted invalid funding_created: signature is not valid"));
}

#[test]
fn execute_recv_funding_signed_duplicate() {
    let channel_id = funding_channel_id();

    // Resend the same `funding_created`, which maps to the same channel, and
    // receive a valid `funding_signed` for each.
    let mut b = ProgramBuilder::new();
    let tx = fund_channel(&mut b).funding_created.tx;
    let second = send_funding_created_with(&mut b, tx, tx.opener_privkey);
    b.append(Operation::RecvFundingSigned, &[second.sent]);

    let err = recv_funding_signed_fixture()
        .queue(&funding_signed_reply(channel_id))
        .run_err(&b.build());
    let ExecuteError::Violation(Violation::InvalidFundingSigned(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, channel_id);
    assert!(reason.contains("duplicate funding_signed: channel already funded"));
}

#[test]
fn execute_send_channel_ready() {
    let channel_id = funding_channel_id();
    let alias = ShortChannelId::new(538_532, 845, 1);
    let mut b = ProgramBuilder::new();
    let funded = fund_channel(&mut b);
    let alias_scid = b.append(Operation::LoadShortChannelId(alias.as_u64()), &[]);
    b.append(
        Operation::SendChannelReady {
            include_alias: false,
        },
        &[
            funded.channel_id,
            funded.funding_created.tx.opener_pubkey,
            alias_scid,
        ],
    );
    b.append(
        Operation::SendChannelReady {
            include_alias: true,
        },
        &[
            funded.channel_id,
            funded.funding_created.tx.acceptor_pubkey,
            alias_scid,
        ],
    );

    let mut fx = recv_funding_signed_fixture();
    fx.run(&b.build());

    // The instructions send 1 `open_channel`, 1 `funding_created` and 2
    // `channel_ready` messages.
    assert_eq!(fx.sent_len(), 4);

    // The two `channel_ready`s carry the opener's and acceptor's funding
    // pubkeys as their points.
    let secp = Secp256k1::new();
    let expected_pcp1 = PublicKey::from_secret_key(&secp, &opener_funding_sk());
    let expected_pcp2 = PublicKey::from_secret_key(&secp, &acceptor_funding_sk());

    // The first channel_ready was sent with include_alias = false, so it must
    // not carry the short_channel_id TLV.
    let cr1: ChannelReady = fx.sent(2);
    assert_eq!(cr1.channel_id, channel_id);
    assert_eq!(cr1.second_per_commitment_point, expected_pcp1);
    assert!(cr1.tlvs.short_channel_id.is_none());

    // The second channel_ready was sent with include_alias = true, so it must
    // carry the alias SCID we loaded in its short_channel_id TLV.
    let cr2: ChannelReady = fx.sent(3);
    assert_eq!(cr2.channel_id, channel_id);
    assert_eq!(cr2.second_per_commitment_point, expected_pcp2);
    assert_eq!(cr2.tlvs.short_channel_id, Some(alias));

    // The holder's next per-commitment point must hold the first
    // `channel_ready`'s point, not any subsequent one.
    let state = fx.channel_state(&channel_id);
    assert_eq!(
        *state.next_holder_per_commitment_point(),
        Some(expected_pcp1)
    );
}

#[test]
fn execute_send_shutdown() {
    let channel_id = ChannelId::new([0x7a; 32]);
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);

    let mut b = ProgramBuilder::new();
    let channel_id_var = b.append(Operation::LoadChannelId(channel_id.0), &[]);
    let scriptpubkey = b.append(Operation::LoadShutdownScript(script.clone()), &[]);
    b.append(Operation::SendShutdown, &[channel_id_var, scriptpubkey]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let sd: Shutdown = fx.sent(0);
    assert_eq!(sd.channel_id, channel_id);
    assert_eq!(sd.scriptpubkey, script.encode());
}

#[test]
fn execute_send_shutdown_empty_scriptpubkey() {
    let channel_id = ChannelId::new([0x7a; 32]);
    // The fuzzer should allow an empty scriptpubkey in the shutdown message
    // to exercise the target's behavior even though it's protocol-invalid.
    let mut b = ProgramBuilder::new();
    let channel_id_var = b.append(Operation::LoadChannelId(channel_id.0), &[]);
    let scriptpubkey = b.append(
        Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
        &[],
    );
    b.append(Operation::SendShutdown, &[channel_id_var, scriptpubkey]);

    let mut fx = Fixture::new();
    fx.run(&b.build());

    assert_eq!(fx.sent_len(), 1);
    let sd: Shutdown = fx.sent(0);
    assert_eq!(sd.channel_id, channel_id);
    assert_eq!(sd.scriptpubkey, b"");
}

#[test]
fn execute_send_shutdown_records_our_script() {
    let (mut fx, _) = recv_channel_ready_fixture();
    let channel_id = funding_channel_id();
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);

    let mut b = ProgramBuilder::new();
    establish_channel(&mut b, 6);
    send_shutdown(&mut b, channel_id, script.clone());

    fx.run(&b.build());

    // Our script is what makes a reply expected on this channel.
    assert_eq!(
        fx.channel_state(&channel_id).our_shutdown_script,
        Some(script.encode())
    );
    assert_eq!(
        fx.channel_state(&channel_id).counterparty_shutdown_script,
        None
    );
}

#[test]
fn execute_recv_shutdown() {
    let (fx, _) = recv_channel_ready_fixture();
    let channel_id = funding_channel_id();
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
    let mut fx = fx.queue(&Message::Shutdown(Shutdown::for_channel(
        channel_id,
        script.encode(),
    )));

    fx.run(&recv_shutdown_program(channel_id, script));

    // TODO: Once we add IR support for building closing transactions, verify
    // the returned scriptpubkey through the closing transaction's output.

    assert!(
        fx.channel_state(&channel_id)
            .counterparty_shutdown_script
            .is_some()
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_skips_implicit_channel_ready() {
    // A `channel_ready` arriving while `RecvShutdown` waits is recorded and
    // skipped, and the target's `shutdown` still completes the receive.
    let (fx, target_pcp) = recv_channel_ready_fixture();
    let channel_id = funding_channel_id();
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
    // A resend carrying the same point, which the `channel_ready` oracle allows.
    let mut fx = fx
        .queue(&channel_ready_reply(target_pcp))
        .queue(&Message::Shutdown(Shutdown::for_channel(
            channel_id,
            script.encode(),
        )));

    fx.run(&recv_shutdown_program(channel_id, script.clone()));

    // The `channel_ready` was skipped instead of ending the program, so the
    // `shutdown` behind it still arrived.
    let state = fx.channel_state(&channel_id);
    assert_eq!(state.counterparty_shutdown_script, Some(script.encode()));
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_received_early() {
    // The target's `shutdown` arrives while `RecvChannelReady` is waiting, so
    // it is recorded before `RecvShutdown` runs, which must still report it.
    let channel_id = funding_channel_id();
    let target_script = ShutdownScriptVariant::P2wpkh([0xcd; 20]);
    let mut fx = recv_funding_signed_fixture()
        .queue(&Message::Shutdown(Shutdown::for_channel(
            channel_id,
            target_script.encode(),
        )))
        .queue(&channel_ready_reply(sample_pubkey(7)));

    let mut b = ProgramBuilder::new();
    fund_channel(&mut b);
    b.append(Operation::MineBlocks(6), &[]);
    let shutdown = send_shutdown(
        &mut b,
        channel_id,
        ShutdownScriptVariant::P2wpkh([0xab; 20]),
    );
    b.append(Operation::RecvChannelReady, &[]);
    let spk = b.append(
        Operation::RecvShutdown,
        &[shutdown.sent, shutdown.channel_id],
    );
    // Put the produced script back on the wire so it can be inspected.
    b.append(Operation::SendShutdown, &[shutdown.channel_id, spk]);

    fx.run(&b.build());

    assert_eq!(
        fx.channel_state(&channel_id).counterparty_shutdown_script,
        Some(target_script.encode())
    );
    let echoed: Shutdown = fx.sent(fx.sent_len() - 1);
    assert_eq!(echoed.scriptpubkey, target_script.encode());
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_reports_own_channel() {
    let channel_id = funding_channel_id();
    let other = second_funding_channel_id();

    // Establish both channels.
    let mut fx = recv_two_accept_channel_fixture()
        .queue(&channel_ready_reply(sample_pubkey(7)))
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: other,
            second_per_commitment_point: sample_pubkey(8),
            tlvs: ChannelReadyTlvs::default(),
        }));
    fx.run(&recv_two_channel_ready_program());

    // We sent a `shutdown` on both channels and the other channel is answered
    // first, so a lookup ignoring the channel would report its script.
    let other_script = ShutdownScriptVariant::P2wpkh([0x11; 20]);
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
    let mut fx = fx
        .queue(&Message::Shutdown(Shutdown::for_channel(
            other,
            other_script.encode(),
        )))
        .queue(&Message::Shutdown(Shutdown::for_channel(
            channel_id,
            script.encode(),
        )));
    let mut b = ProgramBuilder::new();
    send_shutdown(&mut b, other, other_script.clone());
    let shutdown = send_shutdown(&mut b, channel_id, script.clone());
    let spk = b.append(
        Operation::RecvShutdown,
        &[shutdown.sent, shutdown.channel_id],
    );
    // Put the produced script back on the wire so it can be inspected.
    b.append(Operation::SendShutdown, &[shutdown.channel_id, spk]);

    fx.run(&b.build());

    assert_eq!(
        fx.channel_state(&other).counterparty_shutdown_script,
        Some(other_script.encode())
    );
    let echoed: Shutdown = fx.sent(fx.sent_len() - 1);
    assert_eq!(echoed.scriptpubkey, script.encode());
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_unknown_channel() {
    let (fx, _) = recv_channel_ready_fixture();
    let unknown = ChannelId::new([0x7a; 32]);
    let script = ShutdownScriptVariant::P2wpkh([0xcd; 20]);
    // A `shutdown` is judged against its channel, so one for a channel we never
    // funded is a violation.
    let mut fx = fx.queue(&Message::Shutdown(Shutdown::for_channel(
        unknown,
        script.encode(),
    )));

    let err = fx.run_err(&recv_shutdown_program(funding_channel_id(), script));

    let ExecuteError::Violation(Violation::InvalidShutdown(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, unknown);
    assert_eq!(reason, "unknown channel_id: no channel was funded for it");
}

#[test]
fn execute_recv_shutdown_other_tracked_channel() {
    let channel_id = funding_channel_id();
    let other = second_funding_channel_id();

    // Establish both channels.
    let mut fx = recv_two_accept_channel_fixture()
        .queue(&channel_ready_reply(sample_pubkey(7)))
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: other,
            second_per_commitment_point: sample_pubkey(8),
            tlvs: ChannelReadyTlvs::default(),
        }));
    fx.run(&recv_two_channel_ready_program());

    // A `shutdown` on a channel we sent none on may answer one sent there
    // earlier. It is recorded against that channel and skipped, and we keep
    // waiting for ours.
    let other_script = ShutdownScriptVariant::P2wpkh([0x11; 20]);
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
    let mut fx = fx
        .queue(&Message::Shutdown(Shutdown::for_channel(
            other,
            other_script.encode(),
        )))
        .queue(&Message::Shutdown(Shutdown::for_channel(
            channel_id,
            script.encode(),
        )));
    let mut b = ProgramBuilder::new();
    let shutdown = send_shutdown(&mut b, channel_id, script.clone());
    b.append(
        Operation::RecvShutdown,
        &[shutdown.sent, shutdown.channel_id],
    );

    fx.run(&b.build());

    assert_eq!(
        fx.channel_state(&channel_id).counterparty_shutdown_script,
        Some(script.encode())
    );
    assert_eq!(
        fx.channel_state(&other).counterparty_shutdown_script,
        Some(other_script.encode())
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_after_response_is_noop() {
    let (fx, _) = recv_channel_ready_fixture();
    let channel_id = funding_channel_id();
    let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
    // Only one reply is queued: once the target has responded, the second
    // RecvShutdown must be a no-op rather than block on an empty queue.
    let mut fx = fx.queue(&Message::Shutdown(Shutdown::for_channel(
        channel_id,
        script.encode(),
    )));

    let mut b = ProgramBuilder::new();
    establish_channel(&mut b, 6);
    let first = send_shutdown(&mut b, channel_id, script);
    b.append(Operation::RecvShutdown, &[first.sent, first.channel_id]);
    let second = b.append(
        Operation::SendShutdown,
        &[first.channel_id, first.scriptpubkey],
    );
    b.append(Operation::RecvShutdown, &[second, first.channel_id]);

    fx.run(&b.build());

    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_before_channel_ready_is_noop() {
    // The target has not sent `channel_ready`, so it may ignore our `shutdown`.
    // No reply is queued: RecvShutdown must be a no-op rather than block on an
    // empty queue.
    let channel_id = funding_channel_id();
    let mut fx = recv_funding_signed_fixture();

    let mut b = ProgramBuilder::new();
    fund_channel(&mut b);
    let shutdown = send_shutdown(
        &mut b,
        channel_id,
        ShutdownScriptVariant::P2wpkh([0xab; 20]),
    );
    b.append(
        Operation::RecvShutdown,
        &[shutdown.sent, shutdown.channel_id],
    );

    fx.run(&b.build());

    // We sent one, so a reply would be expected once `channel_ready` arrives.
    assert!(fx.channel_state(&channel_id).our_shutdown_script.is_some());
    assert!(
        fx.channel_state(&channel_id)
            .counterparty_shutdown_script
            .is_none()
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_shutdown_untracked_channel_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();
    let untracked = ChannelId::new([0x99; 32]);

    // No shutdown reply is queued: a RecvShutdown for a channel we never
    // established must be a no-op rather than block on an empty queue.
    fx.run(&recv_shutdown_program(
        untracked,
        ShutdownScriptVariant::P2wpkh([0xab; 20]),
    ));

    assert_eq!(fx.queued_len(), 0);
}

fn warning_reply(channel_id: ChannelId) -> Message {
    Message::Warning(Warning {
        channel_id,
        data: b"non-standard scriptpubkey".to_vec(),
    })
}

#[test]
fn execute_recv_shutdown_warning_ends_execution() {
    // BOLT 2 lets the target warn about our non-standard `scriptpubkey` instead
    // of replying, but every implementation except LDK disconnects afterwards
    // and LDK acts as if the `shutdown` never came, so a warning just ends
    // execution, whichever channel it names.
    for channel_id in [
        funding_channel_id(),
        ChannelId::ALL,
        ChannelId::new([0x99; 32]),
    ] {
        let (fx, _) = recv_channel_ready_fixture();
        let mut fx = fx.queue(&warning_reply(channel_id));

        let err = fx.run_err(&recv_shutdown_program(
            funding_channel_id(),
            ShutdownScriptVariant::Empty,
        ));

        assert!(matches!(
            err,
            ExecuteError::UnexpectedMessage {
                expected: MessageType::SHUTDOWN,
                got: MessageType::WARNING,
            }
        ));
    }
}

#[test]
fn execute_recv_shutdown_reply_to_non_standard_script() {
    let (fx, _) = recv_channel_ready_fixture();
    let channel_id = funding_channel_id();
    // The target SHOULD warn about our non-standard `scriptpubkey`, but may
    // reply with a `shutdown` anyway, which must still be valid.
    let mut fx = fx.queue(&Message::Shutdown(Shutdown::for_channel(
        channel_id,
        ShutdownScriptVariant::P2wpkh([0xcd; 20]).encode(),
    )));

    fx.run(&recv_shutdown_program(
        channel_id,
        ShutdownScriptVariant::Empty,
    ));

    assert!(
        fx.channel_state(&channel_id)
            .counterparty_shutdown_script
            .is_some()
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_channel_ready_invalid_funding_outpoint_is_noop() {
    // The target negotiates a funding pubkey that differs from what we use for
    // the funding outpoint's 2-of-2 script, so the executor marks the funding
    // outpoint as invalid and doesn't expect a `channel_ready` response.
    //
    // We change the acceptor's key and not the opener's, since the latter would
    // no longer match the opener private key we sign with and so also set
    // `sent_invalid_signature`, leaving the invalid funding outpoint gate
    // unreached.
    let accept_channel = AcceptChannel {
        funding_pubkey: sample_pubkey(1),
        ..funded_accept_channel()
    };

    // The changed pubkey modifies the funding script, so our precomputed
    // funding_signed signature will no longer verify correctly. That
    // exchange is not what this test is about, so we neither queue the
    // funding_signed nor receive it.
    let mut fx = Fixture::new()
        .queue(&Message::AcceptChannel(accept_channel))
        .queue(&channel_ready_reply(sample_pubkey(1)));
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    send_funding_created(&mut b);
    b.append(Operation::MineBlocks(8), &[]);
    b.append(Operation::RecvChannelReady, &[]);

    // With invalid funding outpoint the target does not owe us a
    // `channel_ready`, so `RecvChannelReady` must be a no-op.
    fx.run(&b.build());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(!state.is_funding_outpoint_valid);
    assert!(!state.was_funding_mined_prematurely);
    assert!(!state.sent_invalid_signature);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert!(state.received_channel_ready_point.is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_below_minimum_depth_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    // Mine one block fewer than the `minimum_depth` negotiated in
    // `funded_accept_channel()`.
    // With fewer than the negotiated `minimum_depth` confirmations the target
    // does not yet owe us a `channel_ready`, so `RecvChannelReady` must be a
    // no-op.
    fx.run(&recv_channel_ready_program(5));
    assert_eq!(fx.bitcoin().mined_private_mempool, Vec::<String>::new());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.is_funding_outpoint_valid);
    assert!(!state.was_funding_mined_prematurely);
    assert!(!state.sent_invalid_signature);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert!(state.received_channel_ready_point.is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_at_minimum_depth_records_point() {
    let (mut fx, target_pcp) = recv_channel_ready_fixture();

    // Mine exactly the `minimum_depth` negotiated in `funded_accept_channel()`.
    // At the negotiated `minimum_depth` confirmations the target owes us a
    // `channel_ready`, which `RecvChannelReady` receives and records.
    fx.run(&recv_channel_ready_program(6));
    assert_eq!(fx.bitcoin().mined_private_mempool, Vec::<String>::new());

    // The `channel_ready` was consumed and the target's next per-commitment
    // point is now recorded.
    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert_eq!(state.received_channel_ready_point, Some(target_pcp));
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_channel_ready_funding_mined_prematurely_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    // Mine past the negotiated `minimum_depth` *before* sending
    // `funding_created`.
    b.append(Operation::MineBlocks(8), &[]);
    let funding_created = send_funding_created_with(&mut b, funding, funding.opener_privkey);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);
    b.append(Operation::RecvChannelReady, &[]);

    // The funding transaction confirmed before `funding_created`, so the
    // target may never observe the confirmation and `RecvChannelReady` must
    // be a no-op even though the confirmation count is sufficient.
    fx.run(&b.build());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.is_funding_outpoint_valid);
    assert!(state.was_funding_mined_prematurely);
    assert!(!state.sent_invalid_signature);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert!(state.received_channel_ready_point.is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_invalid_signature_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, &funded_open_channel());
    let funding = create_funding_tx(&mut b);
    b.append(Operation::BroadcastTransaction, &[funding.tx]);
    // Sign the commitment with the acceptor's private key instead of the
    // opener's, so the signature does not match the `funding_pubkey` negotiated
    // in `open_channel`.
    //
    // A `funding_signed` answering a `funding_created` we signed with the wrong
    // key is itself a violation, which `FundingSignedOracle` reports. So we
    // don't receive one, letting `RecvChannelReady` be reached.
    send_funding_created_with(&mut b, funding, funding.acceptor_privkey);
    b.append(Operation::MineBlocks(8), &[]);
    b.append(Operation::RecvChannelReady, &[]);

    // Having signed with the wrong key, the target does not owe us a
    // `channel_ready`, so `RecvChannelReady` must be a no-op.
    fx.run(&b.build());

    // The target's next per-commitment point is still unknown and the queued
    // `funding_signed` and `channel_ready` remain untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.is_funding_outpoint_valid);
    assert!(!state.was_funding_mined_prematurely);
    assert!(state.sent_invalid_signature);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert!(state.received_channel_ready_point.is_none());
    assert_eq!(fx.queued_len(), 2);
}

#[test]
fn execute_recv_channel_ready_resend_with_new_alias() {
    let target_pcp = sample_pubkey(9);

    // Instead of a `channel_ready` for the second channel, the target resends
    // the first channel's with a different alias but otherwise identical
    // contents.
    let mut fx = recv_two_accept_channel_fixture()
        .queue(&channel_ready_reply(target_pcp))
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: funding_channel_id(),
            second_per_commitment_point: target_pcp,
            tlvs: ChannelReadyTlvs {
                short_channel_id: Some(ShortChannelId::from_u64(0)),
            },
        }));
    fx.run(&recv_two_channel_ready_program());

    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert_eq!(state.received_channel_ready_point, Some(target_pcp));
    assert_eq!(fx.queued_len(), 0);
    assert_eq!(fx.channel_states().len(), 2);
}

#[test]
fn execute_recv_channel_ready_rejects_alias_reused_by_another_channel() {
    // The second channel's `channel_ready` advertises the alias the first
    // channel already advertised.
    let alias = ShortChannelId::from_u64(42);
    let err = recv_two_accept_channel_fixture()
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: funding_channel_id(),
            second_per_commitment_point: sample_pubkey(7),
            tlvs: ChannelReadyTlvs {
                short_channel_id: Some(alias),
            },
        }))
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: second_funding_channel_id(),
            second_per_commitment_point: sample_pubkey(8),
            tlvs: ChannelReadyTlvs {
                short_channel_id: Some(alias),
            },
        }))
        .run_err(&recv_two_channel_ready_program());

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, second_funding_channel_id());
    assert!(reason.contains(&format!(
        "short_channel_id alias {alias} reuses the short_channel_id of channel {}",
        funding_channel_id(),
    )));
}

#[test]
fn execute_recv_channel_ready_rejects_alias_matching_another_channels_scid() {
    // The second channel advertises an alias matching the first channel's real
    // short channel ID.
    let alias = FUNDING_SCID;
    let err = recv_two_accept_channel_fixture()
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: funding_channel_id(),
            second_per_commitment_point: sample_pubkey(7),
            tlvs: ChannelReadyTlvs::default(),
        }))
        .queue(&Message::ChannelReady(ChannelReady {
            channel_id: second_funding_channel_id(),
            second_per_commitment_point: sample_pubkey(8),
            tlvs: ChannelReadyTlvs {
                short_channel_id: Some(alias),
            },
        }))
        .run_err(&recv_two_channel_ready_program());

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, second_funding_channel_id());
    assert!(reason.contains(&format!(
        "short_channel_id alias {alias} reuses the short_channel_id of channel {}",
        funding_channel_id(),
    )));
}

#[test]
fn execute_recv_channel_ready_already_recorded_is_noop() {
    let (fx, target_pcp) = recv_channel_ready_fixture();
    let mut fx = fx.queue(&Message::AcceptChannel(sample_accept_channel()));

    let mut b = ProgramBuilder::new();
    fund_channel(&mut b);
    b.append(Operation::MineBlocks(6), &[]);
    // The target's `channel_ready` arrives before this `accept_channel`, so
    // `RecvAcceptChannel` records it.
    negotiate_channel(&mut b, &announced_open_channel());
    b.append(Operation::RecvChannelReady, &[]);

    // The `channel_ready` was already recorded, so `RecvChannelReady` must be
    // a no-op.
    fx.run(&b.build());

    // The `channel_ready` was consumed and the target's next per-commitment
    // point is now recorded.
    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert_eq!(state.received_channel_ready_point, Some(target_pcp));
    assert!(state.funding_signed_received);
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_channel_ready_resend_rejects_changed_point() {
    let (fx, target_pcp) = recv_channel_ready_fixture();
    let changed = sample_pubkey(8);

    // After the target's first `channel_ready` is received, it resends one for
    // the same channel with a different `second_per_commitment_point`.
    //
    // `RecvChannelReady` becomes a no-op after the first expected
    // `channel_ready` has been recorded, so we negotiate a second unrelated
    // channel whose `RecvAcceptChannel` receives the `channel_ready` implicitly.
    let mut b = ProgramBuilder::new();
    fund_channel(&mut b);
    b.append(Operation::MineBlocks(6), &[]);
    b.append(Operation::RecvChannelReady, &[]);
    negotiate_channel(&mut b, &announced_open_channel());

    let err = fx
        .queue(&channel_ready_reply(changed))
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, funding_channel_id());
    assert!(reason.contains(&format!(
        "channel_ready resend changed second_per_commitment_point from {target_pcp} to {changed}"
    )));
}

#[test]
fn execute_recv_channel_ready_rejects_below_minimum_depth() {
    let (fx, _) = recv_channel_ready_fixture();

    // Mine one block fewer than the `minimum_depth` negotiated in
    // `accept_channel`. The target's `channel_ready` arrives early, which means
    // `RecvChannelReady` acts as a no-op and won't wait for it. Instead we
    // negotiate a second unrelated channel whose `RecvAcceptChannel` receives
    // the `channel_ready` implicitly.
    let mut b = ProgramBuilder::new();
    fund_channel(&mut b);
    b.append(Operation::MineBlocks(5), &[]);
    negotiate_channel(&mut b, &announced_open_channel());

    let err = fx
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, funding_channel_id());
    assert!(
        reason.contains(
            "channel_ready received with 5 funding confirmation(s), below minimum_depth 6"
        )
    );
}

#[test]
fn execute_recv_implicit_channel_ready_unknown_channel() {
    // No channel is tracked, so a `channel_ready` received while waiting for
    // `accept_channel` is a violation.
    let err = Fixture::new()
        .queue(&channel_ready_reply(sample_pubkey(1)))
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&negotiate_channel_program(&announced_open_channel()));
    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, funding_channel_id());
    assert!(reason.contains("unknown channel_id: no channel was funded for it"));
}

#[test]
fn execute_recv_channel_ready_unexpected_message() {
    // The target owes us a `channel_ready` but sends an explicitly handled
    // message instead, which `RecvChannelReady` must not skip.
    let err = recv_funding_signed_fixture()
        .queue(&Message::Init(Init::empty()))
        .run_err(&recv_channel_ready_program(6));
    assert!(matches!(
        err,
        ExecuteError::UnexpectedMessage {
            expected: MessageType::CHANNEL_READY,
            got: MessageType::INIT,
        }
    ));
}

#[test]
fn execute_recv_channel_ready_rejects_reused_our_pubkey() {
    // The target's `channel_ready` reuses a pubkey we revealed in our
    // `open_channel`.
    let reused = funded_open_channel().message.funding_pubkey;

    let mut b = ProgramBuilder::new();
    let funded = fund_channel(&mut b);
    b.append(Operation::MineBlocks(6), &[]);
    b.append(Operation::RecvChannelReady, &[]);

    let err = recv_funding_signed_fixture()
        .queue(&channel_ready_reply(reused))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, funding_channel_id());
    assert!(reason.contains(&format!(
        "second_per_commitment_point {reused} reuses our key from instruction {}",
        funded.negotiated.open_channel.sent,
    )));
}

#[test]
fn execute_recv_channel_ready_rejects_reused_target_static_pubkey() {
    // The target's `channel_ready` reuses a static pubkey it revealed in its
    // `accept_channel`. A distinct key in a non-first field shows every static
    // pubkey is recorded, not just `funding_pubkey`.
    let accept_channel = AcceptChannel {
        delayed_payment_basepoint: sample_pubkey(11),
        ..funded_accept_channel()
    };
    let reused = accept_channel.delayed_payment_basepoint;

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(accept_channel))
        .queue(&funding_signed_reply(funding_channel_id()))
        .queue(&channel_ready_reply(reused))
        .run_err(&recv_channel_ready_program(6));

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, funding_channel_id());
    assert!(reason.contains(&format!(
        "second_per_commitment_point {reused} reuses target's delayed_payment_basepoint on channel {TEMPORARY_CHANNEL_ID}"
    )));
}

#[test]
fn execute_recv_channel_ready_rejects_reused_our_channel_ready_pubkey() {
    let our_sk = SecretKey::from_slice(&[0x42; 32]).expect("valid secret key");
    let reused = PublicKey::from_secret_key(&Secp256k1::new(), &our_sk);

    // Send a `channel_ready` revealing a point we hold the secret for, then the
    // target's `channel_ready` reuses it.
    let mut b = ProgramBuilder::new();
    let channel_id = fund_channel(&mut b).channel_id;
    b.append(Operation::MineBlocks(6), &[]);
    let sk = b.append(Operation::LoadPrivateKey(our_sk.secret_bytes()), &[]);
    let our_point = b.append(Operation::DerivePoint, &[sk]);
    let alias = b.append(Operation::LoadShortChannelId(0), &[]);
    let sent_channel_ready = b.append(
        Operation::SendChannelReady {
            include_alias: true,
        },
        &[channel_id, our_point, alias],
    );
    b.append(Operation::RecvChannelReady, &[]);

    let err = recv_funding_signed_fixture()
        .queue(&channel_ready_reply(reused))
        .run_err(&b.build());

    let ExecuteError::Violation(Violation::InvalidChannelReady(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, funding_channel_id());
    assert!(reason.contains(&format!(
        "second_per_commitment_point {reused} reuses our key from instruction {sent_channel_ready}"
    )));
}

// -- extract_field tests --

// TODO: Once we can actually construct and send accept_channel messages, it
// would be better to test field extraction through an IR program that
// receives an accept_channel, extracts all fields, constructs a new
// accept_channel from those fields, and sends the new accept_channel. Then
// we'll have a full roundtrip test instead of testing the extract_field
// helper function in isolation.

#[test]
fn extract_scalar_fields() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::DustLimitSatoshis),
        Variable::Amount(546)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::MaxHtlcValueInFlightMsat),
        Variable::Amount(100_000_000)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ChannelReserveSatoshis),
        Variable::Amount(10_000)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::HtlcMinimumMsat),
        Variable::Amount(1_000)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::MinimumDepth),
        Variable::BlockHeight(6)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ToSelfDelay),
        Variable::U16(144)
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::MaxAcceptedHtlcs),
        Variable::U16(483)
    );
}

#[test]
fn extract_channel_id() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::TemporaryChannelId),
        Variable::ChannelId(TEMPORARY_CHANNEL_ID)
    );
}

#[test]
fn extract_pubkeys() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::FundingPubkey),
        Variable::Point(sample_pubkey(1))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::RevocationBasepoint),
        Variable::Point(sample_pubkey(2))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::PaymentBasepoint),
        Variable::Point(sample_pubkey(3))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::DelayedPaymentBasepoint),
        Variable::Point(sample_pubkey(4))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::HtlcBasepoint),
        Variable::Point(sample_pubkey(5))
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::FirstPerCommitmentPoint),
        Variable::Point(sample_pubkey(6))
    );
}

#[test]
fn extract_tlvs_present() {
    let ac = sample_accept_channel();
    assert_eq!(
        extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
        Variable::Bytes(vec![0xde, 0xad])
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ChannelType),
        Variable::Features(vec![0x40, 0x10, 0x00])
    );
}

#[test]
fn extract_tlvs_absent() {
    let ac = AcceptChannel {
        tlvs: AcceptChannelTlvs::default(),
        ..sample_accept_channel()
    };
    assert_eq!(
        extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
        Variable::Bytes(vec![])
    );
    assert_eq!(
        extract_field(&ac, AcceptChannelField::ChannelType),
        Variable::Features(vec![])
    );
}
