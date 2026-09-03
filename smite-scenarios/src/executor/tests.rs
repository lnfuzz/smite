mod harness;
mod programs;

use std::str::FromStr;

use super::*;
use bitcoin::Amount;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use harness::*;
use programs::*;
use smite::bolt::{AcceptChannelTlvs, GossipTimestampFilter, Init, Ping};
use smite_ir::Instruction;
use smite_ir::operation::ShutdownScriptVariant;

// -- execute() tests --

#[test]
fn execute_load_build_send() {
    let pk = sample_pubkey(1);
    let mut instrs = open_channel_instructions();
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: (0..20).collect(),
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![20],
    });

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    assert_eq!(fx.sent_len(), 1);
    let oc: OpenChannel = fx.sent(0);
    assert_eq!(oc.chain_hash, [0xcc; 32]);
    assert_eq!(oc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(oc.funding_satoshis, 100_000);
    assert_eq!(oc.push_msat, 0);
    assert_eq!(oc.dust_limit_satoshis, 546);
    assert_eq!(oc.max_htlc_value_in_flight_msat, 100_000_000);
    assert_eq!(oc.channel_reserve_satoshis, 10_000);
    assert_eq!(oc.htlc_minimum_msat, 1_000);
    assert_eq!(oc.feerate_per_kw, 253);
    assert_eq!(oc.to_self_delay, 144);
    assert_eq!(oc.max_accepted_htlcs, 483);
    assert_eq!(oc.funding_pubkey, pk);
    assert_eq!(oc.revocation_basepoint, pk);
    assert_eq!(oc.payment_basepoint, pk);
    assert_eq!(oc.delayed_payment_basepoint, pk);
    assert_eq!(oc.htlc_basepoint, pk);
    assert_eq!(oc.first_per_commitment_point, pk);
    assert_eq!(oc.channel_flags, 1);
    assert_eq!(oc.tlvs.upfront_shutdown_script, Some(vec![]));
    assert_eq!(oc.tlvs.channel_type, Some(vec![0x40, 0x10, 0x00]));
}

#[test]
fn execute_build_channel_announcement() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features = vec![0x01, 0x02];

    let instrs = vec![
        Instruction {
            operation: Operation::LoadFeatures(features.clone()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildChannelAnnouncement,
            inputs: vec![0, 1, 2, 3, 4, 5, 6],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![7],
        },
    ];

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    assert_eq!(fx.sent_len(), 1);
    let ca: ChannelAnnouncement = fx.sent(0);

    let secp = Secp256k1::new();
    let pk = |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
    assert_eq!(ca.features, features);
    assert_eq!(ca.chain_hash, sample_context().chain_hash);
    assert_eq!(ca.short_channel_id, scid);
    assert_eq!(ca.node_id_1, pk(&node_sk_1_bytes));
    assert_eq!(ca.node_id_2, pk(&node_sk_2_bytes));
    assert_eq!(ca.bitcoin_key_1, pk(&bitcoin_sk_1_bytes));
    assert_eq!(ca.bitcoin_key_2, pk(&bitcoin_sk_2_bytes));
    assert!(ca.extra.is_empty());
    assert!(ca.verify());
}

#[test]
fn execute_build_node_announcement() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let rgb_color = [0x11, 0x22, 0x33];
    let mut alias = [0u8; 32];
    alias[..5].copy_from_slice(b"smite");
    let addresses = vec![0xaa, 0xbb, 0xcc];

    let instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey(sk_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTimestamp(1_700_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(addresses.clone()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildNodeAnnouncement { rgb_color, alias },
            inputs: vec![0, 1, 2, 3],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![4],
        },
    ];

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

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
    assert_eq!(na.addresses, addresses);
    assert!(na.extra.is_empty());
    assert!(na.verify());
}

#[test]
fn execute_build_channel_update() {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 0x42;
    let scid = ShortChannelId::new(538_532, 845, 1);

    let instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey(sk_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTimestamp(1_715_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(0x01), // message_flags: must_be_one
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(0x00), // channel_flags
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144), // cltv_expiry_delta
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1_000), // htlc_minimum_msat
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadForwardingFee(1_000), // fee_base_msat
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadForwardingFee(100), // fee_proportional_millionths
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(99_000_000), // htlc_maximum_msat
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildChannelUpdate,
            inputs: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![11],
        },
    ];

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

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
    assert!(cu.extra.is_empty());

    let secp = Secp256k1::new();
    let expected_node_id =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
    assert!(cu.verify(&expected_node_id));
}

#[test]
#[allow(clippy::too_many_lines)]
fn execute_build_announcement_signatures() {
    let node_sk_1_bytes = [0x11; 32];
    let node_sk_2_bytes = [0x22; 32];
    let bitcoin_sk_1_bytes = [0x33; 32];
    let bitcoin_sk_2_bytes = [0x44; 32];
    let channel_id_bytes = [0xbb; 32];
    let scid = ShortChannelId::new(539_268, 845, 1);
    let features = vec![0x01, 0x02];

    // Instruction layout:
    //  v0 = LoadChannelId
    //  v1 = LoadFeatures
    //  v2 = LoadChainHashFromContext
    //  v3 = LoadShortChannelId
    //  v4 = LoadPrivateKey(node_sk_1)     -- our node signing key
    //  v5 = LoadPrivateKey(node_sk_2)     -- target's node key (derive pubkey from)
    //  v6 = DerivePoint(v5)               -- node_id_2 (target's node pubkey)
    //  v7 = LoadPrivateKey(bitcoin_sk_1)  -- our bitcoin signing key
    //  v8 = LoadPrivateKey(bitcoin_sk_2)  -- target's bitcoin key (derive pubkey from)
    //  v9 = DerivePoint(v8)               -- bitcoin_key_2 (target's bitcoin pubkey)
    // v10 = BuildAnnouncementSignatures(v0, v1, v2, v3, v4, v6, v7, v9)
    // v11 = SendMessage(v10)
    let instrs = vec![
        Instruction {
            operation: Operation::LoadChannelId(channel_id_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(features.clone()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(node_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![5],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![8],
        },
        Instruction {
            operation: Operation::BuildAnnouncementSignatures,
            inputs: vec![0, 1, 2, 3, 4, 6, 7, 9],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![10],
        },
    ];

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

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
        features,
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
    let mut instrs = open_channel_instructions();
    instrs[18] = Instruction {
        operation: Operation::LoadBytes(vec![0x00, 0x14, 0xab]),
        inputs: vec![],
    };
    instrs[19] = Instruction {
        operation: Operation::LoadFeatures(vec![0x01, 0x02]),
        inputs: vec![],
    };
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: (0..20).collect(),
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![20],
    });

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    let oc: OpenChannel = fx.sent(0);
    assert_eq!(
        oc.tlvs.upfront_shutdown_script,
        Some(vec![0x00, 0x14, 0xab])
    );
    assert_eq!(oc.tlvs.channel_type, Some(vec![0x01, 0x02]));
}

#[test]
fn execute_derive_point() {
    let mut instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey([0x11; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
    ];

    // Use the derived point in a BuildOpenChannel to verify it produced a
    // valid Point variable.
    let base = instrs.len();
    instrs.extend(open_channel_instructions());
    // Replace funding_pubkey (input 11) with the derived point (v1).
    let mut build_inputs: Vec<usize> = (base..base + 20).collect();
    build_inputs[11] = 1;
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: build_inputs,
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![base + 20],
    });

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    let oc: OpenChannel = fx.sent(0);
    let secp = Secp256k1::new();
    let expected = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    assert_eq!(oc.funding_pubkey, expected);
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

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let accept_channel_idx = instrs.len() - 1;
    for field in fields {
        instrs.push(Instruction {
            operation: Operation::ExtractAcceptChannel(field),
            inputs: vec![accept_channel_idx],
        });
    }

    // TODO: Once we add IR support for building accept_channel messages,
    // rebuild a message from the extracted fields and verify it matches the
    // original.

    Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run(&Program {
            instructions: instrs,
        });
}

#[test]
fn execute_recv_unexpected_message() {
    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let err = Fixture::new()
        .queue(&Message::Init(Init::empty()))
        .run_err(&Program {
            instructions: instrs,
        });
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

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let err = Fixture::new()
        .queue(&Message::Error(peer_error.clone()))
        .run_err(&Program {
            instructions: instrs,
        });
    assert!(matches!(err, ExecuteError::PeerError(e) if e == peer_error));
}

#[test]
#[allow(clippy::similar_names)] // ping and pong are the canonical names
fn execute_recv_auto_pong() {
    let ping = Ping {
        num_pong_bytes: 4,
        ignored: vec![0xaa],
    };

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let mut fx = Fixture::new()
        .queue(&Message::Ping(ping))
        .queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&Program {
        instructions: instrs,
    });

    // Verify exactly two messages were sent: `open_channel` and `pong`.
    assert_eq!(fx.sent_len(), 2);
    fx.sent::<OpenChannel>(0);
    let pong: Pong = fx.sent(1);
    assert_eq!(pong.ignored.len(), 4);
}

#[test]
fn execute_recv_skips_gossip() {
    let gossip = GossipTimestampFilter::new([0u8; 32], 0, 86400);

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let mut fx = Fixture::new()
        .queue(&Message::GossipTimestampFilter(gossip))
        .queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&Program {
        instructions: instrs,
    });

    let accept_channel = fx
        .negotiation(&TemporaryChannelId::new([0xbb; 32]))
        .accept_channel
        .as_ref()
        .expect("accept_channel recorded");
    assert_eq!(accept_channel.clone(), sample_accept_channel());
}

#[test]
fn execute_records_negotiation_for_open_and_accept() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let mut fx = Fixture::new().queue(&Message::AcceptChannel(sample_accept_channel()));
    fx.run(&Program {
        instructions: instrs,
    });

    let pending = fx.negotiation(&temporary_channel_id);
    assert_eq!(
        pending.open_channel.temporary_channel_id,
        temporary_channel_id
    );
    let accept_channel = pending.accept_channel.as_ref().unwrap();
    assert_eq!(accept_channel.clone(), sample_accept_channel());
    assert!(!pending.funding_built);
}

#[test]
fn execute_recv_accept_channel_unknown_channel() {
    let unknown_id = TemporaryChannelId::new([0xcc; 32]);

    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let err = Fixture::new()
        .queue(&Message::AcceptChannel(AcceptChannel {
            temporary_channel_id: unknown_id,
            ..sample_accept_channel()
        }))
        .run_err(&Program {
            instructions: instrs,
        });

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
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // Set `push_msat` so the opener cannot afford the commitment fee
    // requiring the peer to reject the `open_channel` per BOLT 2.
    let mut instrs = send_open_channel_instructions();
    instrs[3] = Instruction {
        operation: Operation::LoadAmount(99_900_000),
        inputs: vec![],
    };
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&Program {
            instructions: instrs,
        });

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, temporary_channel_id);
    assert!(
        reason.contains(
            "invalid open_channel: opener balance 100 sat cannot cover the commitment fee"
        )
    );
}

#[test]
fn execute_recv_accept_channel_rejects_reuse_before_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    let mut instrs = send_open_channel_instructions();
    let built_open_channel = instrs.len() - 2;
    let sent_open_channel = instrs.len() - 1;
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![sent_open_channel],
    });
    let resent_open_channel = instrs.len();
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![built_open_channel],
    });
    instrs.push(Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![resent_open_channel],
    });

    let err = Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run_err(&Program {
            instructions: instrs,
        });

    let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
        panic!("unexpected error: {err:?}");
    };
    assert_eq!(*id, temporary_channel_id);
    assert!(reason.contains(
        "temporary_channel_id reuse: previous negotiation has not reached funding_created"
    ));
}

#[test]
fn execute_records_only_first_open_channel_for_duplicate_id_before_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // First open_channel: funding_satoshis = 100_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 200_000.
    let mut instrs = send_open_channel_instructions();

    // Override only funding_satoshis; reuse the first open_channel's other 19 inputs.
    let funding_satoshis = instrs.len();
    instrs.push(Instruction {
        operation: Operation::LoadAmount(200_000),
        inputs: vec![],
    });
    let mut build_inputs: Vec<usize> = (0..20).collect();
    build_inputs[2] = funding_satoshis;

    let built = instrs.len();
    instrs.push(Instruction {
        operation: Operation::BuildOpenChannel,
        inputs: build_inputs,
    });
    instrs.push(Instruction {
        operation: Operation::SendOpenChannel,
        inputs: vec![built],
    });

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    // Both open_channel messages went out on the wire, but only the first
    // negotiation is recorded for the shared id.
    assert_eq!(fx.sent_len(), 2);
    assert_eq!(fx.sent::<OpenChannel>(0).funding_satoshis, 100_000);
    assert_eq!(fx.sent::<OpenChannel>(1).funding_satoshis, 200_000);
    let pending = fx.negotiation(&temporary_channel_id);
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
}

#[test]
fn execute_records_open_channel_for_duplicate_id_after_funding() {
    let temporary_channel_id = TemporaryChannelId::new([0xbb; 32]);

    // Negotiated open_channel: funding_satoshis = 10_000_000.
    // Second open_channel: same temporary_channel_id, funding_satoshis = 100_000.
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.
    // The second program's input indices are shifted past the funding
    // flow's variables.
    let offset = instrs.len();
    for mut instr in send_open_channel_instructions() {
        for input in &mut instr.inputs {
            *input += offset;
        }
        instrs.push(instr);
    }

    let mut fx = Fixture::new().with_negotiation(sample_funding_negotiation());
    fx.run(&Program {
        instructions: instrs,
    });

    let pending = fx.negotiation(&temporary_channel_id);
    assert_eq!(pending.open_channel.funding_satoshis, 100_000);
    assert!(pending.accept_channel.is_none());
    assert!(!pending.funding_built);
}

// -- Panic path tests --

#[test]
#[should_panic(expected = "expected 1 inputs, got 0")]
fn execute_wrong_input_count_panics() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![], // expects 1 input
        }],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "expected PrivateKey, got Amount")]
fn execute_type_mismatch_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(42),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0], // v0 is Amount, not PrivateKey
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn execute_variable_out_of_bounds_panics() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::SendMessage,
            inputs: vec![99],
        }],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn execute_forward_variable_reference_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x11; 32]),
                inputs: vec![],
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "is void")]
fn execute_void_variable_reference_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::MineBlocks(1),
                inputs: vec![],
            },
            // Try to use the void variable.
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "valid private key")]
fn execute_invalid_private_key_panics() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey([0; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "expected OpenChannelMessage, got Amount")]
fn execute_send_open_channel_wrong_type_panics() {
    let instrs = vec![
        Instruction {
            operation: Operation::LoadAmount(42),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![0],
        },
    ];

    let program = Program {
        instructions: instrs,
    };

    Fixture::new().run(&program);
}

#[test]
#[should_panic(expected = "is void")]
fn execute_affine_overuse_panics() {
    let mut instrs = send_open_channel_instructions();
    let sent_open_channel = instrs.len() - 1;
    instrs.extend([
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        },
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        },
    ]);
    Fixture::new()
        .queue(&Message::AcceptChannel(sample_accept_channel()))
        .run(&Program {
            instructions: instrs,
        });
}

// MineBlocks should track calls to mine_blocks
#[test]
fn execute_mine_blocks_invokes_cli() {
    let instrs = vec![Instruction {
        operation: Operation::MineBlocks(6),
        inputs: vec![],
    }];
    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    // Verify that mine_blocks was called with the correct number
    assert_eq!(fx.bitcoin().mine_blocks_calls, vec![6]);
    assert!(fx.bitcoin().mined_private_mempool.is_empty());
}

#[test]
#[should_panic(expected = "expected 0 inputs, got 1")]
fn execute_mine_blocks_wrong_input() {
    let instrs = vec![
        Instruction {
            operation: Operation::LoadAmount(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![0],
        },
    ];
    let program = Program {
        instructions: instrs,
    };
    Fixture::new().run(&program);
}

#[test]
fn execute_create_and_broadcast_tx() {
    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: create_and_broadcast_tx_instructions(),
    });

    assert_eq!(fx.bitcoin().broadcast_calls.len(), 1);
    let broadcast_tx = &fx.bitcoin().broadcast_calls[0];
    assert_eq!(
        broadcast_tx.compute_txid().to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
}

// LookupShortChannelId should combine the confirmed block position with
// the funding output's vout to produce the correct SCID, which we verify
// by feeding it into a channel_announcement and decoding the sent message.
#[test]
fn execute_lookup_short_channel_id_confirmed() {
    let mut instrs = create_and_broadcast_tx_instructions();
    instrs.push(Instruction {
        operation: Operation::MineBlocks(6),
        inputs: vec![],
    });
    instrs.push(Instruction {
        // Feed the FundingTransaction produced by
        // CreateFundingTransaction (instruction 6) into the lookup. The
        // resulting ShortChannelId is variable 9.
        operation: Operation::LookupShortChannelId,
        inputs: vec![6],
    });
    // Build and send a channel_announcement carrying the looked-up SCID.
    instrs.extend(channel_announcement_from_scid_instructions(instrs.len(), 9));

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    assert_eq!(fx.bitcoin().mine_blocks_calls, vec![6]);
    // The executor must have queried the mock with the broadcast
    // transaction's txid.
    assert_eq!(fx.bitcoin().block_position_lookups.len(), 1);
    let broadcast_txid = fx.bitcoin().broadcast_calls[0].compute_txid();
    assert_eq!(fx.bitcoin().block_position_lookups[0], broadcast_txid);

    // The mock returns block_height=800_042, tx_index=7 for a confirmed
    // tx, and the funding output is always at vout 0.
    let ca: ChannelAnnouncement = fx.sent(0);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(800_042, 7, 0));
}

// LookupShortChannelId should produce the sentinel SCID (0/0/0) when the
// funding transaction is unknown to the node (e.g. never broadcast or
// never confirmed), rather than panicking. We verify the sentinel value
// via the SCID carried in a channel_announcement.
#[test]
fn execute_lookup_short_channel_id_unconfirmed_returns_sentinel() {
    // No BroadcastTransaction and no MineBlocks: the mock reports zero
    // confirmations and get_transaction_block_position returns None.
    let mut instrs = vec![
        Instruction {
            operation: Operation::LoadPrivateKey([1u8; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([2u8; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![2],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(15_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::CreateFundingTransaction,
            inputs: vec![1, 3, 4, 5],
        },
        // The looked-up SCID is variable 7.
        Instruction {
            operation: Operation::LookupShortChannelId,
            inputs: vec![6],
        },
    ];
    instrs.extend(channel_announcement_from_scid_instructions(instrs.len(), 7));

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    // The mock was queried but returned None (zero confirmations), so the
    // executor took the sentinel path without panicking.
    assert!(fx.bitcoin().mine_blocks_calls.is_empty());
    assert_eq!(fx.bitcoin().block_position_lookups.len(), 1);

    let ca: ChannelAnnouncement = fx.sent(0);
    assert_eq!(ca.short_channel_id, ShortChannelId::new(0, 0, 0));
}

#[test]
fn execute_broadcast_dedupes_rejected_tx_in_private_mempool() {
    // Fund with a dust amount so the built funding tx carries a below-dust
    // output.
    let mut instrs = create_and_broadcast_tx_instructions();
    instrs[4] = Instruction {
        operation: Operation::LoadAmount(200),
        inputs: vec![],
    };
    let funding_tx = instrs.len() - 2;
    instrs.push(Instruction {
        operation: Operation::BroadcastTransaction,
        inputs: vec![funding_tx],
    });
    instrs.push(Instruction {
        operation: Operation::MineBlocks(1),
        inputs: vec![],
    });

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    assert_eq!(fx.bitcoin().broadcast_calls.len(), 2);
    assert_eq!(
        fx.bitcoin().broadcast_calls[0].compute_txid(),
        fx.bitcoin().broadcast_calls[1].compute_txid(),
    );

    let rejected_hex = bitcoin::consensus::encode::serialize_hex(&fx.bitcoin().broadcast_calls[0]);
    assert!(fx.private_mempool().is_empty());
    assert_eq!(fx.bitcoin().mined_private_mempool, vec![rejected_hex]);
}

#[test]
fn execute_create_funding_transaction_insufficient_funds() {
    // UTXO too small to cover the funding amount and fees.
    let small_utxo = Utxo {
        amount: Amount::from_sat(1_000),
        ..sample_utxo()
    };
    let err = Fixture::new()
        .with_utxos(vec![small_utxo])
        .run_err(&Program {
            instructions: create_and_broadcast_tx_instructions(),
        });
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
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });

    // The expected signature here was computed using LDK as the source of
    // truth.
    let mut fx = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        }));
    fx.run(&Program {
        instructions: send_funding_created_and_recv_funding_signed_instructions(),
    });

    assert_eq!(fx.sent_len(), 1);
    let fc: FundingCreated = fx.sent(0);

    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(
        fc.funding_txid.to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
    assert_eq!(fc.funding_output_index, 0);

    // Verify the signature sent by the opener on the acceptor side.
    let state = fx.channel_state(&channel_id);
    let holder = HolderIdentity {
        side: Side::Acceptor,
        funding_privkey: SecretKey::from_str(
            "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13",
        )
        .unwrap(),
    };

    assert!(
        state
            .config
            .verify_counterparty_signature(&state.commitment, &holder, &fc.signature)
    );

    let pending = fx.negotiation(&TemporaryChannelId::new([0xbb; 32]));
    assert!(pending.funding_built);
}

#[test]
fn execute_send_funding_created_uses_wire_funding_pubkey() {
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });

    // Swap out the SendFundingCreated privkey. This should not affect the
    // constructed channel config, which uses the negotiated pubkeys. It
    // should only change the signature sent to the target.
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs[9].inputs[1] = 2;

    // The same acceptor signature as the happy path (computed using LDK as
    // the source of truth): computed over the the commitment implied by the
    // negotiated funding pubkeys. It still verifies, because the config is
    // built from the wire pubkeys rather than from the swapped privkey.
    let mut fx = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        }));
    fx.run(&Program {
        instructions: instrs,
    });

    let secp = Secp256k1::new();
    let opener_pk = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
            .unwrap(),
    );
    // The funding pubkey matches what was negotiated.
    let state = fx.channel_state(&channel_id);
    assert_eq!(state.config.opener.funding_pubkey, opener_pk);
    // But the swapped privkey used for signing is the acceptor's, which
    // does not match what was negotiated.
    assert_eq!(
        state.holder.funding_privkey,
        SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
            .unwrap()
    );
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

    // Channel id derived from the first funding transaction's outpoint.
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });

    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.
    instrs.extend(vec![
        // Different funding spk, hence a different outpoint.
        Instruction {
            operation: Operation::CreateFundingTransaction,
            inputs: vec![1, 1, 4, 5],
        },
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![10, 0, 8],
        },
    ]);

    let mut fx = Fixture::new()
        .with_utxos(vec![sample_utxo(), second_utxo])
        .with_negotiation(sample_funding_negotiation());
    fx.run(&Program {
        instructions: instrs,
    });

    // The message still goes out, only the state tracking is suppressed.
    assert_eq!(fx.sent_len(), 2);
    assert_eq!(fx.channel_states().len(), 1);
    assert!(fx.channel_states().contains_key(&channel_id));
}

#[test]
fn execute_send_funding_created_push_exceeds_funding() {
    // A negotiated push_msat larger than the funding amount surfaces the
    // commitment construction error.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.push_msat = 20_000_000_000;
    let err = Fixture::new()
        .with_negotiation(negotiation)
        .run_err(&Program {
            instructions: send_funding_created_and_recv_funding_signed_instructions(),
        });
    assert!(matches!(
        err,
        ExecuteError::Commitment(smite::channel_tx::CommitmentError::PushExceedsFunding)
    ));
}

#[test]
fn execute_send_funding_created_funding_msat_overflow() {
    // A negotiated funding_satoshis of u64::MAX overflows when converted to
    // millisatoshis.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.funding_satoshis = u64::MAX;
    let err = Fixture::new()
        .with_negotiation(negotiation)
        .run_err(&Program {
            instructions: send_funding_created_and_recv_funding_signed_instructions(),
        });
    assert!(matches!(
        err,
        ExecuteError::Commitment(smite::channel_tx::CommitmentError::FundingMsatOverflow)
    ));
}

#[test]
fn execute_send_funding_created_no_open_channel() {
    // No negotiation exists for this temporary_channel_id, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.

    let mut fx = Fixture::new();
    fx.run(&Program {
        instructions: instrs,
    });

    let fc: FundingCreated = fx.sent(0);
    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(
        fc.funding_txid.to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(fx.channel_states().is_empty());
}

#[test]
fn execute_send_funding_created_no_accept_channel() {
    // The `accept_channel` has not been received yet, so we get a
    // `funding_created` with an all-zero signature and no recorded channel
    // state.
    let mut negotiation = sample_funding_negotiation();
    negotiation.accept_channel = None;
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.

    let mut fx = Fixture::new().with_negotiation(negotiation);
    fx.run(&Program {
        instructions: instrs,
    });

    let fc: FundingCreated = fx.sent(0);
    assert_eq!(fc.temporary_channel_id, TemporaryChannelId::new([0xbb; 32]));
    assert_eq!(
        fc.funding_txid.to_string(),
        "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
    );
    assert_eq!(fc.funding_output_index, 0);
    assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
    assert!(fx.channel_states().is_empty());
}

#[test]
fn execute_recv_funding_signed_unknown_channel() {
    let channel_id = ChannelId::new([0xbb; 32]);

    // The expected signature here was computed using LDK as the source of
    // truth.
    let err = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        }))
        .run_err(&Program {
            instructions: send_funding_created_and_recv_funding_signed_instructions(),
        });
    assert!(matches!(
        err,
        ExecuteError::Violation(Violation::UnknownChannel(id)) if id == channel_id
    ));
}

#[test]
fn execute_recv_funding_signed_invalid_signature() {
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });
    let err = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: Signature::from_compact(&[0u8; 64])
                .expect("zero bytes parse as a signature"),
        }))
        .run_err(&Program {
            instructions: send_funding_created_and_recv_funding_signed_instructions(),
        });
    assert!(matches!(
        err,
        ExecuteError::Violation(Violation::InvalidCounterpartySignature(id)) if id == channel_id
    ));
}

#[test]
fn execute_send_channel_ready() {
    let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .unwrap(),
        vout: 0,
    });
    let alias = ShortChannelId::new(538_532, 845, 1);
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.extend([
        Instruction {
            operation: Operation::LoadShortChannelId(alias.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendChannelReady {
                include_alias: false,
            },
            inputs: vec![10, 1, 11],
        },
        Instruction {
            operation: Operation::SendChannelReady {
                include_alias: true,
            },
            inputs: vec![10, 3, 11],
        },
    ]);

    // We also need to send this `funding_signed`, since the instructions reused
    // by this test expect one to be present in the executor's receive queue.
    // The expected signature here was computed using LDK as the source of
    // truth.
    let mut fx = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        }));
    fx.run(&Program {
        instructions: instrs,
    });

    // The instructions send 1 `funding_created` and 2 `channel_ready` messages.
    assert_eq!(fx.sent_len(), 3);

    // The first channel_ready was sent with include_alias = false, so it must
    // not carry the short_channel_id TLV.
    let cr1: ChannelReady = fx.sent(1);
    let expected_pcp1 =
        PublicKey::from_str("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb")
            .unwrap();
    assert_eq!(cr1.channel_id, channel_id);
    assert_eq!(cr1.second_per_commitment_point, expected_pcp1);
    assert!(cr1.tlvs.short_channel_id.is_none());

    // The second channel_ready was sent with include_alias = true, so it must
    // carry the alias SCID we loaded in its short_channel_id TLV.
    let cr2: ChannelReady = fx.sent(2);
    let expected_pcp2 =
        PublicKey::from_str("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1")
            .unwrap();
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
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadChannelId(channel_id.0),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShutdownScript(script.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendShutdown,
                inputs: vec![0, 1],
            },
        ],
    };

    let mut fx = Fixture::new();
    fx.run(&program);

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
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadChannelId(channel_id.0),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendShutdown,
                inputs: vec![0, 1],
            },
        ],
    };

    let mut fx = Fixture::new();
    fx.run(&program);

    assert_eq!(fx.sent_len(), 1);
    let sd: Shutdown = fx.sent(0);
    assert_eq!(sd.channel_id, channel_id);
    assert!(sd.scriptpubkey.is_empty());
}

#[test]
fn execute_recv_channel_ready_invalid_funding_outpoint_is_noop() {
    // Corrupt the negotiated opener funding pubkey so the broadcast funding
    // transaction's output no longer pays the negotiated 2-of-2 script,
    // marking the funding outpoint invalid.
    let mut negotiation = sample_funding_negotiation();
    negotiation.open_channel.funding_pubkey = sample_pubkey(1);

    // The corrupted pubkey changes the funding script, so our precomputed
    // funding_signed signature will no longer verify correctly. That
    // exchange is not what this test is about, so we neither queue the
    // funding_signed nor receive it.
    let mut fx = Fixture::new()
        .with_negotiation(negotiation)
        .queue(&channel_ready_reply(sample_pubkey(1)));
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.pop();

    instrs.extend([
        Instruction {
            operation: Operation::MineBlocks(8),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ]);

    // With invalid funding outpoint the target does not owe us a
    // `channel_ready`, so `RecvChannelReady` must be a no-op.
    fx.run(&Program {
        instructions: instrs,
    });

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_below_minimum_depth_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    // Mine one block fewer than the `minimum_depth` negotiated in `accept_channel` by
    // `sample_funding_negotiation()`.
    // With fewer than the negotiated `minimum_depth` confirmations the target
    // does not yet owe us a `channel_ready`, so `RecvChannelReady` must be a
    // no-op.
    fx.run(&Program {
        instructions: recv_channel_ready_instructions(5),
    });
    assert!(fx.bitcoin().mined_private_mempool.is_empty());

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(fx.queued_len(), 1);
}

#[test]
fn execute_recv_channel_ready_at_minimum_depth_records_point() {
    let (mut fx, target_pcp) = recv_channel_ready_fixture();

    // Mine exactly the `minimum_depth` negotiated in `accept_channel` by
    // `sample_funding_negotiation()`.
    // At the negotiated `minimum_depth` confirmations the target owes us a
    // `channel_ready`, which `RecvChannelReady` receives and records.
    fx.run(&Program {
        instructions: recv_channel_ready_instructions(6),
    });
    assert!(fx.bitcoin().mined_private_mempool.is_empty());

    // The `channel_ready` was consumed and the target's next per-commitment
    // point is now recorded.
    let state = fx.channel_state(&funding_channel_id());
    assert_eq!(
        *state.next_counterparty_per_commitment_point(),
        Some(target_pcp)
    );
    assert_eq!(fx.queued_len(), 0);
}

#[test]
fn execute_recv_channel_ready_funding_mined_prematurely_is_noop() {
    let (mut fx, _) = recv_channel_ready_fixture();

    let mut instrs = create_and_broadcast_tx_instructions();
    instrs.extend([
        Instruction {
            // Mine past the negotiated `minimum_depth` *before* sending
            // `funding_created`.
            operation: Operation::MineBlocks(8),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![6, 0, 9],
        },
        Instruction {
            operation: Operation::RecvFundingSigned,
            inputs: vec![10],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ]);

    // The funding transaction confirmed before `funding_created`, so the
    // target may never observe the confirmation and `RecvChannelReady` must
    // be a no-op even though the confirmation count is sufficient.
    fx.run(&Program {
        instructions: instrs,
    });

    // The target's next per-commitment point is still unknown and the queued
    // `channel_ready` remains untouched.
    let state = fx.channel_state(&funding_channel_id());
    assert!(state.was_funding_mined_prematurely);
    assert!(state.next_counterparty_per_commitment_point().is_none());
    assert_eq!(fx.queued_len(), 1);
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
        Variable::ChannelId(TemporaryChannelId::new([0xbb; 32]))
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
