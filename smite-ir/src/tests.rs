//! Tests for IR types.

use rand::SeedableRng;
use rand::rngs::SmallRng;
use rand::{Rng, RngExt};
use smite::bolt::{MAX_MESSAGE_SIZE, ShortChannelId};

use super::*;
use generators::{
    AnyGenerator, ChannelAnnouncementGenerator, ChannelReadyGenerator, ChannelUpdateGenerator,
    FundingCreatedGenerator, FundingFlowGenerator, NodeAnnouncementGenerator, OpenChannelGenerator,
};
use minimizers::{CommonSubexpressionEliminator, DeadCodeEliminator, Minimizer};
use mutators::{
    GeneratorInsertionMutator, InputSwapMutator, InstructionDeleteMutator,
    InstructionReorderMutator, OperationParamMutator,
};
use operation::{AcceptChannelField, ChannelTypeVariant, ShutdownScriptVariant};

/// Helper to build a private key with a single distinguishing byte.
fn key(byte: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = byte;
    k
}

/// Asserts `program` is well-formed by replaying it through `ProgramBuilder`,
/// which panics on any input-count, SSA-ordering, void-reference, or type
/// mismatch.
fn assert_well_formed(program: &Program) {
    let mut builder = ProgramBuilder::new();
    for instr in &program.instructions {
        builder.append(instr.operation.clone(), &instr.inputs);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn display_open_channel_program() {
    let instructions = vec![
        // 6 key pairs.
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![2],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(3)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![4],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(4)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![6],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(5)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![8],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(6)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![10],
        },
        // Channel parameters.
        Instruction {
            operation: Operation::LoadChannelId([0; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(100_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(0),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(546),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(2500),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(483),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![]),
            inputs: vec![],
        },
        // Build and send open_channel.
        Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: vec![
                13, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 1, 3, 5, 7, 9, 11, 23, 24, 25,
            ],
        },
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![26],
        },
        // Receive accept_channel and extract fields.
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![27],
        },
        Instruction {
            operation: Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
            inputs: vec![28],
        },
        Instruction {
            operation: Operation::ExtractAcceptChannel(AcceptChannelField::FirstPerCommitmentPoint),
            inputs: vec![28],
        },
    ];

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let z32 = "00".repeat(32);

    #[rustfmt::skip]
    let expected: Vec<String> = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = DerivePoint(v0)".into(),
        format!("v2 = LoadPrivateKey(0x{z31}02)"),
        "v3 = DerivePoint(v2)".into(),
        format!("v4 = LoadPrivateKey(0x{z31}03)"),
        "v5 = DerivePoint(v4)".into(),
        format!("v6 = LoadPrivateKey(0x{z31}04)"),
        "v7 = DerivePoint(v6)".into(),
        format!("v8 = LoadPrivateKey(0x{z31}05)"),
        "v9 = DerivePoint(v8)".into(),
        format!("v10 = LoadPrivateKey(0x{z31}06)"),
        "v11 = DerivePoint(v10)".into(),
        format!("v12 = LoadChannelId(0x{z32})"),
        "v13 = LoadChainHashFromContext()".into(),
        "v14 = LoadAmount(100000)".into(),
        "v15 = LoadAmount(0)".into(),
        "v16 = LoadAmount(546)".into(),
        "v17 = LoadAmount(10000000)".into(),
        "v18 = LoadAmount(1000)".into(),
        "v19 = LoadAmount(1)".into(),
        "v20 = LoadFeeratePerKw(2500)".into(),
        "v21 = LoadU16(144)".into(),
        "v22 = LoadU16(483)".into(),
        "v23 = LoadU8(1)".into(),
        "v24 = LoadShutdownScript(Empty)".into(),
        "v25 = LoadFeatures()".into(),
        "v26 = BuildOpenChannel(v13, v12, v14, v15, v16, v17, v18, v19, v20, v21, v22, v1, v3, v5, v7, v9, v11, v23, v24, v25)".into(),
        "v27 = SendOpenChannel(v26)".into(),
        "v28 = RecvAcceptChannel(v27)".into(),
        "v29 = ExtractFundingPubkey(v28)".into(),
        "v30 = ExtractFirstPerCommitmentPoint(v28)".into(),
    ];

    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn display_build_channel_announcement_program() {
    let scid = ShortChannelId::new(539_268, 845, 1);
    let instructions = vec![
        Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
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
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(3)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(4)),
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

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let expected: Vec<String> = vec![
        "v0 = LoadFeatures(0x0102)".into(),
        "v1 = LoadChainHashFromContext()".into(),
        format!("v2 = LoadShortChannelId({scid})"),
        format!("v3 = LoadPrivateKey(0x{z31}01)"),
        format!("v4 = LoadPrivateKey(0x{z31}02)"),
        format!("v5 = LoadPrivateKey(0x{z31}03)"),
        format!("v6 = LoadPrivateKey(0x{z31}04)"),
        "v7 = BuildChannelAnnouncement(v0, v1, v2, v3, v4, v5, v6)".into(),
        "SendMessage(v7)".into(),
    ];
    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn display_build_node_announcement_program() {
    let mut alias = [0u8; 32];
    alias[..5].copy_from_slice(b"smite");
    let instructions = vec![
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTimestamp(1_700_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildNodeAnnouncement {
                rgb_color: [0x11, 0x22, 0x33],
                alias,
            },
            inputs: vec![0, 1, 2, 3],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![4],
        },
    ];

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let alias_hex = format!("0x736d697465{}", "00".repeat(27));
    let expected: Vec<String> = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = LoadFeatures()".into(),
        "v2 = LoadTimestamp(1700000000)".into(),
        "v3 = LoadBytes()".into(),
        format!("v4 = BuildNodeAnnouncement{{rgb=0x112233, alias={alias_hex}}}(v0, v1, v2, v3)"),
        "SendMessage(v4)".into(),
    ];
    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn display_build_channel_update_program() {
    let scid = ShortChannelId::new(538_532, 845, 1);
    let instructions = vec![
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
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
            operation: Operation::LoadU8(0x01), // message_flags
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

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let expected: Vec<String> = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = LoadChainHashFromContext()".into(),
        "v2 = LoadShortChannelId(538532x845x1)".into(),
        "v3 = LoadTimestamp(1715000000)".into(),
        "v4 = LoadU8(1)".into(),
        "v5 = LoadU8(0)".into(),
        "v6 = LoadU16(144)".into(),
        "v7 = LoadAmount(1000)".into(),
        "v8 = LoadForwardingFee(1000)".into(),
        "v9 = LoadForwardingFee(100)".into(),
        "v10 = LoadAmount(99000000)".into(),
        "v11 = BuildChannelUpdate(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10)".into(),
        "SendMessage(v11)".into(),
    ];
    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn display_build_announcement_signatures_program() {
    let scid = ShortChannelId::new(539_268, 845, 1);
    let instructions = vec![
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
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
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        // Target's node public key (input 5 to BuildAnnouncementSignatures).
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
            inputs: vec![],
        },
        // A placeholder for the target's bitcoin pubkey (input 7 to
        // BuildAnnouncementSignatures).  In real usage this would come from the
        // `funding_pubkey` field in the target's `accept_channel` message, not from
        // context; we use LoadTargetPubkeyFromContext here purely for illustration.
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildAnnouncementSignatures,
            inputs: vec![0, 1, 2, 3, 4, 5, 6, 7],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![8],
        },
    ];

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let bb32 = "bb".repeat(32);
    let z31 = "00".repeat(31);
    let expected: Vec<String> = vec![
        format!("v0 = LoadChannelId(0x{bb32})"),
        "v1 = LoadFeatures(0x0102)".into(),
        "v2 = LoadChainHashFromContext()".into(),
        format!("v3 = LoadShortChannelId({scid})"),
        format!("v4 = LoadPrivateKey(0x{z31}01)"),
        "v5 = LoadTargetPubkeyFromContext()".into(),
        format!("v6 = LoadPrivateKey(0x{z31}02)"),
        "v7 = LoadTargetPubkeyFromContext()".into(),
        "v8 = BuildAnnouncementSignatures(v0, v1, v2, v3, v4, v5, v6, v7)".into(),
        "SendMessage(v8)".into(),
    ];
    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }

    // Verify the program survives a postcard round-trip.
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn display_send_and_recv_channel_ready_program() {
    let scid = ShortChannelId::new(936_450, 1_346, 5);
    let instructions = vec![
        Instruction {
            operation: Operation::LoadChannelId([0xcd; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![1],
        },
        Instruction {
            operation: Operation::LoadShortChannelId(scid.as_u64()),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendChannelReady {
                include_alias: true,
            },
            inputs: vec![0, 2, 3],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ];

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let cid_hex = "cd".repeat(32);
    let z31 = "00".repeat(31);
    let expected: Vec<String> = vec![
        format!("v0 = LoadChannelId(0x{cid_hex})"),
        format!("v1 = LoadPrivateKey(0x{z31}01)"),
        "v2 = DerivePoint(v1)".into(),
        format!("v3 = LoadShortChannelId({scid})"),
        "SendChannelReady{include_alias=true}(v0, v2, v3)".into(),
        "RecvChannelReady()".into(),
    ];
    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn display_send_shutdown_program() {
    let instructions = vec![
        Instruction {
            operation: Operation::LoadChannelId([0xcd; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadShutdownScript(ShutdownScriptVariant::P2wpkh([0xab; 20])),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendShutdown,
            inputs: vec![0, 1],
        },
    ];

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let cid_hex = "cd".repeat(32);
    let spk_hex = "ab".repeat(20);
    let expected: Vec<String> = vec![
        format!("v0 = LoadChannelId(0x{cid_hex})"),
        format!("v1 = LoadShutdownScript(P2wpkh(0x{spk_hex}))"),
        "v2 = SendShutdown(v0, v1)".into(),
    ];
    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn postcard_roundtrip() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChannelId([0xab; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShortChannelId(
                    ShortChannelId::new(700_000, 1234, 0).as_u64(),
                ),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(50_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![0x01, 0x02]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::MineBlocks(6),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(2)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![8],
            },
            Instruction {
                operation: Operation::LoadFeeratePerKw(15_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::CreateFundingTransaction,
                inputs: vec![1, 9, 5, 10],
            },
            Instruction {
                operation: Operation::BroadcastTransaction,
                inputs: vec![11],
            },
            Instruction {
                operation: Operation::LoadU16(144),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendFundingCreated,
                inputs: vec![11, 0, 8, 3],
            },
        ],
    };

    assert_well_formed(&program);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn mine_blocks_operation() {
    let op = Operation::MineBlocks(8);
    assert_eq!(op.input_types(), vec![]);
    assert_eq!(op.output_type(), None);
    assert!(op.is_param_mutable());
}

#[test]
fn displays_mine_blocks_program() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![],
        }],
    };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, vec!["MineBlocks(6)"]);
}

#[test]
fn create_and_broadcast_tx_operation() {
    let op = Operation::CreateFundingTransaction;
    assert_eq!(
        op.input_types(),
        vec![
            VariableType::Point,
            VariableType::Point,
            VariableType::Amount,
            VariableType::FeeratePerKw,
        ],
    );
    assert_eq!(op.output_type(), Some(VariableType::FundingTransaction));
    assert!(!op.is_param_mutable());

    let op = Operation::BroadcastTransaction;
    assert_eq!(op.input_types(), vec![VariableType::FundingTransaction]);
    assert_eq!(op.output_type(), None);
    assert!(!op.is_param_mutable());
}

#[test]
fn lookup_short_channel_id_operation() {
    let op = Operation::LookupShortChannelId;
    assert_eq!(op.input_types(), vec![VariableType::FundingTransaction]);
    assert_eq!(op.output_type(), Some(VariableType::ShortChannelId));
    assert!(!op.is_param_mutable());
    // Non-deterministic (depends on chain state), so must not be dropped by DCE
    // or deduplicated by CSE.
    assert!(op.has_side_effects());
    assert_eq!(op.to_string(), "LookupShortChannelId");
}

fn create_and_broadcast_tx_instructions() -> Vec<Instruction> {
    vec![
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
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
        Instruction {
            operation: Operation::BroadcastTransaction,
            inputs: vec![6],
        },
    ]
}

#[test]
fn displays_create_and_broadcast_tx_program() {
    let program = Program {
        instructions: create_and_broadcast_tx_instructions(),
    };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);

    let expected = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = DerivePoint(v0)".into(),
        format!("v2 = LoadPrivateKey(0x{z31}02)"),
        "v3 = DerivePoint(v2)".into(),
        "v4 = LoadAmount(10000000)".into(),
        "v5 = LoadFeeratePerKw(15000)".into(),
        "v6 = CreateFundingTransaction(v1, v3, v4, v5)".into(),
        "BroadcastTransaction(v6)".into(),
    ];
    assert_eq!(lines, expected);
}

#[test]
fn displays_send_funding_created_recv_funding_signed_program() {
    let instructions = vec![
        // Funding transaction.
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
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
            inputs: vec![1, 1, 2, 3],
        },
        // funding_created parameters.
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        // Build and send funding_created.
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![4, 0, 5, 6],
        },
        // receive funding_signed.
        Instruction {
            operation: Operation::RecvFundingSigned,
            inputs: vec![7],
        },
    ];

    let program = Program { instructions };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let b32 = "bb".repeat(32);

    let expected: Vec<String> = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = DerivePoint(v0)".into(),
        "v2 = LoadAmount(10000000)".into(),
        "v3 = LoadFeeratePerKw(15000)".into(),
        "v4 = CreateFundingTransaction(v1, v1, v2, v3)".into(),
        format!("v5 = LoadPrivateKey(0x{z31}02)"),
        format!("v6 = LoadChannelId(0x{b32})"),
        "v7 = SendFundingCreated(v4, v0, v5, v6)".into(),
        "v8 = RecvFundingSigned(v7)".into(),
    ];

    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

// Ensure AcceptChannelField and AcceptChannelField::ALL stay in sync. The
// exhaustive match in this test will fail to compile if a variant is added
// without updating it, and the assertion will fail if the match is updated
// without updating AcceptChannelField::ALL.
#[test]
fn accept_channel_field_all_is_complete() {
    let variant_count = |f: AcceptChannelField| -> usize {
        match f {
            AcceptChannelField::TemporaryChannelId
            | AcceptChannelField::DustLimitSatoshis
            | AcceptChannelField::MaxHtlcValueInFlightMsat
            | AcceptChannelField::ChannelReserveSatoshis
            | AcceptChannelField::HtlcMinimumMsat
            | AcceptChannelField::MinimumDepth
            | AcceptChannelField::ToSelfDelay
            | AcceptChannelField::MaxAcceptedHtlcs
            | AcceptChannelField::FundingPubkey
            | AcceptChannelField::RevocationBasepoint
            | AcceptChannelField::PaymentBasepoint
            | AcceptChannelField::DelayedPaymentBasepoint
            | AcceptChannelField::HtlcBasepoint
            | AcceptChannelField::FirstPerCommitmentPoint
            | AcceptChannelField::UpfrontShutdownScript
            | AcceptChannelField::ChannelType => 16,
        }
    };
    assert_eq!(
        AcceptChannelField::ALL.len(),
        variant_count(AcceptChannelField::ALL[0]),
    );
}

// Ensure AnyGenerator and AnyGenerator::ALL stay in sync. The exhaustive
// match in this test will fail to compile if a variant is added without
// updating it, and the assertion will fail if the match is updated
// without updating AnyGenerator::ALL.
#[test]
fn any_generator_all_is_complete() {
    let variant_count = |f: AnyGenerator| -> usize {
        match f {
            AnyGenerator::ChannelAnnouncement(_)
            | AnyGenerator::ChannelUpdate(_)
            | AnyGenerator::NodeAnnouncement(_)
            | AnyGenerator::OpenChannel(_)
            | AnyGenerator::FundingCreated(_)
            | AnyGenerator::ChannelReady(_)
            | AnyGenerator::FundingFlow(_) => 7,
        }
    };
    assert_eq!(AnyGenerator::ALL.len(), variant_count(AnyGenerator::ALL[0]));
}

// -- ShutdownScriptVariant tests --

// Ensure ShutdownScriptVariant and ShutdownScriptVariant::VARIANT_COUNT stay in
// sync. The exhaustive match below fails to compile if a variant is added
// without updating it, and the assertion fails if the match is updated without
// bumping VARIANT_COUNT.
#[test]
fn shutdown_script_variant_count_is_complete() {
    let variant_count = |v: &ShutdownScriptVariant| -> usize {
        match v {
            ShutdownScriptVariant::Empty
            | ShutdownScriptVariant::P2pkh(_)
            | ShutdownScriptVariant::P2sh(_)
            | ShutdownScriptVariant::P2wpkh(_)
            | ShutdownScriptVariant::P2wsh(_)
            | ShutdownScriptVariant::AnySegwit { .. }
            | ShutdownScriptVariant::OpReturn(_) => 7,
        }
    };
    assert_eq!(
        ShutdownScriptVariant::VARIANT_COUNT,
        variant_count(&ShutdownScriptVariant::Empty),
    );
}

#[test]
fn shutdown_script_empty_encodes_to_zero_bytes() {
    assert_eq!(ShutdownScriptVariant::Empty.encode(), Vec::<u8>::new());
}

#[test]
fn shutdown_script_p2pkh_encoding() {
    let h = [0x42u8; 20];
    let bytes = ShutdownScriptVariant::P2pkh(h).encode();
    assert_eq!(bytes.len(), 25);
    assert_eq!(&bytes[..3], &[0x76, 0xa9, 0x14]);
    assert_eq!(&bytes[3..23], &h);
    assert_eq!(&bytes[23..], &[0x88, 0xac]);
}

#[test]
fn shutdown_script_p2sh_encoding() {
    let h = [0x33u8; 20];
    let bytes = ShutdownScriptVariant::P2sh(h).encode();
    assert_eq!(bytes.len(), 23);
    assert_eq!(&bytes[..2], &[0xa9, 0x14]);
    assert_eq!(&bytes[2..22], &h);
    assert_eq!(bytes[22], 0x87);
}

#[test]
fn shutdown_script_p2wpkh_encoding() {
    let h = [0x55u8; 20];
    let bytes = ShutdownScriptVariant::P2wpkh(h).encode();
    assert_eq!(bytes.len(), 22);
    assert_eq!(&bytes[..2], &[0x00, 0x14]);
    assert_eq!(&bytes[2..], &h);
}

#[test]
fn shutdown_script_p2wsh_encoding() {
    let h = [0x77u8; 32];
    let bytes = ShutdownScriptVariant::P2wsh(h).encode();
    assert_eq!(bytes.len(), 34);
    assert_eq!(&bytes[..2], &[0x00, 0x20]);
    assert_eq!(&bytes[2..], &h);
}

#[test]
fn shutdown_script_anysegwit_p2tr() {
    let prog = [0x99u8; 32];
    let v = ShutdownScriptVariant::AnySegwit {
        version: 1,
        program: prog.to_vec(),
    };
    let bytes = v.encode();
    assert_eq!(bytes.len(), 34);
    assert_eq!(bytes[0], 0x51); // OP_1
    assert_eq!(bytes[1], 32);
    assert_eq!(&bytes[2..], &prog);
}

#[test]
fn shutdown_script_anysegwit_v16_min_program() {
    let v = ShutdownScriptVariant::AnySegwit {
        version: ShutdownScriptVariant::ANYSEGWIT_MAX_VERSION,
        program: vec![0xab, 0xcd],
    };
    let bytes = v.encode();
    assert_eq!(bytes, vec![0x60, 0x02, 0xab, 0xcd]);
}

#[test]
fn shutdown_script_op_return_short_push() {
    // 6..=75 bytes: raw length opcode.
    let data = vec![0x11u8; 75];
    let bytes = ShutdownScriptVariant::OpReturn(data.clone()).encode();
    assert_eq!(bytes.len(), 1 + 1 + 75);
    assert_eq!(bytes[0], 0x6a); // OP_RETURN
    assert_eq!(bytes[1], 75);
    assert_eq!(&bytes[2..], &data[..]);
}

#[test]
fn shutdown_script_op_return_pushdata1() {
    // 76..=80 bytes: OP_PUSHDATA1 + length byte.
    let data = vec![0x22u8; ShutdownScriptVariant::OP_RETURN_MAX_DATA_LEN];
    let bytes = ShutdownScriptVariant::OpReturn(data.clone()).encode();
    assert_eq!(
        bytes.len(),
        1 + 2 + ShutdownScriptVariant::OP_RETURN_MAX_DATA_LEN,
    );
    assert_eq!(bytes[0], 0x6a);
    assert_eq!(bytes[1], 0x4c); // OP_PUSHDATA1
    assert_eq!(
        usize::from(bytes[2]),
        ShutdownScriptVariant::OP_RETURN_MAX_DATA_LEN,
    );
    assert_eq!(&bytes[3..], &data[..]);
}

#[test]
fn shutdown_script_random_respects_bounds() {
    let mut rng = SmallRng::seed_from_u64(1);
    for _ in 0..200 {
        let v = ShutdownScriptVariant::random(&mut rng);
        match &v {
            ShutdownScriptVariant::AnySegwit { version, program } => {
                assert!(
                    (ShutdownScriptVariant::ANYSEGWIT_MIN_VERSION
                        ..=ShutdownScriptVariant::ANYSEGWIT_MAX_VERSION)
                        .contains(version),
                    "version out of range: {version}",
                );
                assert!(
                    (ShutdownScriptVariant::ANYSEGWIT_MIN_PROGRAM_LEN
                        ..=ShutdownScriptVariant::ANYSEGWIT_MAX_PROGRAM_LEN)
                        .contains(&program.len()),
                    "program length out of range: {}",
                    program.len(),
                );
            }
            ShutdownScriptVariant::OpReturn(data) => {
                assert!(
                    (ShutdownScriptVariant::OP_RETURN_MIN_DATA_LEN
                        ..=ShutdownScriptVariant::OP_RETURN_MAX_DATA_LEN)
                        .contains(&data.len()),
                    "OpReturn length out of range: {}",
                    data.len(),
                );
            }
            _ => {}
        }
        // encode() must not panic for any randomly produced variant.
        let _ = v.encode();
    }
}

// -- ChannelTypeVariant tests --

// Ensure ChannelTypeVariant and ChannelTypeVariant::ALL stay in sync. The
// exhaustive match in this test will fail to compile if a variant is added
// without updating it, and the assertion will fail if the match is updated
// without updating ChannelTypeVariant::ALL.
#[test]
fn channel_type_variant_all_is_complete() {
    let variant_count = |v: ChannelTypeVariant| -> usize {
        match v {
            ChannelTypeVariant::StaticRemoteKey
            | ChannelTypeVariant::StaticRemoteKeyScidAlias
            | ChannelTypeVariant::StaticRemoteKeyZeroConf
            | ChannelTypeVariant::StaticRemoteKeyScidAliasZeroConf
            | ChannelTypeVariant::Anchors
            | ChannelTypeVariant::AnchorsScidAlias
            | ChannelTypeVariant::AnchorsZeroConf
            | ChannelTypeVariant::AnchorsScidAliasZeroConf
            | ChannelTypeVariant::ZeroFeeCommitments
            | ChannelTypeVariant::ZeroFeeCommitmentsScidAlias
            | ChannelTypeVariant::ZeroFeeCommitmentsZeroConf
            | ChannelTypeVariant::ZeroFeeCommitmentsScidAliasZeroConf
            | ChannelTypeVariant::SimpleTaproot
            | ChannelTypeVariant::SimpleTaprootScidAlias
            | ChannelTypeVariant::SimpleTaprootZeroConf
            | ChannelTypeVariant::SimpleTaprootScidAliasZeroConf
            | ChannelTypeVariant::SimpleTaprootStaging
            | ChannelTypeVariant::SimpleTaprootStagingScidAlias
            | ChannelTypeVariant::SimpleTaprootStagingZeroConf
            | ChannelTypeVariant::SimpleTaprootStagingScidAliasZeroConf
            | ChannelTypeVariant::ScriptEnforcedLease
            | ChannelTypeVariant::ScriptEnforcedLeaseScidAlias
            | ChannelTypeVariant::ScriptEnforcedLeaseZeroConf
            | ChannelTypeVariant::ScriptEnforcedLeaseScidAliasZeroConf => 24,
        }
    };
    assert_eq!(
        ChannelTypeVariant::ALL.len(),
        variant_count(ChannelTypeVariant::ALL[0]),
    );
}

#[test]
fn channel_type_encode_matches_bits_for_all_variants() {
    // BOLT 9 feature bitmaps are big-endian: bit 0 is the LSB of the last byte.
    fn feature_bit_set(bytes: &[u8], bit: usize) -> bool {
        let byte_from_end = bit / 8;
        if byte_from_end >= bytes.len() {
            return false;
        }
        let idx = bytes.len() - 1 - byte_from_end;
        bytes[idx] & (1 << (bit % 8)) != 0
    }

    for &variant in ChannelTypeVariant::ALL {
        let bits = variant.bits();
        let bytes = variant.encode();

        let max_bit = *bits.iter().max().expect("non-empty bits");
        assert_eq!(
            bytes.len(),
            max_bit / 8 + 1,
            "{variant:?}: byte length should fit highest bit {max_bit}",
        );

        // Every bit listed by bits() must be set; no other bits may be set.
        let total_bits = bytes.len() * 8;
        for bit in 0..total_bits {
            assert_eq!(
                feature_bit_set(&bytes, bit),
                bits.contains(&bit),
                "{variant:?}: bit {bit} mismatch (bits()={bits:?}, encoded={bytes:?})",
            );
        }
    }
}

fn generate_open_channel_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If OpenChannelGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_open_channel_program_is_type_correct() {
    for seed in 0..100 {
        generate_open_channel_program(seed);
    }
}

#[test]
fn generated_open_channel_program_structure() {
    let program = generate_open_channel_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    // Must end with SendOpenChannel, RecvAcceptChannel.
    assert!(
        matches!(ops[ops.len() - 2], Operation::SendOpenChannel),
        "second-to-last instruction should be SendOpenChannel",
    );
    assert!(
        matches!(ops[ops.len() - 1], Operation::RecvAcceptChannel),
        "last instruction should be RecvAcceptChannel",
    );

    // At least one BuildOpenChannel.
    assert!(
        ops.iter()
            .any(|op| matches!(op, Operation::BuildOpenChannel)),
        "expected at least one BuildOpenChannel",
    );

    // At least 6 DerivePoint instructions (fresh basepoints).
    let derive_count = program
        .instructions
        .iter()
        .filter(|i| matches!(i.operation, Operation::DerivePoint))
        .count();
    assert!(
        derive_count >= 6,
        "expected at least 6 DerivePoint, got {derive_count}"
    );
}

fn generate_funding_created_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    FundingCreatedGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If FundingCreatedGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_funding_created_program_is_type_correct() {
    for seed in 0..100 {
        generate_funding_created_program(seed);
    }
}

#[test]
fn generated_funding_created_program_structure() {
    let program = generate_funding_created_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    // Must end with SendFundingCreated, RecvFundingSigned, BroadcastTransaction.
    assert!(
        matches!(ops[ops.len() - 3], Operation::SendFundingCreated),
        "third-to-last instruction should be SendFundingCreated",
    );
    assert!(
        matches!(ops[ops.len() - 2], Operation::RecvFundingSigned),
        "second-to-last instruction should be RecvFundingSigned",
    );
    assert!(
        matches!(ops[ops.len() - 1], Operation::BroadcastTransaction),
        "last instruction should be BroadcastTransaction",
    );

    // Exactly one create funding transaction.
    assert_eq!(
        ops.iter()
            .filter(|op| matches!(op, Operation::CreateFundingTransaction))
            .count(),
        1,
        "expected exactly one CreateFundingTransaction",
    );
}

fn generate_channel_ready_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    ChannelReadyGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If ChannelReadyGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_channel_ready_program_is_type_correct() {
    for seed in 0..100 {
        generate_channel_ready_program(seed);
    }
}

#[test]
fn generated_channel_ready_program_structure() {
    let program = generate_channel_ready_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    // Must end with SendChannelReady, RecvChannelReady.
    assert!(
        matches!(ops[ops.len() - 2], Operation::SendChannelReady { .. }),
        "second-to-last instruction should be SendChannelReady",
    );
    assert!(
        matches!(ops[ops.len() - 1], Operation::RecvChannelReady),
        "last instruction should be RecvChannelReady",
    );

    // At least 1 DerivePoint instructions.
    let derive_count = program
        .instructions
        .iter()
        .filter(|i| matches!(i.operation, Operation::DerivePoint))
        .count();
    assert!(
        derive_count >= 1,
        "expected at least one DerivePoint, got {derive_count}"
    );
}

fn generate_funding_flow_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    FundingFlowGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If FundingFlowGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_funding_flow_program_is_type_correct() {
    for seed in 0..100 {
        generate_funding_flow_program(seed);
    }
}

#[test]
fn generated_funding_flow_program_structure() {
    let program = generate_funding_flow_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    // Must end with SendChannelReady, RecvChannelReady.
    assert!(
        matches!(ops[ops.len() - 2], Operation::SendChannelReady { .. }),
        "second-to-last instruction should be SendChannelReady",
    );
    assert!(
        matches!(ops[ops.len() - 1], Operation::RecvChannelReady),
        "last instruction should be RecvChannelReady",
    );

    // Must extract the funding pubkey from `accept_channel` exactly once.
    assert_eq!(
        ops.iter()
            .filter(|op| matches!(
                op,
                Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey)
            ))
            .count(),
        1,
        "expected exactly one ExtractAcceptChannel(FundingPubkey)",
    );

    // Key operations must appear in protocol order.
    let position = |pred: fn(&Operation) -> bool| {
        ops.iter()
            .position(|op| pred(op))
            .expect("operation present")
    };

    let recv_accept_channel = position(|op| matches!(op, Operation::RecvAcceptChannel));
    let send_funding_created = position(|op| matches!(op, Operation::SendFundingCreated));
    let recv_funding_signed = position(|op| matches!(op, Operation::RecvFundingSigned));
    let broadcast_transaction = position(|op| matches!(op, Operation::BroadcastTransaction));
    let send_channel_ready = position(|op| matches!(op, Operation::SendChannelReady { .. }));
    let recv_channel_ready = position(|op| matches!(op, Operation::RecvChannelReady));

    assert!(
        recv_accept_channel < send_funding_created,
        "RecvAcceptChannel should precede SendFundingCreated",
    );
    assert!(
        recv_funding_signed < broadcast_transaction,
        "RecvFundingSigned should precede BroadcastTransaction",
    );
    assert!(
        broadcast_transaction < send_channel_ready,
        "BroadcastTransaction should precede SendChannelReady",
    );
    assert!(
        send_channel_ready < recv_channel_ready,
        "SendChannelReady should precede RecvChannelReady",
    );

    // At least 7 DerivePoint instructions.
    let derive_count = program
        .instructions
        .iter()
        .filter(|i| matches!(i.operation, Operation::DerivePoint))
        .count();
    assert!(
        derive_count >= 7,
        "expected at least 7 DerivePoint, got {derive_count}"
    );
}

fn generate_channel_announcement_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    ChannelAnnouncementGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If ChannelAnnouncementGenerator completes without panicking, every
// instruction has correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_channel_announcement_program_is_type_correct() {
    for seed in 0..100 {
        generate_channel_announcement_program(seed);
    }
}

#[test]
fn generated_channel_announcement_program_structure() {
    let program = generate_channel_announcement_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    assert!(
        matches!(ops[ops.len() - 1], Operation::SendMessage),
        "last instruction should be SendMessage",
    );
    let build_count = ops
        .iter()
        .filter(|op| matches!(op, Operation::BuildChannelAnnouncement))
        .count();
    assert_eq!(
        build_count, 1,
        "expected exactly one BuildChannelAnnouncement"
    );
}

fn generate_node_announcement_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    NodeAnnouncementGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If NodeAnnouncementGenerator completes without panicking, every instruction
// has correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_node_announcement_program_is_type_correct() {
    for seed in 0..100 {
        generate_node_announcement_program(seed);
    }
}

#[test]
fn generated_node_announcement_program_structure() {
    let program = generate_node_announcement_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    assert!(
        matches!(ops[ops.len() - 1], Operation::SendMessage),
        "last instruction should be SendMessage",
    );
    let build_count = ops
        .iter()
        .filter(|op| matches!(op, Operation::BuildNodeAnnouncement { .. }))
        .count();
    assert_eq!(build_count, 1, "expected exactly one BuildNodeAnnouncement");
}

#[test]
fn generated_node_announcement_alias_is_utf8() {
    for seed in 0..100 {
        let program = generate_node_announcement_program(seed);
        let alias = program
            .instructions
            .iter()
            .find_map(|i| match i.operation {
                Operation::BuildNodeAnnouncement { alias, .. } => Some(alias),
                _ => None,
            })
            .expect("BuildNodeAnnouncement present");
        assert!(str::from_utf8(&alias).is_ok(), "alias is not UTF-8");
    }
}

fn generate_channel_update_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    ChannelUpdateGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If ChannelUpdateGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_channel_update_program_is_type_correct() {
    for seed in 0..100 {
        generate_channel_update_program(seed);
    }
}

#[test]
fn generated_channel_update_program_structure() {
    let program = generate_channel_update_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    assert!(
        matches!(ops[ops.len() - 1], Operation::SendMessage),
        "last instruction should be SendMessage",
    );
    let build_count = ops
        .iter()
        .filter(|op| matches!(op, Operation::BuildChannelUpdate))
        .count();
    assert_eq!(build_count, 1, "expected exactly one BuildChannelUpdate");
}

#[test]
fn generated_open_channel_program_postcard_roundtrip() {
    let program = generate_open_channel_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generated_funding_created_program_postcard_roundtrip() {
    let program = generate_funding_created_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generated_channel_ready_program_postcard_roundtrip() {
    let program = generate_channel_ready_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generated_funding_flow_program_postcard_roundtrip() {
    let program = generate_funding_flow_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generated_channel_announcement_program_postcard_roundtrip() {
    let program = generate_channel_announcement_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generated_node_announcement_program_postcard_roundtrip() {
    let program = generate_node_announcement_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generated_channel_update_program_postcard_roundtrip() {
    let program = generate_channel_update_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generate_fresh_produces_distinct_indices() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let a = builder.generate_fresh(VariableType::Amount, &mut rng);
    let b = builder.generate_fresh(VariableType::Amount, &mut rng);
    assert_ne!(a, b);
}

#[test]
fn generate_mine_blocks_program() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let mb = builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);
    let program = builder.build();

    assert!(matches!(
        program.instructions[mb].operation,
        Operation::MineBlocks(_),
    ),);
}

#[test]
fn pick_variable_reuses_existing() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();

    // Generate one Amount variable.
    let first = builder.generate_fresh(VariableType::Amount, &mut rng);

    // pick_variable should mostly reuse the existing variable. Over 100 calls,
    // at least some should return the original index.
    let mut reuse_count = 0;
    for _ in 0..100 {
        let idx = builder.pick_variable(VariableType::Amount, &mut rng);
        if idx == first {
            reuse_count += 1;
        }
    }
    assert!(
        reuse_count > 0,
        "pick_variable never reused existing variable"
    );
}

#[test]
fn pick_variable_uses_unspent_affine() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);

    let msg_idx = builder.pick_variable(VariableType::OpenChannelMessage, &mut rng);
    let unspent_sent_open_channel = builder.append(Operation::SendOpenChannel, &[msg_idx]);

    // pick_variable should prefer an unspent affine variable.
    let idx = builder.pick_variable(VariableType::SentOpenChannel, &mut rng);
    assert_eq!(idx, unspent_sent_open_channel);
}

#[test]
#[should_panic(expected = "cannot generate fresh SentOpenChannel: affine type")]
fn pick_variable_panics_on_empty_affine() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.pick_variable(VariableType::SentOpenChannel, &mut rng);
}

#[test]
#[should_panic(expected = "no candidates for SentOpenChannel")]
fn pick_variable_panics_on_all_affine_consumed() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);

    // All `SentOpenChannel` have been already consumed.
    builder.pick_variable(VariableType::SentOpenChannel, &mut rng);
}

#[test]
#[should_panic(expected = "cannot generate fresh Message")]
fn generate_fresh_message_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::Message, &mut rng);
}

#[test]
#[should_panic(expected = "cannot generate fresh AcceptChannel")]
fn generate_fresh_accept_channel_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::AcceptChannel, &mut rng);
}

#[test]
#[should_panic(expected = "cannot generate fresh FundingTransaction")]
fn generate_fresh_funding_transaction_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::FundingTransaction, &mut rng);
}

#[test]
#[should_panic(expected = "cannot generate fresh SentOpenChannel: affine type")]
fn generate_fresh_sent_open_channel_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::SentOpenChannel, &mut rng);
}

#[test]
#[should_panic(expected = "expected 1 inputs, got 0")]
fn append_wrong_input_count_panics() {
    let mut builder = ProgramBuilder::new();
    builder.append(Operation::DerivePoint, &[]);
}

#[test]
#[should_panic(expected = "index 99 out of bounds")]
fn append_out_of_bounds_panics() {
    let mut builder = ProgramBuilder::new();
    builder.append(Operation::DerivePoint, &[99]);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn append_void_reference_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    NodeAnnouncementGenerator.generate(&mut builder, &mut rng);
    let program = builder.build();
    // SendMessage is last and has void output.
    let send_idx = program.instructions.len() - 1;
    assert!(
        program.instructions[send_idx]
            .operation
            .output_type()
            .is_none(),
        "expected void operation",
    );
    // Rebuild the same program and try to reference the void instruction.
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    NodeAnnouncementGenerator.generate(&mut builder, &mut rng);
    builder.append(Operation::SendMessage, &[send_idx]);
}

#[test]
#[should_panic(expected = "expected PrivateKey, got Amount")]
fn append_type_mismatch_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let amount = builder.generate_fresh(VariableType::Amount, &mut rng);
    builder.append(Operation::DerivePoint, &[amount]);
}

#[test]
#[should_panic(expected = "RecvAcceptChannel input 0: affine SentOpenChannel already consumed")]
fn append_rejects_affine_overuse() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);

    let msg_idx = builder.pick_variable(VariableType::OpenChannelMessage, &mut rng);
    let sent_open_channel = builder.append(Operation::SendOpenChannel, &[msg_idx]);
    // Add consecutive `RecvAcceptChannel`s.
    builder.append(Operation::RecvAcceptChannel, &[sent_open_channel]);
    builder.append(Operation::RecvAcceptChannel, &[sent_open_channel]);
}

// -- OperationParamMutator tests --

fn assert_false_is_noop<M: Mutator>(mutator: &M, original: &Program) {
    let mut rng = SmallRng::seed_from_u64(0);
    for _ in 0..100 {
        let mut program = original.clone();
        if !mutator.mutate(&mut program, &mut rng) {
            assert_eq!(&program, original, "program modified on false return");
        }
    }
}

fn assert_mutator_preserves_well_formedness<M: Mutator>(mutator: &M, original: &Program) {
    let mut rng = SmallRng::seed_from_u64(0);
    for _ in 0..100 {
        let mut program = original.clone();
        if mutator.mutate(&mut program, &mut rng) {
            assert_well_formed(&program);
        }
    }
}

#[test]
fn param_mutator_false_is_noop() {
    let original = Program {
        // A type-valid program containing ONLY immutable operations.
        instructions: vec![
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
        ],
    };
    assert_false_is_noop(&OperationParamMutator, &original);
}

#[test]
fn param_mutator_changes_values() {
    let original = generate_open_channel_program(0);
    let mut program = original.clone();
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
    }
    assert_ne!(
        program, original,
        "OperationParamMutator never changed the program"
    );
}

#[test]
fn param_mutator_changes_mined_num_blocks() {
    let original = Program {
        instructions: vec![Instruction {
            operation: Operation::MineBlocks(42),
            inputs: vec![],
        }],
    };
    let mut program = original.clone();
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    let mut diff_count = 0;
    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
        // Make sure that MineBlocks contains a value within the clamped range of
        // blocks to be mined.
        let Operation::MineBlocks(num_blocks) = program.instructions[0].operation else {
            panic!("OperationParamMutator changed the operation type");
        };
        assert!((1..=16).contains(&num_blocks));
        if program != original {
            diff_count += 1;
        }
    }
    assert!(
        diff_count > 90,
        "OperationParamMutator has an unexpected bias"
    );
}

#[test]
fn param_mutator_changes_short_channel_id() {
    let original = Program {
        instructions: vec![Instruction {
            operation: Operation::LoadShortChannelId(0),
            inputs: vec![],
        }],
    };
    let mut program = original.clone();
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    let mut diff_count = 0;
    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
        // Ensure the operation type is unchanged.
        assert!(
            matches!(
                program.instructions[0].operation,
                Operation::LoadShortChannelId(_)
            ),
            "OperationParamMutator changed the operation type"
        );
        if program != original {
            diff_count += 1;
        }
    }
    assert!(
        diff_count > 90,
        "OperationParamMutator has an unexpected bias"
    );
}

#[test]
fn param_mutator_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn param_mutator_returns_false_for_singleton_extract_field() {
    // TemporaryChannelId is the only AcceptChannelField with output type
    // ChannelId, so ExtractAcceptChannel(TemporaryChannelId) has no type-
    // compatible alternative to swap to. With it as the only mutable op, the
    // mutator must report no change.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::ExtractAcceptChannel(AcceptChannelField::TemporaryChannelId),
                inputs: vec![0],
            },
        ],
    };
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn param_mutator_caps_byte_length() {
    // Start at exactly MAX_MESSAGE_SIZE so any growth would exceed the cap.
    let mut program = Program {
        instructions: vec![Instruction {
            operation: Operation::LoadBytes(vec![0; MAX_MESSAGE_SIZE]),
            inputs: vec![],
        }],
    };

    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..10_000 {
        mutator.mutate(&mut program, &mut rng);
        let Operation::LoadBytes(b) = &program.instructions[0].operation else {
            panic!("operation type changed");
        };
        assert!(
            b.len() <= MAX_MESSAGE_SIZE,
            "bytes exceeded MAX_MESSAGE_SIZE: got {}",
            b.len(),
        );
    }
}

#[test]
fn param_mutator_modifies_node_announcement_params() {
    let original_rgb = [0x11, 0x22, 0x33];
    let original_alias = [0xaa; 32];
    let mut builder = ProgramBuilder::new();
    let sk = builder.append(Operation::LoadPrivateKey(key(1)), &[]);
    let features = builder.append(Operation::LoadFeatures(vec![]), &[]);
    let timestamp = builder.append(Operation::LoadTimestamp(0), &[]);
    let addresses = builder.append(Operation::LoadBytes(vec![]), &[]);
    let build_idx = builder.append(
        Operation::BuildNodeAnnouncement {
            rgb_color: original_rgb,
            alias: original_alias,
        },
        &[sk, features, timestamp, addresses],
    );
    let mut program = builder.build();

    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
    }

    let Operation::BuildNodeAnnouncement { rgb_color, alias } =
        &program.instructions[build_idx].operation
    else {
        panic!("operation type changed");
    };
    assert_ne!(*rgb_color, original_rgb, "rgb_color never mutated");
    assert_ne!(*alias, original_alias, "alias never mutated");
}

#[test]
fn param_mutator_preserves_extract_field_type() {
    // One ExtractAcceptChannel instruction per field variant.
    let mut instructions = vec![Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![],
    }];
    for &field in AcceptChannelField::ALL {
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel(field),
            inputs: vec![0],
        });
    }

    let mut program = Program { instructions };
    let original_types: Vec<VariableType> = AcceptChannelField::ALL
        .iter()
        .map(|f| f.output_type())
        .collect();

    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);

        for (i, &expected_type) in original_types.iter().enumerate() {
            let field = match &program.instructions[i + 1].operation {
                Operation::ExtractAcceptChannel(f) => *f,
                other => panic!("expected ExtractAcceptChannel, got {other:?}"),
            };
            assert_eq!(
                field.output_type(),
                expected_type,
                "{field:?} has type {:?}, expected {expected_type:?}",
                field.output_type(),
            );
        }
    }
}

// -- InputSwapMutator tests --

#[test]
fn input_swap_false_is_noop() {
    let original = generate_open_channel_program(0);
    assert_false_is_noop(&InputSwapMutator, &original);
}

#[test]
fn input_swap_changes_references() {
    let original = generate_open_channel_program(0);
    let mut program = original.clone();
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
    }
    assert_ne!(
        program, original,
        "InputSwapMutator never changed the program"
    );
}

#[test]
fn input_swap_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn input_swap_returns_false_when_no_alternatives() {
    // DerivePoint consumes the only PrivateKey -- no alternative to swap to.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn input_swap_preserves_well_formedness() {
    let original = generate_open_channel_program(0);
    assert_mutator_preserves_well_formedness(&InputSwapMutator, &original);
}

#[test]
fn input_swap_preserves_affine() {
    let mut program = generate_open_channel_program(0);
    // Get rid of the last instruction in the program: `RecvAcceptChannel`.
    program.instructions.pop();
    // `BuildOpenChannel` is the second-to-last, while `SendOpenChannel`
    // is the last instruction in the program now.
    let open_channel_msg = program.instructions.len() - 2;
    let send_open_channel_1 = program.instructions.len() - 1;

    program.instructions.extend([
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![open_channel_msg],
        },
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![send_open_channel_1],
        },
    ]);
    let accept_channel = program.instructions.len() - 1;

    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
        // Ensure `RecvAcceptChannel`'s input never changed to the inserted `SentOpenChannel`.
        assert_eq!(
            send_open_channel_1,
            program.instructions[accept_channel].inputs[0]
        );
    }
}

// -- InstructionDeleteMutator tests --

#[test]
fn instr_delete_changes_values() {
    let original = generate_open_channel_program(0);
    let mut program = original.clone();
    let mutator = InstructionDeleteMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
    }
    assert_ne!(
        program, original,
        "InstructionDeleteMutator never changed the program"
    );
}

#[test]
fn instr_delete_false_is_noop() {
    let original = generate_open_channel_program(0);
    assert_false_is_noop(&InstructionDeleteMutator, &original);
}

#[test]
fn instr_delete_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    let mutator = InstructionDeleteMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn instr_delete_returns_false_if_unhealable() {
    let original = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    let mutator = InstructionDeleteMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    let mut found_unhealable = false;

    for _ in 0..100 {
        let mut program = original.clone();
        if !mutator.mutate(&mut program, &mut rng) {
            found_unhealable = true;
            break;
        }
    }
    assert!(
        found_unhealable,
        "InstructionDeleteMutator never returned false for unhealable instruction"
    );
}

#[test]
fn instr_delete_shifts_indices_correctly() {
    let original = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(2)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![1, 1],
            },
        ],
    };

    let mutator = InstructionDeleteMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    let mut verified_shift = false;

    for _ in 0..100 {
        let mut program = original.clone();
        if mutator.mutate(&mut program, &mut rng) &&
            program.instructions.len() == 2 &&
            // Check if it deleted index 1, meaning DerivePoint is now at index 1
            program.instructions[1].operation == Operation::DerivePoint
        {
            // input references must have shifted from [1, 1] down to [0, 0]
            assert_eq!(program.instructions[1].inputs, vec![0, 0]);
            verified_shift = true;
            break;
        }
    }
    assert!(
        verified_shift,
        "InstructionDeleteMutator never took the expected target shift path"
    );
}

#[test]
fn instr_delete_preserves_affine_producers() {
    let original = Program {
        instructions: vec![
            Instruction {
                operation: Operation::BuildOpenChannel,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![3],
            },
        ],
    };
    let mutator = InstructionDeleteMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    let mut mutated = false;

    for _ in 0..100 {
        let mut program = original.clone();
        // The only deletable instructions in the program are the `RecvAcceptChannel`s.
        if mutator.mutate(&mut program, &mut rng) {
            assert_eq!(program.instructions.len(), original.instructions.len() - 1);
            assert!(
                // The first `RecvAcceptChannel` was deleted.
                program.instructions[2] == original.instructions[3] ||
                // The second `RecvAcceptChannel` was deleted.
                program.instructions == original.instructions[0..original.instructions.len() - 1],
                "InstructionDeleteMutator deleted an unhealable instruction"
            );
            mutated = true;
        }
    }
    assert!(
        mutated,
        "InstructionDeleteMutator never mutated a mutable program"
    );
}

#[test]
fn instr_delete_redirects_affine_consumer() {
    let original = Program {
        instructions: vec![
            Instruction {
                operation: Operation::BuildOpenChannel,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadU16(42),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![3],
            },
        ],
    };

    let mutator = InstructionDeleteMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    let mut redirected = false;

    for _ in 0..100 {
        let mut program = original.clone();
        if mutator.mutate(&mut program, &mut rng) {
            // We are explicitly looking for the mutation where index 3 was deleted.
            if program.instructions[2].operation == Operation::LoadU16(42)
                && program.instructions[3].operation == Operation::RecvAcceptChannel
            {
                // The orphaned RecvAcceptChannel must have been redirected to the
                // prior unconsumed affine variable at index 1.
                assert_eq!(
                    program.instructions[3].inputs,
                    vec![1],
                    "Affine consumer was not redirected to the unconsumed affine variable"
                );
                redirected = true;
            }
        }
    }
    assert!(
        redirected,
        "InstructionDeleteMutator never triggered the affine redirection path"
    );
}

#[test]
fn instr_delete_maintains_validity() {
    let original = generate_open_channel_program(0);
    assert_mutator_preserves_well_formedness(&InstructionDeleteMutator, &original);
}

// -- InstructionReorderMutator tests --

#[test]
fn instr_reorder_false_is_noop() {
    let original = generate_open_channel_program(0);
    assert_false_is_noop(&InstructionReorderMutator, &original);
}

#[test]
fn instr_reorder_returns_false_on_empty() {
    let mut program = Program {
        instructions: vec![],
    };
    let mut rng = SmallRng::seed_from_u64(0);
    let mutator = InstructionReorderMutator;
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn instr_reorder_returns_false_on_single_or_no_act() {
    // ChannelAnnouncementGenerator produces a single Act instruction: SendMessage.
    let mut program = generate_channel_announcement_program(0);
    let mutator = InstructionReorderMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    assert!(!mutator.mutate(&mut program, &mut rng));
    // Delete the SendMessage instruction at the end. The program is now
    // non-empty with 0 Act instructions.
    program.instructions.pop();
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn instr_reorder_returns_false_if_act2_is_past_usage_boundary() {
    // Invalid program, but mutators shouldn't care about program validity.
    // Two of the three Act instructions are immediately consumed.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::BuildOpenChannel,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::ExtractAcceptChannel(AcceptChannelField::ChannelType),
                inputs: vec![2],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
        ],
    };
    let mut rng = SmallRng::seed_from_u64(0);
    let mutator = InstructionReorderMutator;
    for _ in 0..100 {
        assert!(!mutator.mutate(&mut program, &mut rng));
    }
}

#[test]
fn instr_reorder_swaps_and_heals() {
    // The only swappable instructions are RecvAcceptChannel and SendMessage.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::BuildOpenChannel,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::ExtractAcceptChannel(AcceptChannelField::ChannelType),
                inputs: vec![2],
            },
        ],
    };
    let mut rng = SmallRng::seed_from_u64(0);
    let mutator = InstructionReorderMutator;
    let mut mutated = false;
    for _ in 0..100 {
        if mutator.mutate(&mut program, &mut rng) {
            mutated = true;
            break;
        }
    }
    assert!(
        mutated,
        "InstructionReorderMutator never mutated the program"
    );

    // RecvAcceptChannel and SendMessage should've been swapped.
    assert_eq!(program.instructions[2].operation, Operation::SendMessage);
    assert_eq!(
        program.instructions[4].operation,
        Operation::RecvAcceptChannel
    );
    // The inteleaved instruction shouldn't have been changed.
    assert_eq!(
        program.instructions[3].operation,
        Operation::LoadChainHashFromContext
    );
    // Downstream instructions should be healed.
    assert_eq!(program.instructions[5].inputs[0], 4);
}

#[test]
fn instr_reorder_preserves_well_formedness() {
    let mut original = generate_open_channel_program(0);
    // The generic OpenChannelGenerator program doesn't have swappable Act
    // instructions, so add some.
    let open_channel_msg = original.instructions.len() - 3;
    original.instructions.extend([
        Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![open_channel_msg],
        },
        Instruction {
            operation: Operation::MineBlocks(42),
            inputs: vec![],
        },
    ]);
    assert_mutator_preserves_well_formedness(&InstructionReorderMutator, &original);
}

// -- GeneratorInsertionMutator tests --

// A test generator that doesn't use RNG, ensuring its operations are always predictable.
struct DummyGenerator;
impl Generator for DummyGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, _rng: &mut impl Rng) {
        // Emit fully static operations.
        builder.append(Operation::LoadBlockHeight(100), &[]);
        builder.append(Operation::LoadFeeratePerKw(253), &[]);
        builder.append(Operation::LoadPrivateKey(key(1)), &[]);
        builder.append(Operation::DerivePoint, &[2]);
    }
}

fn generate_dummy_program(seed: u64) -> Program {
    let mut builder = ProgramBuilder::new();
    let mut rng = SmallRng::seed_from_u64(seed);
    DummyGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

#[test]
fn generator_insertion_does_not_drop_instructions() {
    let mut program = generate_open_channel_program(0);
    let original_program_len = program.instructions.len();
    let dummy_program = generate_dummy_program(0);
    let dummy_program_len = dummy_program.instructions.len();

    // DummyGenerator emits static instructions (never calls `pick_variable`).
    // Inserting it in a program deterministically increases instructions count.
    let mutator = GeneratorInsertionMutator::new(DummyGenerator);
    let mut rng = SmallRng::seed_from_u64(0);

    mutator.mutate(&mut program, &mut rng);
    assert_eq!(
        original_program_len + dummy_program_len,
        program.instructions.len()
    );
}

#[test]
fn generator_insertion_returns_generated_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    let dummy_program = generate_dummy_program(0);
    let mutator = GeneratorInsertionMutator::new(DummyGenerator);
    let mut rng = SmallRng::seed_from_u64(0);

    mutator.mutate(&mut program, &mut rng);
    assert_eq!(
        program, dummy_program,
        "GeneratorInsertionMutator didn't insert generated program"
    );
}

#[test]
fn generator_insertion_preserves_generated() {
    let mut program = generate_open_channel_program(0);
    let mut rng = SmallRng::seed_from_u64(0);

    let dummy_program = generate_dummy_program(0);
    let mutator = GeneratorInsertionMutator::new(DummyGenerator);
    mutator.mutate(&mut program, &mut rng);

    let inserted_correctly = program
        .instructions
        .windows(dummy_program.instructions.len())
        .any(|window| {
            window
                .iter()
                .zip(dummy_program.instructions.iter())
                .all(|(a, b)| a.operation == b.operation)
        });

    assert!(
        inserted_correctly,
        "Generated sequence not found intact in mutated program"
    );
}

#[test]
fn generator_insertion_shifts_correctly() {
    let original = generate_open_channel_program(0);
    let mut program = original.clone();

    let mutator = GeneratorInsertionMutator::new(OpenChannelGenerator);
    let mut rng = SmallRng::seed_from_u64(0);
    mutator.mutate(&mut program, &mut rng);

    // Find the exact insert_point chosen by the RNG.
    let mut insert_point = original.instructions.len();
    for i in 0..original.instructions.len() {
        if program.instructions[i].operation != original.instructions[i].operation {
            insert_point = i;
            break;
        }
    }

    // The length of the generated program.
    let offset = program.instructions.len() - original.instructions.len();

    for mut_idx in (insert_point + offset)..program.instructions.len() {
        let orig_idx = mut_idx - offset;
        let mut_instr = &program.instructions[mut_idx];
        let orig_instr = &original.instructions[orig_idx];

        // Ensure the operations align perfectly.
        assert_eq!(mut_instr.operation, orig_instr.operation);
        assert_eq!(mut_instr.inputs.len(), orig_instr.inputs.len());

        for (i, (&mut_in, &orig_in)) in mut_instr
            .inputs
            .iter()
            .zip(orig_instr.inputs.iter())
            .enumerate()
        {
            if orig_in < insert_point {
                // If it pointed to something BEFORE the cut, the index should not change.
                assert_eq!(
                    mut_in, orig_in,
                    "Instruction {mut_idx} input {i} shifted, but it points BEFORE the insertion point",
                );
            } else {
                // If it pointed to something AT or AFTER the cut, the index must shift by the offset.
                assert_eq!(
                    mut_in,
                    orig_in + offset,
                    "Instruction {mut_idx} input {i} failed to shift by exactly {offset}",
                );
            }
        }
    }
}

#[test]
fn generator_insertion_preserves_well_formedness() {
    let original = generate_open_channel_program(0);
    for &generator in AnyGenerator::ALL {
        let mutator = GeneratorInsertionMutator::new(generator);
        assert_mutator_preserves_well_formedness(&mutator, &original);
    }
}

// -- DeadCodeEliminator tests --

#[test]
fn dead_code_removes_dead_instructions() {
    // All three LoadAmount instructions are unreferenced; all three are dropped.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(2),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(3),
                inputs: vec![],
            },
        ],
    };
    assert!(DeadCodeEliminator.minimize(&mut program));
    assert!(
        program.instructions.is_empty(),
        "all dead instructions should be removed"
    );
    assert_well_formed(&program);
}

#[test]
fn dead_code_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    assert!(!DeadCodeEliminator.minimize(&mut program));
    assert!(program.instructions.is_empty());
}

/// Build a program with a dead load appended after the generated program.
/// This gives the `DeadCodeEliminator` at least one candidate to try.
fn program_with_dead_load() -> Program {
    let mut p = generate_open_channel_program(0);
    p.instructions.push(Instruction {
        operation: Operation::LoadAmount(42),
        inputs: vec![],
    });
    p
}

#[test]
fn dead_code_keeps_send_open_channel() {
    let mut program = program_with_dead_load();
    DeadCodeEliminator.minimize(&mut program);
    let has_send = program
        .instructions
        .iter()
        .any(|i| matches!(i.operation, Operation::SendOpenChannel));
    assert!(
        has_send,
        "DeadCodeEliminator must not remove SendOpenChannel"
    );
}

#[test]
fn dead_code_keeps_recv_accept_channel() {
    let mut program = program_with_dead_load();
    DeadCodeEliminator.minimize(&mut program);
    let has_recv = program
        .instructions
        .iter()
        .any(|i| matches!(i.operation, Operation::RecvAcceptChannel));
    assert!(
        has_recv,
        "DeadCodeEliminator must not remove RecvAcceptChannel"
    );
}

#[test]
fn dead_code_result_well_formed() {
    let mut program = program_with_dead_load();
    DeadCodeEliminator.minimize(&mut program);
    assert_well_formed(&program);
}

#[test]
fn dead_code_reindexes_remaining_inputs() {
    // Indexes 0 and 1 are dead loads; 2 is a referenced load; 3 references 2.
    // After dropping 0 and 1, the surviving load shifts to index 0 and the
    // DerivePoint must be rewritten to reference it.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(2),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![2],
            },
        ],
    };
    assert!(DeadCodeEliminator.minimize(&mut program));
    assert_eq!(program.instructions.len(), 2);
    assert!(matches!(
        program.instructions[0].operation,
        Operation::LoadPrivateKey(_)
    ));
    assert!(matches!(
        program.instructions[1].operation,
        Operation::SendMessage
    ));
    assert_eq!(program.instructions[1].inputs, vec![0]);
}

#[test]
fn dead_code_chains_collapse() {
    // Two chains share a root LoadPrivateKey. One DerivePoint feeds an
    // impure SendMessage (alive); the other is unreferenced (dead). DCE
    // drops the dead DerivePoint, but the shared root must survive because
    // the alive chain still references it.
    //
    // Note: this program is type-invalid (SendMessage expects Message, not
    // Point), but the minimizer doesn't typecheck so it's fine for the test.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint, // alive
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::DerivePoint, // dead
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![1],
            },
        ],
    };
    let expected = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![1],
            },
        ],
    };
    assert!(DeadCodeEliminator.minimize(&mut program));
    assert_eq!(program, expected);
}

#[test]
fn dead_code_idempotent() {
    let mut once = program_with_dead_load();
    DeadCodeEliminator.minimize(&mut once);
    let mut twice = once.clone();
    assert!(
        !DeadCodeEliminator.minimize(&mut twice),
        "second pass must report unchanged"
    );
    assert_eq!(once, twice, "elimination is idempotent");
}

// -- CommonSubexpressionEliminator tests --

#[test]
fn cse_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    assert!(!CommonSubexpressionEliminator.minimize(&mut program));
    assert!(program.instructions.is_empty());
}

#[test]
fn cse_rewires_references() {
    // A downstream DerivePoint consumes the duplicate load. After CSE, its
    // input must be rewired from the dropped duplicate (index 1) to the
    // surviving canonical load (index 0).
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)), // duplicate of index 0
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![1], // must be rewired to 0
            },
        ],
    };
    let expected = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    assert!(CommonSubexpressionEliminator.minimize(&mut program));
    assert_eq!(program, expected);
    assert_well_formed(&program);
}

#[test]
fn cse_result_well_formed() {
    let mut program = generate_open_channel_program(0);
    CommonSubexpressionEliminator.minimize(&mut program);
    assert_well_formed(&program);
}

#[test]
fn cse_idempotent() {
    let mut once = generate_open_channel_program(0);
    CommonSubexpressionEliminator.minimize(&mut once);
    let mut twice = once.clone();
    assert!(
        !CommonSubexpressionEliminator.minimize(&mut twice),
        "second pass must report unchanged"
    );
    assert_eq!(once, twice, "merging is idempotent");
}

#[test]
fn cse_merges_compute_ops_through_canonicalized_inputs() {
    // Two LoadPrivateKey duplicates feed two DerivePoint instructions.
    // CSE first merges the loads, which canonicalizes the DerivePoint
    // inputs to the same index, which in turn lets CSE merge the
    // DerivePoints themselves.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)), // duplicate of 0
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![2], // canonicalizes to 0 -> matches index 1
            },
        ],
    };
    assert_well_formed(&program);
    assert!(CommonSubexpressionEliminator.minimize(&mut program));
    assert_eq!(program.instructions.len(), 2);
    assert!(matches!(
        program.instructions[0].operation,
        Operation::LoadPrivateKey(_)
    ));
    assert!(matches!(
        program.instructions[1].operation,
        Operation::DerivePoint
    ));
    assert_eq!(program.instructions[1].inputs, vec![0]);
}

#[test]
fn cse_does_not_merge_send_message() {
    // SendMessage is not pure (network side-effect): two with the same
    // input must both survive. The duplicate LoadBytes upstream should
    // be merged, and both SendMessages remapped to the surviving load.
    //
    // Note: this program is type-invalid (SendMessage expects Message, not
    // Bytes), but the minimizer doesn't typecheck so it's fine for the test.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadBytes(vec![0xab]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadBytes(vec![0xab]), // duplicate of 0
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![2], // canonicalizes to 0
            },
        ],
    };
    let expected = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadBytes(vec![0xab]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
        ],
    };
    assert!(CommonSubexpressionEliminator.minimize(&mut program));
    assert_eq!(program, expected, "SendMessage must not be deduplicated");
}
