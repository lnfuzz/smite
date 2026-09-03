//! Program fragments used by executor tests.
//!
//! Each helper returns the instructions for one flow.

use super::harness::{acceptor_funding_sk, opener_funding_sk};
use crate::executor::*;
use smite_ir::Instruction;

/// Builds the 20 `open_channel` input instructions in wire order.
pub fn open_channel_instructions() -> Vec<Instruction> {
    vec![
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
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
            operation: Operation::LoadAmount(100_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(253),
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
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadTargetPubkeyFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![0x40, 0x10, 0x00]),
            inputs: vec![],
        },
    ]
}

pub fn create_and_broadcast_tx_instructions() -> Vec<Instruction> {
    let opener_privkey = opener_funding_sk().secret_bytes();
    let acceptor_privkey = acceptor_funding_sk().secret_bytes();

    vec![
        Instruction {
            operation: Operation::LoadPrivateKey(opener_privkey),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(acceptor_privkey),
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

/// Builds instructions that construct and send a `channel_announcement`
/// referencing the `ShortChannelId` produced at variable index `scid_var`.
///
/// `base` is the variable index the first appended instruction will occupy
/// (i.e. the current program length), used to wire up the inputs to
/// `BuildChannelAnnouncement`.
pub fn channel_announcement_from_scid_instructions(
    base: usize,
    scid_var: usize,
) -> Vec<Instruction> {
    vec![
        Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x11; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x22; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x33; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadPrivateKey([0x44; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::BuildChannelAnnouncement,
            // features, chain_hash, short_channel_id, node_sk_1, node_sk_2,
            // bitcoin_sk_1, bitcoin_sk_2.
            inputs: vec![
                base,
                base + 1,
                scid_var,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
            ],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![base + 6],
        },
    ]
}

pub fn send_open_channel_instructions() -> Vec<Instruction> {
    let mut instructions = open_channel_instructions();
    instructions.extend([
        Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        },
        Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![20],
        },
    ]);
    instructions
}

pub fn send_funding_created_and_recv_funding_signed_instructions() -> Vec<Instruction> {
    let mut instrs = create_and_broadcast_tx_instructions();
    instrs.extend(vec![
        Instruction {
            operation: Operation::LoadChannelId([0xbb; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::SendFundingCreated,
            inputs: vec![6, 0, 8],
        },
        Instruction {
            operation: Operation::RecvFundingSigned,
            inputs: vec![9],
        },
    ]);
    instrs
}

pub fn recv_channel_ready_instructions(confirmations: u8) -> Vec<Instruction> {
    let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
    instrs.extend([
        Instruction {
            operation: Operation::MineBlocks(confirmations),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::RecvChannelReady,
            inputs: vec![],
        },
    ]);
    instrs
}
