//! Generator for the complete v1 outbound channel funding flow.

use rand::{Rng, RngExt};

use super::Generator;
use super::open_channel::append_open_channel;
use crate::builder::ProgramBuilder;
use crate::operation::AcceptChannelField;
use crate::{Operation, VariableType};

/// Generates the complete v1 outbound channel funding flow.
///
/// Emits instructions to:
/// 1. Build and send `open_channel`, then receive `accept_channel`
/// 2. Build and send `funding_created`, then receive `funding_signed`
/// 3. Broadcast and mine blocks to confirm the funding transaction
/// 4. Complete the `channel_ready` exchange
#[derive(Clone, Copy)]
pub struct FundingFlowGenerator;

impl FundingFlowGenerator {
    /// Blocks mined to confirm an announced channel's funding transaction.
    /// Eight is the deepest default `minimum_depth` across the targets, which
    /// is what gates their `channel_ready`, and it also clears the six
    /// confirmations BOLT 7 requires before a channel may be announced.
    pub const ANNOUNCED_MIN_DEPTH_BLOCKS: u8 = 8;
}

/// Variables produced by [`append_funding_flow`] that callers may reuse.
pub struct FundingFlowVars {
    /// Our funding private key, committed to by the funding output.
    pub funding_privkey: usize,
    /// The acceptor's funding public key from `accept_channel`.
    pub acceptor_funding_pubkey: usize,
    /// The confirmed funding transaction.
    pub funding_transaction: usize,
    /// The channel id returned by `funding_signed`.
    pub channel_id: usize,
}

/// Appends the complete v1 outbound channel funding flow to `builder`.
///
/// If `announce` is set, the channel is opened as announced, its funding
/// transaction is mined deep enough to be announced, and `channel_ready`
/// carries no alias, since an announced channel is reached by its real
/// `short_channel_id`.
pub fn append_funding_flow(
    builder: &mut ProgramBuilder,
    rng: &mut impl Rng,
    announce: bool,
) -> FundingFlowVars {
    // The funding key pair is generated fresh so the funding transaction
    // can later be signed with the key `open_channel` commits to.
    let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
    let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);

    // Build and send open_channel.
    let open_channel = append_open_channel(builder, rng, funding_pubkey, announce);

    // Receive accept_channel.
    let accept_channel = builder.append(
        Operation::RecvAcceptChannel,
        &[open_channel.sent_open_channel],
    );
    let acceptor_funding_pubkey = builder.append(
        Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
        &[accept_channel],
    );

    // Create the BOLT 3 funding transaction.
    let funding_transaction = builder.append(
        Operation::CreateFundingTransaction,
        &[
            funding_pubkey,
            acceptor_funding_pubkey,
            open_channel.funding_satoshis,
            open_channel.feerate_per_kw,
        ],
    );

    // Build and send funding_created.
    let sent_funding_created = builder.append(
        Operation::SendFundingCreated,
        &[
            funding_transaction,
            funding_privkey,
            open_channel.temporary_channel_id,
        ],
    );

    // Receive funding_signed.
    let channel_id = builder.append(Operation::RecvFundingSigned, &[sent_funding_created]);

    // Broadcast the funding transaction.
    builder.append(Operation::BroadcastTransaction, &[funding_transaction]);

    // Mine blocks to confirm the funding transaction.
    let blocks = if announce {
        FundingFlowGenerator::ANNOUNCED_MIN_DEPTH_BLOCKS
    } else {
        rng.random_range(1..=16)
    };
    builder.append(Operation::MineBlocks(blocks), &[]);

    // Channel ready parameters.
    let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
    let short_channel_id = builder.generate_fresh(VariableType::ShortChannelId, rng);
    let include_alias = !announce && rng.random();

    // Build and send channel_ready.
    builder.append(
        Operation::SendChannelReady { include_alias },
        &[channel_id, second_per_commitment_point, short_channel_id],
    );

    // Receive channel_ready.
    builder.append(Operation::RecvChannelReady, &[]);

    FundingFlowVars {
        funding_privkey,
        acceptor_funding_pubkey,
        funding_transaction,
        channel_id,
    }
}

impl Generator for FundingFlowGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        append_funding_flow(builder, rng, false);
    }
}
