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

impl Generator for FundingFlowGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // The funding key pair is generated fresh so the funding transaction
        // can later be signed with the key `open_channel` commits to.
        let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);

        // Generate a fresh HTLC basepoint key pair for the commitment transaction.
        let htlc_basepoint_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        let htlc_basepoint = builder.append(Operation::DerivePoint, &[htlc_basepoint_privkey]);

        // Build and send open_channel.
        let open_channel = append_open_channel(builder, rng, funding_pubkey, htlc_basepoint);

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
                htlc_basepoint_privkey,
                open_channel.temporary_channel_id,
            ],
        );

        // Receive funding_signed.
        let channel_id = builder.append(Operation::RecvFundingSigned, &[sent_funding_created]);

        // Broadcast the funding transaction.
        builder.append(Operation::BroadcastTransaction, &[funding_transaction]);

        // Mine blocks to confirm the funding transaction.
        builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);

        // Channel ready parameters.
        let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
        let short_channel_id = builder.generate_fresh(VariableType::ShortChannelId, rng);
        let include_alias = rng.random();

        // Build and send channel_ready.
        builder.append(
            Operation::SendChannelReady { include_alias },
            &[channel_id, second_per_commitment_point, short_channel_id],
        );

        // Receive channel_ready.
        builder.append(Operation::RecvChannelReady, &[]);
    }
}
