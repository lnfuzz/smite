//! Generator for the complete v1 outbound channel funding flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::AcceptChannelField;
use crate::operation::{ChannelTypeVariant, ShutdownScriptVariant};
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
        // Private/Public keys are generated fresh to ensure they're distinct.
        let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);
        let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        let htlc_basepoint = builder.append(Operation::DerivePoint, &[htlc_basepoint_privkey]);
        let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        // Channel parameters.
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let temporary_channel_id = builder.pick_variable(VariableType::ChannelId, rng);
        let funding_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let push_msat = builder.pick_variable(VariableType::Amount, rng);
        let dust_limit_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let max_htlc_value_in_flight_msat = builder.pick_variable(VariableType::Amount, rng);
        let channel_reserve_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let htlc_minimum_msat = builder.pick_variable(VariableType::Amount, rng);
        let feerate_per_kw = builder.pick_variable(VariableType::FeeratePerKw, rng);
        let to_self_delay = builder.pick_variable(VariableType::U16, rng);
        let max_accepted_htlcs = builder.pick_variable(VariableType::U16, rng);
        let channel_flags = builder.pick_variable(VariableType::U8, rng);
        let shutdown_script_variant = ShutdownScriptVariant::random(rng);
        let upfront_shutdown_script =
            builder.append(Operation::LoadShutdownScript(shutdown_script_variant), &[]);
        let variant = *ChannelTypeVariant::ALL
            .choose(rng)
            .expect("ChannelTypeVariant::ALL is non-empty");
        let channel_type = builder.append(Operation::LoadChannelType(variant), &[]);

        // Build and send open_channel.
        let open_channel_msg = builder.append(
            Operation::BuildOpenChannel,
            &[
                chain_hash,
                temporary_channel_id,
                funding_satoshis,
                push_msat,
                dust_limit_satoshis,
                max_htlc_value_in_flight_msat,
                channel_reserve_satoshis,
                htlc_minimum_msat,
                feerate_per_kw,
                to_self_delay,
                max_accepted_htlcs,
                funding_pubkey,
                revocation_basepoint,
                payment_basepoint,
                delayed_payment_basepoint,
                htlc_basepoint,
                first_per_commitment_point,
                channel_flags,
                upfront_shutdown_script,
                channel_type,
            ],
        );
        let sent_open_channel = builder.append(Operation::SendOpenChannel, &[open_channel_msg]);

        // Receive accept_channel.
        let accept_channel = builder.append(Operation::RecvAcceptChannel, &[sent_open_channel]);
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
                funding_satoshis,
                feerate_per_kw,
            ],
        );

        // Build and send funding_created.
        let sent_funding_created = builder.append(
            Operation::SendFundingCreated,
            &[
                funding_transaction,
                funding_privkey,
                htlc_basepoint_privkey,
                temporary_channel_id,
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
