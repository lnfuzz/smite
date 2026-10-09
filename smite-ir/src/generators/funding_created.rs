//! Generator for `funding_created` message flow.

use rand::Rng;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates a `funding_created` -> `funding_signed` flow.
///
/// Emits instructions to:
/// 1. Create the BOLT 3 funding and commitment transaction
/// 2. Build and send `funding_created`
/// 3. Receive and parse `funding_signed`
/// 4. Broadcast the funding transaction
#[derive(Clone, Copy)]
pub struct FundingCreatedGenerator;

impl Generator for FundingCreatedGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Funding and commitment transaction keys and parameters.
        let opener_funding_privkey = builder.pick_variable(VariableType::PrivateKey, rng);
        let opener_htlc_basepoint_privkey = builder.pick_variable(VariableType::PrivateKey, rng);
        let opener_funding_pubkey =
            builder.append(Operation::DerivePoint, &[opener_funding_privkey]);
        let acceptor_funding_pubkey = builder.pick_variable(VariableType::Point, rng);
        let funding_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let feerate_per_kw = builder.pick_variable(VariableType::FeeratePerKw, rng);
        let temporary_channel_id = builder.pick_variable(VariableType::ChannelId, rng);

        // Create the BOLT 3 funding transaction.
        let funding_transaction = builder.append(
            Operation::CreateFundingTransaction,
            &[
                opener_funding_pubkey,
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
                opener_funding_privkey,
                opener_htlc_basepoint_privkey,
                temporary_channel_id,
            ],
        );

        // Receive funding_signed.
        builder.append(Operation::RecvFundingSigned, &[sent_funding_created]);

        // Broadcast the funding transaction.
        builder.append(Operation::BroadcastTransaction, &[funding_transaction]);
    }
}
