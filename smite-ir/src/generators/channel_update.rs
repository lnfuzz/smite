//! Generator for `channel_update` gossip message.

use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `channel_update` send.
///
/// Emits instructions to build and send a single signed `channel_update`.
/// When a preceding `channel_announcement` is available, the signing key and
/// direction bit are selected together from its node keys. Otherwise, the
/// signing key falls back to the general private-key pool.
#[derive(Clone, Copy)]
pub struct ChannelUpdateGenerator;

impl Generator for ChannelUpdateGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // BOLT 7 selects the signing node from the announcement using the
        // direction bit: 0 for node_id_1, 1 for node_id_2. Keep the key and
        // channel identity together so the update refers to the same channel.
        let (node_sk, direction, chain_hash, short_channel_id) =
            if let Some([chain_hash, short_channel_id, node_sk_1, node_sk_2]) =
                builder.latest_sent_channel_announcement_inputs()
            {
                let direction: u8 = rng.random_range(0..=1);
                let node_sk = if direction == 0 { node_sk_1 } else { node_sk_2 };
                (node_sk, direction, chain_hash, short_channel_id)
            } else {
                let node_sk = builder.pick_variable(VariableType::PrivateKey, rng);
                let direction = rng.random_range(0..=1);
                let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
                let short_channel_id = builder.pick_variable(VariableType::ShortChannelId, rng);
                (node_sk, direction, chain_hash, short_channel_id)
            };

        let timestamp = builder.pick_variable(VariableType::Timestamp, rng);

        // Keep the direction bit consistent with the signer while leaving the
        // other channel_flags bits random and available to the mutator.
        let message_flags = builder.pick_variable(VariableType::U8, rng);
        let channel_flags = builder.append(
            Operation::LoadU8((rng.random::<u8>() & !1_u8) | direction),
            &[],
        );

        let cltv_expiry_delta = builder.pick_variable(VariableType::U16, rng);
        let htlc_minimum_msat = builder.pick_variable(VariableType::Amount, rng);
        let fee_base_msat = builder.pick_variable(VariableType::ForwardingFee, rng);
        let fee_proportional_millionths = builder.pick_variable(VariableType::ForwardingFee, rng);
        let htlc_maximum_msat = builder.pick_variable(VariableType::Amount, rng);

        let msg = builder.append(
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
        builder.append(Operation::SendMessage, &[msg]);
    }
}
