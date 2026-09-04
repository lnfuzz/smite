//! Generator for `open_channel` message flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::{ChannelTypeVariant, ShutdownScriptVariant};
use crate::{Operation, VariableType};

/// Generates an `open_channel` -> `accept_channel` flow.
///
/// Emits instructions to:
/// 1. Generate channel parameters
/// 2. Build and send `open_channel`
/// 3. Receive and parse `accept_channel`
#[derive(Clone, Copy)]
pub struct OpenChannelGenerator;

impl OpenChannelGenerator {
    // Channel parameter bounds accepted by at least one target, so generators
    // mostly produce valid channels.
    pub const MIN_FUNDING_SATOSHIS: u64 = 100_000;
    pub const MAX_FUNDING_SATOSHIS: u64 = (1 << 24) - 1;
    pub const MIN_DUST_LIMIT_SATOSHIS: u64 = 354;
    pub const MAX_DUST_LIMIT_SATOSHIS: u64 = 10_000;
    pub const MAX_FEERATE_PER_KW: u32 = 25_000;
    pub const MAX_TO_SELF_DELAY: u16 = 2016;
    pub const MAX_ACCEPTED_HTLCS: u16 = 114;
}

impl Generator for OpenChannelGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Public keys are generated fresh to ensure they're distinct.
        let funding_pubkey = builder.generate_fresh(VariableType::Point, rng);
        let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        // Bounds for the channel parameters, so generators always choose valid
        // values.
        let funding_sats =
            rng.random_range(Self::MIN_FUNDING_SATOSHIS..=Self::MAX_FUNDING_SATOSHIS);
        let funding_msat = funding_sats * 1000;
        let dust_limit_sats =
            rng.random_range(Self::MIN_DUST_LIMIT_SATOSHIS..=Self::MAX_DUST_LIMIT_SATOSHIS);
        let max_htlc_in_flight_msat = rng.random_range(0..=funding_msat);

        // Channel parameters.
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let temporary_channel_id = builder.pick_variable(VariableType::ChannelId, rng);
        let funding_satoshis = builder.append(Operation::LoadAmount(funding_sats), &[]);
        let push_msat = builder.append(
            Operation::LoadAmount(rng.random_range(0..=funding_msat / 2)),
            &[],
        );
        let dust_limit_satoshis = builder.append(Operation::LoadAmount(dust_limit_sats), &[]);
        let max_htlc_value_in_flight_msat =
            builder.append(Operation::LoadAmount(max_htlc_in_flight_msat), &[]);
        let channel_reserve_satoshis = builder.append(
            Operation::LoadAmount(rng.random_range(dust_limit_sats..funding_sats)),
            &[],
        );
        let htlc_minimum_msat = builder.append(
            Operation::LoadAmount(rng.random_range(0..=max_htlc_in_flight_msat)),
            &[],
        );
        let feerate_per_kw = builder.append(
            Operation::LoadFeeratePerKw(rng.random_range(0..=Self::MAX_FEERATE_PER_KW)),
            &[],
        );
        let to_self_delay = builder.append(
            Operation::LoadU16(rng.random_range(0..=Self::MAX_TO_SELF_DELAY)),
            &[],
        );
        let max_accepted_htlcs = builder.append(
            Operation::LoadU16(rng.random_range(0..=Self::MAX_ACCEPTED_HTLCS)),
            &[],
        );
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
        builder.append(Operation::RecvAcceptChannel, &[sent_open_channel]);
    }
}
