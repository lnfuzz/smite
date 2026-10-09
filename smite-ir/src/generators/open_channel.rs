//! Generator for `open_channel` message flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};
use smite::bolt::ChannelTypeVariant;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::ShutdownScriptVariant;
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
    // are more likely to produce valid channels.

    /// The highest funding floor allowed by the targets: Eclair allows nothing
    /// below `100_000` sat, while LND stops at `20_000`, CLN at `10_000`, and
    /// LDK at `1_000` sat.
    pub const MIN_FUNDING_SATOSHIS: u64 = 100_000;
    /// Highest `funding_satoshis` amount allowed by the targets under BOLT 2
    /// without requiring wumbo support.
    pub const MAX_FUNDING_SATOSHIS: u64 = (1 << 24) - 1;
    /// Self-imposed bound: push at most half the funding so the opener retains
    /// enough balance for the channel reserve and commitment fee checked by
    /// targets.
    pub const FUNDING_TO_PUSH_MSAT_DIVISOR: u64 = 2;
    /// Minimum dust limit allowed by all targets and required by BOLT 2.
    pub const MIN_DUST_LIMIT_SATOSHIS: u64 = 354;
    /// Lowest dust limit ceiling allowed by the targets: LDK caps it at 546 sat
    /// LND at `1_062` sat, Eclair at `5_000` sat, and CLN has no fixed ceiling.
    pub const MAX_DUST_LIMIT_SATOSHIS: u64 = 546;
    /// Lowest reserve ceiling allowed by the targets: Eclair caps it at 5% of
    /// funding, LND at 20%, and LDK and CLN only require it to exceed the dust
    /// limit.
    pub const FUNDING_TO_RESERVE_DIVISOR: u64 = 20;
    /// Lowest `htlc_minimum_msat` ceiling allowed by the targets: LND caps it
    /// at a fifth of `max_htlc_value_in_flight_msat`, CLN at the effective
    /// capacity, LDK at the channel value, and Eclair has no fixed ceiling.
    pub const MAX_HTLC_IN_FLIGHT_TO_MINIMUM_DIVISOR: u64 = 5;
    /// Lowest feerate ceiling allowed by the targets: Eclair caps it at `25_000`
    /// sat/kW for anchor channels, while CLN caps it at ten times its highest
    /// bitcoind estimate. LND and LDK set no ceiling and only require the
    /// funder to cover the resulting commitment fee.
    pub const MAX_FEERATE_PER_KW: u32 = 25_000;
    /// Highest `to_self_delay` allowed by all targets: 2016 blocks (~2 weeks),
    /// beyond which they consider their funds locked for too long.
    pub const MAX_TO_SELF_DELAY: u16 = 2016;
    /// Lowest `max_accepted_htlcs` allowed by the targets: LND requires at least
    /// five HTLC slots, while LDK and CLN allow any value from one and Eclair
    /// has no minimum.
    pub const MIN_MAX_ACCEPTED_HTLCS: u16 = 5;
    /// Lowest `max_accepted_htlcs` ceiling allowed across targets: BOLT 2, LND,
    /// and CLN allow up to 483, while LDK and Eclair cap 0FC channels at 114
    /// due to the v3 package size limit.
    pub const MAX_MAX_ACCEPTED_HTLCS: u16 = 114;
    /// Keep channels unannounced: clearing `announce_channel` keeps
    /// `option_scid_alias` valid, while LDK and LND reject announced channels
    /// that negotiate it.
    pub const CHANNEL_FLAGS: u8 = 0;
}

/// Instruction indices produced by [`append_open_channel`], for later
/// instructions to reference as inputs.
pub struct OpenChannelVars {
    /// The `temporary_channel_id` the message was built with.
    pub temporary_channel_id: usize,
    /// The `funding_satoshis` the message was built with.
    pub funding_satoshis: usize,
    /// The `feerate_per_kw` the message was built with.
    pub feerate_per_kw: usize,
    /// The `SendOpenChannel` instruction, sequenced before receiving
    /// `accept_channel`.
    pub sent_open_channel: usize,
}

/// Appends the instructions that generate bounded channel parameters, then
/// build and send `open_channel` using `funding_pubkey`.
pub fn append_open_channel(
    builder: &mut ProgramBuilder,
    rng: &mut impl Rng,
    funding_pubkey: usize,
    htlc_basepoint: usize,
) -> OpenChannelVars {
    type Bounds = OpenChannelGenerator;

    // Public keys are generated fresh to ensure they're distinct.
    let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

    // Bounds for the channel parameters, so generators are more likely to
    // choose valid values.
    let funding_sats =
        rng.random_range(Bounds::MIN_FUNDING_SATOSHIS..=Bounds::MAX_FUNDING_SATOSHIS);
    let funding_msat = funding_sats * 1000;
    let dust_limit_sats =
        rng.random_range(Bounds::MIN_DUST_LIMIT_SATOSHIS..=Bounds::MAX_DUST_LIMIT_SATOSHIS);
    let max_htlc_in_flight_msat = rng.random_range(0..=funding_msat);

    // Channel parameters.
    let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
    let temporary_channel_id = builder.pick_variable(VariableType::ChannelId, rng);
    let funding_satoshis = builder.append(Operation::LoadAmount(funding_sats), &[]);
    let push_msat = builder.append(
        Operation::LoadAmount(
            rng.random_range(0..=funding_msat / Bounds::FUNDING_TO_PUSH_MSAT_DIVISOR),
        ),
        &[],
    );
    let dust_limit_satoshis = builder.append(Operation::LoadAmount(dust_limit_sats), &[]);
    let max_htlc_value_in_flight_msat =
        builder.append(Operation::LoadAmount(max_htlc_in_flight_msat), &[]);
    let channel_reserve_satoshis = builder.append(
        Operation::LoadAmount(
            rng.random_range(dust_limit_sats..=funding_sats / Bounds::FUNDING_TO_RESERVE_DIVISOR),
        ),
        &[],
    );
    let htlc_minimum_msat = builder.append(
        Operation::LoadAmount(rng.random_range(
            0..=max_htlc_in_flight_msat / Bounds::MAX_HTLC_IN_FLIGHT_TO_MINIMUM_DIVISOR,
        )),
        &[],
    );
    let feerate_per_kw = builder.append(
        Operation::LoadFeeratePerKw(rng.random_range(0..=Bounds::MAX_FEERATE_PER_KW)),
        &[],
    );
    let to_self_delay = builder.append(
        Operation::LoadU16(rng.random_range(0..=Bounds::MAX_TO_SELF_DELAY)),
        &[],
    );
    let max_accepted_htlcs = builder.append(
        Operation::LoadU16(
            rng.random_range(Bounds::MIN_MAX_ACCEPTED_HTLCS..=Bounds::MAX_MAX_ACCEPTED_HTLCS),
        ),
        &[],
    );
    let channel_flags = builder.append(Operation::LoadU8(Bounds::CHANNEL_FLAGS), &[]);
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

    OpenChannelVars {
        temporary_channel_id,
        funding_satoshis,
        feerate_per_kw,
        sent_open_channel,
    }
}

impl Generator for OpenChannelGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // The funding public key and HTLC basepoint are generated fresh to
        // ensure they are distinct from the other basepoints.
        let funding_pubkey = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);

        // Build and send open_channel.
        let open_channel = append_open_channel(builder, rng, funding_pubkey, htlc_basepoint);

        // Receive accept_channel.
        builder.append(
            Operation::RecvAcceptChannel,
            &[open_channel.sent_open_channel],
        );
    }
}
