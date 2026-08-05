//! BOLT 2 `accept_channel` oracle, for the v1 outbound channel funding flow.

use super::Oracle;
use crate::bolt::{AcceptChannel, Features, OpenChannel};
use crate::channel_tx::CommitmentCost;
use crate::pending_channel::PendingChannel;
use crate::violation::Violation;

use bitcoin::Amount;

// Constants from the BOLT 2 `open_channel` and `accept_channel` requirements:
// https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#requirements-8
const MAX_ACCEPTED_HTLCS_LIMIT: u16 = 483;
const MIN_DUST_LIMIT_SATOSHIS: u64 = 354;

/// Context for `AcceptChannelOracle`
pub struct AcceptChannelContext<'a> {
    /// The `accept_channel` received from the peer.
    pub accept_channel: &'a AcceptChannel,
    /// The negotiation the `accept_channel` answers, identified by its
    /// `temporary_channel_id`, or `None` if no matching `open_channel` was sent.
    pub negotiation: Option<&'a PendingChannel>,
}

/// Checks whether the `open_channel` answered by an `accept_channel` satisfied
/// the BOLT 2 v1 channel establishment requirements for acceptance, whether the
/// `accept_channel` itself satisfies them, and that the negotiated
/// `temporary_channel_id` was not reused.
pub struct AcceptChannelOracle;

impl Oracle<AcceptChannelContext<'_>> for AcceptChannelOracle {
    fn evaluate(&self, context: &AcceptChannelContext<'_>) -> Result<(), Violation> {
        // Check that the `accept_channel` answers a known `open_channel`.
        let Some(PendingChannel {
            open_channel,
            accept_channel: previous_accept_channel,
            funding_built,
        }) = context.negotiation
        else {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                "unknown temporary_channel_id: no open_channel was sent for this negotiation"
                    .to_string(),
            ));
        };

        // Check that the `open_channel` was valid to accept.
        if let Err(reason) = verify_accepted_open_channel(open_channel) {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                format!("accepted invalid open_channel: {reason}"),
            ));
        }

        // Check that the `accept_channel` itself is valid.
        if let Err(reason) = verify_accept_channel(context.accept_channel, open_channel) {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                format!("invalid accept_channel: {reason}"),
            ));
        }

        // Check that the `temporary_channel_id` was not reused.
        if previous_accept_channel.is_some() && !funding_built {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                "temporary_channel_id reuse: previous negotiation has not reached funding_created"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Returns an error if our `open_channel` breaches a BOLT 2 requirement, i.e.
/// the reason its receiver had to fail the channel instead of accepting it,
/// or `Ok(())` if it breaches none.
///
/// # Deferred oracle checks
///
/// - dust limit greater than channel reserve: BOLT 2 requires the dust limit to
///   be less than or equal to the channel reserve. However, implementations
///   such as LDK accept zero channel reserves on the receiving side, so we do
///   not enforce this check on the target's receiving side.
fn verify_accepted_open_channel(open_channel: &OpenChannel) -> Result<(), String> {
    // Check that the funding amounts are valid.
    // FIXME: Varies if `option_support_large_channel` is not negotiated.
    let total_supply_satoshis = Amount::MAX_MONEY.to_sat();
    if open_channel.funding_satoshis > total_supply_satoshis {
        return Err(format!(
            "funding_satoshis {} exceeds maximum funding of {total_supply_satoshis} sat",
            open_channel.funding_satoshis,
        ));
    }

    let funding_msat = open_channel.funding_satoshis * 1000;
    if open_channel.push_msat > funding_msat {
        return Err(format!(
            "push_msat {} exceeds funding amount {} msat",
            open_channel.push_msat, funding_msat,
        ));
    }

    // Check that the channel type was included.
    // TODO: Check option_channel_type in negotiated features since it is
    // assumed to be supported.
    let Some(channel_type) = open_channel
        .tlvs
        .channel_type
        .as_deref()
        .map(Features::from)
    else {
        return Err("open_channel does not include a channel_type".to_string());
    };

    // Check the HTLC limit is within the maximum.
    // FIXME: Does not apply to channels whose `channel_type` includes
    // `zero_fee_commitments`. These channel types have a lower upper limit on
    // `max_accepted_htlcs`, so we are currently safe.
    if open_channel.max_accepted_htlcs > MAX_ACCEPTED_HTLCS_LIMIT {
        return Err(format!(
            "max_accepted_htlcs {} exceeds the limit of {MAX_ACCEPTED_HTLCS_LIMIT}",
            open_channel.max_accepted_htlcs,
        ));
    }

    // Check the dust limit is not below the minimum.
    if open_channel.dust_limit_satoshis < MIN_DUST_LIMIT_SATOSHIS {
        return Err(format!(
            "dust_limit_satoshis {} is below the minimum of {MIN_DUST_LIMIT_SATOSHIS} sat",
            open_channel.dust_limit_satoshis,
        ));
    }

    // Check the initial commitment satisfies the channel reserve.
    verify_initial_commitment(
        open_channel,
        &channel_type,
        open_channel.channel_reserve_satoshis,
    )
}

/// Verifies the `accept_channel` against the BOLT 2 requirements it must meet,
/// returning an error if it breaches one, or `Ok(())` if it meets them all.
///
/// # Deferred oracle checks
///
/// - `open_channel` channel reserve less than `accept_channel` dust limit: BOLT 2
///   requires the dust limit to be less than or equal to the channel reserve.
///   However, implementations such as LDK accept zero channel reserves on the
///   receiving side, so we enforce this only on the target's sending side.
fn verify_accept_channel(
    accept_channel: &AcceptChannel,
    open_channel: &OpenChannel,
) -> Result<(), String> {
    // Check that the channel type was included.
    let Some(channel_type) = accept_channel
        .tlvs
        .channel_type
        .as_deref()
        .map(Features::from)
    else {
        return Err("accept_channel does not include a channel_type".to_string());
    };

    // Check that the channel type matches the one in open_channel.
    if open_channel.tlvs.channel_type != accept_channel.tlvs.channel_type {
        return Err("accept_channel channel_type does not match open_channel".to_string());
    }

    // Check the acceptor's channel reserve covers the opener's dust limit.
    if accept_channel.channel_reserve_satoshis < open_channel.dust_limit_satoshis {
        return Err(format!(
            "channel_reserve_satoshis {} is below the open_channel dust_limit_satoshis {}",
            accept_channel.channel_reserve_satoshis, open_channel.dust_limit_satoshis,
        ));
    }

    // Check the channel reserve covers the dust limit.
    if accept_channel.dust_limit_satoshis > accept_channel.channel_reserve_satoshis {
        return Err(format!(
            "dust_limit_satoshis {} exceeds channel_reserve_satoshis {}",
            accept_channel.dust_limit_satoshis, accept_channel.channel_reserve_satoshis,
        ));
    }

    // Check the HTLC limit is within the maximum.
    // FIXME: Does not apply to channels whose `channel_type` includes
    // `zero_fee_commitments`. These channel types have a lower upper limit on
    // `max_accepted_htlcs`, so we are currently safe.
    if accept_channel.max_accepted_htlcs > MAX_ACCEPTED_HTLCS_LIMIT {
        return Err(format!(
            "max_accepted_htlcs {} exceeds the limit of {MAX_ACCEPTED_HTLCS_LIMIT}",
            accept_channel.max_accepted_htlcs,
        ));
    }

    // Check the dust limit is not below the minimum.
    if accept_channel.dust_limit_satoshis < MIN_DUST_LIMIT_SATOSHIS {
        return Err(format!(
            "dust_limit_satoshis {} is below the minimum of {MIN_DUST_LIMIT_SATOSHIS} sat",
            accept_channel.dust_limit_satoshis,
        ));
    }

    // Check the initial commitment satisfies the channel reserve.
    verify_initial_commitment(
        open_channel,
        &channel_type,
        accept_channel.channel_reserve_satoshis,
    )
}

/// Verifies that the initial commitment can cover its fee and satisfies the
/// channel reserve requirement, returning an error if it breaches either, or
/// `Ok(())` if both are met.
///
/// NOTE: This check is safe from false positives for `zero_fee_commitments`
/// and `option_simple_taproot`, although the reported error may be misleading:
///
/// - `zero_fee_commitments` requires `feerate_per_kw == 0`, which we currently
///   do not enforce. A non-zero feerate may cause the error to be reported here
///   even though it is invalid for this channel type.
/// - `option_simple_taproot` has a different commitment fee (968-byte weight),
///   but we calculate it using the lower 724-byte weight. This may allow some
///   invalid cases through, but cannot cause a false positive.
/// - Anchor costs are only included when `option_anchors` is negotiated, so
///   they are not unnecessarily subtracted for these channel types.
fn verify_initial_commitment(
    open_channel: &OpenChannel,
    channel_type: &Features,
    channel_reserve_satoshis: u64,
) -> Result<(), String> {
    // Check that the opener can afford the proposed feerate.
    let opener_balance_sat = (open_channel.funding_satoshis * 1000 - open_channel.push_msat) / 1000;
    let commitment_cost = CommitmentCost::new(open_channel.feerate_per_kw, channel_type);
    let Some(balance_after_fee) = opener_balance_sat.checked_sub(commitment_cost.fee_sat) else {
        return Err(format!(
            "opener balance {opener_balance_sat} sat cannot cover the commitment fee of {} sat",
            commitment_cost.fee_sat
        ));
    };

    // For `option_anchors` channel types, check that the opener's remaining
    // balance can cover the anchor cost.
    let Some(to_local_sat) = balance_after_fee.checked_sub(commitment_cost.anchor_cost_sat) else {
        return Err(format!(
            "opener balance {opener_balance_sat} sat cannot cover anchor cost of {} sat (after fee deduction)",
            commitment_cost.anchor_cost_sat
        ));
    };

    // Check the initial commitment keeps at least one side above its reserve.
    let to_remote_sat = open_channel.push_msat / 1000;
    if to_local_sat <= channel_reserve_satoshis && to_remote_sat <= channel_reserve_satoshis {
        return Err(format!(
            "neither side exceeds channel reserve: to_local {to_local_sat} sat, to_remote {to_remote_sat} sat, reserve {channel_reserve_satoshis} sat",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{AcceptChannelTlvs, ChannelId, OpenChannelTlvs};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn pubkey(seed: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    }

    /// Valid `open_channel` message for testing.
    fn open_channel() -> OpenChannel {
        let key = pubkey(1);
        OpenChannel {
            chain_hash: [0u8; 32],
            temporary_channel_id: ChannelId::new([1u8; 32]),
            funding_satoshis: 10_000_000,
            push_msat: 3_000_000_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            feerate_per_kw: 15_000,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: key,
            revocation_basepoint: key,
            payment_basepoint: key,
            delayed_payment_basepoint: key,
            htlc_basepoint: key,
            first_per_commitment_point: key,
            channel_flags: 1,
            tlvs: OpenChannelTlvs {
                upfront_shutdown_script: None,
                channel_type: Some(vec![0x10, 0x00]),
            },
        }
    }

    /// Valid `accept_channel` message for testing.
    fn accept_channel() -> AcceptChannel {
        let key = pubkey(2);
        AcceptChannel {
            temporary_channel_id: ChannelId::new([1u8; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 6,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: key,
            revocation_basepoint: key,
            payment_basepoint: key,
            delayed_payment_basepoint: key,
            htlc_basepoint: key,
            first_per_commitment_point: key,
            tlvs: AcceptChannelTlvs {
                upfront_shutdown_script: None,
                channel_type: Some(vec![0x10, 0x00]),
            },
        }
    }

    /// Pending channel negotiation for testing.
    fn pending_negotiation(oc: OpenChannel) -> PendingChannel {
        PendingChannel {
            open_channel: oc,
            accept_channel: None,
            funding_built: false,
        }
    }

    #[track_caller]
    fn assert_pass(accept_channel: &AcceptChannel, negotiation: Option<&PendingChannel>) {
        if let Err(err) = AcceptChannelOracle.evaluate(&AcceptChannelContext {
            accept_channel,
            negotiation,
        }) {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(
        accept_channel: &AcceptChannel,
        negotiation: Option<&PendingChannel>,
        expected: &str,
    ) {
        match AcceptChannelOracle.evaluate(&AcceptChannelContext {
            accept_channel,
            negotiation,
        }) {
            Err(Violation::InvalidAcceptChannel(chan_id, reason)) => {
                assert_eq!(accept_channel.temporary_channel_id, chan_id);
                assert!(
                    reason.contains(expected),
                    "unexpected failure reason: {reason}"
                );
            }
            _ => panic!("expected failure: {expected}"),
        }
    }

    #[test]
    fn conforming_negotiation_passes() {
        assert_pass(
            &accept_channel(),
            Some(&pending_negotiation(open_channel())),
        );
    }

    #[test]
    fn accept_channel_for_unknown_temporary_channel_id() {
        assert_fail(
            &accept_channel(),
            None,
            "unknown temporary_channel_id: no open_channel was sent for this negotiation",
        );
    }

    #[test]
    fn funding_satoshis_above_bitcoins_total_supply() {
        let mut oc = open_channel();
        oc.funding_satoshis = Amount::MAX_MONEY.to_sat() + 1;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: funding_satoshis 2100000000000001 exceeds maximum funding",
        );
    }

    #[test]
    fn push_msat_above_the_funding_amount() {
        let mut oc = open_channel();
        oc.push_msat = oc.funding_satoshis * 1000 + 1;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: push_msat 10000000001 exceeds funding amount",
        );
    }

    #[test]
    fn open_channel_without_a_channel_type() {
        let mut oc = open_channel();
        oc.tlvs.channel_type = None;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: open_channel does not include a channel_type",
        );
    }

    #[test]
    fn open_channel_max_accepted_htlcs_above_the_limit() {
        let mut oc = open_channel();
        oc.max_accepted_htlcs = MAX_ACCEPTED_HTLCS_LIMIT + 1;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: max_accepted_htlcs 484 exceeds the limit of 483",
        );
    }

    #[test]
    fn open_channel_dust_limit_below_the_minimum() {
        let mut oc = open_channel();
        oc.dust_limit_satoshis = MIN_DUST_LIMIT_SATOSHIS - 1;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: dust_limit_satoshis 353 is below the minimum of 354 sat",
        );
    }

    #[test]
    fn opener_cannot_afford_commitment_fee() {
        let mut oc = open_channel();
        oc.push_msat = oc.funding_satoshis * 1000 - 10_000_000;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: opener balance 10000 sat cannot cover the commitment fee",
        );
    }

    #[test]
    fn opener_cannot_cover_anchor_outputs() {
        let mut oc = open_channel();
        oc.push_msat = oc.funding_satoshis * 1000 - 17_000_000;
        oc.tlvs.channel_type = Some(vec![0x40, 0x10, 0x00]);

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: opener balance 17000 sat cannot cover anchor cost of 660 sat (after fee deduction)",
        );
    }

    #[test]
    fn open_channel_initial_commitment_below_reserves() {
        let mut oc = open_channel();
        oc.channel_reserve_satoshis = 7_000_000;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: neither side exceeds channel reserve",
        );
    }

    #[test]
    fn accept_channel_without_a_channel_type() {
        let mut ac = accept_channel();
        ac.tlvs.channel_type = None;

        assert_fail(
            &ac,
            Some(&pending_negotiation(open_channel())),
            "invalid accept_channel: accept_channel does not include a channel_type",
        );
    }

    #[test]
    fn accept_channel_channel_type_mismatch_with_open_channel() {
        let mut ac = accept_channel();
        ac.tlvs.channel_type = Some(vec![0x40, 0x10, 0x00]);

        assert_fail(
            &ac,
            Some(&pending_negotiation(open_channel())),
            "invalid accept_channel: accept_channel channel_type does not match open_channel",
        );
    }

    #[test]
    fn accept_channel_reserve_below_the_open_channel_dust_limit() {
        let oc = open_channel();
        let mut ac = accept_channel();
        ac.channel_reserve_satoshis = oc.dust_limit_satoshis - 1;

        assert_fail(
            &ac,
            Some(&pending_negotiation(oc)),
            "invalid accept_channel: channel_reserve_satoshis 545 is below the open_channel dust_limit_satoshis 546",
        );
    }

    #[test]
    fn accept_channel_dust_limit_above_its_channel_reserve() {
        let mut ac = accept_channel();
        ac.dust_limit_satoshis = 5_000;
        ac.channel_reserve_satoshis = 4_000;

        assert_fail(
            &ac,
            Some(&pending_negotiation(open_channel())),
            "invalid accept_channel: dust_limit_satoshis 5000 exceeds channel_reserve_satoshis 4000",
        );
    }

    #[test]
    fn accept_channel_max_accepted_htlcs_above_the_limit() {
        let mut ac = accept_channel();
        ac.max_accepted_htlcs = MAX_ACCEPTED_HTLCS_LIMIT + 1;

        assert_fail(
            &ac,
            Some(&pending_negotiation(open_channel())),
            "invalid accept_channel: max_accepted_htlcs 484 exceeds the limit of 483",
        );
    }

    #[test]
    fn accept_channel_dust_limit_below_the_minimum() {
        let mut ac = accept_channel();
        ac.dust_limit_satoshis = MIN_DUST_LIMIT_SATOSHIS - 1;

        assert_fail(
            &ac,
            Some(&pending_negotiation(open_channel())),
            "invalid accept_channel: dust_limit_satoshis 353 is below the minimum of 354 sat",
        );
    }

    #[test]
    fn accept_channel_initial_commitment_below_reserves() {
        let mut ac = accept_channel();
        ac.channel_reserve_satoshis = 7_000_000;

        assert_fail(
            &ac,
            Some(&pending_negotiation(open_channel())),
            "invalid accept_channel: neither side exceeds channel reserve",
        );
    }

    #[test]
    fn temporary_channel_id_reuse_before_funding_created() {
        let mut negotiation = pending_negotiation(open_channel());
        negotiation.accept_channel = Some(accept_channel());

        assert_fail(
            &accept_channel(),
            Some(&negotiation),
            "temporary_channel_id reuse: previous negotiation has not reached funding_created",
        );
    }

    #[test]
    fn temporary_channel_id_reuse_after_funding_created() {
        let mut negotiation = pending_negotiation(open_channel());
        negotiation.accept_channel = Some(accept_channel());
        negotiation.funding_built = true;

        assert_pass(&accept_channel(), Some(&negotiation));
    }
}
