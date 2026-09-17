//! BOLT 2 `channel_ready` oracle, for the v1 outbound channel funding flow.

use super::Oracle;
use crate::bolt::{ChannelReady, Features};
use crate::channel_tx::ChannelState;
use crate::violation::Violation;

use bitcoin::secp256k1::PublicKey;

use std::collections::HashSet;

/// Context for `ChannelReadyOracle`
pub struct ChannelReadyContext<'a> {
    /// The `channel_ready` received from the peer.
    pub channel_ready: &'a ChannelReady,
    /// The channel the `channel_ready` belongs to, identified by its
    /// `channel_id`, or `None` if no channel was funded for it.
    pub channel: Option<&'a ChannelState>,
    /// Features negotiated between the target node and Smite.
    pub negotiated_features: &'a Features,
    /// Per-commitment points revealed by either us or the target.
    pub per_commitment_points: &'a HashSet<PublicKey>,
}

/// Checks whether a received `channel_ready` satisfies the BOLT 2 v1 channel
/// establishment requirements.
///
/// # Deferred oracle checks
///
/// - `short_channel_id` alias collisions: BOLT 2 requires aliases not to collide
///   with any of the target's real `short_channel_ids`. Checking this requires
///   fetching the `short_channel_id` for all channels we have with the target
///   over RPC. Bulk fetching adds RPC overhead that reduces fuzzing throughput,
///   while lazy lookups can still miss collisions. Until this can be checked
///   more efficiently, it is not worthwhile for this narrow surface.
pub struct ChannelReadyOracle;

impl Oracle<ChannelReadyContext<'_>> for ChannelReadyOracle {
    fn evaluate(&self, context: &ChannelReadyContext<'_>) -> Result<(), Violation> {
        // Check that the `channel_ready` answers a channel we funded.
        if context.channel.is_none() {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                "unknown channel_id: no channel was funded for it".to_string(),
            ));
        }

        // Check that an alias is set when option_scid_alias was negotiated.
        if context
            .negotiated_features
            .supports_feature(Features::OPTION_SCID_ALIAS)
            && context.channel_ready.tlvs.short_channel_id.is_none()
        {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                "option_scid_alias negotiated but short_channel_id alias is missing".to_string(),
            ));
        }

        // Check that the second_per_commitment_point is not reused from an
        // earlier negotiation.
        if context
            .per_commitment_points
            .contains(&context.channel_ready.second_per_commitment_point)
        {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                format!(
                    "second_per_commitment_point {} was reused from an earlier negotiation",
                    context.channel_ready.second_per_commitment_point,
                ),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{ChannelId, ChannelReadyTlvs, Features, ShortChannelId};
    use crate::channel_tx::{
        ChannelConfig, ChannelPartyConfig, CommitmentPartyState, CommitmentState, HolderIdentity,
        Side,
    };
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("valid secret key")
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key(seed))
    }

    /// Valid `channel_ready` message for testing.
    fn channel_ready() -> ChannelReady {
        ChannelReady {
            channel_id: ChannelId::new([1u8; 32]),
            second_per_commitment_point: pubkey(2),
            tlvs: ChannelReadyTlvs::default(),
        }
    }

    /// Funded channel state for testing.
    fn channel_state() -> ChannelState {
        let key = pubkey(1);
        let party = || ChannelPartyConfig {
            funding_pubkey: key,
            payment_basepoint: key,
            revocation_basepoint: key,
            delayed_payment_basepoint: key,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };

        ChannelState::new(
            ChannelConfig {
                funding_outpoint: OutPoint::null(),
                funding_satoshis: 10_000_000,
                channel_type: Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
                opener: party(),
                acceptor: party(),
                minimum_depth: 6,
            },
            HolderIdentity {
                side: Side::Opener,
                funding_privkey: secret_key(1),
            },
            CommitmentState {
                commitment_number: 0,
                feerate_per_kw: 15_000,
                opener: CommitmentPartyState {
                    per_commitment_point: key,
                    balance_msat: 7_000_000_000,
                },
                acceptor: CommitmentPartyState {
                    per_commitment_point: key,
                    balance_msat: 3_000_000_000,
                },
            },
            true,
            false,
            false,
        )
    }

    #[track_caller]
    fn assert_pass(
        channel_ready: &ChannelReady,
        channel: Option<&ChannelState>,
        negotiated_features: &Features,
        per_commitment_points: &HashSet<PublicKey>,
    ) {
        if let Err(err) = ChannelReadyOracle.evaluate(&ChannelReadyContext {
            channel_ready,
            channel,
            negotiated_features,
            per_commitment_points,
        }) {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(
        channel_ready: &ChannelReady,
        channel: Option<&ChannelState>,
        negotiated_features: &Features,
        per_commitment_points: &HashSet<PublicKey>,
        expected: &str,
    ) {
        match ChannelReadyOracle.evaluate(&ChannelReadyContext {
            channel_ready,
            channel,
            negotiated_features,
            per_commitment_points,
        }) {
            Err(Violation::InvalidChannelReady(chan_id, reason)) => {
                assert_eq!(channel_ready.channel_id, chan_id);
                assert!(
                    reason.contains(expected),
                    "unexpected failure reason: {reason}"
                );
            }
            _ => panic!("expected failure: {expected}"),
        }
    }

    #[test]
    fn conforming_channel_ready_passes() {
        assert_pass(
            &channel_ready(),
            Some(&channel_state()),
            &Features::new(),
            &HashSet::new(),
        );
    }

    #[test]
    fn unknown_channel_id_fails() {
        assert_fail(
            &channel_ready(),
            None,
            &Features::new(),
            &HashSet::new(),
            "unknown channel_id: no channel was funded for it",
        );
    }

    #[test]
    fn conforming_option_scid_alias_with_an_alias_passes() {
        let negotiated_features = Features::from_bits(&[Features::OPTION_SCID_ALIAS]);
        let mut cr = channel_ready();
        cr.tlvs.short_channel_id = Some(ShortChannelId::new(800_000, 1, 0));

        assert_pass(
            &cr,
            Some(&channel_state()),
            &negotiated_features,
            &HashSet::new(),
        );
    }

    #[test]
    fn alias_without_option_scid_alias_passes() {
        let mut cr = channel_ready();
        cr.tlvs.short_channel_id = Some(ShortChannelId::new(800_000, 1, 0));

        assert_pass(
            &cr,
            Some(&channel_state()),
            &Features::new(),
            &HashSet::new(),
        );
    }

    #[test]
    fn option_scid_alias_without_an_alias_fails() {
        let negotiated_features = Features::from_bits(&[Features::OPTION_SCID_ALIAS]);

        assert_fail(
            &channel_ready(),
            Some(&channel_state()),
            &negotiated_features,
            &HashSet::new(),
            "option_scid_alias negotiated but short_channel_id alias is missing",
        );
    }

    #[test]
    fn channel_ready_reuses_per_commitment_point_from_earlier_negotiation() {
        let cr = channel_ready();
        let per_commitment_points = HashSet::from([cr.second_per_commitment_point]);

        assert_fail(
            &cr,
            Some(&channel_state()),
            &Features::new(),
            &per_commitment_points,
            &format!(
                "second_per_commitment_point {} was reused from an earlier negotiation",
                cr.second_per_commitment_point,
            ),
        );
    }
}
