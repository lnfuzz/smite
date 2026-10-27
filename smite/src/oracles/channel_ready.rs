//! BOLT 2 `channel_ready` oracle, for the channel funding flow.

use super::Oracle;
use crate::bolt::{ChannelId, ChannelReady, Features, ShortChannelId};
use crate::channel_state::ChannelState;
use crate::pending_channel::KeyOrigin;
use crate::violation::Violation;

use bitcoin::secp256k1::PublicKey;
use std::collections::HashMap;

/// Context for `ChannelReadyOracle`
pub struct ChannelReadyContext<'a> {
    /// The `channel_ready` received from the peer.
    pub channel_ready: &'a ChannelReady,
    /// The channel the `channel_ready` belongs to, identified by its
    /// `channel_id`, or `None` if no channel is tracked for it.
    pub channel: Option<&'a ChannelState>,
    /// Features negotiated between the target node and Smite.
    pub negotiated_features: &'a Features,
    /// Every pubkey revealed on the wire by either side, mapped to its first
    /// origin.
    pub revealed_pubkeys: &'a HashMap<PublicKey, KeyOrigin>,
    /// Every `short_channel_id` revealed on the wire, both advertised aliases
    /// and derived real ones, mapped to the channel that owns it.
    pub revealed_scids: &'a HashMap<ShortChannelId, ChannelId>,
    /// Number of confirmations the funding transaction had when the
    /// `channel_ready` was received, or `0` if it is unconfirmed or unknown.
    pub funding_confirmations: u32,
}

/// Checks whether a received `channel_ready` satisfies the BOLT 2 channel
/// establishment requirements.
pub struct ChannelReadyOracle;

impl Oracle<ChannelReadyContext<'_>> for ChannelReadyOracle {
    fn evaluate(&self, context: &ChannelReadyContext<'_>) -> Result<(), Violation> {
        // Check that the `channel_ready` answers a channel we track.
        let Some(channel) = context.channel else {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                "unknown channel_id: no channel is tracked for it".to_string(),
            ));
        };

        // Check that the target countersigned our commitment before declaring
        // the channel ready. Without a `funding_signed` we hold no valid
        // commitment transaction, so a channel the target treats as ready
        // leaves our funding output spendable only with its cooperation.
        if !channel.funding_signed_received {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                "no funding_signed was received for this channel".to_string(),
            ));
        }

        // Check that the on-chain funding output matches the negotiated funding
        // script and amount.
        if !channel.is_funding_outpoint_valid {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                "funding output does not match the negotiated funding script and amount"
                    .to_string(),
            ));
        }

        // Check that the funding transaction reached `minimum_depth`.
        if context.funding_confirmations < channel.config.minimum_depth {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                format!(
                    "channel_ready received with {} funding confirmation(s), below minimum_depth {}",
                    context.funding_confirmations, channel.config.minimum_depth,
                ),
            ));
        }

        // Check that an alias is set when `option_scid_alias` was negotiated.
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

        // Check that an advertised alias does not reuse a `short_channel_id`
        // already revealed by another channel (its alias or real
        // `short_channel_id`). Reuse is allowed only for a resend of this
        // channel's own alias.
        if let Some(alias) = context.channel_ready.tlvs.short_channel_id
            && let Some(origin) = context.revealed_scids.get(&alias)
            && *origin != context.channel_ready.channel_id
        {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                format!(
                    "short_channel_id alias {alias} reuses the short_channel_id of channel {origin}"
                ),
            ));
        }

        // Check that a resent `channel_ready` repeats the first one's
        // `second_per_commitment_point`.
        if let Some(first) = channel.received_channel_ready_point
            && first != context.channel_ready.second_per_commitment_point
        {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                format!(
                    "channel_ready resend changed second_per_commitment_point from {first} to {}",
                    context.channel_ready.second_per_commitment_point,
                ),
            ));
        }

        // Check that the `second_per_commitment_point` is not reused from a
        // previously revealed key, since its secret will eventually be revealed.
        // Reuse is allowed for repeated `channel_ready` messages (e.g., with
        // different aliases or after reconnection) if the key origin matches
        // the channel and commitment number.
        let known_origin = KeyOrigin::TargetPcp {
            channel: context.channel_ready.channel_id,
            commitment_number: 1,
        };
        if let Some(origin) = context
            .revealed_pubkeys
            .get(&context.channel_ready.second_per_commitment_point)
            && *origin != known_origin
        {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                format!(
                    "second_per_commitment_point {} reuses {origin}",
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
    use crate::bolt::{ChannelId, ChannelReadyTlvs, ShortChannelId};
    use crate::channel_tx::{ChannelConfig, ChannelPartyConfig, HolderIdentity, Side};
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Number of confirmations required to reach the minimum depth and expect
    /// a `channel_ready` message from the target.
    const CONFIRMED_DEPTH: u32 = 6;

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
        let pkey1 = pubkey(1);
        let pkey2 = pubkey(2);
        let party = |key| ChannelPartyConfig {
            funding_pubkey: key,
            payment_basepoint: key,
            revocation_basepoint: key,
            delayed_payment_basepoint: key,
            htlc_basepoint: key,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };

        let config = ChannelConfig {
            funding_outpoint: OutPoint::null(),
            funding_satoshis: 10_000_000,
            channel_type: Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
            opener: party(pkey1),
            acceptor: party(pkey2),
            minimum_depth: CONFIRMED_DEPTH,
        };
        let commitments = config
            .new_initial_commitments(3_000_000_000, 15_000, pkey1, pkey2)
            .expect("valid initial commitments");
        let holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret_key(1),
            htlc_basepoint_privkey: secret_key(1),
        };

        let mut state = ChannelState::new(config, holder, commitments, true, false, false);
        state.funding_signed_received = true;
        state
    }

    /// Oracle inputs for testing. Defaults to a conforming `channel_ready`
    /// for a tracked channel at the minimum depth.
    struct OracleInputs {
        channel_ready: ChannelReady,
        channel: Option<ChannelState>,
        negotiated_features: Features,
        revealed_pubkeys: HashMap<PublicKey, KeyOrigin>,
        revealed_scids: HashMap<ShortChannelId, ChannelId>,
        funding_confirmations: u32,
    }

    impl Default for OracleInputs {
        fn default() -> Self {
            Self {
                channel_ready: channel_ready(),
                channel: Some(channel_state()),
                negotiated_features: Features::new(),
                revealed_pubkeys: HashMap::new(),
                revealed_scids: HashMap::new(),
                funding_confirmations: CONFIRMED_DEPTH,
            }
        }
    }

    impl OracleInputs {
        fn evaluate(&self) -> Result<(), Violation> {
            ChannelReadyOracle.evaluate(&ChannelReadyContext {
                channel_ready: &self.channel_ready,
                channel: self.channel.as_ref(),
                negotiated_features: &self.negotiated_features,
                revealed_pubkeys: &self.revealed_pubkeys,
                revealed_scids: &self.revealed_scids,
                funding_confirmations: self.funding_confirmations,
            })
        }

        fn channel_mut(&mut self) -> &mut ChannelState {
            self.channel.as_mut().expect("tracked channel")
        }
    }

    #[track_caller]
    fn assert_pass(inputs: &OracleInputs) {
        if let Err(err) = inputs.evaluate() {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(inputs: &OracleInputs, expected: &str) {
        match inputs.evaluate() {
            Err(Violation::InvalidChannelReady(chan_id, reason)) => {
                assert_eq!(inputs.channel_ready.channel_id, chan_id);
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
        assert_pass(&OracleInputs::default());
    }

    #[test]
    fn unknown_channel_id_fails() {
        let inputs = OracleInputs {
            channel: None,
            ..OracleInputs::default()
        };

        assert_fail(&inputs, "unknown channel_id: no channel is tracked for it");
    }

    #[test]
    fn channel_ready_without_funding_signed_fails() {
        let mut inputs = OracleInputs::default();
        inputs.channel_mut().funding_signed_received = false;

        assert_fail(&inputs, "no funding_signed was received for this channel");
    }

    #[test]
    fn channel_ready_with_invalid_funding_outpoint_fails() {
        let mut inputs = OracleInputs::default();
        inputs.channel_mut().is_funding_outpoint_valid = false;

        assert_fail(
            &inputs,
            "funding output does not match the negotiated funding script and amount",
        );
    }

    #[test]
    fn channel_ready_below_minimum_depth_fails() {
        let inputs = OracleInputs {
            funding_confirmations: CONFIRMED_DEPTH - 1,
            ..OracleInputs::default()
        };

        assert_fail(
            &inputs,
            "channel_ready received with 5 funding confirmation(s), below minimum_depth 6",
        );
    }

    #[test]
    fn channel_ready_exactly_at_minimum_depth_passes() {
        let inputs = OracleInputs {
            funding_confirmations: CONFIRMED_DEPTH,
            ..OracleInputs::default()
        };

        assert_pass(&inputs);
    }

    #[test]
    fn conforming_option_scid_alias_with_an_alias_passes() {
        let mut inputs = OracleInputs {
            negotiated_features: Features::from_bits(&[Features::OPTION_SCID_ALIAS]),
            ..OracleInputs::default()
        };
        inputs.channel_ready.tlvs.short_channel_id = Some(ShortChannelId::new(800_000, 1, 0));

        assert_pass(&inputs);
    }

    #[test]
    fn alias_without_option_scid_alias_passes() {
        let mut inputs = OracleInputs::default();
        inputs.channel_ready.tlvs.short_channel_id = Some(ShortChannelId::new(800_000, 1, 0));

        assert_pass(&inputs);
    }

    #[test]
    fn option_scid_alias_without_an_alias_fails() {
        let inputs = OracleInputs {
            negotiated_features: Features::from_bits(&[Features::OPTION_SCID_ALIAS]),
            ..OracleInputs::default()
        };

        assert_fail(
            &inputs,
            "option_scid_alias negotiated but short_channel_id alias is missing",
        );
    }

    #[test]
    fn channel_ready_alias_reuses_another_channels_scid_fails() {
        let alias = ShortChannelId::new(800_000, 1, 0);
        let origin = ChannelId::new([2u8; 32]);
        let mut inputs = OracleInputs {
            revealed_scids: HashMap::from([(alias, origin)]),
            ..OracleInputs::default()
        };
        inputs.channel_ready.tlvs.short_channel_id = Some(alias);

        assert_fail(
            &inputs,
            &format!(
                "short_channel_id alias {alias} reuses the short_channel_id of channel {origin}"
            ),
        );
    }

    #[test]
    fn channel_ready_alias_resend_for_same_channel_passes() {
        let alias = ShortChannelId::new(800_000, 1, 0);
        let mut inputs = OracleInputs::default();
        inputs.channel_ready.tlvs.short_channel_id = Some(alias);
        inputs
            .revealed_scids
            .insert(alias, inputs.channel_ready.channel_id);

        assert_pass(&inputs);
    }

    #[test]
    fn channel_ready_resend_different_per_commitment_point_fails() {
        let mut inputs = OracleInputs::default();
        inputs.channel_mut().received_channel_ready_point = Some(pubkey(3));

        assert_fail(
            &inputs,
            &format!(
                "channel_ready resend changed second_per_commitment_point from {} to {}",
                pubkey(3),
                inputs.channel_ready.second_per_commitment_point,
            ),
        );
    }

    #[test]
    fn channel_ready_resend_repeats_per_commitment_point_passes() {
        let mut inputs = OracleInputs::default();
        inputs.channel_mut().received_channel_ready_point =
            Some(inputs.channel_ready.second_per_commitment_point);

        assert_pass(&inputs);
    }

    #[test]
    fn channel_ready_reuses_per_commitment_point_from_previously_revealed_key_fails() {
        let origin = KeyOrigin::TargetPcp {
            channel: ChannelId::new([2u8; 32]),
            commitment_number: 1,
        };
        let mut inputs = OracleInputs::default();
        inputs
            .revealed_pubkeys
            .insert(inputs.channel_ready.second_per_commitment_point, origin);

        assert_fail(
            &inputs,
            &format!(
                "second_per_commitment_point {} reuses {origin}",
                inputs.channel_ready.second_per_commitment_point,
            ),
        );
    }

    #[test]
    fn channel_ready_resends_per_commitment_point_for_same_channel_passes() {
        let mut inputs = OracleInputs::default();
        let origin = KeyOrigin::TargetPcp {
            channel: inputs.channel_ready.channel_id,
            commitment_number: 1,
        };
        inputs
            .revealed_pubkeys
            .insert(inputs.channel_ready.second_per_commitment_point, origin);

        assert_pass(&inputs);
    }
}
