//! BOLT 2 `shutdown` oracle, for the cooperative close flow.

use super::Oracle;
use crate::bolt::Shutdown;
use crate::channel_state::ChannelState;
use crate::violation::Violation;

/// Context for `ShutdownOracle`
pub struct ShutdownContext<'a> {
    /// The `shutdown` received from the peer.
    pub shutdown: &'a Shutdown,
    /// The channel the `shutdown` belongs to, identified by its `channel_id`,
    /// or `None` if no channel is tracked for it.
    pub channel: Option<&'a ChannelState>,
}

/// Checks that a received `shutdown` names a channel we track and that the
/// target funded it.
pub struct ShutdownOracle;

impl Oracle<ShutdownContext<'_>> for ShutdownOracle {
    fn evaluate(&self, context: &ShutdownContext<'_>) -> Result<(), Violation> {
        let Shutdown { channel_id, .. } = context.shutdown;

        // Check that the `shutdown` names a channel we track.
        let Some(channel) = context.channel else {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                "unknown channel_id: no channel is tracked for it".to_string(),
            ));
        };

        // Check that the target funded the channel by sending its `funding_signed`.
        if !channel.funding_signed_received {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                "unfunded channel: no funding_signed was received for it".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{ChannelId, Features};
    use crate::channel_tx::{ChannelConfig, ChannelPartyConfig, HolderIdentity, Side};
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("valid secret key")
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key(seed))
    }

    /// A standard P2WPKH `scriptpubkey`.
    fn p2wpkh() -> Vec<u8> {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[0xab; 20]);
        spk
    }

    /// Valid `shutdown` message for testing.
    fn shutdown() -> Shutdown {
        Shutdown::for_channel(ChannelId::new([1u8; 32]), p2wpkh())
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
            minimum_depth: 6,
            announce_channel: false,
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

    /// Oracle inputs for testing. Defaults to a conforming `shutdown` for a
    /// funded channel.
    struct OracleInputs {
        shutdown: Shutdown,
        channel: Option<ChannelState>,
    }

    impl Default for OracleInputs {
        fn default() -> Self {
            Self {
                shutdown: shutdown(),
                channel: Some(channel_state()),
            }
        }
    }

    impl OracleInputs {
        fn evaluate(&self) -> Result<(), Violation> {
            ShutdownOracle.evaluate(&ShutdownContext {
                shutdown: &self.shutdown,
                channel: self.channel.as_ref(),
            })
        }

        fn channel_mut(&mut self) -> &mut ChannelState {
            self.channel.as_mut().expect("funded channel")
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
            Err(Violation::InvalidShutdown(chan_id, reason)) => {
                assert_eq!(inputs.shutdown.channel_id, chan_id);
                assert!(
                    reason.contains(expected),
                    "unexpected failure reason: {reason}"
                );
            }
            _ => panic!("expected failure: {expected}"),
        }
    }

    #[test]
    fn conforming_shutdown_passes() {
        assert_pass(&OracleInputs::default());
    }

    #[test]
    fn rejects_unknown_channel() {
        let inputs = OracleInputs {
            channel: None,
            ..Default::default()
        };

        assert_fail(&inputs, "unknown channel_id: no channel is tracked for it");
    }

    #[test]
    fn rejects_unfunded_channel() {
        let mut inputs = OracleInputs::default();
        inputs.channel_mut().funding_signed_received = false;

        assert_fail(
            &inputs,
            "unfunded channel: no funding_signed was received for it",
        );
    }
}
