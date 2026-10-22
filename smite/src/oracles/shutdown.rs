//! BOLT 2 `shutdown` oracle, for the cooperative close flow.

use super::Oracle;
use crate::bolt::{Features, Shutdown, is_standard_shutdown_script};
use crate::channel_state::ChannelState;
use crate::violation::Violation;

/// Context for `ShutdownOracle`
pub struct ShutdownContext<'a> {
    /// The `shutdown` received from the peer.
    pub shutdown: &'a Shutdown,
    /// The channel the `shutdown` belongs to, identified by its `channel_id`,
    /// or `None` if no channel was funded for it.
    pub channel: Option<&'a ChannelState>,
    /// Features negotiated between the target node and Smite, which decide the
    /// standard `scriptpubkey` forms.
    pub negotiated_features: &'a Features,
}

/// Checks that a received `shutdown` names a channel we funded, that the target
/// was allowed to reply on it, and that its `scriptpubkey` is a standard form
/// for the negotiated features.
pub struct ShutdownOracle;

impl Oracle<ShutdownContext<'_>> for ShutdownOracle {
    fn evaluate(&self, context: &ShutdownContext<'_>) -> Result<(), Violation> {
        let Shutdown {
            channel_id,
            scriptpubkey,
        } = context.shutdown;

        // Check that the `shutdown` names a channel we funded.
        let Some(channel) = context.channel else {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                "unknown channel_id: no channel was funded for it".to_string(),
            ));
        };

        // Check that the target did not reply on a channel it was required to
        // fail.
        if channel.sent_invalid_signature {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                "replied on a failed channel: we sent an invalid signature".to_string(),
            ));
        }

        // Check that the `scriptpubkey` is a form BOLT 2 permits a sender to use.
        if !is_standard_shutdown_script(scriptpubkey, context.negotiated_features) {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                format!(
                    "non-standard scriptpubkey: {} is not permitted for the negotiated features",
                    hex::encode(scriptpubkey),
                ),
            ));
        }

        // TODO: BOLT 2 forbids sending `shutdown` while HTLCs are still pending.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::ChannelId;
    use crate::channel_tx::{ChannelConfig, ChannelPartyConfig, HolderIdentity, Side};
    use bitcoin::OutPoint;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHBYTES_20,
    };
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

    /// A legacy P2PKH `scriptpubkey`.
    fn p2pkh() -> Vec<u8> {
        let mut spk = vec![OP_DUP.to_u8(), OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()];
        spk.extend_from_slice(&[0xab; 20]);
        spk.extend_from_slice(&[OP_EQUALVERIFY.to_u8(), OP_CHECKSIG.to_u8()]);
        spk
    }

    /// A legacy P2SH `scriptpubkey`.
    fn p2sh() -> Vec<u8> {
        let mut spk = vec![OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()];
        spk.extend_from_slice(&[0xab; 20]);
        spk.push(OP_EQUAL.to_u8());
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
        };
        let commitments = config
            .new_initial_commitments(3_000_000_000, 15_000, pkey1, pkey2)
            .expect("valid initial commitments");
        let holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret_key(1),
            htlc_basepoint_privkey: secret_key(1),
        };

        ChannelState::new(config, holder, commitments, true, false, false)
    }

    /// Oracle inputs for testing. Defaults to a conforming `shutdown` for a
    /// funded channel.
    struct OracleInputs {
        shutdown: Shutdown,
        channel: Option<ChannelState>,
        negotiated_features: Features,
    }

    impl Default for OracleInputs {
        fn default() -> Self {
            Self {
                shutdown: shutdown(),
                channel: Some(channel_state()),
                negotiated_features: Features::new(),
            }
        }
    }

    impl OracleInputs {
        fn evaluate(&self) -> Result<(), Violation> {
            ShutdownOracle.evaluate(&ShutdownContext {
                shutdown: &self.shutdown,
                channel: self.channel.as_ref(),
                negotiated_features: &self.negotiated_features,
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

        assert_fail(&inputs, "unknown channel_id: no channel was funded for it");
    }

    #[test]
    fn rejects_reply_on_failed_channel() {
        let mut inputs = OracleInputs::default();
        inputs.channel_mut().sent_invalid_signature = true;

        assert_fail(
            &inputs,
            "replied on a failed channel: we sent an invalid signature",
        );
    }

    #[test]
    fn rejects_non_standard_scriptpubkey() {
        // A receiver may accept legacy P2PKH/P2SH, but the target is the sender
        // here, and no feature makes them a standard form for a sender to use.
        for spk in [p2pkh(), p2sh()] {
            let inputs = OracleInputs {
                shutdown: Shutdown::for_channel(shutdown().channel_id, spk),
                negotiated_features: Features::from_bits(&[
                    Features::OPTION_SHUTDOWN_ANYSEGWIT,
                    Features::OPTION_SIMPLE_CLOSE,
                ]),
                ..Default::default()
            };

            assert_fail(&inputs, "non-standard scriptpubkey");
        }
    }

    #[test]
    fn accepts_anysegwit_only_when_negotiated() {
        let mut spk = vec![0x51, 0x02];
        spk.extend_from_slice(&[0xcd; 2]);
        let inputs = OracleInputs {
            shutdown: Shutdown::for_channel(shutdown().channel_id, spk),
            ..Default::default()
        };

        assert_fail(&inputs, "non-standard scriptpubkey");

        let inputs = OracleInputs {
            negotiated_features: Features::from_bits(&[Features::OPTION_SHUTDOWN_ANYSEGWIT]),
            ..inputs
        };

        assert_pass(&inputs);
    }
}
