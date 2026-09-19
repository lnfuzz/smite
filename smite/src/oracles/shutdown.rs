//! BOLT 2 `shutdown` oracle, for cooperative-close initiation.

use super::Oracle;
use crate::bolt::{Features, Shutdown, is_standard_shutdown_script};
use crate::channel_tx::ChannelState;
use crate::violation::Violation;

/// Context for [`ShutdownOracle`].
pub struct ShutdownContext<'a> {
    /// The `shutdown` received from the peer.
    pub shutdown: &'a Shutdown,
    /// The `shutdown` we sent, which the received one answers.
    pub sent: &'a Shutdown,
    /// The channel the `shutdown` belongs to, identified by its `channel_id`,
    /// or `None` if no such channel was established.
    pub channel: Option<&'a ChannelState>,
    /// Features negotiated between the target node and Smite, which decide the
    /// standard `scriptpubkey` forms and whether `upfront_shutdown_script`s are
    /// binding.
    pub negotiated_features: &'a Features,
}

/// Checks that a received `shutdown` references a channel we know, answers a
/// `shutdown` the target was allowed to answer, and carries a `scriptpubkey`
/// that matches the peer's committed `upfront_shutdown_script` and is a
/// standard form for the negotiated features.
pub struct ShutdownOracle;

impl Oracle<ShutdownContext<'_>> for ShutdownOracle {
    fn evaluate(&self, context: &ShutdownContext<'_>) -> Result<(), Violation> {
        let Shutdown {
            channel_id,
            scriptpubkey,
        } = context.shutdown;

        // Check that the `shutdown` references a channel we established.
        let Some(channel) = context.channel else {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                "unknown channel_id: no channel was established for this channel".to_string(),
            ));
        };

        // Check that the target did not respond on a channel it was required to
        // fail.
        if channel.sent_invalid_signature {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                "replied on a failed channel: we sent an invalid signature".to_string(),
            ));
        }

        // Check that the target did not respond to a `shutdown` breaking our own
        // upfront commitment, since it must then fail the connection.
        if !channel.verify_holder_upfront_shutdown_script(
            &context.sent.scriptpubkey,
            context.negotiated_features,
        ) {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                format!(
                    "replied to a shutdown breaking our upfront_shutdown_script: sent {}, committed to {}",
                    hex::encode(&context.sent.scriptpubkey),
                    hex::encode(
                        channel
                            .holder_upfront_shutdown_script
                            .as_deref()
                            .unwrap_or_default()
                    ),
                ),
            ));
        }

        // Check that the target kept its own upfront commitment.
        if !channel.verify_counterparty_upfront_shutdown_script(scriptpubkey) {
            return Err(Violation::InvalidShutdown(
                *channel_id,
                format!(
                    "upfront_shutdown_script mismatch: sent {}, committed to {}",
                    hex::encode(scriptpubkey),
                    hex::encode(
                        channel
                            .counterparty_upfront_shutdown_script
                            .as_deref()
                            .unwrap_or_default()
                    ),
                ),
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

        // TODO: BOLT 2 forbids sending `shutdown` while HTLCs are still pending on our commitment.

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
        OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSHBYTES_0, OP_PUSHBYTES_20,
        OP_PUSHNUM_1, OP_RETURN,
    };
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("valid secret key")
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key(seed))
    }

    /// Valid channel state for testing, with the peer committed to `upfront`.
    fn channel_state(upfront: Option<Vec<u8>>) -> ChannelState {
        let pkey1 = pubkey(1);
        let pkey2 = pubkey(2);

        let config = ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                    .parse()
                    .expect("valid txid hex"),
                vout: 0,
            },
            funding_satoshis: 10_000_000,
            channel_type: Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
            opener: ChannelPartyConfig {
                funding_pubkey: pkey1,
                payment_basepoint: pkey1,
                revocation_basepoint: pkey1,
                delayed_payment_basepoint: pkey1,
                dust_limit_satoshis: 546,
                to_self_delay: 144,
            },
            acceptor: ChannelPartyConfig {
                funding_pubkey: pkey2,
                payment_basepoint: pkey2,
                revocation_basepoint: pkey2,
                delayed_payment_basepoint: pkey2,
                dust_limit_satoshis: 546,
                to_self_delay: 144,
            },
            minimum_depth: 8,
        };
        let commitment = config
            .new_initial_commitment(3_000_000_000, 15_000, pkey1, pkey2)
            .expect("valid initial commitment");
        let holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret_key(1),
        };

        ChannelState::new(
            config, holder, commitment, true, false, false, None, upfront,
        )
    }

    fn p2pkh() -> Vec<u8> {
        let mut spk = vec![OP_DUP.to_u8(), OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()];
        spk.extend_from_slice(&[0x11; 20]);
        spk.extend_from_slice(&[OP_EQUALVERIFY.to_u8(), OP_CHECKSIG.to_u8()]);
        spk
    }

    fn p2wpkh(seed: u8) -> Vec<u8> {
        let mut spk = vec![OP_PUSHBYTES_0.to_u8(), OP_PUSHBYTES_20.to_u8()];
        spk.extend_from_slice(&[seed; 20]);
        spk
    }

    fn anysegwit() -> Vec<u8> {
        let mut spk = vec![OP_PUSHNUM_1.to_u8(), 32];
        spk.extend_from_slice(&[0x00; 32]);
        spk
    }

    fn simple_close() -> Vec<u8> {
        let mut spk = vec![OP_RETURN.to_u8(), 6];
        spk.extend_from_slice(&[0xab; 6]);
        spk
    }

    fn shutdown(scriptpubkey: Vec<u8>) -> Shutdown {
        Shutdown::for_channel(ChannelId::new([0x7a; 32]), scriptpubkey)
    }

    /// The `shutdown` we sent, unless a test needs a specific one.
    fn sent() -> Shutdown {
        shutdown(p2wpkh(0x55))
    }

    #[track_caller]
    fn assert_pass(
        shutdown: &Shutdown,
        sent: &Shutdown,
        channel: Option<&ChannelState>,
        features: &Features,
    ) {
        if let Err(err) = ShutdownOracle.evaluate(&ShutdownContext {
            shutdown,
            sent,
            channel,
            negotiated_features: features,
        }) {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(
        shutdown: &Shutdown,
        sent: &Shutdown,
        channel: Option<&ChannelState>,
        features: &Features,
        expected: &str,
    ) {
        match ShutdownOracle.evaluate(&ShutdownContext {
            shutdown,
            sent,
            channel,
            negotiated_features: features,
        }) {
            Err(Violation::InvalidShutdown(chan_id, reason)) => {
                assert_eq!(shutdown.channel_id, chan_id);
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
        assert_pass(
            &shutdown(p2wpkh(0x33)),
            &sent(),
            Some(&channel_state(None)),
            &Features::new(),
        );
    }

    #[test]
    fn shutdown_for_unknown_channel_id() {
        assert_fail(
            &shutdown(p2wpkh(0x33)),
            &sent(),
            None,
            &Features::new(),
            "unknown channel_id: no channel was established for this channel",
        );
    }

    #[test]
    fn shutdown_after_invalid_signature() {
        let mut channel = channel_state(None);
        channel.sent_invalid_signature = true;

        assert_fail(
            &shutdown(p2wpkh(0x33)),
            &sent(),
            Some(&channel),
            &Features::new(),
            "replied on a failed channel: we sent an invalid signature",
        );
    }

    #[test]
    fn shutdown_with_non_standard_script() {
        assert_fail(
            &shutdown(p2pkh()),
            &sent(),
            Some(&channel_state(None)),
            &Features::new(),
            &format!("non-standard scriptpubkey: {}", hex::encode(p2pkh())),
        );
    }

    #[test]
    fn shutdown_script_standard_only_with_negotiated_feature() {
        let channel = channel_state(None);

        for (spk, feature) in [
            (anysegwit(), Features::OPTION_SHUTDOWN_ANYSEGWIT),
            (simple_close(), Features::OPTION_SIMPLE_CLOSE),
        ] {
            assert_fail(
                &shutdown(spk.clone()),
                &sent(),
                Some(&channel),
                &Features::new(),
                "non-standard scriptpubkey",
            );
            assert_pass(
                &shutdown(spk),
                &sent(),
                Some(&channel),
                &Features::from_bits(&[feature]),
            );
        }
    }

    #[test]
    fn shutdown_matching_upfront_script_passes() {
        assert_pass(
            &shutdown(p2wpkh(0x33)),
            &sent(),
            Some(&channel_state(Some(p2wpkh(0x33)))),
            &Features::new(),
        );
    }

    #[test]
    fn shutdown_mismatching_upfront_script() {
        assert_fail(
            &shutdown(p2wpkh(0x44)),
            &sent(),
            Some(&channel_state(Some(p2wpkh(0x33)))),
            &Features::new(),
            &format!(
                "upfront_shutdown_script mismatch: sent {}, committed to {}",
                hex::encode(p2wpkh(0x44)),
                hex::encode(p2wpkh(0x33)),
            ),
        );
    }

    #[test]
    fn shutdown_with_empty_upfront_script_requires_standard_script() {
        let channel = channel_state(Some(Vec::new()));

        assert_pass(
            &shutdown(p2wpkh(0x33)),
            &sent(),
            Some(&channel),
            &Features::new(),
        );
        assert_fail(
            &shutdown(p2pkh()),
            &sent(),
            Some(&channel),
            &Features::new(),
            "non-standard scriptpubkey",
        );
    }

    /// A channel where we committed to `p2wpkh(0x55)` as our
    /// `upfront_shutdown_script`.
    fn holder_committed_channel() -> ChannelState {
        let mut channel = channel_state(None);
        channel.holder_upfront_shutdown_script = Some(p2wpkh(0x55));
        channel
    }

    fn upfront_feature() -> Features {
        Features::from_bits(&[Features::OPTION_UPFRONT_SHUTDOWN_SCRIPT])
    }

    #[test]
    fn shutdown_answering_our_mismatched_upfront_script() {
        assert_fail(
            &shutdown(p2wpkh(0x33)),
            &shutdown(p2wpkh(0x66)),
            Some(&holder_committed_channel()),
            &upfront_feature(),
            &format!(
                "replied to a shutdown breaking our upfront_shutdown_script: sent {}, committed to {}",
                hex::encode(p2wpkh(0x66)),
                hex::encode(p2wpkh(0x55)),
            ),
        );
    }

    #[test]
    fn shutdown_answering_our_matching_upfront_script_passes() {
        assert_pass(
            &shutdown(p2wpkh(0x33)),
            &shutdown(p2wpkh(0x55)),
            Some(&holder_committed_channel()),
            &upfront_feature(),
        );
    }

    #[test]
    fn shutdown_answering_our_mismatched_upfront_script_without_feature_passes() {
        assert_pass(
            &shutdown(p2wpkh(0x33)),
            &shutdown(p2wpkh(0x66)),
            Some(&holder_committed_channel()),
            &Features::new(),
        );
    }

    #[test]
    fn shutdown_answering_our_empty_upfront_script_passes() {
        let mut channel = channel_state(None);
        channel.holder_upfront_shutdown_script = Some(Vec::new());

        assert_pass(
            &shutdown(p2wpkh(0x33)),
            &shutdown(p2wpkh(0x66)),
            Some(&channel),
            &upfront_feature(),
        );
    }
}
