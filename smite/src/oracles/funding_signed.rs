//! BOLT 2 `funding_signed` oracle, for the v1 outbound channel funding flow.

use super::Oracle;
use crate::bolt::FundingSigned;
use crate::channel_tx::ChannelState;
use crate::violation::Violation;

/// Context for `FundingSignedOracle`
pub struct FundingSignedContext<'a> {
    /// The `funding_signed` received from the peer.
    pub funding_signed: &'a FundingSigned,
    /// The channel the `funding_signed` belongs to, identified by its
    /// `channel_id`, or `None` if no matching `funding_created` was sent.
    pub channel: Option<&'a ChannelState>,
}

/// Checks whether the `funding_created` answered by a `funding_signed` satisfied
/// the BOLT 2 v1 channel establishment requirements for acceptance, and whether
/// the `funding_signed` itself satisfies them.
pub struct FundingSignedOracle;

impl Oracle<FundingSignedContext<'_>> for FundingSignedOracle {
    fn evaluate(&self, context: &FundingSignedContext<'_>) -> Result<(), Violation> {
        // Check that the `funding_signed` answers a known `funding_created`.
        let Some(channel) = context.channel else {
            return Err(Violation::InvalidFundingSigned(
                context.funding_signed.channel_id,
                "unknown channel_id: no funding_created was sent for this channel".to_string(),
            ));
        };

        // Check whether we sent a valid signature during `funding_created`.
        if channel.sent_invalid_signature {
            return Err(Violation::InvalidFundingSigned(
                context.funding_signed.channel_id,
                "accepted invalid funding_created: signature is not valid".to_string(),
            ));
        }

        // Check that the `funding_signed` itself is valid.
        //
        // NOTE: There are two possible violations here: the target may have
        // sent an invalid signature, or a valid signature may have been mapped
        // to an existing channel_id due to the XOR relationship between
        // channel_id and the funding outpoint. BOLT 2 does not specify how to
        // handle the latter case, but LND, LDK, and Eclair all reject such
        // channels. Since channel_id is reused across messages, accepting a
        // collision could cause cross-channel state contamination and lead to
        // more serious bugs. Such collisions are also extremely unlikely to
        // occur naturally, so the target should reject them, and we catch them
        // here as well. see: https://github.com/ElementsProject/lightning/issues/9274#issuecomment-5316110622
        if !channel.config.verify_counterparty_signature(
            &channel.commitment,
            &channel.holder,
            &context.funding_signed.signature,
        ) {
            return Err(Violation::InvalidFundingSigned(
                context.funding_signed.channel_id,
                "invalid funding_signed: signature is not valid".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{COMPACT_SIGNATURE_SIZE, ChannelId};
    use crate::channel_tx::{ChannelConfig, ChannelPartyConfig, HolderIdentity, Side};
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("valid secret key")
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key(seed))
    }

    /// Valid channel state for testing.
    fn channel_state() -> ChannelState {
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
            channel_type: vec![0x10, 0x00],
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

        ChannelState::new(config, holder, commitment, true, false, false)
    }

    /// Valid `funding_signed` message for testing.
    fn funding_signed(channel: &ChannelState) -> FundingSigned {
        let acceptor = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: secret_key(2),
        };
        let outpoint = OutPoint {
            txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                .parse()
                .expect("valid txid"),
            vout: 0,
        };
        FundingSigned {
            channel_id: ChannelId::v1_from_funding_outpoint(outpoint),
            signature: channel
                .config
                .sign_counterparty_commitment(&channel.commitment, &acceptor),
        }
    }

    #[track_caller]
    fn assert_pass(funding_signed: &FundingSigned, channel: Option<&ChannelState>) {
        if let Err(err) = FundingSignedOracle.evaluate(&FundingSignedContext {
            funding_signed,
            channel,
        }) {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(funding_signed: &FundingSigned, channel: Option<&ChannelState>, expected: &str) {
        match FundingSignedOracle.evaluate(&FundingSignedContext {
            funding_signed,
            channel,
        }) {
            Err(Violation::InvalidFundingSigned(chan_id, reason)) => {
                assert_eq!(funding_signed.channel_id, chan_id);
                assert!(
                    reason.contains(expected),
                    "unexpected failure reason: {reason}"
                );
            }
            _ => panic!("expected failure: {expected}"),
        }
    }

    #[test]
    fn conforming_funding_signed_passes() {
        let channel = channel_state();

        assert_pass(&funding_signed(&channel), Some(&channel));
    }

    #[test]
    fn funding_signed_for_unknown_channel_id() {
        assert_fail(
            &funding_signed(&channel_state()),
            None,
            "unknown channel_id: no funding_created was sent for this channel",
        );
    }

    #[test]
    fn funding_created_with_invalid_signature() {
        let mut channel = channel_state();
        channel.sent_invalid_signature = true;

        assert_fail(
            &funding_signed(&channel),
            Some(&channel),
            "accepted invalid funding_created: signature is not valid",
        );
    }

    #[test]
    fn funding_signed_with_invalid_signature() {
        let channel = channel_state();
        let mut fs = funding_signed(&channel);
        fs.signature = Signature::from_compact(&[0u8; COMPACT_SIGNATURE_SIZE])
            .expect("zero bytes parse as a signature");

        assert_fail(
            &fs,
            Some(&channel),
            "invalid funding_signed: signature is not valid",
        );
    }
}
