//! BIP-327 `MuSig2` helpers for simple taproot channels.
//!
//! Simple taproot channels replace the 2-of-2 P2WSH funding output with a
//! single P2TR output whose key is the `MuSig2` aggregate of both
//! `funding_pubkey`s, and replace the commitment ECDSA signature with a `MuSig2`
//! partial signature exchanged in `funding_created` / `funding_signed`.
//!
//! This module is the only place that talks to the `musig2` crate. That crate
//! pulls its own `secp256k1` version, distinct from the one `bitcoin`
//! re-exports, so every key crosses the boundary as serialized bytes and the
//! rest of smite only ever sees `bitcoin::secp256k1` types.
//!
//! The `musig2` dependency is removable once `bitcoin` 0.33 is stable:
//! `secp256k1` 0.32 ships `secp256k1::musig`, and `bitcoin` 0.33 re-exports
//! that version.

use bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use musig2::secp256k1::PublicKey as MusigPublicKey;
use musig2::{AggNonce, BinaryEncoding, KeyAggContext, PubNonce, SecNonce, SecNonceBuilder};

use crate::bolt::{PARTIAL_SIGNATURE_SIZE, PublicNonce};

/// Errors produced while building or using a `MuSig2` funding session.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MusigError {
    /// The two `funding_pubkey`s could not be aggregated.
    #[error("failed to aggregate funding pubkeys: {0}")]
    KeyAggregation(String),

    /// The BIP 86 taproot tweak could not be applied to the aggregate key.
    #[error("failed to apply taproot tweak to aggregate funding key: {0}")]
    Tweak(String),

    /// A public nonce received from the peer is not two compressed points.
    #[error("public nonce is not two valid compressed secp256k1 points")]
    InvalidPublicNonce,

    /// Producing our own partial signature failed.
    #[error("failed to produce partial signature: {0}")]
    Signing(String),
}

/// A `MuSig2` secret nonce.
///
/// Wraps `musig2::SecNonce` so that type stays inside this module
#[derive(Debug)]
pub struct SecretNonce(SecNonce);

/// A `MuSig2` partial signature: the `s` scalar of one signer's contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialSignature(pub [u8; PARTIAL_SIGNATURE_SIZE]);

/// Re-parses a secret key into the `musig2` crate's `secp256k1` version.
///
/// Both crates validate the same 32-byte range, so a key valid in one is valid
/// in the other.
fn musig_seckey(funding_privkey: &SecretKey) -> musig2::secp256k1::SecretKey {
    musig2::secp256k1::SecretKey::from_byte_array(funding_privkey.secret_bytes())
        .expect("a valid secp256k1 secret key is valid in either crate version")
}

/// The `MuSig2` signing context for a channel's funding output.
///
/// Holds the key aggregation context built from both `funding_pubkey`s, sorted
/// with `KeySort` and tweaked per BIP 86 as the taproot channel spec requires.
pub struct FundingKeys {
    ctx: KeyAggContext,
}

/// Derives a secret nonce deterministically from `context` and the signer's
/// `funding_pubkey`.
///
/// # Panics
///
/// Panics if `funding_pubkey` does not round-trip between the two `secp256k1`
/// versions, which cannot happen for a valid public key.
#[must_use]
pub fn derive_nonce(context: &[&[u8]], funding_pubkey: &PublicKey) -> SecretNonce {
    let pubkey = MusigPublicKey::from_slice(&funding_pubkey.serialize())
        .expect("a valid secp256k1 pubkey is valid in either crate version");

    let builder = context.iter().fold(
        SecNonce::build_with_pubkey([0u8; 32], pubkey),
        SecNonceBuilder::with_extra_input,
    );

    SecretNonce(builder.build())
}

/// Returns whether a nonce received from the peer is two valid compressed
/// secp256k1 points.
///
/// The wire layer accepts any 66 bytes so that a malformed nonce reaches the
/// oracles instead of failing to decode; this is the check the spec requires
/// before the nonce is used.
#[must_use]
pub fn is_valid_public_nonce(nonce: &PublicNonce) -> bool {
    PubNonce::from_bytes(nonce.as_bytes()).is_ok()
}

/// Converts a wire nonce to the `musig2` crate's representation.
fn to_pub_nonce(nonce: &PublicNonce) -> Result<PubNonce, MusigError> {
    PubNonce::from_bytes(nonce.as_bytes()).map_err(|_| MusigError::InvalidPublicNonce)
}

impl SecretNonce {
    /// Returns the matching public nonce, safe to send to the peer.
    #[must_use]
    pub fn public_nonce(&self) -> PublicNonce {
        PublicNonce(self.0.public_nonce().to_bytes())
    }
}

impl FundingKeys {
    /// Builds the funding signing context from both `funding_pubkey`s.
    ///
    /// The keys are sorted with `KeySort` and aggregated with `KeyAgg`, then
    /// tweaked with the BIP 86 unspendable-script-path tweak. The resulting key
    /// is what the funding output pays to, so the argument order does not
    /// matter.
    ///
    /// # Errors
    ///
    /// Returns [`MusigError::KeyAggregation`] or [`MusigError::Tweak`] if the
    /// aggregate key cannot be formed, which cannot happen for two valid
    /// distinct public keys.
    pub fn new(pubkey1: &PublicKey, pubkey2: &PublicKey) -> Result<Self, MusigError> {
        // `KeySort` from BIP 327: lexicographic over the 33-byte compressed
        // encodings. Sorting here is what lets both peers derive the same
        // aggregate key without exchanging ordering information.
        let mut serialized = [pubkey1.serialize(), pubkey2.serialize()];
        serialized.sort_unstable();

        let keys: Vec<MusigPublicKey> = serialized
            .iter()
            .map(|bytes| {
                MusigPublicKey::from_slice(bytes)
                    .map_err(|e| MusigError::KeyAggregation(e.to_string()))
            })
            .collect::<Result<_, _>>()?;

        let ctx = KeyAggContext::new(keys)
            .map_err(|e| MusigError::KeyAggregation(e.to_string()))?
            .with_unspendable_taproot_tweak()
            .map_err(|e| MusigError::Tweak(e.to_string()))?;

        Ok(Self { ctx })
    }

    /// Returns the tweaked aggregate key the funding output pays to.
    ///
    /// # Panics
    ///
    /// Panics if the aggregate key does not round-trip between the two
    /// `secp256k1` versions, which cannot happen for a key `KeyAgg` produced.
    #[must_use]
    pub fn aggregate_pubkey(&self) -> XOnlyPublicKey {
        let aggregate: MusigPublicKey = self.ctx.aggregated_pubkey();
        XOnlyPublicKey::from_slice(&aggregate.x_only_public_key().0.serialize())
            .expect("musig2 aggregate key is a valid x-only pubkey")
    }

    /// Produces our partial signature over `sighash` for the counterparty's
    /// commitment.
    ///
    /// `our_nonce` is the fresh signing nonce sent alongside the signature;
    /// `their_nonce` is the peer's verification nonce from `open_channel` or
    /// `accept_channel`.
    ///
    /// # Errors
    ///
    /// Returns [`MusigError::InvalidPublicNonce`] if either nonce cannot be
    /// parsed, or [`MusigError::Signing`] if signing fails.
    pub fn partial_sign(
        &self,
        sighash: &[u8; 32],
        funding_privkey: &SecretKey,
        our_nonce: SecretNonce,
        their_nonce: &PublicNonce,
    ) -> Result<PartialSignature, MusigError> {
        let aggregated_nonce = aggregate_nonce(&our_nonce.public_nonce(), their_nonce)?;

        let signature: musig2::PartialSignature = musig2::sign_partial(
            &self.ctx,
            musig_seckey(funding_privkey),
            our_nonce.0,
            &aggregated_nonce,
            sighash,
        )
        .map_err(|e| MusigError::Signing(e.to_string()))?;

        Ok(PartialSignature(signature.serialize()))
    }

    /// Returns whether the peer's partial signature over `sighash` is valid.
    ///
    /// `their_nonce` is the signing nonce the peer sent alongside the
    /// signature; `our_nonce` is the verification nonce we sent earlier.
    ///
    /// # Errors
    ///
    /// Returns [`MusigError::InvalidPublicNonce`] if either nonce cannot be
    /// parsed. An otherwise well-formed but incorrect signature yields
    /// `Ok(false)` rather than an error.
    pub fn verify_partial(
        &self,
        sighash: &[u8; 32],
        signature: &PartialSignature,
        their_pubkey: &PublicKey,
        their_nonce: &PublicNonce,
        our_nonce: &PublicNonce,
    ) -> Result<bool, MusigError> {
        let aggregated_nonce = aggregate_nonce(our_nonce, their_nonce)?;
        let Ok(signature) = musig2::PartialSignature::from_slice(&signature.0) else {
            return Ok(false);
        };
        let pubkey = MusigPublicKey::from_slice(&their_pubkey.serialize())
            .map_err(|e| MusigError::KeyAggregation(e.to_string()))?;

        Ok(musig2::verify_partial(
            &self.ctx,
            signature,
            &aggregated_nonce,
            pubkey,
            &to_pub_nonce(their_nonce)?,
            sighash,
        )
        .is_ok())
    }
}

/// Combines both public nonces with `NonceAgg`. Point addition is commutative,
/// so the argument order does not matter.
fn aggregate_nonce(nonce1: &PublicNonce, nonce2: &PublicNonce) -> Result<AggNonce, MusigError> {
    Ok(AggNonce::sum([
        to_pub_nonce(nonce1)?,
        to_pub_nonce(nonce2)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(hex_str: &str) -> PublicKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        PublicKey::from_slice(&bytes).expect("valid pubkey")
    }

    fn secret(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        SecretKey::from_slice(&bytes).expect("valid secret key")
    }

    // Test vectors from the simple taproot channels spec:
    //   bolt-simple-taproot.md, "Test Vectors" appendix.

    /// The spec's `funding` vector: the aggregate of the two `funding_pubkey`s,
    /// sorted and BIP 86 tweaked, is the key the funding output pays to.
    #[test]
    fn aggregate_funding_key_matches_spec_vector() {
        let local = pubkey("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");
        let remote = pubkey("02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb");

        let keys = FundingKeys::new(&local, &remote).expect("valid funding pubkeys");

        assert_eq!(
            hex::encode(keys.aggregate_pubkey().serialize()),
            "d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e"
        );
    }

    /// `KeySort` runs before `KeyAgg`, so the caller's argument order cannot
    /// change the funding output.
    #[test]
    fn aggregate_funding_key_is_argument_order_independent() {
        let local = pubkey("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");
        let remote = pubkey("02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb");

        let one = FundingKeys::new(&local, &remote).expect("valid funding pubkeys");
        let other = FundingKeys::new(&remote, &local).expect("valid funding pubkeys");

        assert_eq!(one.aggregate_pubkey(), other.aggregate_pubkey());
    }

    /// A partial signature produced by one side verifies against the other
    /// side's view of the same session.
    #[test]
    fn partial_signature_round_trip() {
        let local_sk = secret("20ae2d254ab29afd3dcbf8744a5b88d06070f55a4bd5532483a093ac4db91277");
        let local = pubkey("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");
        let remote = pubkey("02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb");

        let keys = FundingKeys::new(&local, &remote).expect("valid funding pubkeys");
        let sighash = [0x42u8; 32];

        // The verifier's nonce is sent first, in `open_channel`.
        let verification = derive_nonce(&[b"verification"], &remote);
        // The signer's nonce accompanies the signature in `funding_created`.
        let signing = derive_nonce(&[b"signing"], &local);
        let signing_public = signing.public_nonce();

        let signature = keys
            .partial_sign(&sighash, &local_sk, signing, &verification.public_nonce())
            .expect("signing succeeds");

        assert!(
            keys.verify_partial(
                &sighash,
                &signature,
                &local,
                &signing_public,
                &verification.public_nonce(),
            )
            .expect("nonces parse")
        );
    }

    /// A signature over a different commitment must not verify, otherwise
    /// `funding_signed` verification would accept anything.
    #[test]
    fn partial_signature_over_wrong_sighash_is_rejected() {
        let local_sk = secret("20ae2d254ab29afd3dcbf8744a5b88d06070f55a4bd5532483a093ac4db91277");
        let local = pubkey("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");
        let remote = pubkey("02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb");

        let keys = FundingKeys::new(&local, &remote).expect("valid funding pubkeys");

        let verification = derive_nonce(&[b"verification"], &remote);
        let signing = derive_nonce(&[b"signing"], &local);
        let signing_public = signing.public_nonce();

        let signature = keys
            .partial_sign(
                &[0x42u8; 32],
                &local_sk,
                signing,
                &verification.public_nonce(),
            )
            .expect("signing succeeds");

        assert!(
            !keys
                .verify_partial(
                    &[0x43u8; 32],
                    &signature,
                    &local,
                    &signing_public,
                    &verification.public_nonce(),
                )
                .expect("nonces parse")
        );
    }

    /// Peer nonces arrive as untrusted bytes; the spec requires failing the
    /// channel when they are not two compressed points.
    #[test]
    fn malformed_public_nonce_is_not_valid() {
        assert!(!is_valid_public_nonce(&PublicNonce(
            [0x00; crate::bolt::PUBLIC_NONCE_SIZE]
        )));
    }

    #[test]
    fn generated_public_nonce_is_valid() {
        let key = pubkey("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");

        assert!(is_valid_public_nonce(
            &derive_nonce(&[b"ctx"], &key).public_nonce()
        ));
    }
}
