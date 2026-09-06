//! BOLT 2 funding signed message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, PartialSignatureWithNonce};
use super::wire::WireFormat;
use bitcoin::secp256k1::ecdsa::Signature;

/// TLV type for the `MuSig2` partial signature of simple taproot channels.
const TLV_PARTIAL_SIGNATURE_WITH_NONCE: u64 = 2;

/// BOLT 2 `funding_signed` message (type 35).
///
/// Sent by the channel acceptor in response to `funding_created` to provide
/// their signature for the counterparty's first commitment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingSigned {
    /// The channel ID derived from the funding transaction outpoint
    pub channel_id: ChannelId,
    /// The channel acceptor's signature for the counterparty's first commitment transaction.
    ///
    /// Simple taproot channels carry the real signature in
    /// [`FundingSignedTlvs::partial_signature_with_nonce`] and require this
    /// field to be 64 zero bytes.
    pub signature: Signature,
    /// Optional TLV extensions.
    pub tlvs: FundingSignedTlvs,
}

/// TLV extensions for the `funding_signed` message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FundingSignedTlvs {
    /// The `MuSig2` partial signature over the counterparty's first commitment
    /// transaction, with the nonce it was produced with. Required for simple
    /// taproot channels.
    pub partial_signature_with_nonce: Option<PartialSignatureWithNonce>,
}

impl FundingSigned {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.signature.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(partial_signature_with_nonce) = &self.tlvs.partial_signature_with_nonce {
            let mut value = Vec::new();
            partial_signature_with_nonce.write(&mut value);
            tlv_stream.add(TLV_PARTIAL_SIGNATURE_WITH_NONCE, value);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or `InvalidSignature`
    /// if the signature bytes are not a valid compact ECDSA signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let signature = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // Type 2 (`partial_signature_with_nonce`) is an even type defined by
        // the simple taproot channels extension, so we must whitelist it as
        // known.
        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_PARTIAL_SIGNATURE_WITH_NONCE])?;
        let tlvs = FundingSignedTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            signature,
            tlvs,
        })
    }
}

impl FundingSignedTlvs {
    /// Extracts funding signed TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if the `partial_signature_with_nonce` TLV has an
    /// invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let partial_signature_with_nonce =
            stream.get_as::<PartialSignatureWithNonce>(TLV_PARTIAL_SIGNATURE_WITH_NONCE)?;
        Ok(Self {
            partial_signature_with_nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, PARTIAL_SIGNATURE_SIZE, PUBLIC_NONCE_SIZE,
        PublicNonce,
    };
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `FundingSigned` message for testing.
    fn sample_funding_signed() -> FundingSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
            tlvs: FundingSignedTlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_funding_signed();
        let encoded = msg.encode();
        // 32 + 64 = 96
        assert_eq!(encoded.len(), 96);
    }

    #[test]
    fn roundtrip() {
        let original = sample_funding_signed();
        let encoded = original.encode();
        let decoded = FundingSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            FundingSigned::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_signature() {
        // channel_id(32) + 30 bytes into signature
        let msg = sample_funding_signed();
        let encoded = msg.encode();
        let data = &encoded[..62]; // 32 + 30
        assert_eq!(
            FundingSigned::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 30
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let msg = sample_funding_signed();
        let mut encoded = msg.encode();

        // Overwrite the signature (last 64 bytes) with r and s both > curve order
        let sig_offset = encoded.len() - COMPACT_SIGNATURE_SIZE;
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[sig_offset..].copy_from_slice(&bad_sig);

        assert_eq!(
            FundingSigned::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    /// Simple taproot channels zero the fixed `signature` field and carry the
    /// real signature in TLV type 2.
    #[test]
    fn encode_with_partial_signature_with_nonce() {
        let mut msg = sample_funding_signed();
        msg.signature = Signature::from_compact(&[0u8; COMPACT_SIGNATURE_SIZE])
            .expect("zero bytes parse as a signature");
        msg.tlvs.partial_signature_with_nonce = Some(PartialSignatureWithNonce {
            partial_signature: [0xab; PARTIAL_SIGNATURE_SIZE],
            public_nonce: PublicNonce([0xcd; PUBLIC_NONCE_SIZE]),
        });

        let encoded = msg.encode();
        // 96 fixed + TLV: type(1) + len(1) + value(98) = 100
        assert_eq!(encoded.len(), 96 + 100);

        assert_eq!(FundingSigned::decode(&encoded), Ok(msg));
    }
}
