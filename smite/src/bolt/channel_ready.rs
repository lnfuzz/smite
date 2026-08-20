//! BOLT 2 channel ready message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, PublicNonce, ShortChannelId};
use super::wire::WireFormat;
use bitcoin::secp256k1::PublicKey;

/// TLV type for short channel ID alias.
const TLV_SHORT_CHANNEL_ID: u64 = 1;

/// TLV type for the `MuSig2` verification nonce of simple taproot channels.
const TLV_NEXT_LOCAL_NONCE: u64 = 4;

/// BOLT 2 `channel_ready` message (type 36).
///
/// Sent by each side once the funding transaction has reached the agreed-upon
/// `minimum_depth` to signal that the channel is ready for normal operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReady {
    /// The channel ID derived from the funding transaction outpoint
    pub channel_id: ChannelId,
    /// The per-commitment point for the second commitment transaction
    pub second_per_commitment_point: PublicKey,
    /// Optional TLV extensions.
    pub tlvs: ChannelReadyTlvs,
}

/// TLV extensions for the `channel_ready` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelReadyTlvs {
    /// An alias SCID for this channel, used for forwarding before confirmation
    /// and for private channels instead of the real `short_channel_id`.
    pub short_channel_id: Option<ShortChannelId>,
    /// A fresh `MuSig2` verification nonce, replacing the one consumed by the
    /// funding flow. Required for simple taproot channels.
    pub next_local_nonce: Option<PublicNonce>,
}

impl ChannelReady {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.second_per_commitment_point.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(scid) = &self.tlvs.short_channel_id {
            let mut value = Vec::new();
            scid.write(&mut value);
            tlv_stream.add(TLV_SHORT_CHANNEL_ID, value);
        }
        if let Some(next_local_nonce) = &self.tlvs.next_local_nonce {
            let mut value = Vec::new();
            next_local_nonce.write(&mut value);
            tlv_stream.add(TLV_NEXT_LOCAL_NONCE, value);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, `InvalidPublicKey`
    /// if the public key field is invalid, or TLV errors if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let second_per_commitment_point = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // Type 4 (`next_local_nonce`) is an even type defined by the simple
        // taproot channels extension, so we must whitelist it as known.
        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_NEXT_LOCAL_NONCE])?;
        let tlvs = ChannelReadyTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            second_per_commitment_point,
            tlvs,
        })
    }
}

impl ChannelReadyTlvs {
    /// Extracts channel ready TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if the short channel ID or `next_local_nonce`
    /// TLV has an invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let short_channel_id = stream.get_as::<ShortChannelId>(TLV_SHORT_CHANNEL_ID)?;
        let next_local_nonce = stream.get_as::<PublicNonce>(TLV_NEXT_LOCAL_NONCE)?;
        Ok(Self {
            short_channel_id,
            next_local_nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, PUBLIC_KEY_SIZE, PUBLIC_NONCE_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `ChannelReady` message for testing.
    fn sample_channel_ready(tlvs: Option<ChannelReadyTlvs>) -> ChannelReady {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        ChannelReady {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            second_per_commitment_point: pk,
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_channel_ready(None);
        let encoded = msg.encode();
        // channel_id(32) + second_per_commitment_point(33) = 65
        assert_eq!(encoded.len(), 65);
    }

    #[test]
    fn roundtrip() {
        let original = sample_channel_ready(None);
        let encoded = original.encode();
        let decoded = ChannelReady::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ChannelReady::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_second_per_commitment_point() {
        // channel_id(32) + 10 bytes into second_per_commitment_point
        let data = [0x00; 42];
        assert_eq!(
            ChannelReady::decode(&data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_invalid_second_per_commitment_point() {
        // Full length payload (65 bytes) with all-zero public key
        let data = [0x00; 65];
        assert_eq!(
            ChannelReady::decode(&data),
            Err(BoltError::InvalidPublicKey([0x00; PUBLIC_KEY_SIZE]))
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let original = sample_channel_ready(Some(ChannelReadyTlvs {
            short_channel_id: Some(ShortChannelId::from_u64(1_029_637_663_919_046_661)),
            next_local_nonce: Some(PublicNonce([0xcd; PUBLIC_NONCE_SIZE])),
        }));

        let encoded = original.encode();
        let decoded = ChannelReady::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_with_short_channel_id() {
        let msg = sample_channel_ready(Some(ChannelReadyTlvs {
            short_channel_id: Some(ShortChannelId::from_u64(1_029_637_663_919_046_661)),
            ..Default::default()
        }));

        let encoded = msg.encode();
        // 65 fixed + TLV: type(1) + len(1) + value(8) = 10
        assert_eq!(encoded.len(), 65 + 10);

        let decoded = ChannelReady::decode(&encoded).unwrap();
        assert_eq!(
            decoded.tlvs.short_channel_id,
            Some(ShortChannelId::from_u64(1_029_637_663_919_046_661))
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let msg = sample_channel_ready(None);
        let mut encoded = msg.encode();

        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);

        let decoded = ChannelReady::decode(&encoded).unwrap();
        assert!(decoded.tlvs.short_channel_id.is_none());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_short_channel_id_invalid_length() {
        let msg = sample_channel_ready(None);
        let mut encoded = msg.encode();

        // Append short_channel_id TLV with only 4 bytes (need 8)
        encoded.push(TLV_SHORT_CHANNEL_ID as u8); // type = 1
        encoded.push(0x04); // length = 4
        encoded.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        assert_eq!(
            ChannelReady::decode(&encoded),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    // Test constants are known to fit in u8
    #[allow(clippy::cast_possible_truncation)]
    fn decode_short_channel_id_reject_trailing_bytes() {
        let msg = sample_channel_ready(None);
        let mut encoded = msg.encode();

        // short_channel_id TLV should be 8 bytes, but we push 9 bytes
        encoded.push(TLV_SHORT_CHANNEL_ID as u8);
        encoded.push(0x09);
        encoded.extend_from_slice(&[0xbb; 9]);

        assert_eq!(
            ChannelReady::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_SHORT_CHANNEL_ID,
                expected: 8,
                actual: 9,
            })
        );
    }

    #[test]
    fn default_tlvs_are_none() {
        let tlvs = ChannelReadyTlvs::default();
        assert!(tlvs.short_channel_id.is_none());
    }
}
