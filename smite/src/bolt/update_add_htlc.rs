//! BOLT 2 `update_add_htlc` message.

use crate::onion::PAYMENT_ONION_PACKET_SIZE;

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, SHA256_HASH_SIZE};
use super::wire::WireFormat;
use bitcoin::secp256k1::PublicKey;

/// TLV type for the blinded path.
const TLV_BLINDED_PATH: u64 = 0;

/// BOLT 2 `update_add_htlc` message (type 128).
///
/// Offers a new HTLC to the peer, identified by `payment_hash`, and carries the
/// onion packet needed to forward the payment along its route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAddHtlc {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The HTLC ID.
    pub id: u64,
    /// The HTLC amount in millisatoshis.
    pub amount_msat: u64,
    /// The payment hash, the pre-image of which controls HTLC redemption.
    pub payment_hash: [u8; SHA256_HASH_SIZE],
    /// The expiry height of the HTLC.
    pub cltv_expiry: u32,
    /// The onion routing packet with encrypted data for the next hop.
    pub onion_routing_packet: [u8; PAYMENT_ONION_PACKET_SIZE],
    /// Optional TLV extensions.
    pub tlvs: UpdateAddHtlcTlvs,
}

/// TLV extensions for the `update_add_htlc` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateAddHtlcTlvs {
    /// Ephemeral blinding point for decrypting the onion packet and encrypted
    /// payload when relaying or receiving an HTLC over a blinded path.
    pub blinded_path: Option<PublicKey>,
}

impl UpdateAddHtlc {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.id.write(&mut out);
        self.amount_msat.write(&mut out);
        self.payment_hash.write(&mut out);
        self.cltv_expiry.write(&mut out);
        self.onion_routing_packet.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(blinded_path) = &self.tlvs.blinded_path {
            let mut value = Vec::new();
            blinded_path.write(&mut value);
            tlv_stream.add(TLV_BLINDED_PATH, value);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, or
    /// TLV errors if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let id = WireFormat::read(&mut cursor)?;
        let amount_msat = WireFormat::read(&mut cursor)?;
        let payment_hash = WireFormat::read(&mut cursor)?;
        let cltv_expiry = WireFormat::read(&mut cursor)?;
        let onion_routing_packet = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // Type 0 (`blinded_path`) is an even type defined by BOLT 2,
        // so we must whitelist it as known.
        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_BLINDED_PATH])?;
        let tlvs = UpdateAddHtlcTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            id,
            amount_msat,
            payment_hash,
            cltv_expiry,
            onion_routing_packet,
            tlvs,
        })
    }
}

impl UpdateAddHtlcTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if `blinded_path` has invalid length or is not a
    /// valid public key.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let blinded_path = stream.get_as::<PublicKey>(TLV_BLINDED_PATH)?;
        Ok(Self { blinded_path })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, PUBLIC_KEY_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `UpdateAddHtlc` message for testing.
    fn sample_update_add_htlc(tlvs: Option<UpdateAddHtlcTlvs>) -> UpdateAddHtlc {
        UpdateAddHtlc {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            id: 42,
            amount_msat: 1_000_000,
            payment_hash: [0x00; SHA256_HASH_SIZE],
            cltv_expiry: 500,
            onion_routing_packet: [0xbb; PAYMENT_ONION_PACKET_SIZE],
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let encoded = sample_update_add_htlc(None).encode();
        // channel_id(32) + id(8) + amount_msat(8) + payment_hash(32)
        // + cltv_expiry(4) + onion_routing_packet(1366) = 1450
        assert_eq!(encoded.len(), 1450);
    }

    #[test]
    fn roundtrip() {
        let original = sample_update_add_htlc(None);
        let encoded = original.encode();
        let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            UpdateAddHtlc::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_id() {
        // channel_id(32) + 4 bytes into id
        let data = vec![0x00; 36];
        assert_eq!(
            UpdateAddHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_amount_msat() {
        // channel_id(32) + id(8) + 3 bytes into amount_msat
        let data = vec![0x00; 43];
        assert_eq!(
            UpdateAddHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_payment_hash() {
        // channel_id(32) + id(8) + amount_msat(8) + 16 bytes into payment_hash
        let data = vec![0x00; 64];
        assert_eq!(
            UpdateAddHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: SHA256_HASH_SIZE,
                actual: 16
            })
        );
    }

    #[test]
    fn decode_truncated_cltv_expiry() {
        // channel_id(32) + id(8) + amount_msat(8) + payment_hash(32) + 2 bytes
        // into cltv_expiry
        let data = vec![0x00; 82];
        assert_eq!(
            UpdateAddHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_onion_routing_packet() {
        // channel_id(32) + id(8) + amount_msat(8) + payment_hash(32) + cltv_expiry(4)
        // + 1300 bytes into onion_routing_packet
        let data = vec![0x00; 1384];
        assert_eq!(
            UpdateAddHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: PAYMENT_ONION_PACKET_SIZE,
                actual: 1300
            })
        );
    }

    fn sample_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let original = sample_update_add_htlc(Some(UpdateAddHtlcTlvs {
            blinded_path: Some(sample_pubkey()),
        }));

        let encoded = original.encode();
        let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_with_blinded_path() {
        let msg = sample_update_add_htlc(Some(UpdateAddHtlcTlvs {
            blinded_path: Some(sample_pubkey()),
        }));

        let encoded = msg.encode();
        // 1450 fixed + TLV: type(1) + len(1) + value(33) = 35
        assert_eq!(encoded.len(), 1450 + 35);

        let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
        assert_eq!(decoded.tlvs.blinded_path, Some(sample_pubkey()));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_truncated_blinded_path() {
        let msg = sample_update_add_htlc(None);
        let mut encoded = msg.encode();

        // Append blinded_path TLV with only 32 bytes (need 33)
        encoded.push(TLV_BLINDED_PATH as u8); // type = 0
        encoded.push(0x20); // length = 32
        encoded.extend_from_slice(&[0x00; 32]);
        assert_eq!(
            UpdateAddHtlc::decode(&encoded),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 32
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_invalid_blinded_path() {
        let msg = sample_update_add_htlc(None);
        let mut encoded = msg.encode();

        // Append blinded_path TLV with an all-zero (invalid) key.
        encoded.push(TLV_BLINDED_PATH as u8); // type = 0
        encoded.push(0x21); // length = 33
        encoded.extend_from_slice(&[0x00; PUBLIC_KEY_SIZE]);
        assert_eq!(
            UpdateAddHtlc::decode(&encoded),
            Err(BoltError::InvalidPublicKey([0x00; PUBLIC_KEY_SIZE]))
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_blinded_path_reject_trailing_bytes() {
        let msg = sample_update_add_htlc(None);
        let mut encoded = msg.encode();

        // blinded_path TLV should be 33 bytes compressed public key, but we
        // push 34 bytes
        encoded.push(TLV_BLINDED_PATH as u8); // type = 0
        encoded.push(0x22); // length = 34
        encoded.extend_from_slice(&sample_pubkey().serialize());
        encoded.push(0x00);

        assert_eq!(
            UpdateAddHtlc::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_BLINDED_PATH,
                expected: PUBLIC_KEY_SIZE,
                actual: 34,
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let msg = sample_update_add_htlc(None);
        let mut encoded = msg.encode();

        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);

        let decoded = UpdateAddHtlc::decode(&encoded).unwrap();
        assert!(decoded.tlvs.blinded_path.is_none());
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let msg = sample_update_add_htlc(None);
        let mut encoded = msg.encode();

        // Append an unknown even TLV: type 2, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x02, 0x02, 0xaa, 0xbb]);

        assert_eq!(
            UpdateAddHtlc::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        );
    }

    #[test]
    fn decode_default_empty_tlv_values() {
        let tlvs = UpdateAddHtlcTlvs::default();
        assert!(tlvs.blinded_path.is_none());

        let msg = sample_update_add_htlc(Some(tlvs));
        let decoded = UpdateAddHtlc::decode(&msg.encode()).unwrap();
        assert!(decoded.tlvs.blinded_path.is_none());
    }
}
