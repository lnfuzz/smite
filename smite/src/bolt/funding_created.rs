//! BOLT 2 funding created message.

use super::types::TemporaryChannelId;
use super::wire::WireFormat;
use super::{BoltError, MalformableField};
use bitcoin::Txid;
use bitcoin::secp256k1::ecdsa::Signature;

/// BOLT 2 `funding_created` message (type 34).
///
/// Sent by the channel initiator after receiving `accept_channel` to provide the
/// funding transaction outpoint and the channel initiator's signature for the
/// counterparty's first commitment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingCreated {
    /// A temporary channel ID used until the funding outpoint is announced
    pub temporary_channel_id: TemporaryChannelId,
    /// The transaction ID of the funding transaction
    pub funding_txid: Txid,
    /// The specific output index funding this channel
    pub funding_output_index: u16,
    /// The channel initiator's signature for the counterparty's first commitment transaction
    pub signature: Signature,
}

impl FundingCreated {
    /// Fields whose encoded bytes may be overwritten before sending: the
    /// outpoint is derived from the constructed funding transaction and the
    /// signature is computed, so neither is reachable through an IR parameter.
    /// See [`MalformableField`].
    pub const FUNDING_TXID_FIELD: MalformableField = MalformableField {
        name: "funding_txid",
        offset: 34,
        len: 32,
    };
    pub const FUNDING_OUTPUT_INDEX_FIELD: MalformableField = MalformableField {
        name: "funding_output_index",
        offset: 66,
        len: 2,
    };
    pub const SIGNATURE_FIELD: MalformableField = MalformableField {
        name: "signature",
        offset: 68,
        len: 64,
    };
    pub const MALFORMABLE_FIELDS: &'static [MalformableField] = &[
        Self::FUNDING_TXID_FIELD,
        Self::FUNDING_OUTPUT_INDEX_FIELD,
        Self::SIGNATURE_FIELD,
    ];

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.temporary_channel_id.write(&mut out);
        self.funding_txid.write(&mut out);
        self.funding_output_index.write(&mut out);
        self.signature.write(&mut out);
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

        let temporary_channel_id = WireFormat::read(&mut cursor)?;
        let funding_txid = WireFormat::read(&mut cursor)?;
        let funding_output_index = WireFormat::read(&mut cursor)?;
        let signature = WireFormat::read(&mut cursor)?;

        Ok(Self {
            temporary_channel_id,
            funding_txid,
            funding_output_index,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, TXID_SIZE};
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `FundingCreated` message for testing.
    fn sample_funding_created() -> FundingCreated {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingCreated {
            temporary_channel_id: TemporaryChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            funding_txid: Txid::from_byte_array([0xcc; TXID_SIZE]),
            funding_output_index: 0,
            signature: sig,
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_funding_created();
        let encoded = msg.encode();
        // 32 + 32 + 2 + 64 = 130
        assert_eq!(encoded.len(), 130);
    }

    #[test]
    fn roundtrip() {
        let original = sample_funding_created();
        let encoded = original.encode();
        let decoded = FundingCreated::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_temporary_channel_id() {
        assert_eq!(
            FundingCreated::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_funding_txid() {
        // temporary_channel_id(32) + 10 bytes into funding_txid
        let data = [0x00; 42];
        assert_eq!(
            FundingCreated::decode(&data),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_funding_output_index() {
        // temporary_channel_id(32) + funding_txid(32) = 64
        // funding_output_index needs 2, only give 1
        let data = [0x00; 65];
        assert_eq!(
            FundingCreated::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_signature() {
        // temporary_channel_id(32) + funding_txid(32) + funding_output_index(2) = 66
        // signature needs 64, only give 30
        let msg = sample_funding_created();
        let encoded = msg.encode();
        let data = &encoded[..96]; // 66 + 30
        assert_eq!(
            FundingCreated::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 30
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let msg = sample_funding_created();
        let mut encoded = msg.encode();

        // Overwrite the signature (last 64 bytes) with r and s both > curve order
        let sig_offset = encoded.len() - COMPACT_SIGNATURE_SIZE;
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[sig_offset..].copy_from_slice(&bad_sig);

        assert_eq!(
            FundingCreated::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn malformable_field_offsets_match_encoding() {
        let msg = sample_funding_created();
        let encoded = crate::bolt::Message::FundingCreated(msg.clone()).encode();

        let encoded_field = |name: &str| {
            let f = FundingCreated::MALFORMABLE_FIELDS
                .iter()
                .find(|f| f.name == name)
                .expect("field is allowlisted");
            &encoded[f.offset as usize..(f.offset + f.len) as usize]
        };

        assert_eq!(
            encoded_field("funding_txid"),
            msg.funding_txid.to_byte_array()
        );
        assert_eq!(
            encoded_field("funding_output_index"),
            msg.funding_output_index.to_be_bytes()
        );
        assert_eq!(
            encoded_field("signature"),
            msg.signature.serialize_compact()
        );
    }
}
