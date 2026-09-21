//! BOLT 7 `query_short_channel_ids` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::CHAIN_HASH_SIZE;
use super::wire::WireFormat;

/// TLV type for the `query_flags` record.
const TLV_QUERY_FLAGS: u64 = 1;

/// BOLT 7 `query_short_channel_ids` message (type 261).
///
/// Asks a peer for the `channel_announcement` and `channel_update`s of a set
/// of channels, identified by their `short_channel_id`s. The peer answers with
/// the requested gossip followed by a `reply_short_channel_ids_end`.
///
/// Wire layout (per [BOLT 7]):
///
/// ```text
/// [chain_hash:32]
/// [u16:len]
/// [len*byte:encoded_short_ids]
/// [query_short_channel_ids_tlvs:tlvs]
/// ```
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-query_short_channel_ids-and-reply_short_channel_ids_end-messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryShortChannelIds {
    /// The 32-byte hash that uniquely identifies the chain the ids refer to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// The queried `short_channel_id`s, still in their wire encoding.
    ///
    /// The first byte is the `encoding_type`: 0 is an ascending array of
    /// 8-byte ids, and 1 was zlib, which BOLT 7 now says MUST NOT be used.
    /// The codec keeps the bytes as sent so that any encoding type survives a
    /// decode/encode roundtrip, and leaves judging them to an oracle.
    pub encoded_short_ids: Vec<u8>,
    /// Optional TLV extensions.
    pub tlvs: QueryShortChannelIdsTlvs,
}

/// TLV extensions for the `query_short_channel_ids` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryShortChannelIdsTlvs {
    /// One query flag per queried `short_channel_id` (TLV type 1).
    ///
    /// The first byte is the `encoding_type`, as for `encoded_short_ids`, and
    /// the rest is `encoded_query_flags`: one minimally-encoded `bigsize` per
    /// id, selecting which of the channel's gossip messages the sender wants.
    /// Kept as raw bytes for the same reason as `encoded_short_ids`.
    //
    // Note: the flags are variable-width bigsizes, so `TlvStream::get_as_many`
    // cannot be used here -- it infers one chunk size from the first element.
    pub query_flags: Option<Vec<u8>>,
}

impl QueryShortChannelIds {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.encoded_short_ids.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(query_flags) = &self.tlvs.query_flags {
            tlv_stream.add(TLV_QUERY_FLAGS, query_flags.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short, or TLV errors if the
    /// TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let encoded_short_ids = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes). `query_flags` is odd, so no even type
        // is known here.
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = QueryShortChannelIdsTlvs::from_stream(&tlv_stream);

        Ok(Self {
            chain_hash,
            encoded_short_ids,
            tlvs,
        })
    }
}

impl QueryShortChannelIdsTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    fn from_stream(stream: &TlvStream) -> Self {
        Self {
            query_flags: stream.get(TLV_QUERY_FLAGS).map(<[u8]>::to_vec),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `encoded_short_ids` holding two ids under encoding type 0.
    fn sample_encoded_short_ids() -> Vec<u8> {
        let mut ids = vec![0x00];
        ids.extend_from_slice(&[0x00, 0x08, 0x3b, 0x04, 0x00, 0x03, 0x4d, 0x00]);
        ids.extend_from_slice(&[0x00, 0x08, 0x3b, 0x05, 0x00, 0x01, 0x9a, 0x01]);
        ids
    }

    fn sample_msg() -> QueryShortChannelIds {
        QueryShortChannelIds {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            encoded_short_ids: sample_encoded_short_ids(),
            tlvs: QueryShortChannelIdsTlvs::default(),
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_query_flags() {
        let mut msg = sample_msg();
        // encoding type 0, then one minimally-encoded bigsize flag per id
        msg.tlvs.query_flags = Some(vec![0x00, 0x01, 0x1f]);
        let encoded = msg.encode();
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_with_empty_encoded_short_ids() {
        let mut msg = sample_msg();
        msg.encoded_short_ids = Vec::new();
        let encoded = msg.encode();
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn encode_field_order() {
        let encoded = sample_msg().encode();
        assert_eq!(encoded.len(), CHAIN_HASH_SIZE + 2 + 17);
        assert_eq!(encoded[..CHAIN_HASH_SIZE], [0xaa; CHAIN_HASH_SIZE]);
        assert_eq!(encoded[32..34], 17u16.to_be_bytes());
        assert_eq!(encoded[34..51], sample_encoded_short_ids()[..]);
    }

    #[test]
    fn decode_truncated_chain_hash() {
        assert_eq!(
            QueryShortChannelIds::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHAIN_HASH_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_encoded_short_ids_len() {
        let data = [0xaa; CHAIN_HASH_SIZE + 1];
        assert_eq!(
            QueryShortChannelIds::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_encoded_short_ids_data() {
        let mut data = vec![0xaa; CHAIN_HASH_SIZE];
        // len claims 17 bytes, only 5 follow
        data.extend_from_slice(&17u16.to_be_bytes());
        data.extend_from_slice(&[0x00; 5]);
        assert_eq!(
            QueryShortChannelIds::decode(&data),
            Err(BoltError::Truncated {
                expected: 17,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            QueryShortChannelIds::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHAIN_HASH_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_preserves_zlib_encoding_type() {
        let mut msg = sample_msg();
        // Encoding type 1 (zlib) MUST NOT be sent, but a target may still send
        // it, so it has to survive a roundtrip rather than fail to decode.
        msg.encoded_short_ids = vec![0x01, 0x78, 0x9c, 0xff];
        let encoded = msg.encode();
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_preserves_unknown_encoding_type() {
        let mut msg = sample_msg();
        msg.encoded_short_ids = vec![0xff, 0x11, 0x22];
        let encoded = msg.encode();
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_preserves_partial_short_channel_id() {
        let mut msg = sample_msg();
        // Not a whole number of ids: encoding byte plus 3 trailing bytes.
        msg.encoded_short_ids = vec![0x00, 0x01, 0x02, 0x03];
        let encoded = msg.encode();
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let mut encoded = sample_msg().encode();
        // Append an unknown odd TLV (type 3, len 2, value 0xffff)
        encoded.extend_from_slice(&[0x03, 0x02, 0xff, 0xff]);
        let decoded = QueryShortChannelIds::decode(&encoded).unwrap();
        assert_eq!(decoded.encoded_short_ids, sample_encoded_short_ids());
        assert_eq!(decoded.tlvs.query_flags, None);
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let mut encoded = sample_msg().encode();
        // Append an unknown even TLV (type 4, len 1, value 0x00)
        encoded.extend_from_slice(&[0x04, 0x01, 0x00]);
        assert_eq!(
            QueryShortChannelIds::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(4))
        );
    }

    #[test]
    fn default_tlvs_are_none() {
        assert_eq!(QueryShortChannelIdsTlvs::default().query_flags, None);
    }

    #[test]
    #[should_panic(expected = "exceeds maximum size")]
    fn encode_panics_on_oversized_encoded_short_ids() {
        let mut msg = sample_msg();
        msg.encoded_short_ids = vec![0x00; usize::from(u16::MAX) + 1];
        let _ = msg.encode();
    }
}
