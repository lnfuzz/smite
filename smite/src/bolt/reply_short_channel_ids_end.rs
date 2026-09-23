//! BOLT 7 `reply_short_channel_ids_end` message.

use super::BoltError;
use super::types::CHAIN_HASH_SIZE;
use super::wire::WireFormat;

/// BOLT 7 `reply_short_channel_ids_end` message (type 262).
///
/// Terminates the gossip a peer sends in answer to a
/// `query_short_channel_ids`, so the querier does not have to rely on a
/// timeout to know the reply is complete.
///
/// Wire layout (per [BOLT 7]):
///
/// ```text
/// [chain_hash:32]
/// [byte:full_information]
/// ```
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-query_short_channel_ids-and-reply_short_channel_ids_end-messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyShortChannelIdsEnd {
    /// The 32-byte hash that uniquely identifies the chain being replied for.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Whether the sender maintains up-to-date channel information for
    /// `chain_hash`.
    ///
    /// BOLT 7 defines 0 (the sender does not, so look elsewhere) and 1 (it
    /// does); we don't enforce that, to allow fuzzing with arbitrary data.
    pub full_information: u8,
}

impl ReplyShortChannelIdsEnd {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.full_information.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// BOLT 7 defines no `tlv_stream` for this message, so trailing bytes are
    /// ignored rather than parsed as TLVs.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let full_information = WireFormat::read(&mut cursor)?;
        Ok(Self {
            chain_hash,
            full_information,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_msg() -> ReplyShortChannelIdsEnd {
        ReplyShortChannelIdsEnd {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            full_information: 0x01,
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = ReplyShortChannelIdsEnd::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_fixed_field_size() {
        assert_eq!(sample_msg().encode().len(), CHAIN_HASH_SIZE + 1);
    }

    #[test]
    fn encode_field_order() {
        let encoded = sample_msg().encode();
        assert_eq!(encoded[..CHAIN_HASH_SIZE], [0xaa; CHAIN_HASH_SIZE]);
        assert_eq!(encoded[CHAIN_HASH_SIZE], 0x01);
    }

    #[test]
    fn decode_truncated_chain_hash() {
        assert_eq!(
            ReplyShortChannelIdsEnd::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHAIN_HASH_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_full_information() {
        assert_eq!(
            ReplyShortChannelIdsEnd::decode(&[0xaa; CHAIN_HASH_SIZE]),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            ReplyShortChannelIdsEnd::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHAIN_HASH_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let mut encoded = sample_msg().encode();
        encoded.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let decoded = ReplyShortChannelIdsEnd::decode(&encoded).unwrap();
        assert_eq!(decoded, sample_msg());
    }

    #[test]
    fn decode_preserves_out_of_range_full_information() {
        let mut msg = sample_msg();
        msg.full_information = 0xff;
        let encoded = msg.encode();
        let decoded = ReplyShortChannelIdsEnd::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }
}
