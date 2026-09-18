//! BOLT 2 `stfu` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `stfu` message (type 2).
///
/// Sent by either peer to quiesce a channel before a protocol that requires
/// no pending updates.  Requires `option_quiesce`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stfu {
    /// The channel to quiesce.
    pub channel_id: ChannelId,
    /// 1 when initiating quiescence, 0 when replying to a peer's `stfu`.
    pub initiator: u8,
}

impl Stfu {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.initiator.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let initiator = u8::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            initiator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = Stfu {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            initiator: 1,
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 1);
        assert_eq!(encoded[CHANNEL_ID_SIZE], 1);
    }

    #[test]
    fn roundtrip() {
        for initiator in [0, 1, 0xff] {
            let original = Stfu {
                channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
                initiator,
            };
            let encoded = original.encode();
            let decoded = Stfu::decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            Stfu::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_missing_initiator() {
        assert_eq!(
            Stfu::decode(&[0x00; CHANNEL_ID_SIZE]),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            Stfu::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let mut data = vec![0xff; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x01, 0xaa, 0xbb]);
        let decoded = Stfu::decode(&data).unwrap();
        assert_eq!(decoded.channel_id, ChannelId::new([0xff; CHANNEL_ID_SIZE]));
        assert_eq!(decoded.initiator, 1);
    }
}
