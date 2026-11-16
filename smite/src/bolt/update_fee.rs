//! BOLT 2 `update_fee` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `update_fee` message (type 134).
///
/// Sent by the node paying the Bitcoin fee to update the commitment feerate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFee {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The new commitment feerate in satoshis per 1000 weight.
    pub feerate_per_kw: u32,
}

impl UpdateFee {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.feerate_per_kw.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let feerate_per_kw = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            feerate_per_kw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    /// Valid `UpdateFee` message for testing.
    fn sample_update_fee() -> UpdateFee {
        UpdateFee {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            feerate_per_kw: 2500,
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = sample_update_fee();
        let encoded = msg.encode();
        // channel_id(32) + feerate_per_kw(4) = 36
        assert_eq!(encoded.len(), 36);
    }

    #[test]
    fn roundtrip() {
        let original = sample_update_fee();
        let encoded = original.encode();
        let decoded = UpdateFee::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            UpdateFee::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_feerate_per_kw() {
        // channel_id(32) + 2 bytes into feerate_per_kw
        let data = [0x00; 34];
        assert_eq!(
            UpdateFee::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }
}
