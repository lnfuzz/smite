//! BOLT 2 `tx_add_output` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `tx_add_output` message (type 67).
///
/// Sent during interactive transaction construction to propose adding an
/// output to the shared transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAddOutput {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Serial ID for this output. Must be even if sent by the initiator,
    /// odd if sent by the non-initiator (BOLT 2 parity rule).
    pub serial_id: u64,
    /// The value of this output in satoshis.
    pub sats: u64,
    /// The `scriptPubKey` for the output.
    pub script: Vec<u8>,
}

impl TxAddOutput {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.serial_id.write(&mut out);
        self.sats.write(&mut out);
        self.script.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any field.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let serial_id = u64::read(&mut cursor)?;
        let sats = u64::read(&mut cursor)?;
        let script = Vec::<u8>::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            serial_id,
            sats,
            script,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    /// Opener's P2WPKH change `scriptPubKey` from the BOLT 3 dual-funding
    /// test vectors.
    const P2WPKH_SCRIPT: [u8; 22] = [
        0x00, 0x14, 0x1c, 0xa1, 0xcc, 0xa8, 0x85, 0x5b, 0xad, 0x6b, 0xc1, 0xea, 0x54, 0x36, 0xed,
        0xd8, 0xcf, 0xf1, 0x0b, 0x7e, 0x44, 0x8b,
    ];

    /// 2-of-2 funding P2WSH `scriptPubKey` from the BOLT 3 dual-funding test
    /// vectors.
    const P2WSH_SCRIPT: [u8; 34] = [
        0x00, 0x20, 0x29, 0x7b, 0x92, 0xc2, 0x38, 0x16, 0x3e, 0x82, 0x0b, 0x82, 0x48, 0x60, 0x84,
        0x63, 0x4b, 0x48, 0x46, 0xb8, 0x6a, 0x3c, 0x65, 0x8d, 0x87, 0xb9, 0x38, 0x41, 0x92, 0xe6,
        0xbe, 0xa9, 0x8e, 0xc5,
    ];

    fn sample_msg() -> TxAddOutput {
        TxAddOutput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 30,
            sats: 49_999_845,
            script: P2WPKH_SCRIPT.to_vec(),
        }
    }

    #[test]
    fn encode_field_sizes() {
        let encoded = sample_msg().encode();
        // channel_id(32) + serial_id(8) + sats(8) + scriptlen(2) + script(22)
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 8 + 8 + 2 + 22);
        assert_eq!(
            &encoded[CHANNEL_ID_SIZE + 16..CHANNEL_ID_SIZE + 18],
            &[0x00, 0x16]
        );
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = TxAddOutput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_p2wsh_script() {
        // The opener's second output in the BOLT 3 dual-funding vectors.
        let original = TxAddOutput {
            serial_id: 44,
            sats: 400_000_000,
            script: P2WSH_SCRIPT.to_vec(),
            ..sample_msg()
        };
        let encoded = original.encode();
        let decoded = TxAddOutput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// A zero-length script and an out-of-range `sats` are negotiation
    /// failures, not decode failures: the codec must round-trip both so that
    /// they stay reachable as fuzzing inputs.
    #[test]
    fn roundtrip_empty_script_and_max_sats() {
        let original = TxAddOutput {
            sats: u64::MAX,
            script: Vec::new(),
            ..sample_msg()
        };
        let encoded = original.encode();
        let decoded = TxAddOutput::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let original = sample_msg();
        let mut encoded = original.encode();
        encoded.extend_from_slice(&[0xff; 4]);
        assert_eq!(TxAddOutput::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxAddOutput::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_serial_id() {
        assert_eq!(
            TxAddOutput::decode(&[0x00; CHANNEL_ID_SIZE + 4]),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_sats() {
        assert_eq!(
            TxAddOutput::decode(&[0x00; CHANNEL_ID_SIZE + 8 + 3]),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_scriptlen() {
        assert_eq!(
            TxAddOutput::decode(&[0x00; CHANNEL_ID_SIZE + 8 + 8 + 1]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_script() {
        let mut payload = vec![0x00u8; CHANNEL_ID_SIZE + 8 + 8];
        payload.extend_from_slice(&[0x00, 0x16]); // declare 22 bytes
        payload.extend_from_slice(&[0x00; 5]); // only 5 provided
        assert_eq!(
            TxAddOutput::decode(&payload),
            Err(BoltError::Truncated {
                expected: 22,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxAddOutput::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
