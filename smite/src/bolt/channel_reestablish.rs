//! BOLT 2 `channel_reestablish` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, PER_COMMITMENT_SECRET_SIZE};
use super::wire::WireFormat;
use bitcoin::Txid;
use bitcoin::secp256k1::PublicKey;

/// TLV type for the next funding transaction.
const TLV_NEXT_FUNDING: u64 = 1;

/// TLV type for the sender's current locked funding transaction.
const TLV_MY_CURRENT_FUNDING_LOCKED: u64 = 5;

/// BOLT 2 `channel_reestablish` message (type 136).
///
/// Sent by each peer for every channel upon reconnection to determine which
/// messages were lost and need to be retransmitted to resynchronize state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReestablish {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The commitment number of the next `commitment_signed` the sender expects
    /// to receive.
    pub next_commitment_number: u64,
    /// The commitment number of the next `revoke_and_ack` the sender expects
    /// to receive.
    pub next_revocation_number: u64,
    /// The last `per_commitment_secret` the sender received from the recipient,
    /// or all zeroes if none.
    pub your_last_per_commitment_secret: [u8; PER_COMMITMENT_SECRET_SIZE],
    /// The per-commitment point of the sender's current (unrevoked) commitment
    /// transaction.
    pub my_current_per_commitment_point: PublicKey,
    /// Optional TLV extensions.
    pub tlvs: ChannelReestablishTlvs,
}

/// TLV extensions for the `channel_reestablish` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChannelReestablishTlvs {
    /// Interactive funding transaction the sender has sent `commitment_signed`
    /// for but has not received `tx_signatures`.
    pub next_funding: Option<NextFunding>,
    /// Funding transaction of the sender's last `splice_locked`, or of its
    /// `channel_ready` if no splice has locked.
    pub my_current_funding_locked: Option<MyCurrentFundingLocked>,
}

/// An interactive funding transaction awaiting `tx_signatures` and the messages
/// to retransmit for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextFunding {
    /// The Txid of the interactive transaction awaiting `tx_signatures`.
    pub next_funding_txid: Txid,

    /// The messages the receiver must retransmit for `next_funding_txid`.
    ///
    /// Bit 0: `commitment_signed`, set if the sender has not received it.
    pub retransmit_flags: u8,
}

impl WireFormat for NextFunding {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let next_funding_txid = WireFormat::read(data)?;
        let retransmit_flags = WireFormat::read(data)?;
        Ok(Self {
            next_funding_txid,
            retransmit_flags,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.next_funding_txid.write(out);
        self.retransmit_flags.write(out);
    }
}

/// A locked funding transaction and the messages to retransmit for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MyCurrentFundingLocked {
    /// The Txid of the sender's last `splice_locked` or `channel_ready`.
    pub my_current_funding_locked_txid: Txid,

    /// The messages the sender expects the receiver to retransmit.
    ///
    /// Bit 0: `announcement_signatures`, set only for announced channels where
    /// the sender has not received it for this transaction.
    pub retransmit_flags: u8,
}

impl WireFormat for MyCurrentFundingLocked {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let my_current_funding_locked_txid = WireFormat::read(data)?;
        let retransmit_flags = WireFormat::read(data)?;
        Ok(Self {
            my_current_funding_locked_txid,
            retransmit_flags,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.my_current_funding_locked_txid.write(out);
        self.retransmit_flags.write(out);
    }
}

impl ChannelReestablish {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.next_commitment_number.write(&mut out);
        self.next_revocation_number.write(&mut out);
        self.your_last_per_commitment_secret.write(&mut out);
        self.my_current_per_commitment_point.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(next_funding) = &self.tlvs.next_funding {
            let mut value = Vec::new();
            next_funding.write(&mut value);
            tlv_stream.add(TLV_NEXT_FUNDING, value);
        }
        if let Some(funding_locked) = &self.tlvs.my_current_funding_locked {
            let mut value = Vec::new();
            funding_locked.write(&mut value);
            tlv_stream.add(TLV_MY_CURRENT_FUNDING_LOCKED, value);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field,
    /// `InvalidPublicKey` if the public key field is invalid, or TLV errors if
    /// the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let next_commitment_number = WireFormat::read(&mut cursor)?;
        let next_revocation_number = WireFormat::read(&mut cursor)?;
        let your_last_per_commitment_secret = WireFormat::read(&mut cursor)?;
        let my_current_per_commitment_point = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = ChannelReestablishTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            next_commitment_number,
            next_revocation_number,
            your_last_per_commitment_secret,
            my_current_per_commitment_point,
            tlvs,
        })
    }
}

impl ChannelReestablishTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if a TLV value has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let next_funding = stream.get_as::<NextFunding>(TLV_NEXT_FUNDING)?;
        let my_current_funding_locked =
            stream.get_as::<MyCurrentFundingLocked>(TLV_MY_CURRENT_FUNDING_LOCKED)?;
        Ok(Self {
            next_funding,
            my_current_funding_locked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, PUBLIC_KEY_SIZE, TXID_SIZE};
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `ChannelReestablish` message for testing.
    fn sample_channel_reestablish(tlvs: Option<ChannelReestablishTlvs>) -> ChannelReestablish {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        ChannelReestablish {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            next_commitment_number: 5,
            next_revocation_number: 4,
            your_last_per_commitment_secret: [0xcd; PER_COMMITMENT_SECRET_SIZE],
            my_current_per_commitment_point: pk,
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    fn sample_next_funding() -> NextFunding {
        NextFunding {
            next_funding_txid: Txid::from_byte_array([0xbb; TXID_SIZE]),
            retransmit_flags: 0x01,
        }
    }

    fn sample_my_current_funding_locked() -> MyCurrentFundingLocked {
        MyCurrentFundingLocked {
            my_current_funding_locked_txid: Txid::from_byte_array([0xcc; TXID_SIZE]),
            retransmit_flags: 0x01,
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let encoded = sample_channel_reestablish(None).encode();
        // channel_id(32) + next_commitment_number(8)
        // + next_revocation_number(8) + your_last_per_commitment_secret(32)
        // + my_current_per_commitment_point(33) = 113
        assert_eq!(encoded.len(), 113);
    }

    #[test]
    fn roundtrip() {
        let original = sample_channel_reestablish(None);
        let encoded = original.encode();
        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            ChannelReestablish::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_next_commitment_number() {
        // channel_id(32) + 3 bytes into next_commitment_number
        let data = [0x00; 35];
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn decode_truncated_next_revocation_number() {
        // channel_id(32) + next_commitment_number(8)
        // + 5 bytes into next_revocation_number
        let data = [0x00; 45];
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 5
            })
        );
    }

    #[test]
    fn decode_truncated_your_last_per_commitment_secret() {
        // channel_id(32) + next_commitment_number(8) + next_revocation_number(8)
        // + 16 bytes into your_last_per_commitment_secret
        let data = [0x00; 64];
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: PER_COMMITMENT_SECRET_SIZE,
                actual: 16
            })
        );
    }

    #[test]
    fn decode_truncated_my_current_per_commitment_point() {
        // channel_id(32) + next_commitment_number(8) + next_revocation_number(8)
        // + your_last_per_commitment_secret(32)
        // + 10 bytes into my_current_per_commitment_point
        let data = [0x00; 90];
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_invalid_my_current_per_commitment_point() {
        // Full-length payload (113 bytes) with an all-zero (invalid) public key.
        let data = [0x00; 113];
        assert_eq!(
            ChannelReestablish::decode(&data),
            Err(BoltError::InvalidPublicKey([0x00; PUBLIC_KEY_SIZE]))
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let original = sample_channel_reestablish(Some(ChannelReestablishTlvs {
            next_funding: Some(sample_next_funding()),
            my_current_funding_locked: Some(sample_my_current_funding_locked()),
        }));

        let encoded = original.encode();
        // 113 fixed
        // + TLV: type(1) + len(1) + txid(32) + retransmit_flags(1) = 35
        // + TLV: type(1) + len(1) + txid(32) + retransmit_flags(1) = 35
        assert_eq!(encoded.len(), 113 + 35 + 35);

        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_with_next_funding() {
        let msg = sample_channel_reestablish(Some(ChannelReestablishTlvs {
            next_funding: Some(sample_next_funding()),
            my_current_funding_locked: None,
        }));

        let encoded = msg.encode();
        // 113 fixed + TLV: type(1) + len(1) + txid(32) + retransmit_flags(1) = 35
        assert_eq!(encoded.len(), 113 + 35);

        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert_eq!(decoded.tlvs.next_funding, Some(sample_next_funding()));
        assert!(decoded.tlvs.my_current_funding_locked.is_none());
    }

    #[test]
    fn encode_with_my_current_funding_locked() {
        let msg = sample_channel_reestablish(Some(ChannelReestablishTlvs {
            next_funding: None,
            my_current_funding_locked: Some(sample_my_current_funding_locked()),
        }));

        let encoded = msg.encode();
        // 113 fixed + TLV: type(1) + len(1) + txid(32) + retransmit_flags(1) = 35
        assert_eq!(encoded.len(), 113 + 35);

        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert!(decoded.tlvs.next_funding.is_none());
        assert_eq!(
            decoded.tlvs.my_current_funding_locked,
            Some(sample_my_current_funding_locked())
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_truncated_next_funding_txid() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // next_funding TLV with only 31 bytes (need 33)
        encoded.push(TLV_NEXT_FUNDING as u8); // type = 1
        encoded.push(0x1f); // length = 31
        encoded.extend_from_slice(&[0x00; 31]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 31
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_truncated_next_funding_retransmit_flags() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // next_funding TLV with the txid but no retransmit_flags byte
        encoded.push(TLV_NEXT_FUNDING as u8); // type = 1
        encoded.push(0x20); // length = 32
        encoded.extend_from_slice(&[0x00; 32]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_next_funding_reject_trailing_bytes() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // next_funding TLV should be 33 bytes, but we push 34 bytes
        encoded.push(TLV_NEXT_FUNDING as u8); // type = 1
        encoded.push(0x22); // length = 34
        encoded.extend_from_slice(&[0x00; 34]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_NEXT_FUNDING,
                expected: 33,
                actual: 34,
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_truncated_my_current_funding_locked_txid() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // my_current_funding_locked TLV with only 31 bytes (need 33)
        encoded.push(TLV_MY_CURRENT_FUNDING_LOCKED as u8); // type = 5
        encoded.push(0x1f); // length = 31
        encoded.extend_from_slice(&[0x00; 31]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 31
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_truncated_my_current_funding_locked_retransmit_flags() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // my_current_funding_locked TLV with the txid but no retransmit_flags byte
        encoded.push(TLV_MY_CURRENT_FUNDING_LOCKED as u8); // type = 5
        encoded.push(0x20); // length = 32
        encoded.extend_from_slice(&[0x00; 32]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_my_current_funding_locked_reject_trailing_bytes() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // my_current_funding_locked TLV should be 33 bytes, but we push 34 bytes
        encoded.push(TLV_MY_CURRENT_FUNDING_LOCKED as u8); // type = 5
        encoded.push(0x22); // length = 34
        encoded.extend_from_slice(&[0x00; 34]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_MY_CURRENT_FUNDING_LOCKED,
                expected: 33,
                actual: 34,
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_tlvs_not_increasing_rejected() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // my_current_funding_locked (type 5) followed by next_funding (type 1)
        encoded.push(TLV_MY_CURRENT_FUNDING_LOCKED as u8); // type = 5
        encoded.push(0x21); // length = 33
        encoded.extend_from_slice(&[0x00; 33]);
        encoded.push(TLV_NEXT_FUNDING as u8); // type = 1
        encoded.push(0x21); // length = 33
        encoded.extend_from_slice(&[0x00; 33]);
        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::TlvNotIncreasing {
                previous: 5,
                current: 1
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);

        let decoded = ChannelReestablish::decode(&encoded).unwrap();
        assert!(decoded.tlvs.next_funding.is_none());
        assert!(decoded.tlvs.my_current_funding_locked.is_none());
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let msg = sample_channel_reestablish(None);
        let mut encoded = msg.encode();

        // Append an unknown even TLV: type 2, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x02, 0x02, 0xaa, 0xbb]);

        assert_eq!(
            ChannelReestablish::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        );
    }

    #[test]
    fn decode_default_empty_tlv_values() {
        let tlvs = ChannelReestablishTlvs::default();
        assert!(tlvs.next_funding.is_none());
        assert!(tlvs.my_current_funding_locked.is_none());

        let msg = sample_channel_reestablish(Some(tlvs));
        let decoded = ChannelReestablish::decode(&msg.encode()).unwrap();
        assert!(decoded.tlvs.next_funding.is_none());
        assert!(decoded.tlvs.my_current_funding_locked.is_none());
    }
}
