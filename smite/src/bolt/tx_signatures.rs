//! BOLT 2 `tx_signatures` message.

use bitcoin::Txid;
use bitcoin::secp256k1::ecdsa::Signature;

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// TLV type for the shared input signature.
const TLV_SHARED_INPUT_SIGNATURE: u64 = 0;

/// BOLT 2 `tx_signatures` message (type 71).
///
/// Sent once interactive transaction construction has completed, carrying the
/// sender's witnesses for the inputs it contributed to the shared transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSignatures {
    /// The channel this message pertains to.
    pub channel_id: ChannelId,
    /// Transaction ID of the shared transaction being signed.
    pub txid: Txid,
    /// One entry per input added by the sender, ordered by that input's
    /// `serial_id`.
    ///
    /// Each entry is bitcoin-wire-encoded witness data: a `CompactSize`
    /// element count, then each element as a `CompactSize` length followed by
    /// that many bytes.
    pub witnesses: Vec<Vec<u8>>,
    /// Optional TLV extensions.
    pub tlvs: TxSignaturesTlvs,
}

/// TLV extensions for the `tx_signatures` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxSignaturesTlvs {
    /// Signature for the shared input, when one is being spent (splicing).
    pub shared_input_signature: Option<Signature>,
}

impl TxSignaturesTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if `shared_input_signature` has invalid length or
    /// is not a canonical compact ECDSA signature.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let shared_input_signature = stream.get_as::<Signature>(TLV_SHARED_INPUT_SIGNATURE)?;
        Ok(Self {
            shared_input_signature,
        })
    }
}

impl TxSignatures {
    /// Encodes to wire format (without message type prefix).
    ///
    /// # Panics
    ///
    /// Panics if the number of witnesses exceeds `u16::MAX`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.txid.write(&mut out);
        u16::try_from(self.witnesses.len())
            .expect("number of witnesses must not exceed u16::MAX")
            .write(&mut out);
        for witness in &self.witnesses {
            witness.write(&mut out);
        }

        let mut tlv_stream = TlvStream::new();
        if let Some(signature) = &self.tlvs.shared_input_signature {
            tlv_stream.add(
                TLV_SHARED_INPUT_SIGNATURE,
                signature.serialize_compact().to_vec(),
            );
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any field,
    /// `InvalidSignature` if `shared_input_signature` is not a valid compact
    /// ECDSA signature, or a TLV error if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let txid = WireFormat::read(&mut cursor)?;
        let num_witnesses = u16::read(&mut cursor)?;
        let mut witnesses = Vec::with_capacity(num_witnesses.into());
        for _ in 0..num_witnesses {
            witnesses.push(Vec::<u8>::read(&mut cursor)?);
        }

        let tlv_stream = TlvStream::decode_with_known(cursor, &[TLV_SHARED_INPUT_SIGNATURE])?;
        let tlvs = TxSignaturesTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            txid,
            witnesses,
            tlvs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, TXID_SIZE};
    use super::*;
    use bitcoin::secp256k1::hashes::Hash;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Offset of `num_witnesses` within the encoded payload.
    const NUM_WITNESSES_OFFSET: usize = CHANNEL_ID_SIZE + TXID_SIZE;

    fn sample_msg() -> TxSignatures {
        TxSignatures {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            txid: Txid::from_byte_array([0xcd; TXID_SIZE]),
            witnesses: vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0x01, 0x02]],
            tlvs: TxSignaturesTlvs::default(),
        }
    }

    fn sample_signature() -> Signature {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let msg = Message::from_digest([0xaa; 32]);
        secp.sign_ecdsa(&msg, &sk)
    }

    /// Dual-funding test vectors from BOLT 3, "Appendix G: Dual Funded
    /// Transaction Test Vectors". `channel_id` is unspecified there, so the
    /// sample value is used. `txid` is given in display order; the wire
    /// encoding is its reverse, which is what `Txid` writes.
    #[test]
    fn encode_bolt3_dual_funding_vectors() {
        const TXID_DISPLAY: &str =
            "5ca4e657c1aa9d069ea4a5d712045d233a7d7c52738cb02993637289e6386057";
        let opener_witness = "022068656c6c6f2074686572652c2074686973206973206120626974636f6e21212127\
             82012088a820add57dfe5277079d069ca4ad4893c96de91f88ffb981fdc6a2a34d5336c66aff87";
        let accepter_witness = "0247304402207de9ba56bb9f641372e805782575ee840a899e61021c8b1572b3ec1d5b5950e90220\
             69e9ba998915dae193d3c25cb89b5e64370e6a3a7755e7f31cf6d7cbc2a49f6d0121034695f5b786\
             4c580bf11f9f8cb1a94eb336f2ce9ef872d2ae1a90ee276c772484";

        let mut txid_bytes: [u8; TXID_SIZE] =
            hex::decode(TXID_DISPLAY).unwrap().try_into().unwrap();
        txid_bytes.reverse();
        let txid = Txid::from_byte_array(txid_bytes);
        assert_eq!(txid.to_string(), TXID_DISPLAY);

        // (witness hex, declared `len`, expected payload hex)
        let cases = [
            (
                opener_witness,
                74,
                "abababababababababababababababababababababababababababababababab\
                 576038e68972639329b08c73527c7d3a235d0412d7a5a49e069daac157e6a45c0001004a",
            ),
            (
                accepter_witness,
                107,
                "abababababababababababababababababababababababababababababababab\
                 576038e68972639329b08c73527c7d3a235d0412d7a5a49e069daac157e6a45c0001006b",
            ),
        ];

        for (witness_hex, len, prefix_hex) in cases {
            let witness = hex::decode(witness_hex).unwrap();
            assert_eq!(witness.len(), len, "witness `len` field");

            let msg = TxSignatures {
                channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
                txid,
                witnesses: vec![witness],
                tlvs: TxSignaturesTlvs::default(),
            };

            let encoded = msg.encode();
            assert_eq!(hex::encode(&encoded), prefix_hex.to_owned() + witness_hex);
            assert_eq!(TxSignatures::decode(&encoded).unwrap(), msg);
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        // channel_id(32) + txid(32) + num_witnesses(2) + (2+4) + (2+2) = 76
        assert_eq!(encoded.len(), 76);
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_shared_input_signature() {
        let mut original = sample_msg();
        original.tlvs.shared_input_signature = Some(sample_signature());
        let encoded = original.encode();
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// A witness count of zero is a negotiation failure, not a parse failure.
    #[test]
    fn roundtrip_zero_witnesses() {
        let original = TxSignatures {
            witnesses: vec![],
            ..sample_msg()
        };
        let encoded = original.encode();
        assert_eq!(encoded.len(), NUM_WITNESSES_OFFSET + 2);
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// An empty witness is a negotiation failure, not a parse failure.
    #[test]
    fn roundtrip_empty_witness() {
        let original = TxSignatures {
            witnesses: vec![vec![]],
            ..sample_msg()
        };
        let encoded = original.encode();
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(decoded.witnesses, vec![Vec::<u8>::new()]);
        assert_eq!(original, decoded);
    }

    #[test]
    #[should_panic(expected = "number of witnesses must not exceed u16::MAX")]
    fn encode_panics_on_oversized_witnesses() {
        let msg = TxSignatures {
            witnesses: vec![vec![0x00]; usize::from(u16::MAX) + 1],
            ..sample_msg()
        };
        let _ = msg.encode();
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxSignatures::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0,
            })
        );
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxSignatures::decode(&[0x00; 5]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 5,
            })
        );
    }

    #[test]
    fn decode_truncated_txid() {
        assert_eq!(
            TxSignatures::decode(&[0x00; CHANNEL_ID_SIZE + 20]),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 20,
            })
        );
    }

    #[test]
    fn decode_truncated_num_witnesses() {
        assert_eq!(
            TxSignatures::decode(&[0x00; NUM_WITNESSES_OFFSET + 1]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_witness_len() {
        // num_witnesses = 1, then a single byte of the 2-byte witness length.
        let mut payload = vec![0x00u8; NUM_WITNESSES_OFFSET];
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.push(0x00);
        assert_eq!(
            TxSignatures::decode(&payload),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_witness_data() {
        // num_witnesses = 1, witness declares 10 bytes but only 3 are present.
        let mut payload = vec![0x00u8; NUM_WITNESSES_OFFSET];
        payload.extend_from_slice(&[0x00, 0x01]);
        payload.extend_from_slice(&[0x00, 0x0a]);
        payload.extend_from_slice(&[0x00; 3]);
        assert_eq!(
            TxSignatures::decode(&payload),
            Err(BoltError::Truncated {
                expected: 10,
                actual: 3,
            })
        );
    }

    #[test]
    fn decode_missing_witness() {
        // num_witnesses claims 2, but only the first witness is present.
        let encoded = sample_msg().encode();
        let cutoff = NUM_WITNESSES_OFFSET + 2 + 2 + 4;
        assert_eq!(
            TxSignatures::decode(&encoded[..cutoff]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 0,
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let original = sample_msg();
        let mut encoded = original.encode();
        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);
        let decoded = TxSignatures::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let mut encoded = sample_msg().encode();
        // Append unknown even TLV: type 2, length 1, value [0xff]
        encoded.extend_from_slice(&[0x02, 0x01, 0xff]);
        assert_eq!(
            TxSignatures::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        );
    }

    #[test]
    fn decode_wrong_length_shared_input_signature() {
        let mut encoded = sample_msg().encode();
        // Append TLV type 0 with only 32 bytes instead of 64.
        encoded.push(0x00); // type 0
        encoded.push(0x20); // length 32
        encoded.extend_from_slice(&[0xaa; 32]);
        assert_eq!(
            TxSignatures::decode(&encoded),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 32,
            })
        );
    }

    #[test]
    fn decode_invalid_shared_input_signature() {
        let mut encoded = sample_msg().encode();
        // r and s are both above the curve order.
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded.push(0x00); // type 0
        encoded.push(0x40); // length 64
        encoded.extend_from_slice(&bad_sig);
        assert_eq!(
            TxSignatures::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }
}
