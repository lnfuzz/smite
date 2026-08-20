//! BOLT 2 accept channel message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, PublicNonce};
use super::wire::WireFormat;
use bitcoin::secp256k1::PublicKey;

/// TLV type for upfront shutdown script.
const TLV_UPFRONT_SHUTDOWN_SCRIPT: u64 = 0;

/// TLV type for channel type.
const TLV_CHANNEL_TYPE: u64 = 1;

/// TLV type for the `MuSig2` verification nonce of simple taproot channels.
const TLV_NEXT_LOCAL_NONCE: u64 = 4;

/// BOLT 2 `accept_channel` message (type 33).
///
/// Sent by the channel acceptor in response to `open_channel` to continue the v1 channel
/// establishment flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptChannel {
    /// The same temporary channel ID received from the initiator's `open_channel` message.
    pub temporary_channel_id: ChannelId,
    /// The threshold below which outputs on transactions broadcast by the channel acceptor will be omitted
    pub dust_limit_satoshis: u64,
    /// The maximum total value of inbound HTLCs in flight toward the channel acceptor, in millisatoshis
    pub max_htlc_value_in_flight_msat: u64,
    /// The minimum amount that the counterparty must keep as a direct payment, in satoshis
    pub channel_reserve_satoshis: u64,
    /// The minimum HTLC value the channel acceptor will accept, in millisatoshis
    pub htlc_minimum_msat: u64,
    /// The minimum number of confirmations the counterparty should wait for the funding transaction
    pub minimum_depth: u32,
    /// The number of blocks the counterparty must wait to claim on-chain funds after broadcasting a commitment transaction
    pub to_self_delay: u16,
    /// The maximum number of inbound HTLCs toward the channel acceptor
    pub max_accepted_htlcs: u16,
    /// The channel acceptor's public key for the funding transaction
    pub funding_pubkey: PublicKey,
    /// The basepoint used to derive revocation keys for transactions broadcast by the counterparty
    pub revocation_basepoint: PublicKey,
    /// The basepoint used to derive payment keys for transactions broadcast by the counterparty
    pub payment_basepoint: PublicKey,
    /// The basepoint used to derive delayed payment keys for transactions broadcast by the channel acceptor
    pub delayed_payment_basepoint: PublicKey,
    /// The basepoint used to derive HTLC keys for the channel acceptor
    pub htlc_basepoint: PublicKey,
    /// The first per-commitment point for transactions broadcast by the channel acceptor
    pub first_per_commitment_point: PublicKey,
    /// Optional TLV extensions.
    pub tlvs: AcceptChannelTlvs,
}

/// TLV extensions for the `accept_channel` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptChannelTlvs {
    /// Optionally specifies the scriptPubKey for the channel acceptor's output when cooperatively closing the channel
    pub upfront_shutdown_script: Option<Vec<u8>>,
    /// The channel type represented as feature bits
    pub channel_type: Option<Vec<u8>>,
    /// The `MuSig2` nonce the acceptor will use to verify incoming commitment
    /// signatures. Required for simple taproot channels.
    pub next_local_nonce: Option<PublicNonce>,
}

impl AcceptChannel {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.temporary_channel_id.write(&mut out);
        self.dust_limit_satoshis.write(&mut out);
        self.max_htlc_value_in_flight_msat.write(&mut out);
        self.channel_reserve_satoshis.write(&mut out);
        self.htlc_minimum_msat.write(&mut out);
        self.minimum_depth.write(&mut out);
        self.to_self_delay.write(&mut out);
        self.max_accepted_htlcs.write(&mut out);
        self.funding_pubkey.write(&mut out);
        self.revocation_basepoint.write(&mut out);
        self.payment_basepoint.write(&mut out);
        self.delayed_payment_basepoint.write(&mut out);
        self.htlc_basepoint.write(&mut out);
        self.first_per_commitment_point.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(upfront_shutdown_script) = &self.tlvs.upfront_shutdown_script {
            tlv_stream.add(TLV_UPFRONT_SHUTDOWN_SCRIPT, upfront_shutdown_script.clone());
        }
        if let Some(channel_type) = &self.tlvs.channel_type {
            tlv_stream.add(TLV_CHANNEL_TYPE, channel_type.clone());
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
    /// Returns `Truncated` if the payload is too short for any fixed field or `InvalidPublicKey`
    /// if any of the public key fields are invalid
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let temporary_channel_id = WireFormat::read(&mut cursor)?;
        let dust_limit_satoshis = WireFormat::read(&mut cursor)?;
        let max_htlc_value_in_flight_msat = WireFormat::read(&mut cursor)?;
        let channel_reserve_satoshis = WireFormat::read(&mut cursor)?;
        let htlc_minimum_msat = WireFormat::read(&mut cursor)?;
        let minimum_depth = WireFormat::read(&mut cursor)?;
        let to_self_delay = WireFormat::read(&mut cursor)?;
        let max_accepted_htlcs = WireFormat::read(&mut cursor)?;
        let funding_pubkey = WireFormat::read(&mut cursor)?;
        let revocation_basepoint = WireFormat::read(&mut cursor)?;
        let payment_basepoint = WireFormat::read(&mut cursor)?;
        let delayed_payment_basepoint = WireFormat::read(&mut cursor)?;
        let htlc_basepoint = WireFormat::read(&mut cursor)?;
        let first_per_commitment_point = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // Types 0 (`upfront_shutdown_script`) and 4 (`next_local_nonce`) are
        // even types defined by BOLT 2 and the simple taproot channels
        // extension, so we must whitelist them as known.
        let tlv_stream = TlvStream::decode_with_known(
            cursor,
            &[TLV_UPFRONT_SHUTDOWN_SCRIPT, TLV_NEXT_LOCAL_NONCE],
        )?;
        let tlvs = AcceptChannelTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            temporary_channel_id,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            minimum_depth,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            tlvs,
        })
    }
}

impl AcceptChannelTlvs {
    /// Extracts accept channel TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if the `next_local_nonce` TLV has an invalid
    /// length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let upfront_shutdown_script = stream.get(TLV_UPFRONT_SHUTDOWN_SCRIPT).map(Vec::from);
        let channel_type = stream.get(TLV_CHANNEL_TYPE).map(Vec::from);
        let next_local_nonce = stream.get_as::<PublicNonce>(TLV_NEXT_LOCAL_NONCE)?;

        Ok(Self {
            upfront_shutdown_script,
            channel_type,
            next_local_nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PUBLIC_KEY_SIZE, PUBLIC_NONCE_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `AcceptChannel` message for testing.
    fn sample_accept_channel(tlvs: Option<AcceptChannelTlvs>) -> AcceptChannel {
        let secp = Secp256k1::new();
        let secrets: [[u8; 32]; 6] = [
            [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32],
        ];
        let keys: Vec<PublicKey> = secrets
            .iter()
            .map(|s| {
                let sk = SecretKey::from_slice(s).expect("valid secret");
                PublicKey::from_secret_key(&secp, &sk)
            })
            .collect();

        AcceptChannel {
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 3,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: keys[0],
            revocation_basepoint: keys[1],
            payment_basepoint: keys[2],
            delayed_payment_basepoint: keys[3],
            htlc_basepoint: keys[4],
            first_per_commitment_point: keys[5],
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let accept = sample_accept_channel(None);
        let encoded = accept.encode();
        // 32 + 8*4 + 4 + 2 + 2 + 33*6 = 270
        assert_eq!(encoded.len(), 270);
    }

    #[test]
    fn roundtrip() {
        let original = sample_accept_channel(None);
        let encoded = original.encode();
        let decoded = AcceptChannel::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_temporary_channel_id() {
        assert_eq!(
            AcceptChannel::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: 32,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_scalars() {
        // Enough for temporary_channel_id(32) but not
        // dust_limit_satoshis(8).
        let data = [0x00; 32];
        assert_eq!(
            AcceptChannel::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_truncated_minimum_depth() {
        // temporary_channel_id(32) + 4 u64s(32) = 64 bytes
        // minimum_depth needs 4, only give 2
        let data = [0x00; 66];
        assert_eq!(
            AcceptChannel::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_to_self_delay() {
        // temporary_channel_id(32) + 4 u64s(32) + minimum_depth(4) = 68
        // to_self_delay needs 2, only give 1
        let data = [0x00; 69];
        assert_eq!(
            AcceptChannel::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    /// Offset of the first public key field (`funding_pubkey`) in the wire
    /// encoding: 32 + 8×4 + 4 + 2 + 2 = 72 bytes of scalar fields.
    const FIRST_PUBKEY_OFFSET: usize = 72;

    #[test]
    fn decode_truncated_funding_pubkey() {
        // Provide all scalar fields (72 bytes) but only 10 bytes into
        // funding_pubkey (needs 33).
        let data = [0x00; FIRST_PUBKEY_OFFSET + 10];
        assert_eq!(
            AcceptChannel::decode(&data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_truncated_revocation_basepoint() {
        // All scalar fields(72) + funding_pubkey(33) + 15 bytes into
        // revocation_basepoint (needs 33).
        let accept = sample_accept_channel(None);
        let encoded = accept.encode();
        let data = &encoded[..120]; // 72 + 33 + 15
        assert_eq!(
            AcceptChannel::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 15
            })
        );
    }

    #[test]
    fn decode_truncated_first_per_commitment_point() {
        // All scalar fields(72) + 5 pubkeys(165) + 20 bytes into
        // first_per_commitment_point (needs 33).
        let accept = sample_accept_channel(None);
        let encoded = accept.encode();
        let data = &encoded[..257]; // 72 + 165 + 20
        assert_eq!(
            AcceptChannel::decode(data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_invalid_funding_pubkey() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        let offset = FIRST_PUBKEY_OFFSET; // first pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            AcceptChannel::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_revocation_basepoint() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE; // second pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            AcceptChannel::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_payment_basepoint() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 2; // third pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            AcceptChannel::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_delayed_payment_basepoint() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 3; // fourth pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            AcceptChannel::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_htlc_basepoint() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 4; // fifth pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            AcceptChannel::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn decode_invalid_first_per_commitment_point() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        let offset = FIRST_PUBKEY_OFFSET + PUBLIC_KEY_SIZE * 5; // sixth pubkey
        let bad_key = [0x00; PUBLIC_KEY_SIZE];
        encoded[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&bad_key);

        assert_eq!(
            AcceptChannel::decode(&encoded),
            Err(BoltError::InvalidPublicKey(bad_key))
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let original = sample_accept_channel(Some(AcceptChannelTlvs {
            upfront_shutdown_script: Some(vec![0xab; 22]),
            channel_type: Some(vec![0x01, 0x02]),
            next_local_nonce: Some(PublicNonce([0xcd; PUBLIC_NONCE_SIZE])),
        }));

        let encoded = original.encode();
        let decoded = AcceptChannel::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_with_channel_type() {
        let accept = sample_accept_channel(Some(AcceptChannelTlvs {
            channel_type: Some(vec![0x01, 0x02]),
            ..Default::default()
        }));

        let encoded = accept.encode();
        // 270 fixed + TLV: type(1) + len(1) + value(2) = 4
        assert_eq!(encoded.len(), 270 + 4);

        let decoded = AcceptChannel::decode(&encoded).unwrap();
        assert_eq!(decoded.tlvs.channel_type, Some(vec![0x01, 0x02]));
    }

    #[test]
    fn encode_with_both_tlvs() {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0xab; 20]);
        let accept = sample_accept_channel(Some(AcceptChannelTlvs {
            // P2WPKH like script
            upfront_shutdown_script: Some(script),
            channel_type: Some(vec![0x01]),
            ..Default::default()
        }));

        let encoded = accept.encode();
        // 270 fixed
        // + TLV type 0: type(1) + len(1) + value(22) = 24
        // + TLV type 1: type(1) + len(1) + value(1) = 3
        assert_eq!(encoded.len(), 270 + 24 + 3);
    }

    #[test]
    fn decode_empty_tlv_values() {
        // Empty upfront_shutdown_script
        let accept = sample_accept_channel(Some(AcceptChannelTlvs {
            upfront_shutdown_script: Some(vec![]),
            ..Default::default()
        }));
        let decoded = AcceptChannel::decode(&accept.encode()).unwrap();
        assert_eq!(decoded.tlvs.upfront_shutdown_script, Some(vec![]));
        assert_eq!(decoded.tlvs.channel_type, None);

        // Empty channel_type
        let accept = sample_accept_channel(Some(AcceptChannelTlvs {
            channel_type: Some(vec![]),
            ..Default::default()
        }));
        let decoded = AcceptChannel::decode(&accept.encode()).unwrap();
        assert_eq!(decoded.tlvs.channel_type, Some(vec![]));
        assert_eq!(decoded.tlvs.upfront_shutdown_script, None);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let accept = sample_accept_channel(None);
        let mut encoded = accept.encode();

        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);

        let decoded = AcceptChannel::decode(&encoded).unwrap();
        assert!(decoded.tlvs.upfront_shutdown_script.is_none());
        assert!(decoded.tlvs.channel_type.is_none());
    }

    #[test]
    fn default_tlvs_are_none() {
        let tlvs = AcceptChannelTlvs::default();
        assert!(tlvs.upfront_shutdown_script.is_none());
        assert!(tlvs.channel_type.is_none());
        assert!(tlvs.next_local_nonce.is_none());
    }

    /// Simple taproot channels require the acceptor's `MuSig2` verification
    /// nonce in TLV type 4.
    #[test]
    fn encode_with_next_local_nonce() {
        let accept = sample_accept_channel(Some(AcceptChannelTlvs {
            next_local_nonce: Some(PublicNonce([0xcd; PUBLIC_NONCE_SIZE])),
            ..Default::default()
        }));

        let encoded = accept.encode();
        // 270 fixed + TLV: type(1) + len(1) + value(66) = 68
        assert_eq!(encoded.len(), 270 + 68);

        let decoded = AcceptChannel::decode(&encoded).unwrap();
        assert_eq!(
            decoded.tlvs.next_local_nonce,
            Some(PublicNonce([0xcd; PUBLIC_NONCE_SIZE]))
        );
    }
}
