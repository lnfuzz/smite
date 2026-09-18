//! BOLT 4 per-hop `payload` TLV stream.

use bitcoin::secp256k1::PublicKey;

use super::OnionError;
use crate::bolt::{BoltError, SHA256_HASH_SIZE, ShortChannelId, TlvStream, Tu32, Tu64, WireFormat};

/// TLV type of `amt_to_forward`.
const TLV_AMT_TO_FORWARD: u64 = 2;
/// TLV type of `outgoing_cltv_value`.
const TLV_OUTGOING_CLTV_VALUE: u64 = 4;
/// TLV type of `short_channel_id`.
const TLV_SHORT_CHANNEL_ID: u64 = 6;
/// TLV type of `payment_data`.
const TLV_PAYMENT_DATA: u64 = 8;
/// TLV type of `encrypted_recipient_data`.
const TLV_ENCRYPTED_RECIPIENT_DATA: u64 = 10;
/// TLV type of `current_path_key`.
const TLV_CURRENT_PATH_KEY: u64 = 12;
/// TLV type of `payment_metadata`.
const TLV_PAYMENT_METADATA: u64 = 16;
/// TLV type of `total_amount_msat`.
const TLV_TOTAL_AMOUNT_MSAT: u64 = 18;

/// Even TLV types defined for the payload, which a reader must not reject.
const KNOWN_EVEN: &[u64] = &[
    TLV_AMT_TO_FORWARD,
    TLV_OUTGOING_CLTV_VALUE,
    TLV_SHORT_CHANNEL_ID,
    TLV_PAYMENT_DATA,
    TLV_ENCRYPTED_RECIPIENT_DATA,
    TLV_CURRENT_PATH_KEY,
    TLV_PAYMENT_METADATA,
    TLV_TOTAL_AMOUNT_MSAT,
];

/// The `payment_data` record: the payment secret and the total amount of a
/// (possibly multi-part) payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PaymentData {
    /// The payment secret from the invoice.
    pub payment_secret: [u8; SHA256_HASH_SIZE],
    /// Total amount of the payment across all parts, in millisatoshi.
    pub total_msat: u64,
}

impl WireFormat for PaymentData {
    /// Reads the secret followed by a `tu64` filling the remaining bytes.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the secret is incomplete, or a truncated-integer
    /// error if `total_msat` is malformed.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let payment_secret: [u8; SHA256_HASH_SIZE] = WireFormat::read(data)?;
        let total_msat = Tu64::read(data)?;
        Ok(Self {
            payment_secret,
            total_msat: total_msat.0,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.payment_secret.write(out);
        Tu64(self.total_msat).write(out);
    }
}

/// A BOLT 4 per-hop payload.
///
/// Every field is optional and independent, so combinations the spec forbids
/// (a forwarding hop carrying `payment_data`, a final hop carrying a
/// `short_channel_id`, a payload with nothing in it at all) are expressible on
/// purpose. Use [`forward`](Self::forward) and [`receive`](Self::receive) for
/// the two well-formed shapes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HopPayload {
    /// Amount to forward to the next hop, in millisatoshi (type 2).
    pub amt_to_forward: Option<u64>,
    /// CLTV expiry of the outgoing HTLC (type 4).
    pub outgoing_cltv_value: Option<u32>,
    /// Channel to forward over (type 6).
    pub short_channel_id: Option<ShortChannelId>,
    /// Payment secret and total amount (type 8).
    pub payment_data: Option<PaymentData>,
    /// Recipient-encrypted blob for a blinded path (type 10).
    pub encrypted_recipient_data: Option<Vec<u8>>,
    /// Path key of the blinded path this hop belongs to (type 12).
    pub current_path_key: Option<PublicKey>,
    /// Opaque metadata for the recipient (type 16).
    pub payment_metadata: Option<Vec<u8>>,
    /// Total amount of a blinded multi-part payment (type 18).
    pub total_amount_msat: Option<u64>,
}

impl HopPayload {
    /// A payload instructing an intermediate hop to forward over `scid`.
    #[must_use]
    pub fn forward(
        short_channel_id: ShortChannelId,
        amt_to_forward: u64,
        outgoing_cltv_value: u32,
    ) -> Self {
        Self {
            amt_to_forward: Some(amt_to_forward),
            outgoing_cltv_value: Some(outgoing_cltv_value),
            short_channel_id: Some(short_channel_id),
            ..Self::default()
        }
    }

    /// A payload for the final node of a payment.
    #[must_use]
    pub fn receive(
        amt_to_forward: u64,
        outgoing_cltv_value: u32,
        payment_secret: [u8; SHA256_HASH_SIZE],
        total_msat: u64,
    ) -> Self {
        Self {
            amt_to_forward: Some(amt_to_forward),
            outgoing_cltv_value: Some(outgoing_cltv_value),
            payment_data: Some(PaymentData {
                payment_secret,
                total_msat,
            }),
            ..Self::default()
        }
    }

    /// Encodes the payload as a TLV stream, without the `bigsize` length
    /// prefix that [`OnionBuilder`](super::OnionBuilder) adds.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = TlvStream::new();

        if let Some(amt) = self.amt_to_forward {
            let mut value = Vec::new();
            Tu64(amt).write(&mut value);
            stream.add(TLV_AMT_TO_FORWARD, value);
        }
        if let Some(cltv) = self.outgoing_cltv_value {
            let mut value = Vec::new();
            Tu32(cltv).write(&mut value);
            stream.add(TLV_OUTGOING_CLTV_VALUE, value);
        }
        if let Some(scid) = self.short_channel_id {
            let mut value = Vec::new();
            scid.write(&mut value);
            stream.add(TLV_SHORT_CHANNEL_ID, value);
        }
        if let Some(payment_data) = self.payment_data {
            let mut value = Vec::new();
            payment_data.write(&mut value);
            stream.add(TLV_PAYMENT_DATA, value);
        }
        if let Some(data) = &self.encrypted_recipient_data {
            stream.add(TLV_ENCRYPTED_RECIPIENT_DATA, data.clone());
        }
        if let Some(path_key) = self.current_path_key {
            let mut value = Vec::new();
            path_key.write(&mut value);
            stream.add(TLV_CURRENT_PATH_KEY, value);
        }
        if let Some(metadata) = &self.payment_metadata {
            stream.add(TLV_PAYMENT_METADATA, metadata.clone());
        }
        if let Some(total) = self.total_amount_msat {
            let mut value = Vec::new();
            Tu64(total).write(&mut value);
            stream.add(TLV_TOTAL_AMOUNT_MSAT, value);
        }

        stream.encode()
    }

    /// Decodes a payload from a TLV stream.
    ///
    /// # Errors
    ///
    /// Returns [`OnionError::Bolt`] if the stream is malformed, contains an
    /// unknown even type, or a known record has an invalid value.
    pub fn decode(data: &[u8]) -> Result<Self, OnionError> {
        let stream = TlvStream::decode_with_known(data, KNOWN_EVEN)?;

        Ok(Self {
            amt_to_forward: stream.get_as::<Tu64>(TLV_AMT_TO_FORWARD)?.map(|v| v.0),
            outgoing_cltv_value: stream.get_as::<Tu32>(TLV_OUTGOING_CLTV_VALUE)?.map(|v| v.0),
            short_channel_id: stream.get_as(TLV_SHORT_CHANNEL_ID)?,
            payment_data: stream.get_as(TLV_PAYMENT_DATA)?,
            encrypted_recipient_data: stream.get(TLV_ENCRYPTED_RECIPIENT_DATA).map(<[u8]>::to_vec),
            current_path_key: stream.get_as(TLV_CURRENT_PATH_KEY)?,
            payment_metadata: stream.get(TLV_PAYMENT_METADATA).map(<[u8]>::to_vec),
            total_amount_msat: stream.get_as::<Tu64>(TLV_TOTAL_AMOUNT_MSAT)?.map(|v| v.0),
        })
    }
}
