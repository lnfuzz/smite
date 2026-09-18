//! BOLT 4 onion routing (Sphinx) packets.
//!
//! This module implements the construction and decryption of payment onion
//! packets as specified in BOLT 4. [`OnionBuilder`] wraps a route into a
//! packet, and [`peel`] unwraps a single layer.

mod keys;
mod packet;
mod payload;
#[cfg(test)]
mod tests;

pub use keys::{KEY_SIZE, KeyType, apply_stream, derive_key, hmac};
pub use packet::{
    BuiltOnion, HMAC_SIZE, Hop, ONION_VERSION, OnionBuilder, OnionPacket,
    PAYMENT_HOP_PAYLOADS_SIZE, PAYMENT_ONION_PACKET_SIZE, Peeled, derive_shared_secrets, peel,
};
pub use payload::{HopPayload, PaymentData};

use crate::bolt::BoltError;

/// Errors that can occur while constructing or decrypting an onion packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OnionError {
    /// The route contains no hops.
    #[error("NO_HOPS")]
    NoHops,
    /// The hop payloads do not fit in the fixed-size `hop_payloads` field.
    #[error("PAYLOADS_TOO_LONG needed {needed} capacity {capacity}")]
    PayloadsTooLong { needed: u64, capacity: u64 },
    /// The `version` byte is not 0.
    #[error("INVALID_VERSION {0}")]
    InvalidVersion(u8),
    /// The packet HMAC does not match the one computed from the shared secret.
    #[error("HMAC_MISMATCH")]
    HmacMismatch,
    /// The declared payload length is below the 2-byte minimum (0 and 1 are
    /// reserved by BOLT 4).
    #[error("PAYLOAD_TOO_SHORT {0}")]
    PayloadTooShort(u64),
    /// Blinding a key produced an invalid (zero or out-of-range) result.
    ///
    /// Only reachable with maliciously chosen keys; the probability of hitting
    /// it with honest randomness is negligible.
    #[error("KEY_BLINDING_FAILED")]
    KeyBlindingFailed,
    /// Wire decoding failed (bad length prefix, short packet, invalid key, or
    /// a malformed TLV stream in a hop payload).
    #[error(transparent)]
    Bolt(#[from] BoltError),
}
