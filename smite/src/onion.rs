//! BOLT 4 onion routing (Sphinx) packets.
//!
//! This module implements the construction and decryption of payment onion
//! packets as specified in BOLT 4.

mod keys;
mod payload;
#[cfg(test)]
mod tests;

pub use keys::{HMAC_SIZE, KEY_SIZE, KeyType, apply_stream, derive_key, hmac};
pub use payload::{HopPayload, PaymentData};

use crate::bolt::BoltError;

/// Errors that can occur while constructing or decrypting an onion packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OnionError {
    /// Wire decoding failed (bad length prefix, short packet, invalid key, or
    /// a malformed TLV stream in a hop payload).
    #[error(transparent)]
    Bolt(#[from] BoltError),
}
