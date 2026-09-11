//! BOLT 4 onion routing (Sphinx) packets.
//!
//! This module implements the construction and decryption of payment onion
//! packets as specified in BOLT 4.

mod keys;
#[cfg(test)]
mod tests;

pub use keys::{HMAC_SIZE, KEY_SIZE, KeyType, apply_stream, derive_key, hmac};
