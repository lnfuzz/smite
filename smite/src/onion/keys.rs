//! BOLT 4 shared secrets, key derivation and pseudo-random byte streams.

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// Size of a key and HMAC in bytes.
pub const KEY_SIZE: usize = 32;

/// The BOLT 4 key types derived from a shared secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Keys the pseudo-random stream that obfuscates `hop_payloads`.
    Rho,
    /// Keys the packet HMAC.
    Mu,
    /// Keys the HMAC of a returned error message.
    Um,
    /// Keys the pseudo-random filler the packet is initialized with.
    Pad,
    /// Keys the pseudo-random stream that obfuscates a returned error.
    Ammag,
    /// Keys the pseudo-random stream that obfuscates the `attribution_data`
    /// accompanying a returned error.
    Ammagext,
}

impl KeyType {
    /// Returns the key type's label, used as the HMAC key during derivation.
    ///
    /// The labels carry no `0x00` terminator.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Rho => b"rho",
            Self::Mu => b"mu",
            Self::Um => b"um",
            Self::Pad => b"pad",
            Self::Ammag => b"ammag",
            Self::Ammagext => b"ammagext",
        }
    }
}

/// Derives a BOLT 4 key from a 32-byte secret.
///
/// For every key type but [`KeyType::Pad`] the secret is a hop's shared
/// secret; for `Pad` it is the session key.
#[must_use]
pub fn derive_key(key_type: KeyType, secret: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    hmac(key_type.label(), &[secret])
}

/// Computes `HMAC-SHA256(key, parts...)`.
#[must_use]
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; KEY_SIZE] {
    let mut engine = HmacEngine::<Sha256>::new(key);
    for part in parts {
        engine.input(part);
    }
    Hmac::from_engine(engine).to_byte_array()
}

/// XORs `buf` in place with the `ChaCha20` pseudo-random stream for `key`.
///
/// The nonce is the fixed 96-bit zero nonce mandated by BOLT 4, which is safe
/// because every key is derived from a single-use shared secret. Applying the
/// stream to a zeroed buffer yields the raw stream.
pub fn apply_stream(key: &[u8; KEY_SIZE], buf: &mut [u8]) {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(key.into(), &nonce.into());
    cipher.apply_keystream(buf);
}
