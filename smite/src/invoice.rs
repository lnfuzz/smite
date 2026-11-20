//! BOLT 11 invoice decoding.
//!
//! [`Invoice::decode`] extracts the `payment_hash` and `payment_secret` needed
//! to pay a target's any-amount regtest invoice. Other fields are skipped.

use bitcoin::bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bitcoin::bech32::{Bech32, Checksum, Fe32, Fe32IterExt};

use crate::bolt::SHA256_HASH_SIZE;

/// Human-readable part of a regtest invoice without an amount.
const REGTEST_HRP: &str = "lnbcrt";

/// Number of 5-bit field elements in the 35-bit `timestamp`.
const TIMESTAMP_LEN: usize = 7;
/// Number of 5-bit field elements in the 520-bit `signature`.
const SIGNATURE_LEN: usize = 104;
/// Number of 5-bit field elements in a 256-bit `p` or `s` field.
const HASH_LEN: usize = 52;
/// Number of 5-bit field elements in a tagged field's tag and length.
const FIELD_HEADER_LEN: usize = 3;

/// Tagged field `p` (1): `payment_hash`.
const TAG_PAYMENT_HASH: u8 = 1;
/// Tagged field `s` (16): `payment_secret`.
const TAG_PAYMENT_SECRET: u8 = 16;

/// Errors that can occur while decoding an invoice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvoiceError {
    /// The string is not valid bech32.
    #[error("BECH32 {0}")]
    Bech32(#[from] CheckedHrpstringError),
    /// The human-readable part is not `lnbcrt`, so the invoice is for another
    /// chain or carries an amount.
    #[error("UNEXPECTED_HRP {0}")]
    UnexpectedHrp(String),
    /// The data part has no room for the timestamp and signature.
    #[error("DATA_TOO_SHORT {0}")]
    DataTooShort(usize),
    /// A tagged field's header or data runs past the end of the data part.
    #[error("FIELD_TRUNCATED {0}")]
    FieldTruncated(char),
    /// A `p` or `s` field is not 52 field elements (256 bits) long.
    #[error("INVALID_FIELD_LENGTH {tag} expected {HASH_LEN} got {actual}")]
    InvalidFieldLength { tag: char, actual: usize },
    /// The `p` or `s` field appears more than once.
    #[error("DUPLICATE_FIELD {0}")]
    DuplicateField(char),
    /// The `p` or `s` field is missing.
    #[error("MISSING_FIELD {0}")]
    MissingField(char),
}

/// The fields of a decoded invoice needed to pay it with an `update_add_htlc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invoice {
    /// Payment hash (`p`).
    pub payment_hash: [u8; SHA256_HASH_SIZE],
    /// Payment secret for the onion's `payment_data` (`s`).
    pub payment_secret: [u8; SHA256_HASH_SIZE],
}

impl Invoice {
    /// Decodes a BOLT 11 invoice string.
    ///
    /// # Errors
    ///
    /// Returns an [`InvoiceError`] if the string is not a bech32 `lnbcrt`
    /// invoice without an amount, a decoded field is malformed, or `p` or `s`
    /// is missing or repeated.
    pub fn decode(invoice: &str) -> Result<Self, InvoiceError> {
        let parsed = CheckedHrpstring::new::<Bolt11Bech32>(invoice)?;
        let hrp = parsed.hrp().to_lowercase();
        if hrp != REGTEST_HRP {
            return Err(InvoiceError::UnexpectedHrp(hrp));
        }
        Self::from_data(&parsed)
    }

    /// Extracts the payment hash and secret from a checksum-verified invoice,
    /// ignoring its human-readable part.
    fn from_data(parsed: &CheckedHrpstring) -> Result<Self, InvoiceError> {
        // Access the unpacked 5-bit values. The type argument is required by
        // the API but unused.
        let data: Vec<Fe32> = parsed.fe32_iter::<std::iter::Empty<u8>>().collect();
        if data.len() < TIMESTAMP_LEN + SIGNATURE_LEN {
            return Err(InvoiceError::DataTooShort(data.len()));
        }
        // Tagged fields sit between the timestamp and the signature.
        let mut cursor = &data[TIMESTAMP_LEN..data.len() - SIGNATURE_LEN];

        let mut payment_hash = None;
        let mut payment_secret = None;

        while !cursor.is_empty() {
            // Decode the 5-bit tag and the 10-bit big-endian length
            let tag = cursor[0];
            if cursor.len() < FIELD_HEADER_LEN {
                return Err(InvoiceError::FieldTruncated(tag.to_char()));
            }
            let length = usize::from(cursor[1].to_u8()) << 5 | usize::from(cursor[2].to_u8());

            // Check we have enough field elements for the data
            let end = FIELD_HEADER_LEN + length;
            if cursor.len() < end {
                return Err(InvoiceError::FieldTruncated(tag.to_char()));
            }
            let field = &cursor[FIELD_HEADER_LEN..end];
            cursor = &cursor[end..];

            match tag.to_u8() {
                TAG_PAYMENT_HASH => {
                    if payment_hash.is_some() {
                        return Err(InvoiceError::DuplicateField(tag.to_char()));
                    }
                    payment_hash = Some(read_hash(tag, field)?);
                }
                TAG_PAYMENT_SECRET => {
                    if payment_secret.is_some() {
                        return Err(InvoiceError::DuplicateField(tag.to_char()));
                    }
                    payment_secret = Some(read_hash(tag, field)?);
                }
                _ => {}
            }
        }

        Ok(Self {
            payment_hash: payment_hash.ok_or(InvoiceError::MissingField('p'))?,
            payment_secret: payment_secret.ok_or(InvoiceError::MissingField('s'))?,
        })
    }
}

/// The [`Bech32`] checksum algorithm, with extended max length suitable for
/// BOLT 11 invoices.
enum Bolt11Bech32 {}

impl Checksum for Bolt11Bech32 {
    /// Extend the max length from the 1023 characters default.
    const CODE_LENGTH: usize = usize::MAX;

    // Inherit the other fields from `Bech32`.
    type MidstateRepr = <Bech32 as Checksum>::MidstateRepr;
    const CHECKSUM_LENGTH: usize = Bech32::CHECKSUM_LENGTH;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = Bech32::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = Bech32::TARGET_RESIDUE;
}

/// Reads a 256-bit `p` or `s` field, dropping its 4 padding bits.
fn read_hash(tag: Fe32, data: &[Fe32]) -> Result<[u8; SHA256_HASH_SIZE], InvoiceError> {
    if data.len() != HASH_LEN {
        return Err(InvoiceError::InvalidFieldLength {
            tag: tag.to_char(),
            actual: data.len(),
        });
    }
    let bytes: Vec<u8> = data.iter().copied().fes_to_bytes().collect();
    Ok(bytes.try_into().expect("52 field elements hold 32 bytes"))
}

#[cfg(test)]
mod tests;
