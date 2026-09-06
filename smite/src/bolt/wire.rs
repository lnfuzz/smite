//! Wire format serialization and deserialization primitives.

use crate::bolt::BoltError;
use crate::bolt::types::{
    BigSize, CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, ChannelId, PARTIAL_SIGNATURE_SIZE,
    PUBLIC_KEY_SIZE, PUBLIC_NONCE_SIZE, PartialSignatureWithNonce, PublicNonce, SHA256_HASH_SIZE,
    ShortChannelId, TXID_SIZE, Tu32, Tu64,
};
use bitcoin::Txid;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::ecdsa::Signature;

/// A type that can be read from and written to the Lightning wire format.
pub trait WireFormat: Sized {
    /// Reads a value from the byte slice, advancing past the consumed bytes.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if the data is truncated or invalid.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError>;

    /// Writes the value in wire format, appending bytes to `out`.
    fn write(&self, out: &mut Vec<u8>);
}

/// Wire encoding for a zero-length TLV value (boolean flags in BOLT).
///
/// Used with [`TlvStream::get_as`] to decode presence-only TLVs and reject
/// non-empty values as trailing bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyTlv;

impl WireFormat for EmptyTlv {
    fn read(_data: &mut &[u8]) -> Result<Self, BoltError> {
        Ok(EmptyTlv)
    }

    fn write(&self, _out: &mut Vec<u8>) {}
}

impl<const N: usize> WireFormat for [u8; N] {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        if data.len() < N {
            return Err(BoltError::Truncated {
                expected: N,
                actual: data.len(),
            });
        }
        let mut buf = [0u8; N];
        buf.copy_from_slice(&data[..N]);
        *data = &data[N..];
        Ok(buf)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

macro_rules! impl_truncated_int {
    ($name:ident, $inner:ty) => {
        impl WireFormat for $name {
            /// Reads a minimally-encoded truncated integer from all remaining
            /// bytes.
            ///
            /// # Errors
            ///
            /// Returns `TruncatedIntTooLong` if more bytes remain than the
            /// integer's width, or `TruncatedIntNotMinimal` if the first byte
            /// is zero.
            fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
                const WIDTH: usize = std::mem::size_of::<$inner>();

                let bytes = *data;

                if bytes.len() > WIDTH {
                    return Err(BoltError::TruncatedIntTooLong {
                        max: WIDTH,
                        actual: bytes.len(),
                    });
                }
                if bytes.first() == Some(&0) {
                    return Err(BoltError::TruncatedIntNotMinimal);
                }

                *data = &[];

                let mut buf = [0u8; WIDTH];
                buf[WIDTH - bytes.len()..].copy_from_slice(bytes);
                Ok(Self(<$inner>::from_be_bytes(buf)))
            }

            /// Writes the integer big-endian with leading zero bytes stripped.
            ///
            /// Zero encodes to zero bytes.
            fn write(&self, out: &mut Vec<u8>) {
                let bytes = self.0.to_be_bytes();
                let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
                out.extend_from_slice(&bytes[start..]);
            }
        }
    };
}

impl_truncated_int!(Tu32, u32);
impl_truncated_int!(Tu64, u64);

macro_rules! impl_wire_format_int {
    ($type:ty) => {
        impl WireFormat for $type {
            fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
                const SIZE: usize = std::mem::size_of::<$type>();
                let bytes: [u8; SIZE] = WireFormat::read(data)?;
                Ok(<$type>::from_be_bytes(bytes))
            }

            fn write(&self, out: &mut Vec<u8>) {
                self.to_be_bytes().write(out);
            }
        }
    };
}

impl_wire_format_int!(u8);
impl_wire_format_int!(u16);
impl_wire_format_int!(u32);
impl_wire_format_int!(u64);
impl_wire_format_int!(i64);

impl WireFormat for PublicKey {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let buf: [u8; PUBLIC_KEY_SIZE] = WireFormat::read(data)?;
        let pubkey = PublicKey::from_slice(&buf).map_err(|_| BoltError::InvalidPublicKey(buf))?;
        Ok(pubkey)
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.serialize().write(out);
    }
}

impl WireFormat for PublicNonce {
    /// Reads a 66-byte `MuSig2` public nonce.
    ///
    /// The bytes are not checked to be two valid points: a peer sending a
    /// malformed nonce is a spec violation to report, not a decode failure.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let bytes: [u8; PUBLIC_NONCE_SIZE] = WireFormat::read(data)?;
        Ok(Self(bytes))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.as_bytes().write(out);
    }
}

impl WireFormat for PartialSignatureWithNonce {
    /// Reads a 98-byte `partial_signature || public_nonce`.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let partial_signature: [u8; PARTIAL_SIGNATURE_SIZE] = WireFormat::read(data)?;
        let public_nonce = PublicNonce::read(data)?;
        Ok(Self {
            partial_signature,
            public_nonce,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.partial_signature.write(out);
        self.public_nonce.write(out);
    }
}

impl WireFormat for ChannelId {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let bytes: [u8; CHANNEL_ID_SIZE] = WireFormat::read(data)?;
        Ok(Self(bytes))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.as_bytes().write(out);
    }
}

impl WireFormat for ShortChannelId {
    /// Reads a packed 8-byte big-endian `short_channel_id`.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if fewer than 8 bytes remain.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let scid = u64::read(data)?;
        Ok(Self::from_u64(scid))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.as_u64().write(out);
    }
}

impl WireFormat for BigSize {
    /// Reads a `BigSize` value from the byte slice, advancing past the consumed bytes.
    ///
    /// `BigSize` is like Bitcoin's `CompactSize` but big-endian:
    /// - 0x00-0xFC: 1 byte (value as-is)
    /// - 0xFD + 2 bytes BE: values 0xFD-0xFFFF
    /// - 0xFE + 4 bytes BE: values 0x10000-0xFFFFFFFF
    /// - 0xFF + 8 bytes BE: values > 0xFFFFFFFF
    ///
    /// # Errors
    ///
    /// Returns `BigSizeTruncated` if there aren't enough bytes, or
    /// `BigSizeNotMinimal` if the encoding is not minimal.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let prefix = u8::read(data).map_err(|_| BoltError::BigSizeTruncated)?;

        match prefix {
            0..=0xfc => Ok(BigSize::new(u64::from(prefix))),
            0xfd => {
                let value = u64::from(u16::read(data).map_err(|_| BoltError::BigSizeTruncated)?);
                if value < 0xfd {
                    return Err(BoltError::BigSizeNotMinimal);
                }
                Ok(BigSize::new(value))
            }
            0xfe => {
                let value = u64::from(u32::read(data).map_err(|_| BoltError::BigSizeTruncated)?);
                if value < 0x1_0000 {
                    return Err(BoltError::BigSizeNotMinimal);
                }
                Ok(BigSize::new(value))
            }
            0xff => {
                let value = u64::read(data).map_err(|_| BoltError::BigSizeTruncated)?;
                if value < 0x1_0000_0000 {
                    return Err(BoltError::BigSizeNotMinimal);
                }
                Ok(BigSize::new(value))
            }
        }
    }

    /// Writes a `BigSize` value in wire format, appending bytes to `out`.
    #[allow(clippy::cast_possible_truncation)] // Truncation is safe: we check ranges before casting
    fn write(&self, out: &mut Vec<u8>) {
        let value = self.value();
        if value < 0xfd {
            (value as u8).write(out);
        } else if value < 0x1_0000 {
            0xfdu8.write(out);
            (value as u16).write(out);
        } else if value < 0x1_0000_0000 {
            0xfeu8.write(out);
            (value as u32).write(out);
        } else {
            0xffu8.write(out);
            value.write(out);
        }
    }
}

impl WireFormat for Vec<u8> {
    /// Reads a `[u16:len][len*byte]` variable-length field, advancing past both.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if there are fewer bytes than the declared length.
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let len = u16::read(data)? as usize;
        if data.len() < len {
            return Err(BoltError::Truncated {
                expected: len,
                actual: data.len(),
            });
        }
        let bytes = data[..len].to_vec();
        *data = &data[len..];
        Ok(bytes)
    }

    /// Writes a `[u16:len][len*byte]` variable-length field.
    ///
    /// # Panics
    ///
    /// Panics if `self.len()` exceeds `MAX_MESSAGE_SIZE`.
    fn write(&self, out: &mut Vec<u8>) {
        u16::try_from(self.len())
            .unwrap_or_else(|_| panic!("Vec<u8> length {} exceeds maximum size", self.len()))
            .write(out);
        out.extend_from_slice(self);
    }
}

impl WireFormat for Txid {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let buf: [u8; TXID_SIZE] = WireFormat::read(data)?;
        Ok(Txid::from_byte_array(buf))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.to_byte_array().write(out);
    }
}

impl WireFormat for Signature {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let buf: [u8; COMPACT_SIGNATURE_SIZE] = WireFormat::read(data)?;
        Signature::from_compact(&buf).map_err(|_| BoltError::InvalidSignature(buf))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.serialize_compact().write(out);
    }
}

impl WireFormat for sha256::Hash {
    fn read(data: &mut &[u8]) -> Result<Self, BoltError> {
        let buf: [u8; SHA256_HASH_SIZE] = WireFormat::read(data)?;
        Ok(sha256::Hash::from_byte_array(buf))
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.to_byte_array().write(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::SHORT_CHANNEL_ID_SIZE;
    use bitcoin::secp256k1::{self, Secp256k1, SecretKey};

    #[test]
    fn u8_read_valid() {
        let mut data: &[u8] = &[0x00, 0xff];
        assert_eq!(u8::read(&mut data).unwrap(), 0);
        assert_eq!(data, &[0xff]);
        assert_eq!(u8::read(&mut data).unwrap(), 255);
        assert!(data.is_empty());
    }

    #[test]
    fn u8_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u8::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn u8_write_roundtrip() {
        for value in [0u8, 1, 127, 255] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 1);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u8::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn u16_read_valid() {
        let mut data: &[u8] = &[0x00, 0x00, 0x00, 0x01];
        assert_eq!(u16::read(&mut data).unwrap(), 0);
        assert_eq!(data, &[0x00, 0x01]);
        assert_eq!(u16::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn u16_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u16::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 0
            })
        );

        let mut one_byte: &[u8] = &[0x00];
        assert_eq!(
            u16::read(&mut one_byte),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn u16_write_roundtrip() {
        for value in [0u16, 1, 255, 256, 65535] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 2);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u16::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn u32_read_valid() {
        let mut data: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(u32::read(&mut data).unwrap(), 0);
        assert_eq!(data, &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(u32::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn u32_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u32::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x00, 0x01, 0x02];
        assert_eq!(
            u32::read(&mut short),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn u32_write_roundtrip() {
        for value in [0u32, 1, 65535, 65536, u32::MAX] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 4);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u32::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn u64_read_valid() {
        let mut data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(u64::read(&mut data).unwrap(), 0);
        assert_eq!(data.len(), 8);
        assert_eq!(u64::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn u64_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            u64::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x00; 7];
        assert_eq!(
            u64::read(&mut short),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 7
            })
        );
    }

    #[test]
    fn u64_write_roundtrip() {
        for value in [0u64, 1, u64::from(u32::MAX), u64::MAX] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 8);
            let mut cursor: &[u8] = &buf;
            assert_eq!(u64::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn i64_read_valid() {
        // Two values back-to-back; verify cursor advances after each read.
        let mut data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
        ];
        assert_eq!(i64::read(&mut data).unwrap(), 0);
        assert_eq!(data.len(), 8);
        assert_eq!(i64::read(&mut data).unwrap(), 1);
        assert!(data.is_empty());

        // Negative (-1 = 0xffffffffffffffff in two's complement)
        let mut data: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(i64::read(&mut data).unwrap(), -1);

        // Negative (-100_000)
        let mut data: &[u8] = &(-100_000i64).to_be_bytes();
        assert_eq!(i64::read(&mut data).unwrap(), -100_000);

        // i64::MAX
        let mut data: &[u8] = &i64::MAX.to_be_bytes();
        assert_eq!(i64::read(&mut data).unwrap(), i64::MAX);

        // i64::MIN
        let mut data: &[u8] = &i64::MIN.to_be_bytes();
        assert_eq!(i64::read(&mut data).unwrap(), i64::MIN);
    }

    #[test]
    fn i64_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            i64::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x00; 7];
        assert_eq!(
            i64::read(&mut short),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 7
            })
        );
    }

    #[test]
    fn i64_write_roundtrip() {
        for value in [0i64, 1, -1, i64::MAX, i64::MIN, -100_000, 500_000] {
            let mut buf = Vec::new();
            value.write(&mut buf);
            assert_eq!(buf.len(), 8);
            let mut cursor: &[u8] = &buf;
            assert_eq!(i64::read(&mut cursor).unwrap(), value);
        }
    }

    #[test]
    fn i64_negative_wire_encoding() {
        // Verify negative values use big-endian two's complement
        let mut buf = Vec::new();
        (-1i64).write(&mut buf);
        assert_eq!(buf, vec![0xff; 8]);

        let mut buf = Vec::new();
        i64::MIN.write(&mut buf);
        assert_eq!(buf, vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn byte_array_read_valid() {
        let mut data: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let arr = <[u8; 3]>::read(&mut data).unwrap();
        assert_eq!(arr, [0xaa, 0xbb, 0xcc]);
        assert_eq!(data, &[0xdd, 0xee]);
    }

    #[test]
    fn byte_array_read_truncated() {
        let mut short: &[u8] = &[0xaa, 0xbb];
        assert_eq!(
            <[u8; 4]>::read(&mut short),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );

        let mut empty: &[u8] = &[];
        assert_eq!(
            <[u8; 1]>::read(&mut empty),
            Err(BoltError::Truncated {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn empty_tlv_read_leaves_trailing_bytes() {
        let mut data: &[u8] = &[0xaa, 0xbb, 0xcc];
        EmptyTlv::read(&mut data).unwrap();
        assert_eq!(data, &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn byte_array_write_roundtrip() {
        let original = [0x11, 0x22, 0x33, 0x44, 0x55];
        let mut buf = Vec::new();
        original.write(&mut buf);
        assert_eq!(buf.len(), 5);
        let mut cursor: &[u8] = &buf;
        let decoded = <[u8; 5]>::read(&mut cursor).unwrap();
        assert_eq!(decoded, original);
        assert!(cursor.is_empty());
    }

    #[test]
    fn pubkey_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            PublicKey::read(&mut empty),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0x02; 20];
        assert_eq!(
            PublicKey::read(&mut short),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn pubkey_read_invalid() {
        let invalid = [0x00; PUBLIC_KEY_SIZE];
        let mut data: &[u8] = &invalid;
        assert_eq!(
            PublicKey::read(&mut data),
            Err(BoltError::InvalidPublicKey(invalid))
        );
    }

    #[test]
    fn pubkey_write_roundtrip() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let mut buf = Vec::new();
        pk.write(&mut buf);
        assert_eq!(buf.len(), PUBLIC_KEY_SIZE);
        let mut cursor: &[u8] = &buf;
        let decoded = PublicKey::read(&mut cursor).unwrap();
        assert_eq!(decoded, pk);
        assert!(cursor.is_empty());
    }

    #[test]
    fn channel_id_write_roundtrip() {
        let original = ChannelId::new([0xab; CHANNEL_ID_SIZE]);
        let mut buf = Vec::new();
        original.write(&mut buf);
        assert_eq!(buf.len(), CHANNEL_ID_SIZE);

        let mut cursor: &[u8] = &buf;
        let decoded = ChannelId::read(&mut cursor).unwrap();
        assert_eq!(decoded, original);
        assert!(cursor.is_empty());
    }

    #[test]
    fn channel_id_read_truncated() {
        let mut short: &[u8] = &[0x00; 20];
        assert_eq!(
            ChannelId::read(&mut short),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20,
            })
        );
    }

    #[test]
    fn channel_id_read_advances_cursor() {
        let mut data: &[u8] = &[0x11; CHANNEL_ID_SIZE + 8]; // 8 extra bytes
        let id = ChannelId::read(&mut data).unwrap();
        assert_eq!(id, ChannelId::new([0x11; CHANNEL_ID_SIZE]));
        assert_eq!(data.len(), 8); // 8 bytes remaining
    }

    #[test]
    fn short_channel_id_write_roundtrip() {
        let scid = ShortChannelId::new(539_268, 845, 1);
        let mut buf = Vec::new();
        scid.write(&mut buf);
        assert_eq!(buf.len(), SHORT_CHANNEL_ID_SIZE);

        let mut cursor: &[u8] = &buf;
        let decoded = ShortChannelId::read(&mut cursor).unwrap();
        assert_eq!(decoded, scid);
        assert!(cursor.is_empty());
    }

    #[test]
    fn short_channel_id_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            ShortChannelId::read(&mut empty),
            Err(BoltError::Truncated {
                expected: SHORT_CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn short_channel_id_wire_layout_is_big_endian_packed() {
        let scid = ShortChannelId::new(0x00_08_37_a4, 0x00_00_03_4d, 0x0001);
        let mut buf = Vec::new();
        scid.write(&mut buf);
        assert_eq!(buf, [0x08, 0x37, 0xa4, 0x00, 0x03, 0x4d, 0x00, 0x01]);
    }

    #[test]
    fn vec_u8_read_empty_field() {
        let mut data: &[u8] = &[0x00, 0x00];
        let result = Vec::<u8>::read(&mut data).unwrap();
        assert_eq!(result, Vec::<u8>::new());
        assert!(data.is_empty());
    }

    #[test]
    fn vec_u8_read_valid() {
        let mut data: &[u8] = &[0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let result = Vec::<u8>::read(&mut data).unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc]);
        assert!(data.is_empty());
    }

    #[test]
    fn vec_u8_read_truncated_length() {
        let mut data: &[u8] = &[0x00];
        assert_eq!(
            Vec::<u8>::read(&mut data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn vec_u8_read_truncated_data() {
        let mut data: &[u8] = &[0x00, 0x05, 0xaa, 0xbb];
        assert_eq!(
            Vec::<u8>::read(&mut data),
            Err(BoltError::Truncated {
                expected: 5,
                actual: 2
            })
        );
    }

    #[test]
    fn vec_u8_read_advances_cursor() {
        let mut data: &[u8] = &[0x00, 0x02, 0xaa, 0xbb, 0xff, 0xff];
        let result = Vec::<u8>::read(&mut data).unwrap();
        assert_eq!(result, vec![0xaa, 0xbb]);
        assert_eq!(data, &[0xff, 0xff]);
    }

    #[test]
    fn vec_u8_write_roundtrip() {
        let original = vec![0xaa, 0xbb];
        let mut buf = Vec::new();
        original.write(&mut buf);

        let mut cursor: &[u8] = &buf;
        let decoded = Vec::<u8>::read(&mut cursor).unwrap();
        assert_eq!(decoded, original);
        assert!(cursor.is_empty());
    }

    #[test]
    #[should_panic(expected = "Vec<u8> length 65536 exceeds maximum size")]
    fn vec_u8_write_u16_overflow() {
        let oversized = vec![0x00; 0xffff + 1];
        let mut buf = Vec::new();
        oversized.write(&mut buf);
    }

    // Test vectors from BOLT 1 Appendix A
    // https://github.com/lightning/bolts/blob/master/01-messaging.md#appendix-a-bigsize-test-vectors

    #[test]
    fn bigsize_read_valid() {
        let tests: &[(&[u8], u64)] = &[
            (&[0x00], 0),
            (&[0xfc], 252),
            (&[0xfd, 0x00, 0xfd], 253),
            (&[0xfd, 0xff, 0xff], 65535),
            (&[0xfe, 0x00, 0x01, 0x00, 0x00], 65536),
            (&[0xfe, 0xff, 0xff, 0xff, 0xff], 4_294_967_295),
            (
                &[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
                4_294_967_296,
            ),
            (
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                18_446_744_073_709_551_615,
            ),
        ];

        for (bytes, expected) in tests {
            let mut cursor: &[u8] = bytes;
            let bs = BigSize::read(&mut cursor).expect("valid bigsize");
            assert_eq!(bs.value(), *expected, "decoding {bytes:02x?}");
            assert_eq!(bs.len(), bytes.len());
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn bigsize_write_valid() {
        let tests: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (252, &[0xfc]),
            (253, &[0xfd, 0x00, 0xfd]),
            (65535, &[0xfd, 0xff, 0xff]),
            (65536, &[0xfe, 0x00, 0x01, 0x00, 0x00]),
            (4_294_967_295, &[0xfe, 0xff, 0xff, 0xff, 0xff]),
            (
                4_294_967_296,
                &[0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                18_446_744_073_709_551_615,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in tests {
            let mut encoded = Vec::new();
            BigSize::new(*value).write(&mut encoded);
            assert_eq!(encoded.as_slice(), *expected, "encoding {value}");
        }
    }

    #[test]
    fn bigsize_write_roundtrip() {
        let values = [
            0u64,
            1,
            252,
            253,
            254,
            65535,
            65536,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ];
        for value in values {
            let bs = BigSize(value);
            let mut encoded = Vec::new();
            bs.write(&mut encoded);

            let mut cursor: &[u8] = &encoded;
            let decoded = BigSize::read(&mut cursor).expect("valid bigsize");
            assert_eq!(value, decoded.value());
            assert_eq!(bs.len(), encoded.len());
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn bigsize_read_not_minimal() {
        // Two-byte encoding for value < 253
        let mut invalid: &[u8] = &[0xfd, 0x00, 0xfc];
        assert_eq!(
            BigSize::read(&mut invalid),
            Err(BoltError::BigSizeNotMinimal)
        );

        // Four-byte encoding for value < 65536
        let mut invalid: &[u8] = &[0xfe, 0x00, 0x00, 0xff, 0xff];
        assert_eq!(
            BigSize::read(&mut invalid),
            Err(BoltError::BigSizeNotMinimal)
        );

        // Eight-byte encoding for value < 4294967296
        let mut invalid: &[u8] = &[0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            BigSize::read(&mut invalid),
            Err(BoltError::BigSizeNotMinimal)
        );
    }

    #[test]
    fn bigsize_read_truncated() {
        // Test vectors from BOLT 1 Appendix A "short read" and "no read"

        // No read tests (just prefix, no payload bytes)
        assert_eq!(
            BigSize::read(&mut &[][..]),
            Err(BoltError::BigSizeTruncated)
        ); // one byte no read
        assert_eq!(
            BigSize::read(&mut &[0xfd][..]),
            Err(BoltError::BigSizeTruncated)
        ); // two byte no read
        assert_eq!(
            BigSize::read(&mut &[0xfe][..]),
            Err(BoltError::BigSizeTruncated)
        ); // four byte no read
        assert_eq!(
            BigSize::read(&mut &[0xff][..]),
            Err(BoltError::BigSizeTruncated)
        ); // eight byte no read

        // Short read tests (prefix + partial payload)
        assert_eq!(
            BigSize::read(&mut &[0xfd, 0x00][..]),
            Err(BoltError::BigSizeTruncated)
        ); // two byte short read
        assert_eq!(
            BigSize::read(&mut &[0xfe, 0xff, 0xff][..]),
            Err(BoltError::BigSizeTruncated)
        ); // four byte short read
        assert_eq!(
            BigSize::read(&mut &[0xff, 0xff, 0xff, 0xff, 0xff][..]),
            Err(BoltError::BigSizeTruncated)
        ); // eight byte short read
    }

    #[test]
    fn bigsize_len_matches_encode() {
        let values = [0, 252, 253, 65535, 65536, 0xffff_ffff, 0x1_0000_0000];
        for value in values {
            let mut encoded = Vec::new();
            BigSize::new(value).write(&mut encoded);
            assert_eq!(BigSize::new(value).len(), encoded.len());
        }
    }

    #[test]
    fn bigsize_read_advances_cursor() {
        // Single-byte BigSize followed by extra bytes
        let mut data: &[u8] = &[0x05, 0xff, 0xff];
        let bs = BigSize::read(&mut data).unwrap();
        assert_eq!(bs, BigSize::new(5));
        assert_eq!(data, &[0xff, 0xff]);

        // Two-byte BigSize followed by extra bytes
        let mut data: &[u8] = &[0xfd, 0x00, 0xfd, 0xaa];
        let bs = BigSize::read(&mut data).unwrap();
        assert_eq!(bs, BigSize::new(253));
        assert_eq!(data, &[0xaa]);
    }

    #[test]
    fn txid_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            Txid::read(&mut empty),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0xaa; 20];
        assert_eq!(
            Txid::read(&mut short),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn txid_write_roundtrip() {
        let txid = Txid::from_byte_array([0xcc; TXID_SIZE]);

        let mut buf = Vec::new();
        txid.write(&mut buf);
        assert_eq!(buf.len(), TXID_SIZE);
        let mut cursor: &[u8] = &buf;
        let decoded = Txid::read(&mut cursor).unwrap();
        assert_eq!(decoded, txid);
        assert!(cursor.is_empty());
    }

    #[test]
    fn signature_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            Signature::read(&mut empty),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0xdd; 30];
        assert_eq!(
            Signature::read(&mut short),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 30
            })
        );
    }

    #[test]
    fn signature_read_invalid() {
        // r = 0xff..ff and s = 0xff..ff are both > curve order n,
        // so from_compact must reject this
        let invalid = [0xff; COMPACT_SIGNATURE_SIZE];
        let mut data: &[u8] = &invalid;
        assert_eq!(
            Signature::read(&mut data),
            Err(BoltError::InvalidSignature(invalid))
        );
    }

    #[test]
    fn signature_write_roundtrip() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let msg = secp256k1::Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        let mut buf = Vec::new();
        sig.write(&mut buf);
        assert_eq!(buf.len(), COMPACT_SIGNATURE_SIZE);
        let mut cursor: &[u8] = &buf;
        let decoded = Signature::read(&mut cursor).unwrap();
        assert_eq!(decoded, sig);
        assert!(cursor.is_empty());
    }

    #[test]
    fn sha256_hash_read_truncated() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            sha256::Hash::read(&mut empty),
            Err(BoltError::Truncated {
                expected: SHA256_HASH_SIZE,
                actual: 0
            })
        );

        let mut short: &[u8] = &[0xaa; 31]; // One byte short
        assert_eq!(
            sha256::Hash::read(&mut short),
            Err(BoltError::Truncated {
                expected: SHA256_HASH_SIZE,
                actual: 31
            })
        );
    }

    #[test]
    fn sha256_hash_write_roundtrip() {
        let hash = sha256::Hash::from_byte_array([0xee; SHA256_HASH_SIZE]);

        let mut buf = Vec::new();
        hash.write(&mut buf);
        assert_eq!(buf.len(), SHA256_HASH_SIZE);

        let mut cursor: &[u8] = &buf;
        let decoded = sha256::Hash::read(&mut cursor).unwrap();
        assert_eq!(decoded, hash);
        assert!(cursor.is_empty());
    }

    #[test]
    fn sha256_hash_read_advances_cursor() {
        let mut data: &[u8] = &[0x55; SHA256_HASH_SIZE + 5]; // 5 extra bytes
        let hash = sha256::Hash::read(&mut data).unwrap();
        assert_eq!(
            hash,
            sha256::Hash::from_byte_array([0x55; SHA256_HASH_SIZE])
        );
        assert_eq!(data.len(), 5); // 5 bytes remaining
    }

    // Test vectors for `n1`s `tlv1`s `amount_msat` (`tu64`) from BOLT 1 Appendix B
    // https://github.com/lightning/bolts/blob/master/01-messaging.md#appendix-b-type-length-value-test-vectors

    #[test]
    fn bolt_tu64_decoding_successes() {
        let cases: &[(&[u8], u64)] = &[
            (&[], 0),
            (&[0x01], 1),
            (&[0x01, 0x00], 256),
            (&[0x01, 0x00, 0x00], 65_536),
            (&[0x01, 0x00, 0x00, 0x00], 16_777_216),
            (&[0x01, 0x00, 0x00, 0x00, 0x00], 4_294_967_296),
            (&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00], 1_099_511_627_776),
            (
                &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                281_474_976_710_656,
            ),
            (
                &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                72_057_594_037_927_936,
            ),
        ];

        for (bytes, value) in cases {
            let mut cursor = *bytes;
            assert_eq!(Tu64::read(&mut cursor), Ok(Tu64(*value)), "value {value}");
            assert!(cursor.is_empty(), "value {value}");

            let mut buf = Vec::new();
            Tu64(*value).write(&mut buf);
            assert_eq!(buf, *bytes, "value {value}");
        }
    }

    #[test]
    fn bolt_tu64_rejects_oversized_encoding() {
        // 0x01 09 ffffffffffffffffff: greater than encoding length for tu64.
        let mut data: &[u8] = &[0xff; 9];
        assert_eq!(
            Tu64::read(&mut data),
            Err(BoltError::TruncatedIntTooLong { max: 8, actual: 9 })
        );
    }

    #[test]
    fn bolt_tu64_rejects_non_minimal_encoding() {
        // 0x01 01 00 through 0x01 08 0001000000000000: leading zero byte.
        let cases: &[&[u8]] = &[
            &[0x00],
            &[0x00, 0x01],
            &[0x00, 0x01, 0x00],
            &[0x00, 0x01, 0x00, 0x00],
            &[0x00, 0x01, 0x00, 0x00, 0x00],
            &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        for bytes in cases {
            let mut cursor = *bytes;
            assert_eq!(
                Tu64::read(&mut cursor),
                Err(BoltError::TruncatedIntNotMinimal),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn tu32_roundtrips_minimal_encodings() {
        let cases: &[(&[u8], u32)] = &[
            (&[], 0),
            (&[0x01], 1),
            (&[0x01, 0x00], 256),
            (&[0x01, 0x00, 0x00], 65_536),
            (&[0x01, 0x00, 0x00, 0x00], 16_777_216),
            (&[0xff, 0xff, 0xff, 0xff], u32::MAX),
        ];

        for (bytes, value) in cases {
            let mut cursor = *bytes;
            assert_eq!(Tu32::read(&mut cursor), Ok(Tu32(*value)), "value {value}");
            assert!(cursor.is_empty(), "value {value}");

            let mut buf = Vec::new();
            Tu32(*value).write(&mut buf);
            assert_eq!(buf, *bytes, "value {value}");
        }
    }

    #[test]
    fn tu32_rejects_oversized_encoding() {
        let mut data: &[u8] = &[0x01; 5];
        assert_eq!(
            Tu32::read(&mut data),
            Err(BoltError::TruncatedIntTooLong { max: 4, actual: 5 })
        );

        // Five bytes still fit in a tu64.
        let mut data: &[u8] = &[0x01; 5];
        assert_eq!(Tu64::read(&mut data), Ok(Tu64(0x01_0101_0101)));
    }

    #[test]
    fn tu32_rejects_non_minimal_encoding() {
        let mut data: &[u8] = &[0x00, 0x01];
        assert_eq!(
            Tu32::read(&mut data),
            Err(BoltError::TruncatedIntNotMinimal)
        );
    }
}
