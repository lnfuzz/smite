//! Byte-level malformation of encoded messages.
//!
//! A few message fields are computed rather than supplied as IR variables, so
//! no mutator can give them an invalid value -- see
//! [`smite::bolt::MalformableField`]. A [`Malformation`] overwrites one such
//! field of an encoded message immediately before it goes on the wire. Which
//! fields those are is fixed per message type by
//! [`smite::bolt::MessageType::malformable_fields`], which lives with the
//! codecs.

use serde::{Deserialize, Serialize};

/// Overwrites one field of an encoded message with the given bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Malformation {
    /// Byte offset into the encoded message, including the 2-byte type prefix.
    pub offset: u16,
    /// Replacement bytes.
    pub bytes: Vec<u8>,
}

impl Malformation {
    /// Overwrites `msg` from `offset` with the replacement bytes. Returns
    /// `true` if the bytes changed.
    ///
    /// # Panics
    ///
    /// Panics if the replacement runs past the end of `msg`. Offsets and
    /// lengths come from the fixed-size fields of
    /// [`smite::bolt::MalformableField`], so a panic here means a field table
    /// and the codec it describes have drifted apart.
    pub fn apply(&self, msg: &mut [u8]) -> bool {
        let start = self.offset as usize;
        let end = start + self.bytes.len();
        assert!(
            end <= msg.len(),
            "malformation of {} bytes at offset {} runs past the end of a {}-byte message",
            self.bytes.len(),
            self.offset,
            msg.len(),
        );

        if msg[start..end] == self.bytes[..] {
            return false;
        }

        msg[start..end].copy_from_slice(&self.bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_overwrites_field() {
        let mut msg = vec![0x00, 0x11, 0x22, 0xaa, 0xaa, 0xaa];
        let malformation = Malformation {
            offset: 3,
            bytes: vec![0xff, 0xff, 0xff],
        };

        assert!(malformation.apply(&mut msg));
        assert_eq!(msg, vec![0x00, 0x11, 0x22, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn apply_reports_unchanged_bytes() {
        let mut msg = vec![0x00, 0x22, 0xff, 0xff, 0xbb];
        let malformation = Malformation {
            offset: 2,
            bytes: vec![0xff, 0xff],
        };

        assert!(!malformation.apply(&mut msg));
        assert_eq!(msg, vec![0x00, 0x22, 0xff, 0xff, 0xbb]);
    }

    #[test]
    #[should_panic(
        expected = "malformation of 2 bytes at offset 2 runs past the end of a 3-byte message"
    )]
    fn apply_past_end_panics() {
        let mut msg = vec![0x00, 0x22, 0xaa];
        let malformation = Malformation {
            offset: 2,
            bytes: vec![0xff, 0xff],
        };

        malformation.apply(&mut msg);
    }
}
