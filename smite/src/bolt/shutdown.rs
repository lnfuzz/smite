//! BOLT 2 shutdown message.

use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::{Script, WitnessVersion};

use super::BoltError;
use super::Features;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 shutdown message (type 38).
///
/// Sent by either peer to initiate a cooperative close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shutdown {
    /// Channel to be closed.
    pub channel_id: ChannelId,
    /// The output script where that peer wants to receive their funds.
    pub scriptpubkey: Vec<u8>,
}

impl Shutdown {
    /// Creates a shutdown for a specific channel.
    #[must_use]
    pub fn for_channel(channel_id: ChannelId, scriptpubkey: Vec<u8>) -> Self {
        Self {
            channel_id,
            scriptpubkey,
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.scriptpubkey.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let scriptpubkey = Vec::<u8>::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            scriptpubkey,
        })
    }
}

/// Returns `true` if `spk` is a standard `shutdown` scriptpubkey per BOLT 2: P2WPKH or P2WSH.
/// Negotiated `features` widen the accepted set.
///
/// Legacy P2PKH/P2SH are rejected. A receiver may accept them for backward compatibility, but this
/// oracle judges the sender's output.
#[must_use]
pub fn is_standard_shutdown_script(spk: &[u8], features: &Features) -> bool {
    let script = Script::from_bytes(spk);
    let witness_v0 = script.is_p2wpkh() || script.is_p2wsh();
    let anysegwit = features.supports_feature(Features::OPTION_SHUTDOWN_ANYSEGWIT)
        && matches!(script.witness_version(), Some(v) if v != WitnessVersion::V0);
    let simple_close = features.supports_feature(Features::OPTION_SIMPLE_CLOSE)
        && is_simple_close_op_return(script);
    witness_v0 || anysegwit || simple_close
}

/// Returns `true` if `script` is a BOLT 2 `option_simple_close` `OP_RETURN` script: `OP_RETURN`
/// followed by a single minimal push of 6..=80 bytes.
///
/// A non-minimal push here would be `OP_PUSHDATA1` used for a payload of fewer than 76 bytes.
fn is_simple_close_op_return(script: &Script) -> bool {
    let mut instrs = script.instructions_minimal();
    if !matches!(instrs.next(), Some(Ok(Instruction::Op(op))) if op == OP_RETURN) {
        return false;
    }
    match instrs.next() {
        // matches any minimal push
        Some(Ok(Instruction::PushBytes(bytes))) => {
            (6..=80).contains(&bytes.len()) && instrs.next().is_none()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHBYTES_0, OP_PUSHBYTES_1,
        OP_PUSHBYTES_20, OP_PUSHBYTES_21, OP_PUSHBYTES_32, OP_PUSHDATA1, OP_PUSHNUM_1,
        OP_PUSHNUM_16, OP_RETURN,
    };

    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    fn no_features() -> Features {
        Features::new()
    }
    fn with_anysegwit() -> Features {
        Features::from_bits(&[Features::OPTION_SHUTDOWN_ANYSEGWIT])
    }
    fn with_simple_close() -> Features {
        Features::from_bits(&[Features::OPTION_SIMPLE_CLOSE])
    }
    fn all_shutdown_features() -> Features {
        Features::from_bits(&[
            Features::OPTION_SHUTDOWN_ANYSEGWIT,
            Features::OPTION_SIMPLE_CLOSE,
        ])
    }

    #[test]
    fn shutdown_for_channel() {
        let channel_id = ChannelId::new([0x42; CHANNEL_ID_SIZE]);
        let spk = vec![0x00, 0x14, 0xab, 0xcd];
        let shutdown = Shutdown::for_channel(channel_id, spk);
        assert_eq!(shutdown.channel_id, channel_id);
        assert_eq!(shutdown.scriptpubkey, &[0x00, 0x14, 0xab, 0xcd]);
    }

    #[test]
    fn shutdown_encode() {
        let channel_id = ChannelId::new([0x00; CHANNEL_ID_SIZE]);
        let spk = vec![0x51, 0x20]; // p2tr-ish prefix
        let shutdown = Shutdown::for_channel(channel_id, spk);
        let encoded = shutdown.encode();
        // channel_id(32) + len(2) + scriptpubkey(2)
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 2 + 2);
        assert_eq!(
            &encoded[CHANNEL_ID_SIZE..CHANNEL_ID_SIZE + 2],
            &[0x00, 0x02]
        );
        assert_eq!(&encoded[CHANNEL_ID_SIZE + 2..], &[0x51, 0x20]);
    }

    #[test]
    fn shutdown_decode() {
        let mut data = vec![0x11u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x03]); // len = 3
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let shutdown = Shutdown::decode(&data).unwrap();
        assert_eq!(
            shutdown.channel_id,
            ChannelId::new([0x11u8; CHANNEL_ID_SIZE])
        );
        assert_eq!(shutdown.scriptpubkey, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn shutdown_roundtrip() {
        let original = Shutdown::for_channel(
            ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            vec![0x00, 0x14, 0x01, 0x02, 0x03],
        );
        let encoded = original.encode();
        let decoded = Shutdown::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn shutdown_decode_truncated_channel_id() {
        assert_eq!(
            Shutdown::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn shutdown_decode_truncated_len() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.push(0x00); // only 1 byte of len
        assert_eq!(
            Shutdown::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn shutdown_decode_truncated_scriptpubkey() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x10]); // len = 16
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes
        assert_eq!(
            Shutdown::decode(&data),
            Err(BoltError::Truncated {
                expected: 16,
                actual: 3
            })
        );
    }

    #[test]
    fn shutdown_empty_scriptpubkey() {
        let original = Shutdown::for_channel(ChannelId::new([0xff; CHANNEL_ID_SIZE]), vec![]);
        let encoded = original.encode();
        let decoded = Shutdown::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert!(decoded.scriptpubkey.is_empty());
    }

    #[test]
    fn is_standard_shutdown_script_accepts_witness_v0() {
        // Witness v0 forms are accepted regardless of features.
        let v0 = OP_PUSHBYTES_0.to_u8();
        let mut p2wpkh = vec![v0, OP_PUSHBYTES_20.to_u8()];
        p2wpkh.extend_from_slice(&[0x33; 20]);
        assert!(is_standard_shutdown_script(&p2wpkh, &no_features()));
        assert!(is_standard_shutdown_script(
            &p2wpkh,
            &all_shutdown_features()
        ));

        let mut p2wsh = vec![v0, OP_PUSHBYTES_32.to_u8()];
        p2wsh.extend_from_slice(&[0x44; 32]);
        assert!(is_standard_shutdown_script(&p2wsh, &no_features()));
        assert!(is_standard_shutdown_script(
            &p2wsh,
            &all_shutdown_features()
        ));
    }

    #[test]
    fn is_standard_shutdown_script_accepts_anysegwit() {
        // BOLT 2 anysegwit: witness versions 1..=16 with a 2..=40 byte program.
        for v in OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8() {
            for len in [2u8, 20, 40] {
                // For 1..=75, the push opcode byte equals the pushed length.
                let mut anysegwit = vec![v, len];
                anysegwit.extend_from_slice(&vec![0x00; usize::from(len)]);
                // Gated on option_shutdown_anysegwit; option_simple_close alone doesn't help.
                assert!(!is_standard_shutdown_script(&anysegwit, &no_features()));
                assert!(!is_standard_shutdown_script(
                    &anysegwit,
                    &with_simple_close()
                ));
                assert!(is_standard_shutdown_script(&anysegwit, &with_anysegwit()));
                assert!(is_standard_shutdown_script(
                    &anysegwit,
                    &all_shutdown_features()
                ));
            }
        }
    }

    #[test]
    fn is_standard_shutdown_script_accepts_simple_close_op_return() {
        // OP_RETURN + a single direct push of 6..=75 bytes.
        for len in [6u8, 40, 75] {
            let mut spk = vec![OP_RETURN.to_u8(), len];
            spk.extend_from_slice(&vec![0xab; usize::from(len)]);
            // Gated on option_simple_close; option_shutdown_anysegwit alone doesn't help.
            assert!(!is_standard_shutdown_script(&spk, &no_features()));
            assert!(!is_standard_shutdown_script(&spk, &with_anysegwit()));
            assert!(is_standard_shutdown_script(&spk, &with_simple_close()));
            assert!(is_standard_shutdown_script(&spk, &all_shutdown_features()));
        }

        // OP_RETURN + OP_PUSHDATA1 + a single push of 76..=80 bytes.
        for len in [76u8, 80] {
            let mut spk = vec![OP_RETURN.to_u8(), OP_PUSHDATA1.to_u8(), len];
            spk.extend_from_slice(&vec![0xab; usize::from(len)]);
            assert!(!is_standard_shutdown_script(&spk, &no_features()));
            assert!(is_standard_shutdown_script(&spk, &with_simple_close()));
        }
    }

    #[test]
    fn is_standard_shutdown_script_rejects_legacy() {
        // Legacy P2PKH/P2SH are non-standard even with all features negotiated.
        //
        // TODO: Oracle verification depends on if we're verifying a target's message or our own
        // message. Legacy scripts MAY be accepted by receivers, but MUST NOT be sent.
        let mut p2pkh = vec![OP_DUP.to_u8(), OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()];
        p2pkh.extend_from_slice(&[0x11; 20]);
        p2pkh.extend_from_slice(&[OP_EQUALVERIFY.to_u8(), OP_CHECKSIG.to_u8()]);
        assert!(!is_standard_shutdown_script(
            &p2pkh,
            &all_shutdown_features()
        ));

        let mut p2sh = vec![OP_HASH160.to_u8(), OP_PUSHBYTES_20.to_u8()];
        p2sh.extend_from_slice(&[0x22; 20]);
        p2sh.push(OP_EQUAL.to_u8());
        assert!(!is_standard_shutdown_script(
            &p2sh,
            &all_shutdown_features()
        ));
    }

    #[test]
    fn is_standard_shutdown_script_rejects_invalid_segwit() {
        // Witness version 0 with a non-{20,32} program length
        let v0 = OP_PUSHBYTES_0.to_u8();
        let mut witness_v0_invalid_prog_length_spk = vec![v0, OP_PUSHBYTES_21.to_u8()];
        witness_v0_invalid_prog_length_spk.extend_from_slice(&[0x00; 21]);
        assert!(!is_standard_shutdown_script(
            &witness_v0_invalid_prog_length_spk,
            &all_shutdown_features()
        ));

        // Witness version 1 with a program length just outside 2..=40
        for len in [1u8, 41] {
            let mut witness_v1_invalid_prog_length_spk = vec![OP_PUSHNUM_1.to_u8(), len];
            witness_v1_invalid_prog_length_spk.extend_from_slice(&vec![0x00; usize::from(len)]);
            assert!(!is_standard_shutdown_script(
                &witness_v1_invalid_prog_length_spk,
                &all_shutdown_features()
            ));
        }

        // Length prefix disagrees with the actual program length
        let mut witness_v0_invalid_length_prefix_spk = vec![v0, OP_PUSHBYTES_20.to_u8()];
        witness_v0_invalid_length_prefix_spk.extend_from_slice(&[0x00; 19]);
        assert!(!is_standard_shutdown_script(
            &witness_v0_invalid_length_prefix_spk,
            &all_shutdown_features()
        ));
    }

    #[test]
    fn is_standard_shutdown_script_rejects_invalid_simple_close_op_return() {
        // Rejected even with option_simple_close negotiated.

        // Bare OP_RETURN with no push.
        assert!(!is_standard_shutdown_script(
            &[OP_RETURN.to_u8()],
            &all_shutdown_features()
        ));

        // Direct push below the 6-byte minimum.
        let mut too_short = vec![OP_RETURN.to_u8(), 5];
        too_short.extend_from_slice(&[0xab; 5]);
        assert!(!is_standard_shutdown_script(
            &too_short,
            &all_shutdown_features()
        ));

        // Push length disagrees with the trailing data (claims 6, has 5).
        let mut len_mismatch = vec![OP_RETURN.to_u8(), 6];
        len_mismatch.extend_from_slice(&[0xab; 5]);
        assert!(!is_standard_shutdown_script(
            &len_mismatch,
            &all_shutdown_features()
        ));

        // Extra bytes after the single push (multiple pushes not allowed).
        let mut trailing = vec![OP_RETURN.to_u8(), 6];
        trailing.extend_from_slice(&[0xab; 6]);
        trailing.extend_from_slice(&[OP_PUSHBYTES_1.to_u8(), 0xff]);
        assert!(!is_standard_shutdown_script(
            &trailing,
            &all_shutdown_features()
        ));

        // OP_PUSHDATA1 with a length above the 80-byte maximum.
        let mut too_long = vec![OP_RETURN.to_u8(), OP_PUSHDATA1.to_u8(), 81];
        too_long.extend_from_slice(&[0xab; 81]);
        assert!(!is_standard_shutdown_script(
            &too_long,
            &all_shutdown_features()
        ));

        // Non-minimal push: OP_PUSHDATA1 used for less than 76 bytes.
        let mut non_minimal = vec![OP_RETURN.to_u8(), OP_PUSHDATA1.to_u8(), 75];
        non_minimal.extend_from_slice(&[0xab; 75]);
        assert!(!is_standard_shutdown_script(
            &non_minimal,
            &all_shutdown_features()
        ));
    }

    #[test]
    fn is_standard_shutdown_script_rejects_other() {
        // Malformed scripts that are always rejected.
        let empty_spk = vec![];
        assert!(!is_standard_shutdown_script(
            &empty_spk,
            &all_shutdown_features()
        ));

        let random_spk = vec![0x00, 0x01, 0x02];
        assert!(!is_standard_shutdown_script(
            &random_spk,
            &all_shutdown_features()
        ));
    }
}
