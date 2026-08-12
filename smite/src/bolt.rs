//! BOLT message encoding and decoding.
//!
//! This module implements encoding and decoding for Lightning Network
//! protocol messages as specified in the BOLT specifications.

mod accept_channel;
mod accept_channel2;
mod announcement_signatures;
mod attribution_data;
mod channel_announcement;
mod channel_ready;
mod channel_update;
mod closing_complete;
mod closing_sig;
mod commitment_signed;
mod error;
mod funding_created;
mod funding_signed;
mod gossip_timestamp_filter;
mod init;
mod node_announcement;
mod open_channel;
mod open_channel2;
mod ping;
mod pong;
mod revoke_and_ack;
mod shutdown;
mod tlv;
mod tx_abort;
mod tx_ack_rbf;
mod tx_add_input;
mod tx_complete;
mod tx_init_rbf;
mod tx_remove_input;
mod tx_remove_output;
mod types;
mod update_add_htlc;
mod update_fail_htlc;
mod update_fail_malformed_htlc;
mod update_fulfill_htlc;
mod warning;
mod wire;

pub use accept_channel::{AcceptChannel, AcceptChannelTlvs};
pub use accept_channel2::{AcceptChannel2, AcceptChannel2Tlvs};
pub use announcement_signatures::AnnouncementSignatures;
pub use attribution_data::{AttributionData, TruncatedHmac};
pub use channel_announcement::ChannelAnnouncement;
pub use channel_ready::{ChannelReady, ChannelReadyTlvs};
pub use channel_update::ChannelUpdate;
pub use closing_complete::{ClosingComplete, ClosingTlvs};
pub use closing_sig::ClosingSig;
pub use commitment_signed::{CommitmentSigned, CommitmentSignedTlvs};
pub use error::Error;
pub use funding_created::FundingCreated;
pub use funding_signed::FundingSigned;
pub use gossip_timestamp_filter::GossipTimestampFilter;
pub use init::{Init, InitTlvs};
pub use node_announcement::NodeAnnouncement;
pub use open_channel::{OpenChannel, OpenChannelTlvs};
pub use open_channel2::{OpenChannel2, OpenChannel2Tlvs};
pub use ping::Ping;
pub use pong::Pong;
pub use revoke_and_ack::RevokeAndAck;
pub use shutdown::Shutdown;
pub use tlv::{TlvRecord, TlvStream};
pub use tx_abort::TxAbort;
pub use tx_ack_rbf::{TxAckRbf, TxAckRbfTlvs};
pub use tx_add_input::{TxAddInput, TxAddInputTlvs};
pub use tx_complete::TxComplete;
pub use tx_init_rbf::{TxInitRbf, TxInitRbfTlvs};
pub use tx_remove_input::TxRemoveInput;
pub use tx_remove_output::TxRemoveOutput;
pub use types::{
    BigSize, CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, ChannelId, MAX_MESSAGE_SIZE,
    PAYMENT_ONION_PACKET_SIZE, PER_COMMITMENT_SECRET_SIZE, PUBLIC_KEY_SIZE, SHA256_HASH_SIZE,
    SHORT_CHANNEL_ID_SIZE, ShortChannelId, TXID_SIZE, Tu32, Tu64,
};
pub use update_add_htlc::{UpdateAddHtlc, UpdateAddHtlcTlvs};
pub use update_fail_htlc::{UpdateFailHtlc, UpdateFailHtlcTlvs};
pub use update_fail_malformed_htlc::UpdateFailMalformedHtlc;
pub use update_fulfill_htlc::{UpdateFulfillHtlc, UpdateFulfillHtlcTlvs};
pub use warning::Warning;
pub use wire::{EmptyTlv, WireFormat};

/// Errors that can occur during BOLT message encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoltError {
    // General decoding errors
    /// Not enough bytes to decode (message or field truncated)
    #[error("TRUNCATED expected {expected} got {actual}")]
    Truncated { expected: usize, actual: usize },
    /// Unknown even message type (must close connection per BOLT 1)
    #[error("UNKNOWN_EVEN_TYPE {0}")]
    UnknownEvenType(u16),
    /// The bytes do not represent a valid compressed secp256k1 public key
    #[error("INVALID_PUBLIC_KEY {}", hex::encode(.0))]
    InvalidPublicKey([u8; PUBLIC_KEY_SIZE]),
    /// The bytes do not represent a valid compact ECDSA signature
    #[error("INVALID_SIGNATURE {}", hex::encode(.0))]
    InvalidSignature([u8; COMPACT_SIGNATURE_SIZE]),

    // BigSize errors
    /// `BigSize` not minimally encoded
    #[error("BIGSIZE_NOT_MINIMAL")]
    BigSizeNotMinimal,
    /// `BigSize` truncated (unexpected EOF)
    #[error("BIGSIZE_TRUNCATED")]
    BigSizeTruncated,

    // Truncated integer errors
    /// Truncated integer (`tu32`/`tu64`) wider than its maximum encoding
    #[error("TRUNCATED_INT_TOO_LONG max {max} got {actual}")]
    TruncatedIntTooLong { max: usize, actual: usize },
    /// Truncated integer (`tu32`/`tu64`) has a leading zero byte
    #[error("TRUNCATED_INT_NOT_MINIMAL")]
    TruncatedIntNotMinimal,

    // TLV errors
    /// TLV type not in strictly increasing order
    #[error("TLV_NOT_INCREASING previous {previous} current {current}")]
    TlvNotIncreasing { previous: u64, current: u64 },
    /// TLV length exceeds remaining bytes
    #[error("TLV_LENGTH_OVERFLOW")]
    TlvLengthOverflow,
    /// Unknown even TLV type (must reject per BOLT 1)
    #[error("TLV_UNKNOWN_EVEN_TYPE {0}")]
    TlvUnknownEvenType(u64),
    /// TLV value longer than the known encoding for its type
    #[error("TLV_TRAILING_BYTES type {tlv_type} expected {expected} got {actual}")]
    TlvTrailingBytes {
        tlv_type: u64,
        expected: usize,
        actual: usize,
    },
}

/// A BOLT message type number that displays as `name(type)`, e.g.
/// `open_channel(32)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageType(u16);

impl MessageType {
    /// Warning message (BOLT 1).
    pub const WARNING: MessageType = MessageType(1);
    /// Init message (BOLT 1).
    pub const INIT: MessageType = MessageType(16);
    /// Error message (BOLT 1).
    pub const ERROR: MessageType = MessageType(17);
    /// Ping message (BOLT 1).
    pub const PING: MessageType = MessageType(18);
    /// Pong message (BOLT 1).
    pub const PONG: MessageType = MessageType(19);
    /// `open_channel` message (BOLT 2).
    pub const OPEN_CHANNEL: MessageType = MessageType(32);
    /// `accept_channel` message (BOLT 2).
    pub const ACCEPT_CHANNEL: MessageType = MessageType(33);
    /// `funding_created` message (BOLT 2).
    pub const FUNDING_CREATED: MessageType = MessageType(34);
    /// `funding_signed` message (BOLT 2).
    pub const FUNDING_SIGNED: MessageType = MessageType(35);
    /// `channel_ready` message (BOLT 2).
    pub const CHANNEL_READY: MessageType = MessageType(36);
    /// Shutdown message (BOLT 2).
    pub const SHUTDOWN: MessageType = MessageType(38);
    /// `closing_complete` message (BOLT 2).
    pub const CLOSING_COMPLETE: MessageType = MessageType(40);
    /// `closing_sig` message (BOLT 2).
    pub const CLOSING_SIG: MessageType = MessageType(41);
    /// `open_channel2` message (BOLT 2).
    pub const OPEN_CHANNEL2: MessageType = MessageType(64);
    /// `accept_channel2` message (BOLT 2).
    pub const ACCEPT_CHANNEL2: MessageType = MessageType(65);
    /// `tx_add_input` message (BOLT 2).
    pub const TX_ADD_INPUT: MessageType = MessageType(66);
    /// `tx_remove_input` message (BOLT 2).
    pub const TX_REMOVE_INPUT: MessageType = MessageType(68);
    /// `tx_remove_output` message (BOLT 2).
    pub const TX_REMOVE_OUTPUT: MessageType = MessageType(69);
    /// `tx_complete` message (BOLT 2).
    pub const TX_COMPLETE: MessageType = MessageType(70);
    /// `tx_init_rbf` message (BOLT 2).
    pub const TX_INIT_RBF: MessageType = MessageType(72);
    /// `tx_ack_rbf` message (BOLT 2).
    pub const TX_ACK_RBF: MessageType = MessageType(73);
    /// `tx_abort` message (BOLT 2).
    pub const TX_ABORT: MessageType = MessageType(74);
    /// `update_add_htlc` message (BOLT 2).
    pub const UPDATE_ADD_HTLC: MessageType = MessageType(128);
    /// `update_fulfill_htlc` message (BOLT 2).
    pub const UPDATE_FULFILL_HTLC: MessageType = MessageType(130);
    /// `update_fail_htlc` message (BOLT 2).
    pub const UPDATE_FAIL_HTLC: MessageType = MessageType(131);
    /// `commitment_signed` message (BOLT 2).
    pub const COMMITMENT_SIGNED: MessageType = MessageType(132);
    /// `revoke_and_ack` message (BOLT 2).
    pub const REVOKE_AND_ACK: MessageType = MessageType(133);
    /// `update_fail_malformed_htlc` message (BOLT 2).
    pub const UPDATE_FAIL_MALFORMED_HTLC: MessageType = MessageType(135);
    /// `channel_announcement` message (BOLT 7).
    pub const CHANNEL_ANNOUNCEMENT: MessageType = MessageType(256);
    /// `node_announcement` message (BOLT 7).
    pub const NODE_ANNOUNCEMENT: MessageType = MessageType(257);
    /// `channel_update` message (BOLT 7).
    pub const CHANNEL_UPDATE: MessageType = MessageType(258);
    /// `announcement_signatures` message (BOLT 7).
    pub const ANNOUNCEMENT_SIGNATURES: MessageType = MessageType(259);
    /// Gossip timestamp filter message (BOLT 7).
    pub const GOSSIP_TIMESTAMP_FILTER: MessageType = MessageType(265);

    /// Constructs a message type from its raw wire number.
    #[must_use]
    pub const fn from_u16(ty: u16) -> Self {
        Self(ty)
    }

    /// Returns the raw wire number.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the BOLT name for this message type (e.g. `open_channel`), or
    /// `unknown` if the type is not recognized.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::WARNING => "warning",
            Self::INIT => "init",
            Self::ERROR => "error",
            Self::PING => "ping",
            Self::PONG => "pong",
            Self::OPEN_CHANNEL => "open_channel",
            Self::ACCEPT_CHANNEL => "accept_channel",
            Self::FUNDING_CREATED => "funding_created",
            Self::FUNDING_SIGNED => "funding_signed",
            Self::CHANNEL_READY => "channel_ready",
            Self::SHUTDOWN => "shutdown",
            Self::CLOSING_COMPLETE => "closing_complete",
            Self::CLOSING_SIG => "closing_sig",
            Self::OPEN_CHANNEL2 => "open_channel2",
            Self::ACCEPT_CHANNEL2 => "accept_channel2",
            Self::TX_ADD_INPUT => "tx_add_input",
            Self::TX_REMOVE_INPUT => "tx_remove_input",
            Self::TX_REMOVE_OUTPUT => "tx_remove_output",
            Self::TX_COMPLETE => "tx_complete",
            Self::TX_INIT_RBF => "tx_init_rbf",
            Self::TX_ACK_RBF => "tx_ack_rbf",
            Self::TX_ABORT => "tx_abort",
            Self::UPDATE_ADD_HTLC => "update_add_htlc",
            Self::UPDATE_FULFILL_HTLC => "update_fulfill_htlc",
            Self::UPDATE_FAIL_HTLC => "update_fail_htlc",
            Self::COMMITMENT_SIGNED => "commitment_signed",
            Self::REVOKE_AND_ACK => "revoke_and_ack",
            Self::UPDATE_FAIL_MALFORMED_HTLC => "update_fail_malformed_htlc",
            Self::CHANNEL_ANNOUNCEMENT => "channel_announcement",
            Self::NODE_ANNOUNCEMENT => "node_announcement",
            Self::CHANNEL_UPDATE => "channel_update",
            Self::ANNOUNCEMENT_SIGNATURES => "announcement_signatures",
            Self::GOSSIP_TIMESTAMP_FILTER => "gossip_timestamp_filter",
            _ => "unknown",
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name(), self.0)
    }
}

/// A decoded BOLT message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// Warning message (type 1).
    Warning(Warning),
    /// Init message (type 16).
    Init(Init),
    /// Error message (type 17).
    Error(Error),
    /// Ping message (type 18).
    Ping(Ping),
    /// Pong message (type 19).
    Pong(Pong),
    /// `open_channel` message (type 32).
    OpenChannel(OpenChannel),
    /// `accept_channel` message (type 33).
    AcceptChannel(AcceptChannel),
    /// `funding_created` message (type 34).
    FundingCreated(FundingCreated),
    /// `funding_signed` message (type 35).
    FundingSigned(FundingSigned),
    /// `channel_ready` message (type 36).
    ChannelReady(ChannelReady),
    /// Shutdown message (type 38).
    Shutdown(Shutdown),
    /// `closing_complete` message (type 40).
    ClosingComplete(ClosingComplete),
    /// `closing_sig` message (type 41).
    ClosingSig(ClosingSig),
    /// `open_channel2` message (type 64).
    OpenChannel2(OpenChannel2),
    /// `accept_channel2` message (type 65).
    AcceptChannel2(AcceptChannel2),
    /// `tx_add_input` message (type 66).
    TxAddInput(TxAddInput),
    /// `tx_remove_input` message (type 68).
    TxRemoveInput(TxRemoveInput),
    /// `tx_remove_output` message (type 69).
    TxRemoveOutput(TxRemoveOutput),
    /// `tx_complete` message (type 70).
    TxComplete(TxComplete),
    /// `tx_init_rbf` message (type 72).
    TxInitRbf(TxInitRbf),
    /// `tx_ack_rbf` message (type 73).
    TxAckRbf(TxAckRbf),
    /// `tx_abort` message (type 74).
    TxAbort(TxAbort),
    /// `update_add_htlc` message (type 128).
    UpdateAddHtlc(UpdateAddHtlc),
    /// `update_fulfill_htlc` message (type 130).
    UpdateFulfillHtlc(UpdateFulfillHtlc),
    /// `update_fail_htlc` message (type 131).
    UpdateFailHtlc(UpdateFailHtlc),
    /// `commitment_signed` message (type 132).
    CommitmentSigned(CommitmentSigned),
    /// `revoke_and_ack` message (type 133).
    RevokeAndAck(RevokeAndAck),
    /// `update_fail_malformed_htlc` message (type 135).
    UpdateFailMalformedHtlc(UpdateFailMalformedHtlc),
    /// `channel_announcement` message (type 256).
    ChannelAnnouncement(ChannelAnnouncement),
    /// `node_announcement` message (type 257).
    NodeAnnouncement(NodeAnnouncement),
    /// `channel_update` message (type 258).
    ChannelUpdate(ChannelUpdate),
    /// `announcement_signatures` message (type 259).
    AnnouncementSignatures(AnnouncementSignatures),
    /// Gossip timestamp filter message (type 265).
    GossipTimestampFilter(GossipTimestampFilter),
    /// Unknown message type.
    ///
    /// Stored for odd types that we don't recognize but must accept.
    /// Even unknown types cause decode to fail.
    Unknown {
        /// The message type.
        msg_type: u16,
        /// The raw payload (without type prefix).
        payload: Vec<u8>,
    },
}

impl Message {
    /// Returns the message type.
    #[must_use]
    pub fn msg_type(&self) -> MessageType {
        match self {
            Self::Warning(_) => MessageType::WARNING,
            Self::Init(_) => MessageType::INIT,
            Self::Error(_) => MessageType::ERROR,
            Self::Ping(_) => MessageType::PING,
            Self::Pong(_) => MessageType::PONG,
            Self::OpenChannel(_) => MessageType::OPEN_CHANNEL,
            Self::AcceptChannel(_) => MessageType::ACCEPT_CHANNEL,
            Self::FundingCreated(_) => MessageType::FUNDING_CREATED,
            Self::FundingSigned(_) => MessageType::FUNDING_SIGNED,
            Self::ChannelReady(_) => MessageType::CHANNEL_READY,
            Self::Shutdown(_) => MessageType::SHUTDOWN,
            Self::ClosingComplete(_) => MessageType::CLOSING_COMPLETE,
            Self::ClosingSig(_) => MessageType::CLOSING_SIG,
            Self::OpenChannel2(_) => MessageType::OPEN_CHANNEL2,
            Self::AcceptChannel2(_) => MessageType::ACCEPT_CHANNEL2,
            Self::TxAddInput(_) => MessageType::TX_ADD_INPUT,
            Self::TxRemoveInput(_) => MessageType::TX_REMOVE_INPUT,
            Self::TxRemoveOutput(_) => MessageType::TX_REMOVE_OUTPUT,
            Self::TxComplete(_) => MessageType::TX_COMPLETE,
            Self::TxInitRbf(_) => MessageType::TX_INIT_RBF,
            Self::TxAckRbf(_) => MessageType::TX_ACK_RBF,
            Self::TxAbort(_) => MessageType::TX_ABORT,
            Self::UpdateAddHtlc(_) => MessageType::UPDATE_ADD_HTLC,
            Self::UpdateFulfillHtlc(_) => MessageType::UPDATE_FULFILL_HTLC,
            Self::UpdateFailHtlc(_) => MessageType::UPDATE_FAIL_HTLC,
            Self::CommitmentSigned(_) => MessageType::COMMITMENT_SIGNED,
            Self::RevokeAndAck(_) => MessageType::REVOKE_AND_ACK,
            Self::UpdateFailMalformedHtlc(_) => MessageType::UPDATE_FAIL_MALFORMED_HTLC,
            Self::ChannelAnnouncement(_) => MessageType::CHANNEL_ANNOUNCEMENT,
            Self::NodeAnnouncement(_) => MessageType::NODE_ANNOUNCEMENT,
            Self::ChannelUpdate(_) => MessageType::CHANNEL_UPDATE,
            Self::AnnouncementSignatures(_) => MessageType::ANNOUNCEMENT_SIGNATURES,
            Self::GossipTimestampFilter(_) => MessageType::GOSSIP_TIMESTAMP_FILTER,
            Self::Unknown { msg_type, .. } => MessageType(*msg_type),
        }
    }

    /// Encodes to wire format (with 2-byte message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.msg_type().as_u16().write(&mut out);
        match self {
            Self::Warning(m) => out.extend(m.encode()),
            Self::Init(m) => out.extend(m.encode()),
            Self::Error(m) => out.extend(m.encode()),
            Self::Ping(m) => out.extend(m.encode()),
            Self::Pong(m) => out.extend(m.encode()),
            Self::OpenChannel(m) => out.extend(m.encode()),
            Self::AcceptChannel(m) => out.extend(m.encode()),
            Self::FundingCreated(m) => out.extend(m.encode()),
            Self::FundingSigned(m) => out.extend(m.encode()),
            Self::ChannelReady(m) => out.extend(m.encode()),
            Self::Shutdown(m) => out.extend(m.encode()),
            Self::ClosingComplete(m) => out.extend(m.encode()),
            Self::ClosingSig(m) => out.extend(m.encode()),
            Self::OpenChannel2(m) => out.extend(m.encode()),
            Self::AcceptChannel2(m) => out.extend(m.encode()),
            Self::TxAddInput(m) => out.extend(m.encode()),
            Self::TxRemoveInput(m) => out.extend(m.encode()),
            Self::TxRemoveOutput(m) => out.extend(m.encode()),
            Self::TxComplete(m) => out.extend(m.encode()),
            Self::TxInitRbf(m) => out.extend(m.encode()),
            Self::TxAckRbf(m) => out.extend(m.encode()),
            Self::TxAbort(m) => out.extend(m.encode()),
            Self::UpdateAddHtlc(m) => out.extend(m.encode()),
            Self::UpdateFulfillHtlc(m) => out.extend(m.encode()),
            Self::UpdateFailHtlc(m) => out.extend(m.encode()),
            Self::CommitmentSigned(m) => out.extend(m.encode()),
            Self::RevokeAndAck(m) => out.extend(m.encode()),
            Self::UpdateFailMalformedHtlc(m) => out.extend(m.encode()),
            Self::ChannelAnnouncement(m) => out.extend(m.encode()),
            Self::NodeAnnouncement(m) => out.extend(m.encode()),
            Self::ChannelUpdate(m) => out.extend(m.encode()),
            Self::AnnouncementSignatures(m) => out.extend(m.encode()),
            Self::GossipTimestampFilter(m) => out.extend(m.encode()),
            Self::Unknown { payload, .. } => out.extend(payload),
        }
        out
    }

    /// Decodes from wire format (with 2-byte message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the message is too short, `UnknownEvenType` if
    /// the message type is an unknown even number, or a decode error from the
    /// specific message type.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = data;
        let msg_type = u16::read(&mut cursor)?;

        match MessageType(msg_type) {
            MessageType::WARNING => Ok(Self::Warning(Warning::decode(cursor)?)),
            MessageType::INIT => Ok(Self::Init(Init::decode(cursor)?)),
            MessageType::ERROR => Ok(Self::Error(Error::decode(cursor)?)),
            MessageType::PING => Ok(Self::Ping(Ping::decode(cursor)?)),
            MessageType::PONG => Ok(Self::Pong(Pong::decode(cursor)?)),
            MessageType::OPEN_CHANNEL => Ok(Self::OpenChannel(OpenChannel::decode(cursor)?)),
            MessageType::ACCEPT_CHANNEL => Ok(Self::AcceptChannel(AcceptChannel::decode(cursor)?)),
            MessageType::FUNDING_CREATED => {
                Ok(Self::FundingCreated(FundingCreated::decode(cursor)?))
            }
            MessageType::FUNDING_SIGNED => Ok(Self::FundingSigned(FundingSigned::decode(cursor)?)),
            MessageType::CHANNEL_READY => Ok(Self::ChannelReady(ChannelReady::decode(cursor)?)),
            MessageType::SHUTDOWN => Ok(Self::Shutdown(Shutdown::decode(cursor)?)),
            MessageType::CLOSING_COMPLETE => {
                Ok(Self::ClosingComplete(ClosingComplete::decode(cursor)?))
            }
            MessageType::CLOSING_SIG => Ok(Self::ClosingSig(ClosingSig::decode(cursor)?)),
            MessageType::OPEN_CHANNEL2 => Ok(Self::OpenChannel2(OpenChannel2::decode(cursor)?)),
            MessageType::ACCEPT_CHANNEL2 => {
                Ok(Self::AcceptChannel2(AcceptChannel2::decode(cursor)?))
            }
            MessageType::TX_ADD_INPUT => Ok(Self::TxAddInput(TxAddInput::decode(cursor)?)),
            MessageType::TX_REMOVE_INPUT => Ok(Self::TxRemoveInput(TxRemoveInput::decode(cursor)?)),
            MessageType::TX_REMOVE_OUTPUT => {
                Ok(Self::TxRemoveOutput(TxRemoveOutput::decode(cursor)?))
            }
            MessageType::TX_COMPLETE => Ok(Self::TxComplete(TxComplete::decode(cursor)?)),
            MessageType::TX_INIT_RBF => Ok(Self::TxInitRbf(TxInitRbf::decode(cursor)?)),
            MessageType::TX_ACK_RBF => Ok(Self::TxAckRbf(TxAckRbf::decode(cursor)?)),
            MessageType::TX_ABORT => Ok(Self::TxAbort(TxAbort::decode(cursor)?)),
            MessageType::UPDATE_ADD_HTLC => Ok(Self::UpdateAddHtlc(UpdateAddHtlc::decode(cursor)?)),
            MessageType::UPDATE_FULFILL_HTLC => {
                Ok(Self::UpdateFulfillHtlc(UpdateFulfillHtlc::decode(cursor)?))
            }
            MessageType::UPDATE_FAIL_HTLC => {
                Ok(Self::UpdateFailHtlc(UpdateFailHtlc::decode(cursor)?))
            }
            MessageType::COMMITMENT_SIGNED => {
                Ok(Self::CommitmentSigned(CommitmentSigned::decode(cursor)?))
            }
            MessageType::REVOKE_AND_ACK => Ok(Self::RevokeAndAck(RevokeAndAck::decode(cursor)?)),
            MessageType::UPDATE_FAIL_MALFORMED_HTLC => Ok(Self::UpdateFailMalformedHtlc(
                UpdateFailMalformedHtlc::decode(cursor)?,
            )),
            MessageType::CHANNEL_ANNOUNCEMENT => Ok(Self::ChannelAnnouncement(
                ChannelAnnouncement::decode(cursor)?,
            )),
            MessageType::NODE_ANNOUNCEMENT => {
                Ok(Self::NodeAnnouncement(NodeAnnouncement::decode(cursor)?))
            }
            MessageType::CHANNEL_UPDATE => Ok(Self::ChannelUpdate(ChannelUpdate::decode(cursor)?)),
            MessageType::ANNOUNCEMENT_SIGNATURES => Ok(Self::AnnouncementSignatures(
                AnnouncementSignatures::decode(cursor)?,
            )),
            MessageType::GOSSIP_TIMESTAMP_FILTER => Ok(Self::GossipTimestampFilter(
                GossipTimestampFilter::decode(cursor)?,
            )),
            _ => {
                // Unknown even types must be rejected per BOLT 1
                if msg_type % 2 == 0 {
                    Err(BoltError::UnknownEvenType(msg_type))
                } else {
                    Ok(Self::Unknown {
                        msg_type,
                        payload: cursor.to_vec(),
                    })
                }
            }
        }
    }
}

/// Creates a raw message with the given type and payload.
///
/// This is useful for fuzzing - it allows sending arbitrary payloads
/// with any message type, bypassing normal encoding.
#[must_use]
pub fn message_with_type(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    msg_type.write(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::ecdsa::Signature;
    use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
    use types::CHAIN_HASH_SIZE;

    // Tests ordered by message type number: Warning(1), Init(16), Error(17), Ping(18), Pong(19)

    #[test]
    fn message_warning_roundtrip() {
        let warning = Warning::all_channels("test warning");
        let msg = Message::Warning(warning.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Warning(warning));
    }

    #[test]
    fn message_init_roundtrip() {
        let init = Init::empty();
        let msg = Message::Init(init.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Init(init));
    }

    #[test]
    fn message_error_roundtrip() {
        let error = Error::all_channels("test error");
        let msg = Message::Error(error.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Error(error));
    }

    #[test]
    fn message_ping_roundtrip() {
        let ping = Ping::new(10);
        let msg = Message::Ping(ping.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Ping(ping));
    }

    #[test]
    fn message_pong_roundtrip() {
        let pong = Pong::new(5);
        let msg = Message::Pong(pong.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Pong(pong));
    }

    /// Valid `OpenChannel` message for testing.
    fn sample_open_channel() -> OpenChannel {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        OpenChannel {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_satoshis: 100_000,
            push_msat: 0,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            feerate_per_kw: 253,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            channel_flags: 0x01,
            tlvs: OpenChannelTlvs::default(),
        }
    }

    #[test]
    fn message_open_channel_roundtrip() {
        let open = sample_open_channel();
        let msg = Message::OpenChannel(open.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::OpenChannel(open));
    }

    /// Valid `AcceptChannel` message for testing.
    fn sample_accept_channel() -> AcceptChannel {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        AcceptChannel {
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 3,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            tlvs: AcceptChannelTlvs::default(),
        }
    }

    #[test]
    fn message_accept_channel_roundtrip() {
        let accept = sample_accept_channel();
        let msg = Message::AcceptChannel(accept.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::AcceptChannel(accept));
    }

    /// Valid `FundingCreated` message for testing.
    fn sample_funding_created() -> FundingCreated {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = secp256k1::Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingCreated {
            temporary_channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            funding_txid: Txid::from_byte_array([0xcc; TXID_SIZE]),
            funding_output_index: 0,
            signature: sig,
        }
    }

    #[test]
    fn message_funding_created_roundtrip() {
        let fc = sample_funding_created();
        let msg = Message::FundingCreated(fc.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::FundingCreated(fc));
    }

    /// Valid `FundingSigned` message for testing.
    fn sample_funding_signed() -> FundingSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let msg = secp256k1::Message::from_digest([0xaa; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        FundingSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            signature: sig,
        }
    }

    #[test]
    fn message_funding_signed_roundtrip() {
        let fs = sample_funding_signed();
        let msg = Message::FundingSigned(fs.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::FundingSigned(fs));
    }

    /// Valid `ChannelReady` message for testing.
    fn sample_channel_ready() -> ChannelReady {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        ChannelReady {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            second_per_commitment_point: pk,
            tlvs: ChannelReadyTlvs::default(),
        }
    }

    #[test]
    fn message_channel_ready_roundtrip() {
        let cr = sample_channel_ready();
        let msg = Message::ChannelReady(cr.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::ChannelReady(cr));
    }

    #[test]
    fn message_shutdown_roundtrip() {
        let shutdown = Shutdown::for_channel(ChannelId::default(), vec![0x00, 0x14, 0xab, 0xcd]);
        let msg = Message::Shutdown(shutdown.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Shutdown(shutdown));
    }

    /// Valid `ClosingComplete` message for testing.
    fn sample_closing_complete() -> ClosingComplete {
        let sig1 = Signature::from_compact(&[1u8; 64]).expect("valid signature");
        let sig2 = Signature::from_compact(&[2u8; 64]).expect("valid signature");
        let sig3 = Signature::from_compact(&[3u8; 64]).expect("valid signature");
        let tlvs = ClosingTlvs {
            closer_output_only: Some(sig1),
            closee_output_only: Some(sig2),
            closer_and_closee_outputs: Some(sig3),
        };
        ClosingComplete {
            channel_id: ChannelId::new([0xaa; 32]),
            closer_scriptpubkey: vec![0x00; 22],
            closee_scriptpubkey: vec![0x11; 22],
            fee_satoshis: 1000,
            locktime: 0,
            tlvs,
        }
    }

    #[test]
    fn message_closing_complete_roundtrip() {
        let cc = sample_closing_complete();
        let msg = Message::ClosingComplete(cc.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::ClosingComplete(cc));
    }

    /// Valid `ClosingSig` message for testing.
    fn sample_closing_sig() -> ClosingSig {
        let cc = sample_closing_complete();
        ClosingSig {
            channel_id: cc.channel_id,
            closer_scriptpubkey: cc.closer_scriptpubkey,
            closee_scriptpubkey: cc.closee_scriptpubkey,
            fee_satoshis: cc.fee_satoshis,
            locktime: cc.locktime,
            tlvs: cc.tlvs,
        }
    }

    #[test]
    fn message_closing_sig_roundtrip() {
        let cs = sample_closing_sig();
        let msg = Message::ClosingSig(cs.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::ClosingSig(cs));
    }

    /// Valid `OpenChannel2` message for testing.
    fn sample_open_channel2() -> OpenChannel2 {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        OpenChannel2 {
            chain_hash: [0xaa; CHAIN_HASH_SIZE],
            temporary_channel_id: ChannelId::new([0xbb; 32]),
            funding_feerate_perkw: 2_500,
            commitment_feerate_perkw: 253,
            funding_satoshis: 100_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            htlc_minimum_msat: 1_000,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            locktime: 800_000,
            funding_pubkey: pk,
            revocation_basepoint: pk,
            payment_basepoint: pk,
            delayed_payment_basepoint: pk,
            htlc_basepoint: pk,
            first_per_commitment_point: pk,
            second_per_commitment_point: pk,
            channel_flags: 0x01,
            tlvs: OpenChannel2Tlvs::default(),
        }
    }

    #[test]
    fn message_open_channel2_roundtrip() {
        let open = sample_open_channel2();
        let msg = Message::OpenChannel2(open.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::OpenChannel2(open));
    }

    /// Valid `AcceptChannel2` message for testing.
    fn sample_accept_channel2(tlvs: Option<AcceptChannel2Tlvs>) -> AcceptChannel2 {
        let secp = Secp256k1::new();
        let secrets: [[u8; 32]; 7] = [
            [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32], [0x66; 32], [0x77; 32],
        ];
        let keys: Vec<PublicKey> = secrets
            .iter()
            .map(|s| {
                let sk = SecretKey::from_slice(s).expect("valid secret");
                PublicKey::from_secret_key(&secp, &sk)
            })
            .collect();

        AcceptChannel2 {
            temporary_channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            funding_satoshis: 50_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
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
            second_per_commitment_point: keys[6],
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn message_accept_channel2_roundtrip() {
        let accept2 = sample_accept_channel2(None);
        let msg = Message::AcceptChannel2(accept2.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::AcceptChannel2(accept2));
    }

    /// Valid `TxAddInput` message for testing.
    fn sample_tx_add_input() -> TxAddInput {
        TxAddInput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
            prevtx: vec![0xde, 0xad, 0xbe, 0xef],
            prevtx_vout: 0,
            sequence: 0xffff_fffd,
            tlvs: TxAddInputTlvs::default(),
        }
    }

    #[test]
    fn message_tx_add_input_roundtrip() {
        let tx_add_input = sample_tx_add_input();
        let msg = Message::TxAddInput(tx_add_input.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxAddInput(tx_add_input));
    }

    #[test]
    fn message_tx_remove_input_roundtrip() {
        let tx_remove_input = TxRemoveInput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 42,
        };
        let msg = Message::TxRemoveInput(tx_remove_input.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxRemoveInput(tx_remove_input));
    }

    #[test]
    fn message_tx_remove_output_roundtrip() {
        let tx_remove_output = TxRemoveOutput {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            serial_id: 99,
        };
        let msg = Message::TxRemoveOutput(tx_remove_output.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxRemoveOutput(tx_remove_output));
    }

    #[test]
    fn message_tx_complete_roundtrip() {
        let tx_complete = TxComplete {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
        };
        let msg = Message::TxComplete(tx_complete.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxComplete(tx_complete));
    }

    #[test]
    fn message_tx_init_rbf_roundtrip() {
        let tx_init_rbf = TxInitRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            locktime: 800_000,
            feerate: 5_000,
            tlvs: TxInitRbfTlvs::default(),
        };
        let msg = Message::TxInitRbf(tx_init_rbf.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxInitRbf(tx_init_rbf));
    }

    #[test]
    fn message_tx_ack_rbf_roundtrip() {
        let tx_ack_rbf = TxAckRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            tlvs: TxAckRbfTlvs::default(),
        };
        let msg = Message::TxAckRbf(tx_ack_rbf.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxAckRbf(tx_ack_rbf));
    }

    #[test]
    fn message_tx_abort_roundtrip() {
        let tx_abort = TxAbort::new(ChannelId::new([0xcd; CHANNEL_ID_SIZE]), "abort reason");
        let msg = Message::TxAbort(tx_abort.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::TxAbort(tx_abort));
    }

    /// Valid `UpdateAddHtlc` message for testing.
    fn sample_update_add_htlc() -> UpdateAddHtlc {
        UpdateAddHtlc {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            id: 42,
            amount_msat: 1_000_000,
            payment_hash: [0x00; SHA256_HASH_SIZE],
            cltv_expiry: 500,
            onion_routing_packet: [0xbb; PAYMENT_ONION_PACKET_SIZE],
            tlvs: UpdateAddHtlcTlvs::default(),
        }
    }

    #[test]
    fn message_update_add_htlc_roundtrip() {
        let msg = sample_update_add_htlc();
        let encoded = Message::UpdateAddHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateAddHtlc(msg));
    }

    #[test]
    fn message_update_fulfill_htlc_roundtrip() {
        let msg = UpdateFulfillHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 42,
            payment_preimage: [0xcd; 32],
            tlvs: UpdateFulfillHtlcTlvs::default(),
        };
        let encoded = Message::UpdateFulfillHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateFulfillHtlc(msg));
    }

    #[test]
    fn message_update_fail_htlc_roundtrip() {
        let msg = UpdateFailHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 7,
            reason: vec![0xde, 0xad, 0xbe, 0xef],
            tlvs: UpdateFailHtlcTlvs::default(),
        };
        let encoded = Message::UpdateFailHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateFailHtlc(msg));
    }

    /// Valid `CommitmentSigned` message for testing.
    fn sample_commitment_signed() -> CommitmentSigned {
        let sig = |seed: u8| {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
            let msg = secp256k1::Message::from_digest([seed; 32]);
            secp.sign_ecdsa(&msg, &sk)
        };

        CommitmentSigned {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            signature: sig(0x11),
            htlc_signatures: vec![sig(0x22), sig(0x33)],
            tlvs: CommitmentSignedTlvs {
                funding_txid: Some(Txid::from_byte_array([0xbb; TXID_SIZE])),
            },
        }
    }

    #[test]
    fn message_commitment_signed_roundtrip() {
        let msg = sample_commitment_signed();
        let encoded = Message::CommitmentSigned(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::CommitmentSigned(msg));
    }

    /// Valid `RevokeAndAck` message for testing.
    fn sample_revoke_and_ack() -> RevokeAndAck {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        RevokeAndAck {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            per_commitment_secret: [0xcd; PER_COMMITMENT_SECRET_SIZE],
            next_per_commitment_point: pk,
        }
    }

    #[test]
    fn message_revoke_and_ack_roundtrip() {
        let msg = sample_revoke_and_ack();
        let encoded = Message::RevokeAndAck(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::RevokeAndAck(msg));
    }

    #[test]
    fn message_update_fail_malformed_htlc_roundtrip() {
        let msg = UpdateFailMalformedHtlc {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            id: 12345,
            sha256_of_onion: sha256::Hash::from_byte_array([0xaa; SHA256_HASH_SIZE]),
            failure_code: 0x8001,
        };
        let encoded = Message::UpdateFailMalformedHtlc(msg.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::UpdateFailMalformedHtlc(msg));
    }

    /// Valid `ChannelAnnouncement` message for testing.
    fn sample_channel_announcement() -> ChannelAnnouncement {
        let secp = Secp256k1::new();
        let node_sk_1 = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let node_sk_2 = SecretKey::from_slice(&[0x22; 32]).expect("valid secret");
        let bitcoin_sk_1 = SecretKey::from_slice(&[0x33; 32]).expect("valid secret");
        let bitcoin_sk_2 = SecretKey::from_slice(&[0x44; 32]).expect("valid secret");
        let placeholder = Signature::from_compact(&[0u8; COMPACT_SIGNATURE_SIZE]).unwrap();

        let mut ca = ChannelAnnouncement {
            node_signature_1: placeholder,
            node_signature_2: placeholder,
            bitcoin_signature_1: placeholder,
            bitcoin_signature_2: placeholder,
            features: vec![0x01, 0x02],
            chain_hash: [0x6f; CHAIN_HASH_SIZE],
            short_channel_id: ShortChannelId::new(539_268, 845, 1),
            node_id_1: PublicKey::from_secret_key(&secp, &node_sk_1),
            node_id_2: PublicKey::from_secret_key(&secp, &node_sk_2),
            bitcoin_key_1: PublicKey::from_secret_key(&secp, &bitcoin_sk_1),
            bitcoin_key_2: PublicKey::from_secret_key(&secp, &bitcoin_sk_2),
            extra: Vec::new(),
        };
        ca.sign(&node_sk_1, &node_sk_2, &bitcoin_sk_1, &bitcoin_sk_2);
        ca
    }

    #[test]
    fn message_channel_announcement_roundtrip() {
        let ca = sample_channel_announcement();
        let encoded = Message::ChannelAnnouncement(ca.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::ChannelAnnouncement(ca));
    }

    /// Valid `NodeAnnouncement` message for testing.
    fn sample_node_announcement() -> NodeAnnouncement {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");

        let mut na = NodeAnnouncement {
            signature: Signature::from_compact(&[0u8; 64]).unwrap(),
            features: vec![0x01, 0x02],
            timestamp: 1_700_000_000,
            node_id: PublicKey::from_secret_key(&secp, &sk),
            rgb_color: [0xaa, 0xbb, 0xcc],
            alias: [0x42; 32],
            addresses: vec![0x01, 0x7f, 0x00, 0x00, 0x01, 0x23, 0x45],
            extra: vec![0x01, 0x02, 0x03],
        };
        na.sign(&sk);
        na
    }

    #[test]
    fn message_node_announcement_roundtrip() {
        let na = sample_node_announcement();
        let encoded = Message::NodeAnnouncement(na.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::NodeAnnouncement(na));
    }

    fn sample_channel_update() -> ChannelUpdate {
        let sk = SecretKey::from_slice(&[0x22; 32]).expect("valid secret");

        let mut cu = ChannelUpdate {
            // Placeholder; overwritten by `sign` below.
            signature: Signature::from_compact(&[0; COMPACT_SIGNATURE_SIZE])
                .expect("zero signature parses"),
            chain_hash: [0x6f; CHAIN_HASH_SIZE],
            short_channel_id: ShortChannelId::from_u64(0x0000_0824_0000_0035),
            timestamp: 1_715_000_000,
            message_flags: 1, // must_be_one
            channel_flags: 0,
            cltv_expiry_delta: 144,
            htlc_minimum_msat: 1_000,
            fee_base_msat: 1_000,
            fee_proportional_millionths: 100,
            htlc_maximum_msat: 99_000_000,
            extra: Vec::new(),
        };
        cu.sign(&sk);
        cu
    }

    #[test]
    fn message_channel_update_roundtrip() {
        let cu = sample_channel_update();
        let msg = Message::ChannelUpdate(cu.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::ChannelUpdate(cu));
    }

    /// Valid `AnnouncementSignatures` message for testing.
    fn sample_announcement_signatures() -> AnnouncementSignatures {
        let secp = Secp256k1::new();
        let node_sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let bitcoin_sk = SecretKey::from_slice(&[0x22; 32]).expect("valid secret");
        let digest = secp256k1::Message::from_digest([0xab; 32]);

        AnnouncementSignatures {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            short_channel_id: ShortChannelId::new(539_268, 845, 1),
            node_signature: secp.sign_ecdsa(&digest, &node_sk),
            bitcoin_signature: secp.sign_ecdsa(&digest, &bitcoin_sk),
        }
    }

    #[test]
    fn message_announcement_signatures_roundtrip() {
        let ann_sigs = sample_announcement_signatures();
        let encoded = Message::AnnouncementSignatures(ann_sigs.clone()).encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::AnnouncementSignatures(ann_sigs));
    }

    #[test]
    fn message_gossip_timestamp_filter_roundtrip() {
        let chain_hash = [0x6f; 32];
        let filter = GossipTimestampFilter::new(chain_hash, 1_000_000, 86400);
        let msg = Message::GossipTimestampFilter(filter.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::GossipTimestampFilter(filter));
    }

    #[test]
    fn message_unknown_roundtrip() {
        let msg = Message::Unknown {
            msg_type: 101,
            payload: vec![0x11, 0x22, 0x33],
        };
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn message_type_values() {
        assert_eq!(
            Message::Warning(Warning::all_channels("")).msg_type(),
            MessageType::WARNING
        );
        assert_eq!(Message::Init(Init::empty()).msg_type(), MessageType::INIT);
        assert_eq!(
            Message::Error(Error::all_channels("")).msg_type(),
            MessageType::ERROR
        );
        assert_eq!(Message::Ping(Ping::new(0)).msg_type(), MessageType::PING);
        assert_eq!(Message::Pong(Pong::new(0)).msg_type(), MessageType::PONG);
        assert_eq!(
            Message::OpenChannel(sample_open_channel()).msg_type(),
            MessageType::OPEN_CHANNEL
        );
        assert_eq!(
            Message::AcceptChannel(sample_accept_channel()).msg_type(),
            MessageType::ACCEPT_CHANNEL
        );
        assert_eq!(
            Message::FundingCreated(sample_funding_created()).msg_type(),
            MessageType::FUNDING_CREATED
        );
        assert_eq!(
            Message::FundingSigned(sample_funding_signed()).msg_type(),
            MessageType::FUNDING_SIGNED
        );
        assert_eq!(
            Message::ChannelReady(sample_channel_ready()).msg_type(),
            MessageType::CHANNEL_READY
        );
        assert_eq!(
            Message::Shutdown(Shutdown::for_channel(ChannelId([0; 32]), vec![])).msg_type(),
            MessageType::SHUTDOWN
        );
        assert_eq!(
            Message::ClosingComplete(sample_closing_complete()).msg_type(),
            MessageType::CLOSING_COMPLETE,
        );
        assert_eq!(
            Message::ClosingSig(sample_closing_sig()).msg_type(),
            MessageType::CLOSING_SIG,
        );
        assert_eq!(
            Message::OpenChannel2(sample_open_channel2()).msg_type(),
            MessageType::OPEN_CHANNEL2
        );
        assert_eq!(
            Message::AcceptChannel2(sample_accept_channel2(None)).msg_type(),
            MessageType::ACCEPT_CHANNEL2
        );
        assert_eq!(
            Message::TxAddInput(sample_tx_add_input()).msg_type(),
            MessageType::TX_ADD_INPUT
        );
        assert_eq!(
            Message::TxRemoveInput(TxRemoveInput {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                serial_id: 0
            })
            .msg_type(),
            MessageType::TX_REMOVE_INPUT
        );
        assert_eq!(
            Message::TxRemoveOutput(TxRemoveOutput {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                serial_id: 0
            })
            .msg_type(),
            MessageType::TX_REMOVE_OUTPUT
        );
        assert_eq!(
            Message::TxComplete(TxComplete {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE])
            })
            .msg_type(),
            MessageType::TX_COMPLETE
        );
        assert_eq!(
            Message::TxInitRbf(TxInitRbf {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                locktime: 0,
                feerate: 0,
                tlvs: TxInitRbfTlvs::default(),
            })
            .msg_type(),
            MessageType::TX_INIT_RBF
        );
        assert_eq!(
            Message::TxAckRbf(TxAckRbf {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                tlvs: TxAckRbfTlvs::default(),
            })
            .msg_type(),
            MessageType::TX_ACK_RBF
        );
        assert_eq!(
            Message::TxAbort(TxAbort::new(ChannelId::new([0; CHANNEL_ID_SIZE]), "")).msg_type(),
            MessageType::TX_ABORT
        );
        assert_eq!(
            Message::UpdateAddHtlc(sample_update_add_htlc()).msg_type(),
            MessageType::UPDATE_ADD_HTLC
        );
        assert_eq!(
            Message::UpdateFulfillHtlc(UpdateFulfillHtlc {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                id: 0,
                payment_preimage: [0; 32],
                tlvs: UpdateFulfillHtlcTlvs::default(),
            })
            .msg_type(),
            MessageType::UPDATE_FULFILL_HTLC
        );
        assert_eq!(
            Message::UpdateFailHtlc(UpdateFailHtlc {
                channel_id: ChannelId::new([0; CHANNEL_ID_SIZE]),
                id: 0,
                reason: vec![],
                tlvs: UpdateFailHtlcTlvs::default(),
            })
            .msg_type(),
            MessageType::UPDATE_FAIL_HTLC
        );
        assert_eq!(
            Message::CommitmentSigned(sample_commitment_signed()).msg_type(),
            MessageType::COMMITMENT_SIGNED
        );
        assert_eq!(
            Message::RevokeAndAck(sample_revoke_and_ack()).msg_type(),
            MessageType::REVOKE_AND_ACK
        );
        assert_eq!(
            Message::UpdateFailMalformedHtlc(UpdateFailMalformedHtlc {
                channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
                id: 12345,
                sha256_of_onion: sha256::Hash::from_byte_array([0xaa; SHA256_HASH_SIZE]),
                failure_code: 0x8001,
            })
            .msg_type(),
            MessageType::UPDATE_FAIL_MALFORMED_HTLC
        );
        assert_eq!(
            Message::ChannelAnnouncement(sample_channel_announcement()).msg_type(),
            MessageType::CHANNEL_ANNOUNCEMENT
        );
        assert_eq!(
            Message::NodeAnnouncement(sample_node_announcement()).msg_type(),
            MessageType::NODE_ANNOUNCEMENT
        );
        assert_eq!(
            Message::ChannelUpdate(sample_channel_update()).msg_type(),
            MessageType::CHANNEL_UPDATE
        );
        assert_eq!(
            Message::AnnouncementSignatures(sample_announcement_signatures()).msg_type(),
            MessageType::ANNOUNCEMENT_SIGNATURES
        );
        assert_eq!(
            Message::GossipTimestampFilter(GossipTimestampFilter::no_gossip([0u8; 32])).msg_type(),
            MessageType::GOSSIP_TIMESTAMP_FILTER
        );
        assert_eq!(
            Message::Unknown {
                msg_type: 99,
                payload: vec![]
            }
            .msg_type(),
            MessageType(99)
        );
    }

    #[test]
    fn message_decode_unknown_odd() {
        // Type 99 is odd and unknown - should be accepted
        let data = message_with_type(99, &[0xaa, 0xbb]);
        let msg = Message::decode(&data).unwrap();
        assert_eq!(
            msg,
            Message::Unknown {
                msg_type: 99,
                payload: vec![0xaa, 0xbb]
            }
        );
    }

    #[test]
    fn message_decode_unknown_even() {
        // Type 100 is even and unknown - should be rejected
        let data = message_with_type(100, &[0xaa, 0xbb]);
        assert_eq!(Message::decode(&data), Err(BoltError::UnknownEvenType(100)));
    }

    #[test]
    fn message_decode_truncated() {
        // Only 1 byte - need at least 2 for type
        assert_eq!(
            Message::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn message_with_type_helper() {
        let data = message_with_type(MessageType::PING.as_u16(), &[0x00, 0x04, 0x00, 0x00]);
        assert_eq!(data, [0x00, 0x12, 0x00, 0x04, 0x00, 0x00]); // 0x12 = 18 = PING
    }
}
