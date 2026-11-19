//! Runtime variables produced by the executor.
//!
//! Variables exist only during program execution -- they are never serialized.
//! The serialized program stores data only in [`Operation`] literals.

use bitcoin::secp256k1::PublicKey;
use smite::bolt::{AcceptChannel, ChannelId, OpenChannel, ShortChannelId};
use smite::channel_tx::FundingTransaction;

const CHAIN_HASH_SIZE: usize = 32;
const PRIVATE_KEY_SIZE: usize = 32;

/// A typed runtime value produced by executing an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Variable {
    /// Raw bytes (scriptpubkeys, onion packets, etc.).
    Bytes(Vec<u8>),
    /// Chain hash (genesis block hash).
    ChainHash([u8; CHAIN_HASH_SIZE]),
    /// 32-byte channel identifier.
    ChannelId(ChannelId),
    /// BOLT 7 `short_channel_id` (packed block / `tx_index` / `output_index`).
    ShortChannelId(ShortChannelId),
    /// secp256k1 public key.
    Point(PublicKey),
    /// secp256k1 private key.
    PrivateKey([u8; PRIVATE_KEY_SIZE]),
    /// Satoshi or millisatoshi amount.
    Amount(u64),
    /// Fee rate in sat/kw.
    FeeratePerKw(u32),
    /// Block height or count (`minimum_depth`, `cltv_expiry`, `locktime`).
    BlockHeight(u32),
    /// Unix timestamp in seconds.
    Timestamp(u32),
    /// BOLT 7 `channel_update` fee (`fee_base_msat` in millisatoshi or
    /// `fee_proportional_millionths` in millionths).
    ForwardingFee(u32),
    /// Generic u16 protocol parameter (`to_self_delay`, `max_accepted_htlcs`,
    /// `cltv_expiry_delta`, etc.).
    U16(u16),
    /// Generic u8 protocol parameter (`channel_flags`, `initiator`, etc.).
    U8(u8),
    /// Feature bits.
    Features(Vec<u8>),
    /// Encoded BOLT message with type prefix, ready to send.
    Message(Vec<u8>),
    /// BOLT `open_channel` message, ready to send.
    OpenChannelMessage(OpenChannel),
    /// Parsed `accept_channel` response.
    AcceptChannel(AcceptChannel),
    /// Constructed funding transaction with funding output index.
    FundingTransaction(FundingTransaction),

    // Affine (single-use) variables
    /// `open_channel` has been sent, so `accept_channel` may now be received.
    SentOpenChannel,
    /// `funding_created` has been sent, so `funding_signed` may now be received.
    SentFundingCreated,
}

impl Variable {
    /// Returns the type tag for this variable.
    #[must_use]
    pub fn var_type(&self) -> VariableType {
        match self {
            Self::Bytes(_) => VariableType::Bytes,
            Self::ChainHash(_) => VariableType::ChainHash,
            Self::ChannelId(_) => VariableType::ChannelId,
            Self::ShortChannelId(_) => VariableType::ShortChannelId,
            Self::Point(_) => VariableType::Point,
            Self::PrivateKey(_) => VariableType::PrivateKey,
            Self::Amount(_) => VariableType::Amount,
            Self::FeeratePerKw(_) => VariableType::FeeratePerKw,
            Self::BlockHeight(_) => VariableType::BlockHeight,
            Self::Timestamp(_) => VariableType::Timestamp,
            Self::ForwardingFee(_) => VariableType::ForwardingFee,
            Self::U16(_) => VariableType::U16,
            Self::U8(_) => VariableType::U8,
            Self::Features(_) => VariableType::Features,
            Self::Message(_) => VariableType::Message,
            Self::OpenChannelMessage(_) => VariableType::OpenChannelMessage,
            Self::AcceptChannel(_) => VariableType::AcceptChannel,
            Self::FundingTransaction(_) => VariableType::FundingTransaction,
            Self::SentOpenChannel => VariableType::SentOpenChannel,
            Self::SentFundingCreated => VariableType::SentFundingCreated,
        }
    }
}

/// Lightweight type tag for variables, used by mutators for type-safe input
/// swapping and by builders for variable selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VariableType {
    Bytes,
    ChainHash,
    ChannelId,
    ShortChannelId,
    Point,
    PrivateKey,
    Amount,
    FeeratePerKw,
    BlockHeight,
    Timestamp,
    ForwardingFee,
    U16,
    U8,
    Features,
    Message,
    OpenChannelMessage,
    AcceptChannel,
    FundingTransaction,
    SentOpenChannel,
    SentFundingCreated,
}

impl VariableType {
    #[must_use]
    pub fn is_affine(&self) -> bool {
        match self {
            Self::SentOpenChannel | Self::SentFundingCreated => true,

            Self::Bytes
            | Self::ChainHash
            | Self::ChannelId
            | Self::Point
            | Self::PrivateKey
            | Self::Amount
            | Self::FeeratePerKw
            | Self::BlockHeight
            | Self::Timestamp
            | Self::ForwardingFee
            | Self::U16
            | Self::U8
            | Self::Features
            | Self::Message
            | Self::OpenChannelMessage
            | Self::AcceptChannel
            | Self::ShortChannelId
            | Self::FundingTransaction => false,
        }
    }
}
