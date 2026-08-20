//! BOLT 3 channel transaction construction.
//!
//! This module builds Lightning channel on-chain transactions: the funding
//! transaction and the commitment transaction.

mod commitment;
mod funding;
mod taproot;

pub use commitment::{
    ChannelConfig, ChannelPartyConfig, ChannelState, CommitmentCost, CommitmentError,
    CommitmentPartyState, CommitmentState, HolderIdentity, Side,
};
pub use funding::{
    FundingError, FundingTransaction, InsufficientFunds, build_funding_scriptpubkey,
    build_funding_transaction,
};
