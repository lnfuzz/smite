//! BOLT 3 channel transaction construction.
//!
//! This module builds Lightning channel on-chain transactions: the funding
//! transaction, the commitment transaction, and the shared transaction
//! negotiated by BOLT 2 interactive transaction construction.

mod commitment;
mod funding;
mod interactive_tx;

pub use commitment::{
    ChannelCommitments, ChannelConfig, ChannelPartyConfig, CommitmentCost, CommitmentError,
    CommitmentState, HolderIdentity, Htlc, Side,
};
pub use funding::{FundingTransaction, InsufficientFunds, build_funding_transaction};
pub use interactive_tx::{
    Contributor, MAX_INPUTS, MAX_OUTPUTS, MAX_SEQUENCE, SharedInput, SharedOutput,
    SharedTransaction,
};
