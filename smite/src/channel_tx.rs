//! BOLT 3 channel transaction construction.
//!
//! This module builds Lightning channel on-chain transactions: the funding
//! transaction, the commitment transaction, and the shared transaction
//! negotiated by BOLT 2 interactive transaction construction.

mod commitment;
mod funding;
mod interactive_tx;

pub use commitment::{
    ChannelConfig, ChannelPartyConfig, ChannelState, CommitmentCost, CommitmentError,
    CommitmentPartyState, CommitmentState, HolderIdentity, Side,
};
pub use funding::{
    FundingTransaction, InsufficientFunds, build_funding_transaction, build_funding_witness_script,
};
pub use interactive_tx::{
    Contributor, MAX_INPUTS, MAX_OUTPUTS, MAX_SEQUENCE, SharedInput, SharedOutput,
    SharedTransaction, signs_first,
};
