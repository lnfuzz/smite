//! Generator for `channel_announcement` gossip message.

use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `channel_announcement` send backed by a real
/// funding output.
///
/// Emits instructions to:
/// 1. Create, broadcast, and confirm a 2-of-2 P2WSH funding transaction
/// 2. Look up the `short_channel_id` of the confirmed funding output
/// 3. Build and send `channel_announcement`
///
/// The announced bitcoin keys are the ones committed to by the funding
/// output's witness script, so the message can pass the on-chain UTXO
/// validation performed by CLN and LND.
#[derive(Clone, Copy)]
pub struct ChannelAnnouncementGenerator;

impl ChannelAnnouncementGenerator {
    /// BOLT 2 caps `funding_satoshis` at 2^24-1 for non-wumbo channels, and we
    /// only have so much wallet balance to spend.
    pub const MAX_FUNDING_SATOSHIS: u64 = 16_777_215;

    /// Bounded so that fees don't exhaust the wallet.
    pub const MAX_FEERATE_PER_KW: u32 = 10_000;
}

impl Generator for ChannelAnnouncementGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let features = builder.pick_variable(VariableType::Features, rng);
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);

        // Use fresh private keys since channel_announcement validation
        // generally requires distinct keys.
        let node_sk_1 = builder.generate_fresh(VariableType::PrivateKey, rng);
        let node_sk_2 = builder.generate_fresh(VariableType::PrivateKey, rng);
        let bitcoin_sk_1 = builder.generate_fresh(VariableType::PrivateKey, rng);
        let bitcoin_sk_2 = builder.generate_fresh(VariableType::PrivateKey, rng);

        // The funding output must pay to the same bitcoin keys the message
        // announces, so derive the funding pubkeys instead of picking them.
        let funding_pubkey_1 = builder.append(Operation::DerivePoint, &[bitcoin_sk_1]);
        let funding_pubkey_2 = builder.append(Operation::DerivePoint, &[bitcoin_sk_2]);

        // Load the funding amount and feerate rather than picking them, since a
        // full-range random amount exceeds Bitcoin's maximum supply and fails
        // coin selection, aborting the program before the announcement is sent.
        let funding_satoshis = builder.append(
            Operation::LoadAmount(rng.random_range(0..=Self::MAX_FUNDING_SATOSHIS)),
            &[],
        );
        let feerate_per_kw = builder.append(
            Operation::LoadFeeratePerKw(rng.random_range(0..=Self::MAX_FEERATE_PER_KW)),
            &[],
        );

        // Create the 2-of-2 P2WSH funding transaction and confirm it.
        let funding_transaction = builder.append(
            Operation::CreateFundingTransaction,
            &[
                funding_pubkey_1,
                funding_pubkey_2,
                funding_satoshis,
                feerate_per_kw,
            ],
        );
        builder.append(Operation::BroadcastTransaction, &[funding_transaction]);
        builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);

        // Derive the short_channel_id from the confirmed funding output. If a
        // mutator drops the MineBlocks above, the executor yields a sentinel
        // scid and the announcement simply fails on-chain validation.
        let short_channel_id =
            builder.append(Operation::LookupShortChannelId, &[funding_transaction]);

        // Build and send channel_announcement.
        let msg = builder.append(
            Operation::BuildChannelAnnouncement,
            &[
                features,
                chain_hash,
                short_channel_id,
                node_sk_1,
                node_sk_2,
                bitcoin_sk_1,
                bitcoin_sk_2,
            ],
        );
        builder.append(Operation::SendMessage, &[msg]);
    }
}
