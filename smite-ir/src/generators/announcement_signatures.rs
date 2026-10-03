//! Generator for `announcement_signatures` message flow.

use rand::Rng;

use super::Generator;
use super::funding_flow::append_funding_flow;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an announced channel and signs its `channel_announcement`.
///
/// Emits instructions to:
/// 1. Open, fund, and confirm an announced channel
/// 2. Complete the `channel_ready` exchange
/// 3. Look up the `short_channel_id` of the confirmed funding output
/// 4. Build and send `announcement_signatures`
///
/// The signatures cover the `channel_announcement` body the target rebuilds
/// for itself, so they only verify if every field matches what the target
/// already knows: the channel's real `short_channel_id`, our node identity,
/// and the funding keys the channel was opened with.
#[derive(Clone, Copy)]
pub struct AnnouncementSignaturesGenerator;

impl AnnouncementSignaturesGenerator {
    /// Blocks mined after the `channel_ready` exchange. Targets re-check
    /// whether a channel may be announced as new blocks arrive, so give them
    /// one while the channel is usable.
    pub const POST_READY_BLOCKS: u8 = 1;
}

impl Generator for AnnouncementSignaturesGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Open, fund, and confirm the channel. It is announced, since targets
        // ignore `announcement_signatures` for a private one. The funding
        // secret signs the announcement as `bitcoin_key_1`, and the target
        // announces the acceptor's funding key as `bitcoin_key_2`.
        let funding = append_funding_flow(builder, rng, true);
        builder.append(Operation::MineBlocks(Self::POST_READY_BLOCKS), &[]);

        // The announcement covers the channel's real short_channel_id.
        let short_channel_id = builder.append(
            Operation::LookupShortChannelId,
            &[funding.funding_transaction],
        );

        // Targets rebuild the announcement body with empty channel features,
        // so any other value changes the digest and fails every signature
        // check.
        let features = builder.append(Operation::LoadFeatures(Vec::new()), &[]);
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);

        // Our node secret comes from the context because the target verifies
        // `node_signature` against the identity we handshook with.
        let node_sk = builder.append(Operation::LoadLocalNodeSecretFromContext, &[]);
        let target_node_id = builder.append(Operation::LoadTargetPubkeyFromContext, &[]);

        // Build and send announcement_signatures.
        let msg = builder.append(
            Operation::BuildAnnouncementSignatures,
            &[
                funding.channel_id,
                features,
                chain_hash,
                short_channel_id,
                node_sk,
                target_node_id,
                funding.funding_privkey,
                funding.acceptor_funding_pubkey,
            ],
        );
        builder.append(Operation::SendMessage, &[msg]);
    }
}
