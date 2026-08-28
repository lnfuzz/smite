//! Generator for the complete channel establishment v2 (dual-funded) flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::{
    AcceptChannel2Field, ChannelTypeVariant, ShutdownScriptVariant, TxOutputRole,
};
use crate::{Operation, VariableType};

/// `serial_id` of the funding output we contribute. BOLT 2 requires the
/// initiator to use even ids; picking these from a high range keeps them clear
/// of the ones assigned to inputs.
const FUNDING_OUTPUT_SERIAL_ID: u64 = 2000;

/// `serial_id` of our change output.
const CHANGE_OUTPUT_SERIAL_ID: u64 = 2002;

/// `nSequence` for the inputs we contribute. BOLT 2 caps it at `0xfffffffd` so
/// every input signals replaceability, and recommends one shared value across
/// implementations to avoid fingerprinting.
const SEQUENCE: u32 = 0xffff_fffd;

/// Channel types most likely to be accepted, so the flow reaches its later
/// steps often enough to cover them. `LoadChannelType` is mutable, so the
/// mutator still reaches the rest.
const LIKELY_CHANNEL_TYPES: &[ChannelTypeVariant] = &[
    ChannelTypeVariant::Anchors,
    ChannelTypeVariant::StaticRemoteKey,
];

/// Generates the complete channel establishment v2 flow.
///
/// Emits instructions to:
/// 1. Build and send `open_channel2`, then receive `accept_channel2`
/// 2. Contribute inputs, the funding output and a change output through
///    interactive transaction construction, concluding with `tx_complete`
/// 3. Exchange `commitment_signed`, then `tx_signatures`
/// 4. Broadcast and confirm the funding transaction
/// 5. Complete the `channel_ready` exchange
///
/// Unlike [`FundingFlowGenerator`](super::FundingFlowGenerator), the values
/// that decide whether the negotiation can conclude at all are emitted as
/// literals rather than drawn from the builder's pool. The v2 success region is
/// a joint condition -- the funding output must be worth both contributions and
/// our inputs must cover our outputs plus our share of the fee -- that random
/// values essentially never satisfy, and everything from `commitment_signed`
/// onward is unreachable until they do. The mutators still reach outward from
/// the seeded values, since every one of them is param-mutable.
#[derive(Clone, Copy)]
pub struct DualFundingFlowGenerator;

impl Generator for DualFundingFlowGenerator {
    // One linear protocol script, from open_channel2 through channel_ready.
    // Splitting it would scatter a sequence that reads best in wire order.
    #[allow(clippy::too_many_lines)]
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Keys are generated fresh to ensure they're distinct.
        let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);
        let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
        let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        // BOLT 2 derives the v2 temporary_channel_id from our revocation
        // basepoint with a zeroed one standing in for the peer.
        let temporary_channel_id = builder.append(
            Operation::DeriveTemporaryChannelIdV2,
            &[revocation_basepoint],
        );

        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let funding_satoshis = builder.append(
            Operation::LoadAmount(rng.random_range(100_000..=1_000_000)),
            &[],
        );
        let funding_feerate_perkw = builder.append(
            Operation::LoadFeeratePerKw(rng.random_range(253..=2_000)),
            &[],
        );
        let commitment_feerate_perkw = builder.append(
            Operation::LoadFeeratePerKw(rng.random_range(253..=5_000)),
            &[],
        );
        let dust_limit_satoshis = builder.append(Operation::LoadAmount(546), &[]);
        let max_htlc_value_in_flight_msat = builder.append(Operation::LoadAmount(100_000_000), &[]);
        let htlc_minimum_msat = builder.append(Operation::LoadAmount(1), &[]);
        let to_self_delay = builder.append(Operation::LoadU16(144), &[]);
        let max_accepted_htlcs = builder.append(Operation::LoadU16(483), &[]);
        let locktime = builder.append(Operation::LoadBlockHeight(0), &[]);
        let channel_flags = builder.append(Operation::LoadU8(u8::from(rng.random::<bool>())), &[]);
        let upfront_shutdown_script = builder.append(
            Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
            &[],
        );
        let channel_type_variant = if rng.random_range(0..4) == 0 {
            *ChannelTypeVariant::ALL
                .choose(rng)
                .expect("ChannelTypeVariant::ALL is non-empty")
        } else {
            *LIKELY_CHANNEL_TYPES
                .choose(rng)
                .expect("LIKELY_CHANNEL_TYPES is non-empty")
        };
        let channel_type = builder.append(Operation::LoadChannelType(channel_type_variant), &[]);

        // Build and send open_channel2.
        let open_channel2_msg = builder.append(
            Operation::BuildOpenChannel2 {
                require_confirmed_inputs: rng.random_range(0..8) == 0,
            },
            &[
                chain_hash,
                temporary_channel_id,
                funding_feerate_perkw,
                commitment_feerate_perkw,
                funding_satoshis,
                dust_limit_satoshis,
                max_htlc_value_in_flight_msat,
                htlc_minimum_msat,
                to_self_delay,
                max_accepted_htlcs,
                locktime,
                funding_pubkey,
                revocation_basepoint,
                payment_basepoint,
                delayed_payment_basepoint,
                htlc_basepoint,
                first_per_commitment_point,
                second_per_commitment_point,
                channel_flags,
                upfront_shutdown_script,
                channel_type,
            ],
        );
        let sent_open_channel2 = builder.append(Operation::SendOpenChannel2, &[open_channel2_msg]);

        // Receive accept_channel2, which reveals the peer's revocation
        // basepoint and so the channel_id every later message carries.
        let accept_channel2 = builder.append(Operation::RecvAcceptChannel2, &[sent_open_channel2]);
        let peer_revocation_basepoint = builder.append(
            Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            &[accept_channel2],
        );
        let channel_id = builder.append(
            Operation::DeriveChannelIdV2,
            &[revocation_basepoint, peer_revocation_basepoint],
        );

        // Interactive transaction construction. The protocol is turn-based, so
        // every message we send is followed by the peer's reply.
        for i in 0..rng.random_range(1u8..=3) {
            let sent = builder.append(
                Operation::SendTxAddInput {
                    // Even ids, as BOLT 2 requires of the initiator.
                    serial_id: 2 * (u64::from(i) + 1),
                    utxo_index: i,
                    sequence: SEQUENCE,
                },
                &[channel_id],
            );
            builder.append(Operation::RecvInteractiveTx, &[sent]);
        }

        // The opener must contribute the funding output, and pays its fees.
        for (serial_id, role) in [
            (FUNDING_OUTPUT_SERIAL_ID, TxOutputRole::Funding),
            (CHANGE_OUTPUT_SERIAL_ID, TxOutputRole::Change),
        ] {
            let sent = builder.append(
                Operation::SendTxAddOutput { serial_id, role },
                // The value and script are derived from the negotiation for
                // both roles here; they matter only once a mutator switches
                // the role to `Explicit`.
                &[channel_id, funding_satoshis, upfront_shutdown_script],
            );
            builder.append(Operation::RecvInteractiveTx, &[sent]);
        }

        let sent_tx_complete = builder.append(Operation::SendTxComplete, &[channel_id]);
        builder.append(Operation::RecvInteractiveTx, &[sent_tx_complete]);

        // Exchange commitment signatures over the negotiated transaction.
        let funding_transaction =
            builder.append(Operation::BuildFundingTransactionV2, &[channel_id]);
        let sent_commitment_signed = builder.append(
            Operation::SendCommitmentSigned,
            &[funding_transaction, funding_privkey, channel_id],
        );
        let funded_channel_id =
            builder.append(Operation::RecvCommitmentSigned, &[sent_commitment_signed]);

        // We contribute every input, so BOLT 2 has the peer send its
        // tx_signatures first.
        builder.append(Operation::RecvTxSignatures, &[channel_id]);
        builder.append(
            Operation::SendTxSignatures,
            &[channel_id, funding_transaction],
        );

        builder.append(Operation::BroadcastTransaction, &[funding_transaction]);
        builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);

        // Reuse the second_per_commitment_point already committed to in
        // open_channel2: implementations may cross-check the two, and feeding
        // an unrelated point would fail channel_ready for a reason that has
        // nothing to do with the flow under test.
        let short_channel_id = builder.generate_fresh(VariableType::ShortChannelId, rng);
        builder.append(
            Operation::SendChannelReady {
                include_alias: rng.random(),
            },
            &[
                funded_channel_id,
                second_per_commitment_point,
                short_channel_id,
            ],
        );
        builder.append(Operation::RecvChannelReady, &[]);
    }
}
