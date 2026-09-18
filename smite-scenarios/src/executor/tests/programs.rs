//! Program fragments used by executor tests.
//!
//! Each helper appends one fragment to a [`ProgramBuilder`] and returns the
//! variables it produced, so that callers compose fragments without tracking
//! instruction indices. `*_program` helpers build a whole program.
//!
//! `raw_program` is an exception and doesn't use [`ProgramBuilder`] since its
//! purpose is to create malformed program.

use super::harness::{PointSource, SampleOpenChannel, acceptor_funding_sk, opener_funding_sk};
use crate::executor::*;
use smite::bolt::ChannelTypeVariant;
use smite_ir::Instruction;
use smite_ir::builder::ProgramBuilder;
use smite_ir::operation::{AcceptChannel2Field, TxOutputRole};

/// Loads the private key `sk` and derives its point.
fn load_point(b: &mut ProgramBuilder, sk: [u8; 32]) -> usize {
    let sk = b.append(Operation::LoadPrivateKey(sk), &[]);
    b.append(Operation::DerivePoint, &[sk])
}

// -- open_channel --

/// The variables a `BuildOpenChannel` fragment produces, named so that callers
/// don't need to manually track instruction indices.
#[derive(Clone, Copy)]
pub struct OpenChannelVars {
    pub chain_hash: usize,
    pub temporary_channel_id: usize,
    pub funding_satoshis: usize,
    pub push_msat: usize,
    pub dust_limit_satoshis: usize,
    pub max_htlc_value_in_flight_msat: usize,
    pub channel_reserve_satoshis: usize,
    pub htlc_minimum_msat: usize,
    pub feerate_per_kw: usize,
    pub to_self_delay: usize,
    pub max_accepted_htlcs: usize,
    pub funding_pubkey: usize,
    pub revocation_basepoint: usize,
    pub payment_basepoint: usize,
    pub delayed_payment_basepoint: usize,
    pub htlc_basepoint: usize,
    pub first_per_commitment_point: usize,
    pub channel_flags: usize,
    pub upfront_shutdown_script: usize,
    pub channel_type: usize,
    /// The `BuildOpenChannel` result.
    pub built: usize,
}

impl OpenChannelVars {
    /// The `BuildOpenChannel` inputs in order.
    pub fn build_inputs(&self) -> [usize; 20] {
        [
            self.chain_hash,
            self.temporary_channel_id,
            self.funding_satoshis,
            self.push_msat,
            self.dust_limit_satoshis,
            self.max_htlc_value_in_flight_msat,
            self.channel_reserve_satoshis,
            self.htlc_minimum_msat,
            self.feerate_per_kw,
            self.to_self_delay,
            self.max_accepted_htlcs,
            self.funding_pubkey,
            self.revocation_basepoint,
            self.payment_basepoint,
            self.delayed_payment_basepoint,
            self.htlc_basepoint,
            self.first_per_commitment_point,
            self.channel_flags,
            self.upfront_shutdown_script,
            self.channel_type,
        ]
    }
}

/// Emits inputs needed to construct `oc.message`, then the `BuildOpenChannel`
/// consuming them.
///
/// Uses `oc.points` to derive all six pubkeys and loads the chain hash from the
/// program context, ignoring those corresponding fields in `oc.message`.
pub fn build_open_channel(b: &mut ProgramBuilder, oc: &SampleOpenChannel) -> OpenChannelVars {
    let msg = &oc.message;
    let pubkey = match oc.points {
        PointSource::TargetContext => b.append(Operation::LoadTargetPubkeyFromContext, &[]),
        PointSource::Secret(bytes) => load_point(b, bytes),
    };

    let mut vars = OpenChannelVars {
        chain_hash: b.append(Operation::LoadChainHashFromContext, &[]),
        temporary_channel_id: b.append(Operation::LoadChannelId(msg.temporary_channel_id.0), &[]),
        funding_satoshis: b.append(Operation::LoadAmount(msg.funding_satoshis), &[]),
        push_msat: b.append(Operation::LoadAmount(msg.push_msat), &[]),
        dust_limit_satoshis: b.append(Operation::LoadAmount(msg.dust_limit_satoshis), &[]),
        max_htlc_value_in_flight_msat: b.append(
            Operation::LoadAmount(msg.max_htlc_value_in_flight_msat),
            &[],
        ),
        channel_reserve_satoshis: b
            .append(Operation::LoadAmount(msg.channel_reserve_satoshis), &[]),
        htlc_minimum_msat: b.append(Operation::LoadAmount(msg.htlc_minimum_msat), &[]),
        feerate_per_kw: b.append(Operation::LoadFeeratePerKw(msg.feerate_per_kw), &[]),
        to_self_delay: b.append(Operation::LoadU16(msg.to_self_delay), &[]),
        max_accepted_htlcs: b.append(Operation::LoadU16(msg.max_accepted_htlcs), &[]),
        funding_pubkey: pubkey,
        revocation_basepoint: pubkey,
        payment_basepoint: pubkey,
        delayed_payment_basepoint: pubkey,
        htlc_basepoint: pubkey,
        first_per_commitment_point: pubkey,
        channel_flags: b.append(Operation::LoadU8(msg.channel_flags), &[]),
        upfront_shutdown_script: b.append(
            Operation::LoadBytes(msg.tlvs.upfront_shutdown_script.clone().unwrap_or_default()),
            &[],
        ),
        channel_type: b.append(
            Operation::LoadFeatures(msg.tlvs.channel_type.clone().unwrap_or_default()),
            &[],
        ),
        // Filled in as soon as the inputs it consumes exist.
        built: 0,
    };
    vars.built = b.append(Operation::BuildOpenChannel, &vars.build_inputs());

    vars
}

/// The variables a sent `open_channel` produces.
#[derive(Clone, Copy)]
pub struct SentOpenChannel {
    /// The inputs of the message and the message itself.
    pub vars: OpenChannelVars,
    /// The `SendOpenChannel` result, an affine variable a single
    /// `RecvAcceptChannel` may consume.
    pub sent: usize,
}

/// Emits `oc` and sends it.
pub fn send_open_channel(b: &mut ProgramBuilder, oc: &SampleOpenChannel) -> SentOpenChannel {
    let vars = build_open_channel(b, oc);
    let sent = b.append(Operation::SendOpenChannel, &[vars.built]);

    SentOpenChannel { vars, sent }
}

/// A program that builds and sends `oc`.
pub fn send_open_channel_program(oc: &SampleOpenChannel) -> Program {
    let mut b = ProgramBuilder::new();
    send_open_channel(&mut b, oc);

    b.build()
}

/// The variables a channel negotiation produces.
#[derive(Clone, Copy)]
pub struct NegotiatedChannel {
    pub open_channel: SentOpenChannel,
    /// The `RecvAcceptChannel` result.
    pub accept_channel: usize,
}

/// Emits `oc`, sends it, and receives the peer's `accept_channel`.
pub fn negotiate_channel(b: &mut ProgramBuilder, oc: &SampleOpenChannel) -> NegotiatedChannel {
    let open_channel = send_open_channel(b, oc);
    let accept_channel = b.append(Operation::RecvAcceptChannel, &[open_channel.sent]);

    NegotiatedChannel {
        open_channel,
        accept_channel,
    }
}

/// A program that negotiates `oc`.
pub fn negotiate_channel_program(oc: &SampleOpenChannel) -> Program {
    let mut b = ProgramBuilder::new();
    negotiate_channel(&mut b, oc);

    b.build()
}

// -- Funding transaction --

/// The funding amount and feerate the funding-flow programs negotiate.
const FUNDING_SATOSHIS: u64 = 10_000_000;
const FUNDING_FEERATE_PER_KW: u32 = 15_000;

/// The variables a funding transaction fragment produces.
#[derive(Clone, Copy)]
pub struct FundingTxVars {
    pub opener_privkey: usize,
    pub opener_pubkey: usize,
    pub acceptor_privkey: usize,
    pub acceptor_pubkey: usize,
    pub funding_satoshis: usize,
    pub feerate_per_kw: usize,
    /// The `CreateFundingTransaction` result.
    pub tx: usize,
}

/// Emits a `CreateFundingTransaction` for [`FUNDING_SATOSHIS`] at
/// [`FUNDING_FEERATE_PER_KW`].
pub fn create_funding_tx(b: &mut ProgramBuilder) -> FundingTxVars {
    create_funding_tx_with(b, FUNDING_SATOSHIS, FUNDING_FEERATE_PER_KW)
}

/// Emits a `CreateFundingTransaction` between the opener and acceptor funding
/// keys.
pub fn create_funding_tx_with(
    b: &mut ProgramBuilder,
    funding_satoshis: u64,
    feerate_per_kw: u32,
) -> FundingTxVars {
    let opener_privkey = b.append(
        Operation::LoadPrivateKey(opener_funding_sk().secret_bytes()),
        &[],
    );
    let opener_pubkey = b.append(Operation::DerivePoint, &[opener_privkey]);
    let acceptor_privkey = b.append(
        Operation::LoadPrivateKey(acceptor_funding_sk().secret_bytes()),
        &[],
    );
    let acceptor_pubkey = b.append(Operation::DerivePoint, &[acceptor_privkey]);
    let funding_satoshis = b.append(Operation::LoadAmount(funding_satoshis), &[]);
    let feerate_per_kw = b.append(Operation::LoadFeeratePerKw(feerate_per_kw), &[]);
    let tx = b.append(
        Operation::CreateFundingTransaction,
        &[
            opener_pubkey,
            acceptor_pubkey,
            funding_satoshis,
            feerate_per_kw,
        ],
    );

    FundingTxVars {
        opener_privkey,
        opener_pubkey,
        acceptor_privkey,
        acceptor_pubkey,
        funding_satoshis,
        feerate_per_kw,
        tx,
    }
}

// -- funding_created --

/// The variables a sent `funding_created` produces.
#[derive(Clone, Copy)]
pub struct SentFundingCreated {
    pub tx: FundingTxVars,
    pub temporary_channel_id: usize,
    /// The `SendFundingCreated` result, an affine variable a single
    /// `RecvFundingSigned` may consume.
    pub sent: usize,
}

/// Creates a funding transaction, broadcasts it, and sends `funding_created`
/// signed with the opener's funding key.
pub fn send_funding_created(b: &mut ProgramBuilder) -> SentFundingCreated {
    let tx = create_funding_tx(b);
    b.append(Operation::BroadcastTransaction, &[tx.tx]);

    send_funding_created_with(b, tx, tx.opener_privkey)
}

/// Sends `funding_created` for `tx`, signed with the `PrivateKey` variable
/// `signing_privkey`.
///
/// The `temporary_channel_id` is the one `announced_open_channel` and
/// `sample_funding_negotiation` use, so that the executor finds the negotiation
/// whose commitment it must sign.
pub fn send_funding_created_with(
    b: &mut ProgramBuilder,
    tx: FundingTxVars,
    signing_privkey: usize,
) -> SentFundingCreated {
    let temporary_channel_id = b.append(Operation::LoadChannelId([0xbb; 32]), &[]);
    let sent = b.append(
        Operation::SendFundingCreated,
        &[tx.tx, signing_privkey, temporary_channel_id],
    );

    SentFundingCreated {
        tx,
        temporary_channel_id,
        sent,
    }
}

/// A program that sends `funding_created` without awaiting `funding_signed`.
pub fn send_funding_created_program() -> Program {
    let mut b = ProgramBuilder::new();
    send_funding_created(&mut b);

    b.build()
}

/// A program that sends `funding_created` and receives the peer's
/// `funding_signed`.
pub fn send_funding_created_and_recv_funding_signed_program() -> Program {
    let mut b = ProgramBuilder::new();
    let funding_created = send_funding_created(&mut b);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);

    b.build()
}

/// A program that sends `funding_created`, receives `funding_signed`, mines
/// `confirmations` blocks, and receives the target's `channel_ready`.
pub fn recv_channel_ready_program(confirmations: u8) -> Program {
    let mut b = ProgramBuilder::new();
    let funding_created = send_funding_created(&mut b);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);
    b.append(Operation::MineBlocks(confirmations), &[]);
    b.append(Operation::RecvChannelReady, &[]);

    b.build()
}

// -- Gossip --

/// Emits a `channel_announcement` carrying the `ShortChannelId` variable
/// `scid`, and sends it.
pub fn send_channel_announcement(b: &mut ProgramBuilder, scid: usize) {
    let features = b.append(Operation::LoadFeatures(vec![0x01, 0x02]), &[]);
    let chain_hash = b.append(Operation::LoadChainHashFromContext, &[]);
    let node_sk_1 = b.append(Operation::LoadPrivateKey([0x11; 32]), &[]);
    let node_sk_2 = b.append(Operation::LoadPrivateKey([0x22; 32]), &[]);
    let bitcoin_sk_1 = b.append(Operation::LoadPrivateKey([0x33; 32]), &[]);
    let bitcoin_sk_2 = b.append(Operation::LoadPrivateKey([0x44; 32]), &[]);
    let announcement = b.append(
        Operation::BuildChannelAnnouncement,
        &[
            features,
            chain_hash,
            scid,
            node_sk_1,
            node_sk_2,
            bitcoin_sk_1,
            bitcoin_sk_2,
        ],
    );
    b.append(Operation::SendMessage, &[announcement]);
}

// -- Channel establishment v2 --

/// The `open_channel2` inputs, named so that callers can swap one before
/// building.
#[derive(Clone, Copy)]
pub struct OpenChannel2Inputs {
    pub chain_hash: usize,
    pub temporary_channel_id: usize,
    pub funding_feerate_perkw: usize,
    pub commitment_feerate_perkw: usize,
    pub funding_satoshis: usize,
    pub dust_limit_satoshis: usize,
    pub max_htlc_value_in_flight_msat: usize,
    pub htlc_minimum_msat: usize,
    pub to_self_delay: usize,
    pub max_accepted_htlcs: usize,
    pub locktime: usize,
    pub funding_pubkey: usize,
    pub revocation_basepoint: usize,
    pub payment_basepoint: usize,
    pub delayed_payment_basepoint: usize,
    pub htlc_basepoint: usize,
    pub first_per_commitment_point: usize,
    pub second_per_commitment_point: usize,
    pub channel_flags: usize,
    pub upfront_shutdown_script: usize,
    pub channel_type: usize,
    /// The key behind `funding_pubkey`, which `SendCommitmentSigned` signs
    /// with.
    pub funding_privkey: usize,
}

impl OpenChannel2Inputs {
    /// The `BuildOpenChannel2` inputs in wire order.
    pub fn build_inputs(&self) -> [usize; 21] {
        [
            self.chain_hash,
            self.temporary_channel_id,
            self.funding_feerate_perkw,
            self.commitment_feerate_perkw,
            self.funding_satoshis,
            self.dust_limit_satoshis,
            self.max_htlc_value_in_flight_msat,
            self.htlc_minimum_msat,
            self.to_self_delay,
            self.max_accepted_htlcs,
            self.locktime,
            self.funding_pubkey,
            self.revocation_basepoint,
            self.payment_basepoint,
            self.delayed_payment_basepoint,
            self.htlc_basepoint,
            self.first_per_commitment_point,
            self.second_per_commitment_point,
            self.channel_flags,
            self.upfront_shutdown_script,
            self.channel_type,
        ]
    }
}

/// Emits the inputs of `sample_open_channel2`, deriving the
/// `temporary_channel_id` from our revocation basepoint (the `[0x22; 32]`
/// key) as BOLT 2 requires.
pub fn load_open_channel2_inputs(b: &mut ProgramBuilder) -> OpenChannel2Inputs {
    let funding_privkey = b.append(Operation::LoadPrivateKey([0x11; 32]), &[]);
    let revocation_basepoint = load_point(b, [0x22; 32]);

    OpenChannel2Inputs {
        chain_hash: b.append(Operation::LoadChainHashFromContext, &[]),
        temporary_channel_id: b.append(
            Operation::DeriveTemporaryChannelIdV2,
            &[revocation_basepoint],
        ),
        funding_feerate_perkw: b.append(Operation::LoadFeeratePerKw(253), &[]),
        commitment_feerate_perkw: b.append(Operation::LoadFeeratePerKw(2500), &[]),
        funding_satoshis: b.append(Operation::LoadAmount(200_000), &[]),
        dust_limit_satoshis: b.append(Operation::LoadAmount(546), &[]),
        max_htlc_value_in_flight_msat: b.append(Operation::LoadAmount(100_000_000), &[]),
        htlc_minimum_msat: b.append(Operation::LoadAmount(1_000), &[]),
        to_self_delay: b.append(Operation::LoadU16(144), &[]),
        max_accepted_htlcs: b.append(Operation::LoadU16(483), &[]),
        locktime: b.append(Operation::LoadBlockHeight(120), &[]),
        funding_pubkey: b.append(Operation::DerivePoint, &[funding_privkey]),
        revocation_basepoint,
        payment_basepoint: load_point(b, [0x33; 32]),
        delayed_payment_basepoint: load_point(b, [0x44; 32]),
        htlc_basepoint: load_point(b, [0x55; 32]),
        first_per_commitment_point: load_point(b, [0x66; 32]),
        second_per_commitment_point: load_point(b, [0x77; 32]),
        channel_flags: b.append(Operation::LoadU8(0), &[]),
        upfront_shutdown_script: b.append(Operation::LoadBytes(vec![]), &[]),
        channel_type: b.append(Operation::LoadChannelType(ChannelTypeVariant::Anchors), &[]),
        funding_privkey,
    }
}

/// The variables a sent `open_channel2` produces.
#[derive(Clone, Copy)]
pub struct SentOpenChannel2 {
    pub inputs: OpenChannel2Inputs,
    /// The `SendOpenChannel2` result, an affine variable a single
    /// `RecvAcceptChannel2` may consume.
    pub sent: usize,
}

/// Emits `sample_open_channel2` and sends it.
pub fn send_open_channel2(b: &mut ProgramBuilder) -> SentOpenChannel2 {
    let inputs = load_open_channel2_inputs(b);

    send_open_channel2_with(b, inputs, false)
}

/// Builds `open_channel2` from `inputs` and sends it.
pub fn send_open_channel2_with(
    b: &mut ProgramBuilder,
    inputs: OpenChannel2Inputs,
    require_confirmed_inputs: bool,
) -> SentOpenChannel2 {
    let built = b.append(
        Operation::BuildOpenChannel2 {
            require_confirmed_inputs,
        },
        &inputs.build_inputs(),
    );
    let sent = b.append(Operation::SendOpenChannel2, &[built]);

    SentOpenChannel2 { inputs, sent }
}

/// The variables a v2 channel negotiation produces.
#[derive(Clone, Copy)]
pub struct NegotiatedChannel2 {
    pub open_channel2: SentOpenChannel2,
    /// The `RecvAcceptChannel2` result.
    pub accept_channel2: usize,
}

/// Emits `sample_open_channel2`, sends it, and receives the peer's
/// `accept_channel2`.
pub fn negotiate_channel2(b: &mut ProgramBuilder) -> NegotiatedChannel2 {
    let open_channel2 = send_open_channel2(b);
    let accept_channel2 = b.append(Operation::RecvAcceptChannel2, &[open_channel2.sent]);

    NegotiatedChannel2 {
        open_channel2,
        accept_channel2,
    }
}

/// A program that negotiates `sample_open_channel2`.
pub fn negotiate_channel2_program() -> Program {
    let mut b = ProgramBuilder::new();
    negotiate_channel2(&mut b);

    b.build()
}

/// The variables a v2 negotiation with its `channel_id` derived produces.
#[derive(Clone, Copy)]
pub struct V2Channel {
    pub inputs: OpenChannel2Inputs,
    /// The `DeriveChannelIdV2` result, which every later message on the
    /// channel carries.
    pub channel_id: usize,
}

/// Negotiates `sample_open_channel2` and derives the v2 `channel_id` from
/// both revocation basepoints.
pub fn negotiate_v2_channel(b: &mut ProgramBuilder) -> V2Channel {
    let negotiated = negotiate_channel2(b);
    let inputs = negotiated.open_channel2.inputs;
    let peer_revocation_basepoint = b.append(
        Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
        &[negotiated.accept_channel2],
    );
    let channel_id = b.append(
        Operation::DeriveChannelIdV2,
        &[inputs.revocation_basepoint, peer_revocation_basepoint],
    );

    V2Channel { inputs, channel_id }
}

// -- Interactive transaction construction --

/// The `sequence` our `tx_add_input`s carry, opting into RBF.
const TX_ADD_INPUT_SEQUENCE: u32 = 0xffff_fffd;

/// Sends a `tx_add_input` spending the wallet's `utxo_index`th coin on the
/// `ChannelId` variable `channel_id`.
pub fn send_tx_add_input(
    b: &mut ProgramBuilder,
    channel_id: usize,
    serial_id: u64,
    utxo_index: u8,
) -> usize {
    b.append(
        Operation::SendTxAddInput {
            serial_id,
            utxo_index,
            sequence: TX_ADD_INPUT_SEQUENCE,
        },
        &[channel_id],
    )
}

/// Sends a `tx_add_output` of `role` on `channel_id`. The value and script
/// inputs only matter for [`TxOutputRole::Explicit`], so placeholders are
/// loaded for them.
pub fn send_tx_add_output(
    b: &mut ProgramBuilder,
    channel_id: usize,
    serial_id: u64,
    role: TxOutputRole,
) -> usize {
    let sats = b.append(Operation::LoadAmount(0), &[]);
    let script = b.append(Operation::LoadBytes(vec![]), &[]);

    b.append(
        Operation::SendTxAddOutput { serial_id, role },
        &[channel_id, sats, script],
    )
}

/// Sends a `tx_complete` on `channel_id`.
pub fn send_tx_complete(b: &mut ProgramBuilder, channel_id: usize) -> usize {
    b.append(Operation::SendTxComplete, &[channel_id])
}

/// Reads the peer's reply to the `SentInteractiveTx` variable `sent`.
pub fn recv_interactive_tx(b: &mut ProgramBuilder, sent: usize) {
    b.append(Operation::RecvInteractiveTx, &[sent]);
}

/// The variables the v2 funding flow produces.
#[derive(Clone, Copy)]
pub struct V2FundingFlow {
    pub inputs: OpenChannel2Inputs,
    /// The v2 `channel_id`.
    pub channel_id: usize,
    /// The `BuildFundingTransactionV2` result.
    pub funding_tx: usize,
}

/// Negotiates the v2 channel, contributes an input, the funding output and a
/// change output, and builds the funding transaction from them. The peer's
/// replies come from `v2_flow_fixture`.
pub fn v2_funding_flow(b: &mut ProgramBuilder) -> V2FundingFlow {
    let V2Channel { inputs, channel_id } = negotiate_v2_channel(b);
    send_tx_add_input(b, channel_id, 2, 0);
    send_tx_add_output(b, channel_id, 4, TxOutputRole::Funding);
    send_tx_add_output(b, channel_id, 6, TxOutputRole::Change);
    let funding_tx = b.append(Operation::BuildFundingTransactionV2, &[channel_id]);

    V2FundingFlow {
        inputs,
        channel_id,
        funding_tx,
    }
}

// -- Commitment and signature exchange --

/// Sends our `commitment_signed` over `flow`'s funding transaction, signed
/// with the funding key the open advertised.
pub fn send_commitment_signed(b: &mut ProgramBuilder, flow: &V2FundingFlow) -> usize {
    b.append(
        Operation::SendCommitmentSigned,
        &[
            flow.funding_tx,
            flow.inputs.funding_privkey,
            flow.channel_id,
        ],
    )
}

/// Sends our `tx_signatures` over `flow`'s funding transaction.
pub fn send_tx_signatures(b: &mut ProgramBuilder, flow: &V2FundingFlow) {
    b.append(
        Operation::SendTxSignatures,
        &[flow.channel_id, flow.funding_tx],
    );
}

/// A program that runs the v2 funding flow and sends our `commitment_signed`.
pub fn send_commitment_signed_program() -> Program {
    let mut b = ProgramBuilder::new();
    let flow = v2_funding_flow(&mut b);
    send_commitment_signed(&mut b, &flow);

    b.build()
}

/// A program that runs the v2 funding flow, sends our `commitment_signed`, and
/// receives the peer's.
pub fn exchange_commitment_signed_program() -> Program {
    let mut b = ProgramBuilder::new();
    let flow = v2_funding_flow(&mut b);
    let sent = send_commitment_signed(&mut b, &flow);
    b.append(Operation::RecvCommitmentSigned, &[sent]);

    b.build()
}

/// The program from a real CLN run: four contributions go out with three
/// replies unread, then a `tx_complete` and a change output. The peer's
/// `tx_complete` answering the last input and ours are consecutive, so the
/// exchange concluded without the change output, but the program builds the
/// funding transaction and signs over it before reading the reply that says
/// so. Returns the `SendCommitmentSigned` result; the peer's replies come from
/// `settle_before_build_fixture`.
pub fn settle_before_build(b: &mut ProgramBuilder) -> usize {
    let V2Channel { inputs, channel_id } = negotiate_v2_channel(b);
    let first_input = send_tx_add_input(b, channel_id, 2, 0);
    send_tx_add_output(b, channel_id, 2000, TxOutputRole::Funding);
    send_tx_add_input(b, channel_id, 4, 1);
    let last_input = send_tx_add_input(b, channel_id, 6, 2);
    recv_interactive_tx(b, first_input);
    let complete = send_tx_complete(b, channel_id);
    let change = send_tx_add_output(b, channel_id, 2002, TxOutputRole::Change);
    recv_interactive_tx(b, change);
    recv_interactive_tx(b, complete);
    // The reply to the last input is still unread here.
    let funding_tx = b.append(Operation::BuildFundingTransactionV2, &[channel_id]);
    let sent = b.append(
        Operation::SendCommitmentSigned,
        &[funding_tx, inputs.funding_privkey, channel_id],
    );
    recv_interactive_tx(b, last_input);

    sent
}

// -- Malformed programs --

/// Builds a program from `(operation, inputs)` pairs, skipping the
/// well-formedness checks [`ProgramBuilder`] applies.
///
/// Only for tests asserting the executor rejects a malformed program, which
/// can't use `ProgramBuilder` since it too panics on malformed programs.
pub fn raw_program(instructions: &[(Operation, &[usize])]) -> Program {
    Program {
        instructions: instructions
            .iter()
            .map(|(operation, inputs)| Instruction {
                operation: operation.clone(),
                inputs: inputs.to_vec(),
            })
            .collect(),
    }
}
