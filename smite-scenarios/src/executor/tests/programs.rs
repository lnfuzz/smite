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
use smite_ir::Instruction;
use smite_ir::builder::ProgramBuilder;
use smite_ir::operation::ShutdownScriptVariant;

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
        PointSource::Secret(bytes) => {
            let sk = b.append(Operation::LoadPrivateKey(bytes), &[]);
            b.append(Operation::DerivePoint, &[sk])
        }
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

/// Sends `funding_created`, receives `funding_signed`, mines `confirmations`
/// blocks, and receives the target's `channel_ready`.
pub fn establish_channel(b: &mut ProgramBuilder, confirmations: u8) {
    let funding_created = send_funding_created(b);
    b.append(Operation::RecvFundingSigned, &[funding_created.sent]);
    b.append(Operation::MineBlocks(confirmations), &[]);
    b.append(Operation::RecvChannelReady, &[]);
}

/// A program that runs [`establish_channel`].
pub fn recv_channel_ready_program(confirmations: u8) -> Program {
    let mut b = ProgramBuilder::new();
    establish_channel(&mut b, confirmations);

    b.build()
}

// -- shutdown --

/// The variables a sent `shutdown` produces.
#[derive(Clone, Copy)]
pub struct SentShutdown {
    pub channel_id: usize,
    pub scriptpubkey: usize,
    /// The `SendShutdown` result, an affine variable a single `RecvShutdown`
    /// may consume.
    pub sent: usize,
}

/// Sends a `shutdown` for `channel_id` carrying `script`.
pub fn send_shutdown(
    b: &mut ProgramBuilder,
    channel_id: ChannelId,
    script: ShutdownScriptVariant,
) -> SentShutdown {
    let channel_id = b.append(Operation::LoadChannelId(channel_id.0), &[]);
    let scriptpubkey = b.append(Operation::LoadShutdownScript(script), &[]);
    let sent = b.append(Operation::SendShutdown, &[channel_id, scriptpubkey]);

    SentShutdown {
        channel_id,
        scriptpubkey,
        sent,
    }
}

/// A program that establishes the funding flow's channel, sends a `shutdown`
/// for `channel_id` carrying `script`, and receives the target's `shutdown`.
pub fn recv_shutdown_program(channel_id: ChannelId, script: ShutdownScriptVariant) -> Program {
    let mut b = ProgramBuilder::new();
    establish_channel(&mut b, 6);
    let shutdown = send_shutdown(&mut b, channel_id, script);
    b.append(Operation::RecvShutdown, &[shutdown.sent]);

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
