//! Mocks and fixtures shared by the executor tests.

use crate::executor::*;
use bitcoin::{Amount, Transaction};
use smite::bolt::{
    AcceptChannel2Tlvs, AcceptChannelTlvs, ChannelTypeVariant, CommitmentSigned,
    CommitmentSignedTlvs, FromMessage,
};
use smite::pending_channel::PendingChannelV2;
use std::collections::VecDeque;
use std::str::FromStr;

// -- MockConnection --

struct MockConnection {
    recv_queue: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl MockConnection {
    fn new() -> Self {
        Self {
            recv_queue: VecDeque::new(),
            sent: Vec::new(),
        }
    }
}

impl Connection for MockConnection {
    fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError> {
        self.sent.push(msg.to_vec());
        Ok(())
    }

    fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError> {
        self.recv_queue
            .pop_front()
            .ok_or_else(|| ConnectionError::Io(std::io::ErrorKind::UnexpectedEof.into()))
    }

    fn set_read_timeout(&mut self, _timeout: Option<Duration>) -> Result<(), ConnectionError> {
        Ok(())
    }

    fn read_timeout(&self) -> Result<Option<Duration>, ConnectionError> {
        Ok(None)
    }
}

// Mocking BitcoinCli via MockBitcoinCli

#[derive(Default)]
pub struct MockBitcoinCli {
    pub mine_blocks_calls: Vec<u8>,
    pub mined_private_mempool: Vec<String>,
    pub broadcast_calls: Vec<Transaction>,
    pub block_position_lookups: Vec<Txid>,
    pub locked_outpoints: Vec<OutPoint>,
    utxos: Vec<Utxo>,
    change_spk: ScriptBuf,
    confirmations: u32,
    /// Serialized transactions the node knows about, keyed by txid, as
    /// `getrawtransaction` would return them.
    raw_transactions: HashMap<Txid, Vec<u8>>,
    /// Outpoints the wallet can sign. `sign_tx` attaches a witness only to
    /// these, the way bitcoind signs only what it owns.
    signable_outpoints: Vec<OutPoint>,
    /// When set, `sign_tx` fails outright.
    signing_fails: bool,
}

impl BitcoinRpc for MockBitcoinCli {
    fn mine_blocks(&mut self, num_blocks: u8, private_mempool: &[String]) {
        self.mine_blocks_calls.push(num_blocks);
        self.mined_private_mempool = private_mempool.to_vec();
        self.confirmations += u32::from(num_blocks);
    }

    fn get_utxos(&mut self) -> Vec<Utxo> {
        self.utxos.clone()
    }

    fn get_new_address_script_pubkey(&mut self) -> ScriptBuf {
        self.change_spk.clone()
    }

    fn get_raw_transaction(&mut self, txid: Txid) -> Option<Vec<u8>> {
        self.raw_transactions.get(&txid).cloned()
    }

    fn sign_tx(&mut self, tx: &bitcoin::Transaction) -> Option<bitcoin::Transaction> {
        if self.signing_fails {
            return None;
        }
        let mut signed = tx.clone();
        for txin in &mut signed.input {
            if self.signable_outpoints.contains(&txin.previous_output) {
                // A distinguishable two-element witness, so tests can tell
                // which input a witness came from.
                txin.witness = bitcoin::Witness::from_slice(&[
                    vec![0xaa; 72],
                    txin.previous_output.txid.to_string().into_bytes(),
                ]);
            }
        }
        Some(signed)
    }

    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) -> Option<String> {
        self.broadcast_calls.push(tx.clone());

        // Simulate a mempool-policy rejection: if any output is below its
        // dust threshold, return the tx hex so it gets queued in the
        // private mempool. Otherwise the tx is accepted.
        let has_dust = tx
            .output
            .iter()
            .any(|o| o.value < o.script_pubkey.minimal_non_dust());
        if has_dust {
            Some(bitcoin::consensus::encode::serialize_hex(tx))
        } else {
            None
        }
    }

    fn lock_utxos(&mut self, outpoints: &[OutPoint]) {
        self.locked_outpoints.extend_from_slice(outpoints);
        self.utxos.retain(|u| !outpoints.contains(&u.outpoint));
    }

    fn get_transaction_confirmations(&mut self, _txid: Txid) -> u32 {
        self.confirmations
    }

    fn get_transaction_block_position(&mut self, txid: Txid) -> Option<TxBlockPosition> {
        self.block_position_lookups.push(txid);
        // Distinctive coordinates so tests can verify the executor
        // combined them with the funding transaction's vout.
        (self.confirmations > 0).then_some(TxBlockPosition {
            block_height: 800_042,
            tx_index: 7,
        })
    }
}

// Mocking TargetRpc via MockTargetRpc

#[derive(Default)]
pub struct MockTargetRpc {
    pub chain_syncs: usize,
}

impl TargetRpc for MockTargetRpc {
    fn chain_sync(&mut self) {
        self.chain_syncs += 1;
    }
}

// -- Fixture --

/// An [`Executor`] wired to a mock peer and a mock bitcoind.
pub struct Fixture {
    executor: Executor<MockConnection, MockBitcoinCli, MockTargetRpc>,
}

impl Fixture {
    /// A fixture with a silent peer and a wallet holding [`sample_utxo`].
    pub fn new() -> Self {
        let bitcoin_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        Self {
            executor: Executor::new(
                MockConnection::new(),
                bitcoin_cli,
                MockTargetRpc::default(),
                sample_context(),
            ),
        }
    }

    /// Funds the wallet with `utxos` instead of the default [`sample_utxo`].
    pub fn with_utxos(mut self, utxos: Vec<Utxo>) -> Self {
        self.executor.bitcoin_cli.utxos = utxos;
        self
    }

    /// Adds `utxo` to the wallet.
    pub fn with_utxo(mut self, utxo: Utxo) -> Self {
        self.executor.bitcoin_cli.utxos.push(utxo);
        self
    }

    /// Lets the wallet sign every coin it holds, so `tx_signatures` has
    /// witnesses to carry.
    pub fn with_signable_wallet(mut self) -> Self {
        let cli = &mut self.executor.bitcoin_cli;
        cli.signable_outpoints = cli.utxos.iter().map(|u| u.outpoint).collect();
        self
    }

    /// Makes every signing attempt fail outright.
    pub fn with_signing_failure(mut self) -> Self {
        self.executor.bitcoin_cli.signing_fails = true;
        self
    }

    /// Funds the wallet with one spendable output of [`sample_prevtx`], with
    /// that transaction available to `getrawtransaction`.
    pub fn with_v2_wallet(mut self) -> Self {
        let prevtx = sample_prevtx();
        let txid = prevtx.compute_txid();
        self.executor.bitcoin_cli.utxos = vec![Utxo {
            amount: prevtx.output[0].value,
            outpoint: OutPoint { txid, vout: 0 },
            script_pubkey: prevtx.output[0].script_pubkey.clone(),
        }];
        self.executor
            .bitcoin_cli
            .raw_transactions
            .insert(txid, bitcoin::consensus::encode::serialize(&prevtx));
        self
    }

    /// Records `pending` as the negotiation for its `temporary_channel_id`.
    pub fn with_negotiation(mut self, pending: PendingChannel) -> Self {
        self.executor
            .negotiations
            .insert(pending.open_channel.temporary_channel_id, pending);
        self
    }

    /// Queues `msg` as the peer's next reply.
    pub fn queue(mut self, msg: &Message) -> Self {
        self.executor.conn.recv_queue.push_back(msg.encode());
        self
    }

    /// Queues `msg` as the peer's next `count` replies.
    pub fn queue_repeated(mut self, msg: &Message, count: usize) -> Self {
        for _ in 0..count {
            self.executor.conn.recv_queue.push_back(msg.encode());
        }
        self
    }

    /// Queues the peer's side of `v2_funding_flow`: `accept`, then a
    /// `tx_complete` answering each of the three contributions, which
    /// `BuildFundingTransactionV2` reads to settle the negotiation before
    /// building.
    pub fn queue_v2_flow_replies(self, accept: AcceptChannel2) -> Self {
        self.queue(&Message::AcceptChannel2(accept))
            .queue_repeated(&tx_complete_reply(v2_channel_id()), 3)
    }

    /// Returns the number of queued peer replies the executor has not read.
    pub fn queued_len(&self) -> usize {
        self.executor.conn.recv_queue.len()
    }

    /// Returns the type of each queued peer reply the executor has not read.
    pub fn queued_types(&self) -> Vec<MessageType> {
        self.executor
            .conn
            .recv_queue
            .iter()
            .map(|bytes| Message::decode(bytes).expect("valid message").msg_type())
            .collect()
    }

    /// Runs `program` against the target, panicking if execution fails.
    pub fn run(&mut self, program: &Program) {
        self.executor
            .execute(program, std::time::Instant::now())
            .expect("program execution successful");
    }

    /// Runs `program` against the target, returning the error it fails with.
    pub fn run_err(&mut self, program: &Program) -> ExecuteError {
        self.executor
            .execute(program, std::time::Instant::now())
            .expect_err("program execution failure")
    }

    /// Returns the negotiation recorded for `id`.
    pub fn negotiation(&self, id: &TemporaryChannelId) -> &PendingChannel {
        self.executor
            .negotiations
            .get(id)
            .expect("negotiation recorded")
    }

    /// Returns the v2 negotiation recorded for `id`, a temporary or a
    /// derived `channel_id`.
    pub fn negotiation_v2(&self, id: ChannelId) -> &PendingChannelV2 {
        self.executor
            .negotiations_v2
            .get(id)
            .expect("v2 negotiation recorded")
    }

    /// Returns the channel state recorded for `id`.
    pub fn channel_state(&self, id: &ChannelId) -> &ChannelState {
        self.executor
            .channel_states
            .get(id)
            .expect("channel state recorded")
    }

    /// Returns the channel state recorded for `id`, for a test to tamper
    /// with.
    pub fn channel_state_mut(&mut self, id: &ChannelId) -> &mut ChannelState {
        self.executor
            .channel_states
            .get_mut(id)
            .expect("channel state recorded")
    }

    /// Returns every channel state the executor recorded.
    pub fn channel_states(&self) -> &HashMap<ChannelId, ChannelState> {
        &self.executor.channel_states
    }

    /// Returns the mock bitcoind the executor drives.
    pub fn bitcoin(&self) -> &MockBitcoinCli {
        &self.executor.bitcoin_cli
    }

    /// Returns the mock RPC interface to the target.
    pub fn rpc(&self) -> &MockTargetRpc {
        &self.executor.rpc
    }

    /// Returns the transactions held outside Bitcoin Core's mempool.
    pub fn private_mempool(&self) -> &[(Txid, String)] {
        &self.executor.private_mempool
    }

    /// Returns the number of messages the executor sent.
    pub fn sent_len(&self) -> usize {
        self.executor.conn.sent.len()
    }

    /// Decodes the `n`th message the executor sent, panicking if it is not an
    /// `M`.
    pub fn sent<M: FromMessage>(&self, n: usize) -> M {
        let bytes = self.executor.conn.sent.get(n).unwrap_or_else(|| {
            panic!(
                "expected at least {} sent messages, got {}",
                n + 1,
                self.sent_len()
            )
        });
        let msg = Message::decode(bytes).expect("valid message");
        let got = msg.to_string();
        M::from_message(msg).unwrap_or_else(|| panic!("expected {}, got {got}", M::TYPE))
    }

    /// Decodes the last message the executor sent, panicking if it is not an
    /// `M`.
    pub fn last_sent<M: FromMessage>(&self) -> M {
        let last = self
            .sent_len()
            .checked_sub(1)
            .expect("at least one sent message");
        self.sent(last)
    }

    /// Returns the type of each message the executor sent, in order.
    pub fn sent_types(&self) -> Vec<MessageType> {
        self.executor
            .conn
            .sent
            .iter()
            .map(|bytes| Message::decode(bytes).expect("valid message").msg_type())
            .collect()
    }
}

// -- Helpers --

pub fn sample_pubkey(byte: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let mut key_bytes = [0u8; 32];
    key_bytes[31] = byte;
    let sk = SecretKey::from_slice(&key_bytes).expect("valid secret key");
    PublicKey::from_secret_key(&secp, &sk)
}

pub fn sample_context() -> ProgramContext {
    ProgramContext {
        target_pubkey: sample_pubkey(1),
        local_pubkey: sample_pubkey(2),
        chain_hash: [0xcc; 32],
        block_height: 800_000,
        negotiated_features: Features::from_bits(&[
            Features::OPTION_STATIC_REMOTEKEY,
            Features::OPTION_ANCHORS,
        ]),
    }
}

pub fn sample_utxo() -> Utxo {
    Utxo {
        amount: Amount::from_sat(10_008_942),
        outpoint: OutPoint {
            txid: "a1f7b953dc8c3db0222d931d3e2613f9971af75a09a005b31af057f8414cc5d7"
                .parse()
                .expect("valid txid"),
            vout: 0,
        },
        script_pubkey: ScriptBuf::from(
            hex::decode("0014a10d9257489e685dda030662390dc177852faf13")
                .expect("valid P2WPKH scriptpubkey hex"),
        ),
    }
}

pub fn sample_change_spk() -> ScriptBuf {
    ScriptBuf::from(
        hex::decode("00142e532c12351a5c81e23c8a76d19345ca7b6de57a")
            .expect("valid P2WPKH scriptpubkey hex"),
    )
}

pub fn sample_accept_channel() -> AcceptChannel {
    AcceptChannel {
        temporary_channel_id: TemporaryChannelId::new([0xbb; 32]),
        dust_limit_satoshis: 546,
        max_htlc_value_in_flight_msat: 100_000_000,
        channel_reserve_satoshis: 10_000,
        htlc_minimum_msat: 1_000,
        minimum_depth: 6,
        to_self_delay: 144,
        max_accepted_htlcs: 483,
        funding_pubkey: sample_pubkey(1),
        revocation_basepoint: sample_pubkey(2),
        payment_basepoint: sample_pubkey(3),
        delayed_payment_basepoint: sample_pubkey(4),
        htlc_basepoint: sample_pubkey(5),
        first_per_commitment_point: sample_pubkey(6),
        tlvs: AcceptChannelTlvs {
            upfront_shutdown_script: Some(vec![0xde, 0xad]),
            channel_type: Some(vec![0x40, 0x10, 0x00]),
        },
    }
}

// -- Sample open_channel --

/// How a program produces the six pubkeys of an `open_channel`.
///
/// The IR cannot load a literal point, so program builders need a `PointSource`
/// to derive them.
#[derive(Clone, Copy)]
pub enum PointSource {
    /// The target's pubkey, read from the program context.
    TargetContext,
    /// A pubkey derived from this private key.
    Secret([u8; 32]),
}

impl PointSource {
    /// The pubkey a program built from this source should derive.
    pub fn pubkey(self) -> PublicKey {
        match self {
            Self::TargetContext => sample_context().target_pubkey,
            Self::Secret(bytes) => {
                let sk = SecretKey::from_slice(&bytes).expect("valid private key");
                PublicKey::from_secret_key(&Secp256k1::new(), &sk)
            }
        }
    }
}

/// An `open_channel` a test sends, paired with the source of its pubkeys.
///
/// `message` is exactly what the executor must put on the wire, so tests can
/// compare it to what the executor actually sent.
pub struct SampleOpenChannel {
    /// What the executor must send.
    pub message: OpenChannel,
    /// How the program produces the six pubkeys of `message`.
    pub points: PointSource,
}

impl SampleOpenChannel {
    /// A sample `open_channel` whose pubkeys come from `points`.
    pub fn new(points: PointSource) -> Self {
        let pubkey = points.pubkey();
        Self {
            message: OpenChannel {
                chain_hash: sample_context().chain_hash,
                temporary_channel_id: TemporaryChannelId::new([0xbb; 32]),
                funding_satoshis: 100_000,
                push_msat: 0,
                dust_limit_satoshis: 546,
                max_htlc_value_in_flight_msat: 100_000_000,
                channel_reserve_satoshis: 10_000,
                htlc_minimum_msat: 1_000,
                feerate_per_kw: 253,
                to_self_delay: 144,
                max_accepted_htlcs: 483,
                funding_pubkey: pubkey,
                revocation_basepoint: pubkey,
                payment_basepoint: pubkey,
                delayed_payment_basepoint: pubkey,
                htlc_basepoint: pubkey,
                first_per_commitment_point: pubkey,
                channel_flags: 1,
                tlvs: OpenChannelTlvs {
                    upfront_shutdown_script: Some(vec![]),
                    channel_type: Some(ChannelTypeVariant::Anchors.encode()),
                },
            },
            points,
        }
    }
}

/// The `open_channel` the message-building tests send: an announced channel
/// carrying the target's pubkey in every pubkey field.
pub fn announced_open_channel() -> SampleOpenChannel {
    SampleOpenChannel::new(PointSource::TargetContext)
}

// -- Funding fixture --
//
// The funding keys are chosen from BOLT 3 test vectors. All other constants are
// derived from these keys.

/// The opener's funding key for the funding flow.
pub fn opener_funding_sk() -> SecretKey {
    SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
        .expect("valid secret key")
}

/// The acceptor's funding key for the funding flow.
pub fn acceptor_funding_sk() -> SecretKey {
    SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
        .expect("valid secret key")
}

/// The outpoint of the funding transaction the funding-flow programs build.
pub fn funding_outpoint() -> OutPoint {
    OutPoint {
        txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
            .parse()
            .expect("valid txid"),
        vout: 0,
    }
}

/// The channel id the funding flow's transaction produces.
pub fn funding_channel_id() -> ChannelId {
    ChannelId::v1_from_funding_outpoint(funding_outpoint())
}

/// The acceptor's `funding_signed` for `channel_id`.
///
/// The signature was computed by LDK over this fixture's commitment, so the
/// executor accepting it shows both implementations built the same commitment
/// transaction.
pub fn funding_signed_reply(channel_id: ChannelId) -> Message {
    Message::FundingSigned(FundingSigned {
        channel_id,
        signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7"
            .parse()
            .expect("valid DER signature"),
    })
}

/// The target's `channel_ready` for the funding flow's channel.
pub fn channel_ready_reply(second_per_commitment_point: PublicKey) -> Message {
    Message::ChannelReady(ChannelReady {
        channel_id: funding_channel_id(),
        second_per_commitment_point,
        tlvs: ChannelReadyTlvs::default(),
    })
}

/// A fixture with the funding negotiation seeded and the target's
/// `funding_signed` queued, as the funding-flow instructions expect.
pub fn recv_funding_signed_fixture() -> Fixture {
    Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&funding_signed_reply(funding_channel_id()))
}

/// A [`recv_funding_signed_fixture`] with the target's `channel_ready` queued
/// too, plus the per-commitment point it carries for the assertions.
pub fn recv_channel_ready_fixture() -> (Fixture, PublicKey) {
    let target_pcp = sample_pubkey(1);
    let fx = recv_funding_signed_fixture().queue(&channel_ready_reply(target_pcp));

    (fx, target_pcp)
}

#[allow(clippy::similar_names)]
pub fn sample_funding_negotiation() -> PendingChannel {
    let secp = Secp256k1::new();
    let opener_pk = PublicKey::from_secret_key(&secp, &opener_funding_sk());
    let acceptor_pk = PublicKey::from_secret_key(&secp, &acceptor_funding_sk());

    PendingChannel {
        open_channel: OpenChannel {
            chain_hash: [0xcc; 32],
            temporary_channel_id: TemporaryChannelId::new([0xbb; 32]),
            funding_satoshis: 10_000_000,
            push_msat: 3_000_000_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            feerate_per_kw: 15_000,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: opener_pk,
            revocation_basepoint: opener_pk,
            payment_basepoint: opener_pk,
            delayed_payment_basepoint: opener_pk,
            htlc_basepoint: opener_pk,
            first_per_commitment_point: opener_pk,
            channel_flags: 1,
            tlvs: OpenChannelTlvs::default(),
        },
        accept_channel: Some(AcceptChannel {
            temporary_channel_id: TemporaryChannelId::new([0xbb; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 6,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: acceptor_pk,
            revocation_basepoint: acceptor_pk,
            payment_basepoint: acceptor_pk,
            delayed_payment_basepoint: acceptor_pk,
            htlc_basepoint: acceptor_pk,
            first_per_commitment_point: acceptor_pk,
            tlvs: AcceptChannelTlvs::default(),
        }),
        funding_built: false,
    }
}

// -- Channel establishment v2 --

pub fn sample_accept_channel2(temporary_channel_id: TemporaryChannelId) -> AcceptChannel2 {
    AcceptChannel2 {
        temporary_channel_id,
        // The acceptor contributes nothing, the common case for CLN and
        // Eclair when they are not configured to provide liquidity.
        funding_satoshis: 0,
        dust_limit_satoshis: 546,
        max_htlc_value_in_flight_msat: 100_000_000,
        htlc_minimum_msat: 1_000,
        minimum_depth: 6,
        to_self_delay: 144,
        max_accepted_htlcs: 483,
        funding_pubkey: sample_pubkey(11),
        revocation_basepoint: sample_pubkey(12),
        payment_basepoint: sample_pubkey(13),
        delayed_payment_basepoint: sample_pubkey(14),
        htlc_basepoint: sample_pubkey(15),
        first_per_commitment_point: sample_pubkey(16),
        second_per_commitment_point: sample_pubkey(17),
        tlvs: AcceptChannel2Tlvs {
            upfront_shutdown_script: Some(vec![0xde, 0xad]),
            channel_type: Some(vec![0x00, 0x40, 0x10, 0x00]),
            require_confirmed_inputs: false,
        },
    }
}

/// The `open_channel2` that `send_open_channel2` puts on the wire.
pub fn sample_open_channel2() -> OpenChannel2 {
    let secp = Secp256k1::new();
    let pk = |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
    OpenChannel2 {
        chain_hash: [0xcc; 32],
        temporary_channel_id: sample_v2_temporary_channel_id(),
        funding_feerate_perkw: 253,
        commitment_feerate_perkw: 2500,
        funding_satoshis: 200_000,
        dust_limit_satoshis: 546,
        max_htlc_value_in_flight_msat: 100_000_000,
        htlc_minimum_msat: 1_000,
        to_self_delay: 144,
        max_accepted_htlcs: 483,
        locktime: 120,
        funding_pubkey: pk(&[0x11; 32]),
        revocation_basepoint: sample_v2_revocation_basepoint(),
        payment_basepoint: pk(&[0x33; 32]),
        delayed_payment_basepoint: pk(&[0x44; 32]),
        htlc_basepoint: pk(&[0x55; 32]),
        first_per_commitment_point: pk(&[0x66; 32]),
        second_per_commitment_point: pk(&[0x77; 32]),
        channel_flags: 0,
        tlvs: OpenChannel2Tlvs {
            upfront_shutdown_script: Some(vec![]),
            channel_type: Some(ChannelTypeVariant::Anchors.encode()),
            require_confirmed_inputs: false,
        },
    }
}

/// Our `revocation_basepoint`, and hence the `temporary_channel_id` that
/// `load_open_channel2_inputs` derives from it.
pub fn sample_v2_revocation_basepoint() -> PublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x22; 32]).expect("valid secret key");
    PublicKey::from_secret_key(&secp, &sk)
}

pub fn sample_v2_temporary_channel_id() -> TemporaryChannelId {
    ChannelId::v2_temporary_from_revocation_basepoint(&sample_v2_revocation_basepoint())
}

// -- Interactive transaction construction --

/// A minimal previous transaction paying one 1 BTC P2WPKH output, used as
/// the `prevtx` a `tx_add_input` carries.
pub fn sample_prevtx() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: sample_change_spk(),
        }],
    }
}

/// The peer's `accept_channel2` answering `send_open_channel2`.
pub fn accept_channel2_reply() -> Message {
    Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
}

/// A `tx_add_input` from the peer spending the output of [`sample_prevtx`].
pub fn tx_add_input_reply(channel_id: ChannelId, serial_id: u64) -> Message {
    Message::TxAddInput(TxAddInput {
        channel_id,
        serial_id,
        prevtx: bitcoin::consensus::encode::serialize(&sample_prevtx()),
        prevtx_vout: 0,
        sequence: 0xffff_fffd,
        tlvs: TxAddInputTlvs::default(),
    })
}

/// A `tx_add_output` from the peer paying 50,000 sat to [`sample_change_spk`].
pub fn tx_add_output_reply(channel_id: ChannelId, serial_id: u64) -> Message {
    Message::TxAddOutput(TxAddOutput {
        channel_id,
        serial_id,
        sats: 50_000,
        script: sample_change_spk().into_bytes(),
    })
}

pub fn tx_remove_input_reply(channel_id: ChannelId, serial_id: u64) -> Message {
    Message::TxRemoveInput(TxRemoveInput {
        channel_id,
        serial_id,
    })
}

pub fn tx_remove_output_reply(channel_id: ChannelId, serial_id: u64) -> Message {
    Message::TxRemoveOutput(TxRemoveOutput {
        channel_id,
        serial_id,
    })
}

pub fn tx_complete_reply(channel_id: ChannelId) -> Message {
    Message::TxComplete(TxComplete { channel_id })
}

/// A `commitment_signed` with a zero signature, standing for whatever the
/// peer sends once the interactive transaction exchange concludes.
pub fn commitment_signed_reply(channel_id: ChannelId) -> Message {
    Message::CommitmentSigned(CommitmentSigned {
        channel_id,
        signature: Signature::from_compact(&[0u8; 64]).expect("zero signature"),
        htlc_signatures: Vec::new(),
        tlvs: CommitmentSignedTlvs::default(),
    })
}

/// A fixture with the v2 wallet and the peer's `accept_channel2` queued, ready
/// for a program that negotiates the v2 channel and exchanges interactive
/// transaction messages on it.
pub fn v2_fixture() -> Fixture {
    Fixture::new()
        .with_v2_wallet()
        .queue(&accept_channel2_reply())
}

/// A fixture with the v2 wallet and the peer's side of `v2_funding_flow`
/// queued, answered with the sample `accept_channel2`.
pub fn v2_flow_fixture() -> Fixture {
    Fixture::new()
        .with_v2_wallet()
        .queue_v2_flow_replies(sample_accept_channel2(sample_v2_temporary_channel_id()))
}

/// A [`v2_fixture`] with the peer's side of `settle_before_build` queued: one
/// `tx_complete` per contribution before our own `tx_complete`, then whatever
/// the peer moved on to.
pub fn settle_before_build_fixture(then: &Message) -> Fixture {
    v2_fixture()
        .queue_repeated(&tx_complete_reply(v2_channel_id()), 4)
        .queue(then)
}

// -- Commitment and signature exchange --

pub fn v2_channel_id() -> ChannelId {
    ChannelId::v2_from_revocation_basepoints(
        &sample_v2_revocation_basepoint(),
        &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
    )
}

/// A plausible P2WPKH witness from the peer: signature and pubkey.
pub fn sample_peer_witness() -> Witness {
    Witness::from_slice(&[vec![0xbb; 71], vec![0xcc; 33]])
}

/// [`sample_peer_witness`] encoded the way `tx_signatures` carries
/// `witness_data`.
pub fn sample_peer_witness_data() -> Vec<u8> {
    bitcoin::consensus::encode::serialize(&sample_peer_witness())
}

/// The private key behind [`sample_accept_channel2`]'s `funding_pubkey`,
/// which is `sample_pubkey(11)`.
pub fn sample_acceptor_funding_privkey() -> SecretKey {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 11;
    SecretKey::from_slice(&sk_bytes).expect("valid secret key")
}
