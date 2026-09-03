//! Mocks and fixtures shared by the executor tests.

use crate::executor::*;
use bitcoin::{Amount, Transaction};
use smite::bolt::AcceptChannelTlvs;
use std::collections::VecDeque;
use std::str::FromStr;

// -- MockConnection --

pub struct MockConnection {
    pub recv_queue: VecDeque<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
}

impl MockConnection {
    pub fn new() -> Self {
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
    pub utxos: Vec<Utxo>,
    pub change_spk: ScriptBuf,
    pub confirmations: u32,
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

// -- Fixture --

/// An [`Executor`] wired to a mock peer and a mock bitcoind.
pub struct Fixture {
    executor: Executor<MockConnection, MockBitcoinCli>,
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
            executor: Executor::new(MockConnection::new(), bitcoin_cli, sample_context()),
        }
    }

    /// Funds the wallet with `utxos` instead of the default [`sample_utxo`].
    pub fn with_utxos(mut self, utxos: Vec<Utxo>) -> Self {
        self.executor.bitcoin_cli.utxos = utxos;
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

    /// Returns the number of queued peer replies the executor has not read.
    pub fn queued_len(&self) -> usize {
        self.executor.conn.recv_queue.len()
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

    /// Returns the channel state recorded for `id`.
    pub fn channel_state(&self, id: &ChannelId) -> &ChannelState {
        self.executor
            .channel_states
            .get(id)
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
}

/// Extracts a specific BOLT message from a decoded [`Message`].
pub trait FromMessage: Sized {
    /// Wire type of the expected BOLT message.
    const TYPE: MessageType;

    /// Returns the extracted BOLT message if `msg`'s type matches, `None`
    /// otherwise.
    fn from_message(msg: Message) -> Option<Self>;
}

/// Implements [`FromMessage`] for BOLT messages whose [`Message`] variant has
/// the same name.
macro_rules! impl_from_message {
    ($($bolt_msg:ident => $msg_type:ident,)*) => {
        $(
            impl FromMessage for $bolt_msg {
                const TYPE: MessageType = MessageType::$msg_type;

                fn from_message(msg: Message) -> Option<Self> {
                    match msg {
                        Message::$bolt_msg(bolt_msg) => Some(bolt_msg),
                        _ => None,
                    }
                }
            }
        )*
    };
}

impl_from_message! {
    Pong => PONG,
    OpenChannel => OPEN_CHANNEL,
    FundingCreated => FUNDING_CREATED,
    ChannelReady => CHANNEL_READY,
    Shutdown => SHUTDOWN,
    ChannelAnnouncement => CHANNEL_ANNOUNCEMENT,
    NodeAnnouncement => NODE_ANNOUNCEMENT,
    ChannelUpdate => CHANNEL_UPDATE,
    AnnouncementSignatures => ANNOUNCEMENT_SIGNATURES,
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
        chain_hash: [0xcc; 32],
        block_height: 800_000,
        target_features: vec![],
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

/// A fixture with the funding negotiation seeded and both target replies
/// queued, plus the target's per-commitment point for the assertions.
pub fn recv_channel_ready_fixture() -> (Fixture, PublicKey) {
    let target_pcp = sample_pubkey(1);

    // We also need to queue a `funding_signed`, since the instructions reused
    // by these tests expect one to be present in the receive queue.
    let fx = Fixture::new()
        .with_negotiation(sample_funding_negotiation())
        .queue(&funding_signed_reply(funding_channel_id()))
        .queue(&channel_ready_reply(target_pcp));

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
