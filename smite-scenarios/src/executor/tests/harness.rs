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

    pub fn queue_recv(&mut self, msg_bytes: Vec<u8>) {
        self.recv_queue.push_back(msg_bytes);
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
        negotiated_features: Features::from_bits(&[
            Features::OPTION_STATIC_REMOTEKEY,
            Features::OPTION_ANCHORS,
            Features::OPTION_CHANNEL_TYPE,
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

#[allow(clippy::similar_names)]
pub fn sample_funding_negotiation() -> PendingChannel {
    let secp = Secp256k1::new();
    let opener_sk =
        SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
            .unwrap();
    let acceptor_sk =
        SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
            .unwrap();
    let opener_pk = PublicKey::from_secret_key(&secp, &opener_sk);
    let acceptor_pk = PublicKey::from_secret_key(&secp, &acceptor_sk);

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
