//! IR program executor.
//!
//! Executes an IR program against a target node over an established connection,
//! producing side effects (sending/receiving messages).

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, TxOut, Txid};
use smite::bitcoin::{BitcoinCli, TxBlockPosition, Utxo};
use smite::bolt::{
    AcceptChannel, AcceptChannel2, AnnouncementSignatures, ChannelAnnouncement, ChannelId,
    ChannelReady, ChannelReadyTlvs, ChannelUpdate, CommitmentSigned, CommitmentSignedTlvs,
    FundingCreated, FundingSigned, MAX_MESSAGE_SIZE, Message, MessageType, NodeAnnouncement,
    OpenChannel, OpenChannel2, OpenChannel2Tlvs, OpenChannelTlvs, Pong, ShortChannelId, Shutdown,
    TxAddInput, TxAddInputTlvs, TxAddOutput, TxComplete, TxRemoveInput, TxRemoveOutput,
    TxSignatures, TxSignaturesTlvs,
};
use smite::channel_tx::{
    ChannelConfig, ChannelPartyConfig, ChannelState, Contributor, FundingTransaction,
    HolderIdentity, SharedInput, SharedOutput, Side, build_funding_transaction,
    build_funding_witness_script, signs_first,
};
use smite::noise::{ConnectionError, NoiseConnection};
use smite::oracles::{AcceptChannelContext, AcceptChannelOracle, Oracle};
use smite::pending_channel::{PendingChannel, PendingChannelV2};
use smite::violation::Violation;
use smite_ir::operation::{AcceptChannel2Field, AcceptChannelField, TxOutputRole};
use smite_ir::{Operation, Program, Variable};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// The timeout used when receiving messages from the target. We will wait this
/// long to receive an expected message before aborting program execution.
///
/// To determine the timeout value, we measured target response times to
/// `open_channel` (`accept_channel` response) and `funding_created`
/// (`funding_signed` response) within the Nyx VM while running a fuzzing
/// campaign that saturated all CPU cores. The *maximum* response times observed
/// were:
/// - LDK: 3ms `accept_channel`; 3ms `funding_signed`
/// - LND: 68ms `accept_channel`; 5ms `funding_signed`
/// - CLN: 142ms `accept_channel`; 179ms `funding_signed`
/// - Eclair: 444ms `accept_channel`; 288ms `funding_signed`
///
/// Thus a timeout of 1s provides more than a 2x buffer over the slowest
/// observed response times.
///
/// TODO: Once HTLC/commitment operations are supported, measure response times
/// for commitment operations and increase timeout if needed.
///
/// TODO: Investigate optimizations to the Eclair workload and remeasure
/// response times to see if timeout can be decreased further.
pub const RECV_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

/// The timeout used when receiving a `channel_ready` message from the target.
///
/// Most targets poll for new blocks every 2s or less, so 5s is enough time to
/// wait for their `channel_ready` after mining the funding transaction.
///
/// FIXME: CLN polls every 30s, so this timeout is not enough for CLN. Look into
/// reconfiguring or patching CLN to poll more frequently.
pub const RECV_CHANNEL_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Abstraction over bitcoin-cli operations, allowing mock implementations in tests.
pub trait BitcoinRpc {
    /// Mines the given number of blocks, including any transactions in the
    /// `private_mempool` in the first block.
    fn mine_blocks(&mut self, num_blocks: u8, private_mempool: &[String]);

    /// Returns the wallet's spendable UTXOs.
    #[must_use]
    fn get_utxos(&mut self) -> Vec<Utxo>;

    /// Returns the scriptPubKey for a newly generated wallet address.
    #[must_use]
    fn get_new_address_script_pubkey(&mut self) -> ScriptBuf;

    /// Returns the consensus-serialized transaction with the given txid, or
    /// `None` if it is unknown to the node. Used for `tx_add_input`'s `prevtx`.
    #[must_use]
    fn get_raw_transaction(&mut self, txid: Txid) -> Option<Vec<u8>>;

    /// Signs and broadcasts a transaction. Returns hex-encoded raw transaction
    /// if it is consensus-valid but rejected by mempool policy, so it can be
    /// added to the `private_mempool`; returns `None` if it was broadcast or is
    /// already confirmed.
    #[must_use]
    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) -> Option<String>;

    /// Signs the wallet-owned inputs of a transaction without broadcasting it,
    /// leaving inputs the wallet cannot sign untouched. Used to lift our own
    /// witnesses for `tx_signatures`.
    #[must_use]
    fn sign_tx(&mut self, tx: &bitcoin::Transaction) -> Option<bitcoin::Transaction>;

    /// Locks the given outpoints so subsequent [`get_utxos`](Self::get_utxos)
    /// calls exclude them, preventing independently built transactions from
    /// reusing the same coins.
    fn lock_utxos(&mut self, outpoints: &[OutPoint]);

    /// Returns the number of confirmations for the transaction with the given
    /// txid, or `0` if it is unconfirmed or unknown to the node.
    #[must_use]
    fn get_transaction_confirmations(&mut self, txid: Txid) -> u32;

    /// Returns the confirmed block position of the transaction with the given
    /// txid, or `None` if it is unconfirmed or unknown to the node.
    fn get_transaction_block_position(&mut self, txid: Txid) -> Option<TxBlockPosition>;
}

impl BitcoinRpc for BitcoinCli {
    fn mine_blocks(&mut self, num_blocks: u8, private_mempool: &[String]) {
        BitcoinCli::mine_blocks(self, num_blocks, private_mempool);
    }

    fn get_utxos(&mut self) -> Vec<Utxo> {
        BitcoinCli::get_utxos(self)
    }

    fn get_new_address_script_pubkey(&mut self) -> ScriptBuf {
        BitcoinCli::get_new_address_script_pubkey(self)
    }

    fn get_raw_transaction(&mut self, txid: Txid) -> Option<Vec<u8>> {
        BitcoinCli::get_raw_transaction(self, txid)
    }

    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) -> Option<String> {
        BitcoinCli::sign_and_broadcast_tx(self, tx)
    }

    fn sign_tx(&mut self, tx: &bitcoin::Transaction) -> Option<bitcoin::Transaction> {
        BitcoinCli::sign_tx(self, tx)
    }

    fn lock_utxos(&mut self, outpoints: &[OutPoint]) {
        BitcoinCli::lock_utxos(self, outpoints);
    }

    fn get_transaction_confirmations(&mut self, txid: Txid) -> u32 {
        BitcoinCli::get_transaction_confirmations(self, txid)
    }

    fn get_transaction_block_position(&mut self, txid: Txid) -> Option<TxBlockPosition> {
        BitcoinCli::get_transaction_block_position(self, txid)
    }
}

/// State captured during snapshot setup, available to IR programs at execution
/// time via `LoadContext*` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramContext {
    /// Target node's identity public key.
    pub target_pubkey: PublicKey,
    /// Our own identity public key, derived from the fixed Noise static key.
    /// BOLT 2 breaks a `tx_signatures` ordering tie on the lexicographically
    /// lower `node_id`, so both are needed to decide who signs first.
    pub local_pubkey: PublicKey,
    /// Chain hash (genesis block hash).
    pub chain_hash: [u8; 32],
    /// Current block height at snapshot time.
    pub block_height: u32,
    /// Target's advertised feature bits from init message.
    pub target_features: Vec<u8>,
}

/// Abstraction over a Noise-encrypted connection, allowing mock implementations
/// in tests.
pub trait Connection {
    /// Sends an encrypted message.
    ///
    /// # Errors
    ///
    /// Returns an error if the send fails.
    fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError>;

    /// Receives and decrypts the next message.
    ///
    /// # Errors
    ///
    /// Returns an error if the receive fails.
    fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError>;

    /// Sets the read timeout applied to subsequent `recv_message` calls. `None`
    /// makes reads block indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error if the timeout cannot be set.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), ConnectionError>;

    /// Returns the current read timeout or `None` if reads block indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error if the timeout cannot be read.
    fn read_timeout(&self) -> Result<Option<Duration>, ConnectionError>;
}

impl Connection for NoiseConnection {
    fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError> {
        NoiseConnection::send_message(self, msg)
    }

    fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError> {
        NoiseConnection::recv_message(self)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), ConnectionError> {
        NoiseConnection::set_read_timeout(self, timeout)
    }

    fn read_timeout(&self) -> Result<Option<Duration>, ConnectionError> {
        NoiseConnection::read_timeout(self)
    }
}

/// Error from executing an IR program.
///
/// These represent target-side behavior or transport failures. Invariant
/// violations of the program itself cause panics instead.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    /// Connection or send/receive failure.
    #[error("connection: {0}")]
    Connection(#[from] smite::noise::ConnectionError),

    /// Failed to decode a received message.
    #[error("decode: {0}")]
    Decode(#[from] smite::bolt::BoltError),

    /// Received a different message type than expected.
    #[error("unexpected message: expected {expected}, got {got}")]
    UnexpectedMessage {
        expected: MessageType,
        got: MessageType,
    },

    /// The target sent a BOLT `error`.
    #[error("peer error on {:?}: {}", .0.channel_id, .0.message().unwrap_or("<non-utf8>"))]
    PeerError(smite::bolt::Error),

    /// Wallet UTXOs could not cover the funding amount and fees.
    #[error("funding: {0}")]
    InsufficientFunds(#[from] smite::channel_tx::InsufficientFunds),

    /// Failed to construct the initial commitment state.
    #[error("commitment: {0}")]
    Commitment(#[from] smite::channel_tx::CommitmentError),

    /// The target broke a protocol invariant. Surfaced to the scenario as a
    /// failure; see [`Violation`] for the full catalog of target-bug findings.
    #[error(transparent)]
    Violation(#[from] Violation),
}

/// Executes IR programs against a target over an established connection.
pub struct Executor<C, B> {
    /// Connection used to send and receive Lightning messages.
    conn: C,
    /// Interface to bitcoind for wallet and chain operations.
    bitcoin_cli: B,
    /// Immutable state captured during snapshot setup.
    context: ProgramContext,
    /// Channel states maintained implicitly across program execution, keyed by
    /// `ChannelId`. Created by the funding flow and initialized with the
    /// channel's static configuration and initial commitment state, then
    /// updated as commitments are exchanged and revoked.
    channel_states: HashMap<ChannelId, ChannelState>,
    /// Negotiation state captured during program execution, keyed by
    /// `temporary_channel_id`, so the funding flow can build commitments from
    /// the parameters actually sent on the wire.
    negotiations: HashMap<ChannelId, PendingChannel>,
    /// Channel establishment v2 negotiation state, keyed by
    /// `temporary_channel_id`.
    negotiations_v2: HashMap<ChannelId, PendingChannelV2>,
    /// Maps a v2 `channel_id` back to the `temporary_channel_id` keying
    /// `negotiations_v2`. Every message after `accept_channel2` carries the v2
    /// `channel_id`, which is only derivable once the peer's revocation
    /// basepoint is known.
    v2_channel_ids: HashMap<ChannelId, ChannelId>,
    /// Transactions stored outside Bitcoin Core's mempool, typically because they
    /// were rejected by mempool policy, to be included in the next `MineBlocks`
    /// operation. Each is stored as `(txid, raw_hex)`: re-signing the same
    /// transaction can change its raw hex, but the txid stays the same, so
    /// deduplication keys on the txid while the raw hex is what gets mined.
    private_mempool: Vec<(Txid, String)>,
    /// Transactions broadcast but not yet mined. Unlike `private_mempool`,
    /// which only holds what Bitcoin Core's mempool rejected, this tracks every
    /// broadcast.
    unmined_txids: HashSet<Txid>,
    /// Transactions broadcast and since mined.
    mined_txids: HashSet<Txid>,
}

impl<C: Connection, B: BitcoinRpc> Executor<C, B> {
    /// Creates an executor with the given connection, bitcoin-cli handle, and
    /// program context. Channel state and negotiations start empty.
    pub fn new(conn: C, bitcoin_cli: B, context: ProgramContext) -> Self {
        Self {
            conn,
            bitcoin_cli,
            context,
            channel_states: HashMap::new(),
            negotiations: HashMap::new(),
            negotiations_v2: HashMap::new(),
            v2_channel_ids: HashMap::new(),
            private_mempool: Vec::new(),
            unmined_txids: HashSet::new(),
            mined_txids: HashSet::new(),
        }
    }

    /// Returns a mutable reference to the underlying connection.
    pub fn conn_mut(&mut self) -> &mut C {
        &mut self.conn
    }

    /// Executes an IR program against the target.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - a connection/send/receive operation fails
    /// - a received message fails to decode
    /// - the target sends an unexpected message type
    /// - wallet funds are insufficient to perform a channel operation
    /// - the initial commitment transaction cannot be constructed
    /// - the target commits a [`Violation`] (unknown channel, temporary
    ///   channel id reuse, opener cannot afford the commitment feerate, or
    ///   invalid counterparty signature)
    ///
    /// # Panics
    ///
    /// Panics on any invariant violation of the program:
    /// - input count does not match the operation's expected input count
    /// - input variable index out of bounds
    /// - input variable refers to a void instruction
    /// - input variable has the wrong type
    /// - `MineBlocks(0)` (panics inside `BitcoinCli::mine_blocks`)
    /// - `LoadShutdownScript(AnySegwit { .. })` with an out-of-range version or
    ///   program length (panics inside the encoder)
    /// - `LoadBytes` / `LoadFeatures` payload exceeding `MAX_MESSAGE_SIZE` (panics
    ///   inside the encoder)
    /// - `LoadPrivateKey` whose bytes are all-zero or >= the secp256k1 curve
    ///   order (probability ~2^-128 for uniform random input)
    #[allow(clippy::too_many_lines)]
    pub fn execute(
        &mut self,
        program: &Program,
        start: std::time::Instant,
    ) -> Result<(), ExecuteError> {
        let secp = Secp256k1::new();
        let mut variables: Vec<Option<Variable>> = Vec::with_capacity(program.instructions.len());

        for instr in &program.instructions {
            let expected_count = instr.operation.input_types().len();
            assert_eq!(
                instr.inputs.len(),
                expected_count,
                "{:?}: expected {expected_count} inputs, got {}",
                instr.operation,
                instr.inputs.len(),
            );

            let result = match &instr.operation {
                // -- Load operations --
                Operation::LoadAmount(v) => Some(Variable::Amount(*v)),
                Operation::LoadShortChannelId(v) => {
                    Some(Variable::ShortChannelId(ShortChannelId::from_u64(*v)))
                }
                Operation::LoadFeeratePerKw(v) => Some(Variable::FeeratePerKw(*v)),
                Operation::LoadBlockHeight(v) => Some(Variable::BlockHeight(*v)),
                Operation::LoadTimestamp(v) => Some(Variable::Timestamp(*v)),
                Operation::LoadForwardingFee(v) => Some(Variable::ForwardingFee(*v)),
                Operation::LoadU16(v) => Some(Variable::U16(*v)),
                Operation::LoadU8(v) => Some(Variable::U8(*v)),
                Operation::LoadBytes(b) => Some(Variable::Bytes(b.clone())),
                Operation::LoadFeatures(b) => Some(Variable::Features(b.clone())),
                Operation::LoadPrivateKey(k) => Some(Variable::PrivateKey(*k)),
                Operation::LoadChannelId(id) => Some(Variable::ChannelId(ChannelId::new(*id))),
                Operation::LoadShutdownScript(variant) => Some(Variable::Bytes(variant.encode())),
                Operation::LoadChannelType(variant) => Some(Variable::Features(variant.encode())),
                Operation::LoadTargetPubkeyFromContext => {
                    Some(Variable::Point(self.context.target_pubkey))
                }
                Operation::LoadChainHashFromContext => {
                    Some(Variable::ChainHash(self.context.chain_hash))
                }

                // -- Compute operations --
                Operation::DerivePoint => {
                    let key_bytes = resolve_private_key(&variables, instr.inputs[0]);
                    let sk = SecretKey::from_slice(&key_bytes).expect("valid private key");
                    let pk = PublicKey::from_secret_key(&secp, &sk);
                    Some(Variable::Point(pk))
                }

                Operation::ExtractAcceptChannel(field) => {
                    let ac = resolve_accept_channel(&variables, instr.inputs[0]);
                    Some(extract_field(ac, *field))
                }

                Operation::CreateFundingTransaction => {
                    let ft = create_funding_transaction(
                        &variables,
                        &instr.inputs,
                        &mut self.bitcoin_cli,
                    )?;
                    Some(Variable::FundingTransaction(ft))
                }

                // -- Build operations --
                Operation::BuildOpenChannel => {
                    let oc = build_open_channel(&variables, &instr.inputs);
                    Some(Variable::OpenChannelMessage(oc))
                }

                Operation::BuildChannelAnnouncement => {
                    let ca = build_channel_announcement(&variables, &instr.inputs);
                    let encoded = Message::ChannelAnnouncement(ca).encode();
                    Some(Variable::Message(encoded))
                }

                Operation::BuildNodeAnnouncement { rgb_color, alias } => {
                    let na = build_node_announcement(&variables, &instr.inputs, *rgb_color, *alias);
                    let encoded = Message::NodeAnnouncement(na).encode();
                    Some(Variable::Message(encoded))
                }

                Operation::BuildChannelUpdate => {
                    let cu = build_channel_update(&variables, &instr.inputs);
                    let encoded = Message::ChannelUpdate(cu).encode();
                    Some(Variable::Message(encoded))
                }

                Operation::BuildAnnouncementSignatures => {
                    let ann_sigs = build_announcement_signatures(&variables, &instr.inputs);
                    let encoded = Message::AnnouncementSignatures(ann_sigs).encode();
                    Some(Variable::Message(encoded))
                }

                // -- Act operations --
                Operation::SendMessage => {
                    let bytes = resolve_message(&variables, instr.inputs[0]);
                    let ty = u16::from_be_bytes(
                        *bytes
                            .first_chunk::<2>()
                            .expect("encoded message has a 2-byte type prefix"),
                    );
                    log::debug!(
                        "[{:?}] SendMessage: {}, {} bytes",
                        start.elapsed(),
                        MessageType::from_u16(ty),
                        bytes.len(),
                    );
                    self.conn.send_message(bytes)?;
                    None
                }

                Operation::SendOpenChannel => {
                    let oc = resolve_open_channel_message(&variables, instr.inputs[0]);
                    record_send_open_channel(&mut self.negotiations, oc);
                    let encoded = Message::OpenChannel(oc.clone()).encode();
                    log::debug!(
                        "[{:?}] SendOpenChannel: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentOpenChannel)
                }

                Operation::SendFundingCreated => {
                    let fc = build_funding_created(
                        &variables,
                        &instr.inputs,
                        &mut self.channel_states,
                        &mut self.negotiations,
                        &self.mined_txids,
                    )?;
                    let encoded = Message::FundingCreated(fc).encode();
                    log::debug!(
                        "[{:?}] SendFundingCreated: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentFundingCreated)
                }

                Operation::SendChannelReady { include_alias } => {
                    let cr = build_channel_ready(
                        &variables,
                        &instr.inputs,
                        *include_alias,
                        &mut self.channel_states,
                    );
                    let encoded = Message::ChannelReady(cr).encode();
                    log::debug!(
                        "[{:?}] SendChannelReady: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    None
                }

                Operation::SendShutdown => {
                    let sd = build_shutdown(&variables, &instr.inputs);
                    let encoded = Message::Shutdown(sd).encode();
                    log::debug!(
                        "[{:?}] SendShutdown: {} bytes",
                        start.elapsed(),
                        encoded.len()
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentShutdown)
                }

                Operation::RecvAcceptChannel => {
                    consume_sent_open_channel(&mut variables, instr.inputs[0]);
                    log::debug!("[{:?}] RecvAcceptChannel: waiting", start.elapsed());
                    let ac = recv_accept_channel(&mut self.conn)?;
                    log::debug!("[{:?}] RecvAcceptChannel: received", start.elapsed());
                    AcceptChannelOracle.evaluate(&AcceptChannelContext {
                        accept_channel: &ac,
                        negotiation: self.negotiations.get(&ac.temporary_channel_id),
                    })?;
                    record_recv_accept_channel(&mut self.negotiations, &ac);
                    Some(Variable::AcceptChannel(ac))
                }

                Operation::RecvFundingSigned => {
                    consume_sent_funding_created(&mut variables, instr.inputs[0]);
                    log::debug!("[{:?}] RecvFundingSigned: waiting", start.elapsed());
                    let fs = recv_funding_signed(&mut self.conn)?;
                    log::debug!("[{:?}] RecvFundingSigned: received", start.elapsed());
                    verify_funding_signed(&fs, &self.channel_states)?;
                    Some(Variable::ChannelId(fs.channel_id))
                }

                Operation::RecvChannelReady => {
                    if is_channel_ready_expected(&self.channel_states, &mut self.bitcoin_cli) {
                        log::debug!("[{:?}] RecvChannelReady: waiting", start.elapsed());
                        recv_channel_ready(&mut self.conn, &mut self.channel_states)?;
                        log::debug!("[{:?}] RecvChannelReady: received", start.elapsed());
                    }
                    None
                }

                Operation::MineBlocks(v) => {
                    // Clear the private mempool and mine the requested blocks,
                    // adding those transactions to the first block.
                    let private_mempool: Vec<String> = std::mem::take(&mut self.private_mempool)
                        .into_iter()
                        .map(|(_, hex)| hex)
                        .collect();
                    self.bitcoin_cli.mine_blocks(*v, &private_mempool);
                    self.mined_txids.extend(self.unmined_txids.drain());
                    log::debug!("[{:?}] MineBlocks: mined {} block(s)", start.elapsed(), v);
                    None
                }

                Operation::BroadcastTransaction => {
                    let ft = resolve_funding_transaction(&variables, instr.inputs[0]);
                    let txid = ft.tx.compute_txid();
                    log::debug!(
                        "[{:?}] BroadcastTransaction: txid={}",
                        start.elapsed(),
                        txid
                    );
                    // Queue transactions rejected by the mempool in the private
                    // mempool so they can be mined later. Dedup on txid so the
                    // same transaction broadcast again before then is queued
                    // once, regardless of any change to its signed hex.
                    if let Some(hex) = self.bitcoin_cli.sign_and_broadcast_tx(&ft.tx)
                        && !self.private_mempool.iter().any(|(t, _)| *t == txid)
                    {
                        self.private_mempool.push((txid, hex));
                    }
                    self.unmined_txids.insert(txid);
                    None
                }

                Operation::LookupShortChannelId => {
                    let ft = resolve_funding_transaction(&variables, instr.inputs[0]);
                    let txid = ft.tx.compute_txid();
                    // Fall back to a sentinel SCID when the transaction is
                    // unknown to the node or still in the mempool (e.g. a
                    // mutator dropped `MineBlocks`). The resulting gossip
                    // message will simply fail on-chain validation, which is
                    // the intended fuzzing behaviour for a valid but
                    // unconfirmed program.
                    let scid = match self.bitcoin_cli.get_transaction_block_position(txid) {
                        Some(pos) => {
                            let funding_output_index =
                                u16::try_from(ft.vout).expect("funding output index fits in u16");
                            ShortChannelId::new(
                                pos.block_height,
                                pos.tx_index,
                                funding_output_index,
                            )
                        }
                        None => ShortChannelId::new(0, 0, 0),
                    };
                    log::debug!(
                        "[{:?}] LookupShortChannelId: txid={} scid={}",
                        start.elapsed(),
                        txid,
                        scid,
                    );
                    Some(Variable::ShortChannelId(scid))
                }

                // -- Channel establishment v2 --
                Operation::DeriveTemporaryChannelIdV2 => {
                    let revocation_basepoint = resolve_pubkey(&variables, instr.inputs[0]);
                    Some(Variable::ChannelId(
                        ChannelId::v2_temporary_from_revocation_basepoint(&revocation_basepoint),
                    ))
                }

                Operation::DeriveChannelIdV2 => {
                    let ours = resolve_pubkey(&variables, instr.inputs[0]);
                    let theirs = resolve_pubkey(&variables, instr.inputs[1]);
                    Some(Variable::ChannelId(
                        ChannelId::v2_from_revocation_basepoints(&ours, &theirs),
                    ))
                }

                Operation::ExtractAcceptChannel2(field) => {
                    let ac = resolve_accept_channel2(&variables, instr.inputs[0]);
                    Some(extract_field_v2(ac, *field))
                }

                Operation::BuildOpenChannel2 {
                    require_confirmed_inputs,
                } => {
                    let oc =
                        build_open_channel2(&variables, &instr.inputs, *require_confirmed_inputs);
                    Some(Variable::OpenChannel2Message(oc))
                }

                Operation::SendOpenChannel2 => {
                    let oc = resolve_open_channel2_message(&variables, instr.inputs[0]);
                    record_send_open_channel2(&mut self.negotiations_v2, oc);
                    let encoded = Message::OpenChannel2(oc.clone()).encode();
                    log::debug!(
                        "[{:?}] SendOpenChannel2: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentOpenChannel2)
                }

                Operation::RecvAcceptChannel2 => {
                    consume_sent_open_channel2(&mut variables, instr.inputs[0]);
                    log::debug!("[{:?}] RecvAcceptChannel2: waiting", start.elapsed());
                    let ac = recv_accept_channel2(&mut self.conn)?;
                    log::debug!("[{:?}] RecvAcceptChannel2: received", start.elapsed());
                    record_recv_accept_channel2(
                        &mut self.negotiations_v2,
                        &mut self.v2_channel_ids,
                        &ac,
                    );
                    Some(Variable::AcceptChannel2(ac))
                }

                Operation::SendTxAddInput {
                    serial_id,
                    utxo_index,
                    sequence,
                } => {
                    let msg = build_tx_add_input(
                        &variables,
                        &instr.inputs,
                        *serial_id,
                        *utxo_index,
                        *sequence,
                        &mut self.bitcoin_cli,
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                    );
                    let encoded = Message::TxAddInput(msg).encode();
                    log::debug!(
                        "[{:?}] SendTxAddInput: serial_id={serial_id}, {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx)
                }

                Operation::SendTxAddOutput { serial_id, role } => {
                    let msg = build_tx_add_output(
                        &variables,
                        &instr.inputs,
                        *serial_id,
                        *role,
                        &mut self.bitcoin_cli,
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                    );
                    let encoded = Message::TxAddOutput(msg).encode();
                    log::debug!(
                        "[{:?}] SendTxAddOutput: serial_id={serial_id}, role={role}, {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx)
                }

                Operation::SendTxRemoveInput { serial_id } => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    if let Some(pending) = negotiation_v2_mut(
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                        channel_id,
                    ) {
                        // BOLT 2 forbids removing an input the peer added. If
                        // a program does it anyway the peer keeps the input, so
                        // only drop our own to stay in step with it.
                        if pending
                            .shared_tx
                            .inputs()
                            .any(|(id, i)| id == *serial_id && i.contributor == Contributor::Local)
                        {
                            pending.shared_tx.remove_input(*serial_id);
                        }
                        pending.tx_negotiation.sent_tx_complete = false;
                    }
                    let encoded = Message::TxRemoveInput(TxRemoveInput {
                        channel_id,
                        serial_id: *serial_id,
                    })
                    .encode();
                    log::debug!(
                        "[{:?}] SendTxRemoveInput: serial_id={serial_id}",
                        start.elapsed(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx)
                }

                Operation::SendTxRemoveOutput { serial_id } => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    if let Some(pending) = negotiation_v2_mut(
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                        channel_id,
                    ) {
                        if pending
                            .shared_tx
                            .outputs()
                            .any(|(id, o)| id == *serial_id && o.contributor == Contributor::Local)
                        {
                            pending.shared_tx.remove_output(*serial_id);
                        }
                        pending.tx_negotiation.sent_tx_complete = false;
                    }
                    let encoded = Message::TxRemoveOutput(TxRemoveOutput {
                        channel_id,
                        serial_id: *serial_id,
                    })
                    .encode();
                    log::debug!(
                        "[{:?}] SendTxRemoveOutput: serial_id={serial_id}",
                        start.elapsed(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx)
                }

                Operation::SendTxComplete => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    if let Some(pending) = negotiation_v2_mut(
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                        channel_id,
                    ) {
                        pending.tx_negotiation.sent_tx_complete = true;
                    }
                    let encoded = Message::TxComplete(TxComplete { channel_id }).encode();
                    log::debug!("[{:?}] SendTxComplete", start.elapsed());
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx)
                }

                Operation::RecvInteractiveTx => {
                    consume_sent_interactive_tx(&mut variables, instr.inputs[0]);
                    log::debug!("[{:?}] RecvInteractiveTx: waiting", start.elapsed());
                    let msg = recv_non_ping(&mut self.conn, RECV_IDLE_TIMEOUT)?;
                    log::debug!("[{:?}] RecvInteractiveTx: got {msg}", start.elapsed());
                    apply_interactive_tx(&mut self.negotiations_v2, &self.v2_channel_ids, msg)?;
                    None
                }

                Operation::BuildFundingTransactionV2 => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    let ft = build_funding_transaction_v2(
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                        channel_id,
                    );
                    log::debug!(
                        "[{:?}] BuildFundingTransactionV2: txid={} vout={}",
                        start.elapsed(),
                        ft.tx.compute_txid(),
                        ft.vout,
                    );
                    Some(Variable::FundingTransaction(ft))
                }

                Operation::SendCommitmentSigned => {
                    let cs = build_commitment_signed(
                        &variables,
                        &instr.inputs,
                        &mut self.channel_states,
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                        &self.mined_txids,
                    )?;
                    let encoded = Message::CommitmentSigned(cs).encode();
                    log::debug!(
                        "[{:?}] SendCommitmentSigned: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentCommitmentSigned)
                }

                Operation::RecvCommitmentSigned => {
                    consume_sent_commitment_signed(&mut variables, instr.inputs[0]);
                    log::debug!("[{:?}] RecvCommitmentSigned: waiting", start.elapsed());
                    let cs = recv_commitment_signed(&mut self.conn)?;
                    log::debug!("[{:?}] RecvCommitmentSigned: received", start.elapsed());
                    verify_commitment_signed(
                        &cs,
                        &self.channel_states,
                        &mut self.negotiations_v2,
                        &self.v2_channel_ids,
                    )?;
                    Some(Variable::ChannelId(cs.channel_id))
                }

                Operation::RecvTxSignatures => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    if is_tx_signatures_expected(
                        &self.negotiations_v2,
                        &self.v2_channel_ids,
                        channel_id,
                        &self.context,
                    ) {
                        log::debug!("[{:?}] RecvTxSignatures: waiting", start.elapsed());
                        let ts = recv_tx_signatures(&mut self.conn)?;
                        log::debug!("[{:?}] RecvTxSignatures: received", start.elapsed());
                        if let Some(pending) = negotiation_v2_mut(
                            &mut self.negotiations_v2,
                            &self.v2_channel_ids,
                            ts.channel_id,
                        ) {
                            pending.commitment_exchange.received_tx_signatures = true;
                        }
                    }
                    None
                }

                Operation::SendTxSignatures => {
                    let ts = build_tx_signatures(
                        &variables,
                        &instr.inputs,
                        &mut self.bitcoin_cli,
                        &self.negotiations_v2,
                        &self.v2_channel_ids,
                    );
                    let encoded = Message::TxSignatures(ts).encode();
                    log::debug!(
                        "[{:?}] SendTxSignatures: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    None
                }
            };

            variables.push(result);
        }

        Ok(())
    }
}

// -- Variable resolution --
//
// Each resolver looks up a variable by index and checks its type, panicking on
// any invariant violation. Any panic from a resolver indicates that either our
// custom mutators aren't being used or that there's a bug in our custom
// mutators or generators.

fn resolve(variables: &[Option<Variable>], index: usize) -> &Variable {
    let slot = variables
        .get(index)
        .unwrap_or_else(|| panic!("variable {index} out of bounds (have {})", variables.len()));
    slot.as_ref()
        .unwrap_or_else(|| panic!("variable {index} is void"))
}

fn resolve_amount(variables: &[Option<Variable>], index: usize) -> u64 {
    match resolve(variables, index) {
        Variable::Amount(v) => *v,
        other => panic!(
            "variable {index}: expected Amount, got {:?}",
            other.var_type()
        ),
    }
}

fn resolve_feerate(variables: &[Option<Variable>], index: usize) -> u32 {
    match resolve(variables, index) {
        Variable::FeeratePerKw(v) => *v,
        other => panic!(
            "variable {index}: expected FeeratePerKw, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_forwarding_fee(variables: &[Option<Variable>], index: usize) -> u32 {
    match resolve(variables, index) {
        Variable::ForwardingFee(v) => *v,
        other => panic!(
            "variable {index}: expected ForwardingFee, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_timestamp(variables: &[Option<Variable>], index: usize) -> u32 {
    match resolve(variables, index) {
        Variable::Timestamp(v) => *v,
        other => panic!(
            "variable {index}: expected Timestamp, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_block_height(variables: &[Option<Variable>], index: usize) -> u32 {
    match resolve(variables, index) {
        Variable::BlockHeight(v) => *v,
        other => panic!(
            "variable {index}: expected BlockHeight, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_u16(variables: &[Option<Variable>], index: usize) -> u16 {
    match resolve(variables, index) {
        Variable::U16(v) => *v,
        other => panic!("variable {index}: expected U16, got {:?}", other.var_type()),
    }
}

fn resolve_u8(variables: &[Option<Variable>], index: usize) -> u8 {
    match resolve(variables, index) {
        Variable::U8(v) => *v,
        other => panic!("variable {index}: expected U8, got {:?}", other.var_type()),
    }
}

fn resolve_bytes(variables: &[Option<Variable>], index: usize) -> &[u8] {
    match resolve(variables, index) {
        Variable::Bytes(v) => v,
        other => panic!(
            "variable {index}: expected Bytes, got {:?}",
            other.var_type()
        ),
    }
}

fn resolve_features(variables: &[Option<Variable>], index: usize) -> &[u8] {
    match resolve(variables, index) {
        Variable::Features(v) => v,
        other => panic!(
            "variable {index}: expected Features, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_chain_hash(variables: &[Option<Variable>], index: usize) -> [u8; 32] {
    match resolve(variables, index) {
        Variable::ChainHash(v) => *v,
        other => panic!(
            "variable {index}: expected ChainHash, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_channel_id(variables: &[Option<Variable>], index: usize) -> ChannelId {
    match resolve(variables, index) {
        Variable::ChannelId(v) => *v,
        other => panic!(
            "variable {index}: expected ChannelId, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_pubkey(variables: &[Option<Variable>], index: usize) -> PublicKey {
    match resolve(variables, index) {
        Variable::Point(pk) => *pk,
        other => panic!(
            "variable {index}: expected Point, got {:?}",
            other.var_type()
        ),
    }
}

fn resolve_short_channel_id(variables: &[Option<Variable>], index: usize) -> ShortChannelId {
    match resolve(variables, index) {
        Variable::ShortChannelId(v) => *v,
        other => panic!(
            "variable {index}: expected ShortChannelId, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_private_key(variables: &[Option<Variable>], index: usize) -> [u8; 32] {
    match resolve(variables, index) {
        Variable::PrivateKey(v) => *v,
        other => panic!(
            "variable {index}: expected PrivateKey, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_message(variables: &[Option<Variable>], index: usize) -> &[u8] {
    match resolve(variables, index) {
        Variable::Message(v) => v,
        other => panic!(
            "variable {index}: expected Message, got {:?}",
            other.var_type()
        ),
    }
}

fn resolve_open_channel_message(variables: &[Option<Variable>], index: usize) -> &OpenChannel {
    match resolve(variables, index) {
        Variable::OpenChannelMessage(v) => v,
        other => panic!(
            "variable {index}: expected OpenChannelMessage, got {:?}",
            other.var_type()
        ),
    }
}

fn resolve_accept_channel(variables: &[Option<Variable>], index: usize) -> &AcceptChannel {
    match resolve(variables, index) {
        Variable::AcceptChannel(v) => v,
        other => panic!(
            "variable {index}: expected AcceptChannel, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_open_channel2_message(variables: &[Option<Variable>], index: usize) -> &OpenChannel2 {
    match resolve(variables, index) {
        Variable::OpenChannel2Message(v) => v,
        other => panic!(
            "variable {index}: expected OpenChannel2Message, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_accept_channel2(variables: &[Option<Variable>], index: usize) -> &AcceptChannel2 {
    match resolve(variables, index) {
        Variable::AcceptChannel2(v) => v,
        other => panic!(
            "variable {index}: expected AcceptChannel2, got {:?}",
            other.var_type(),
        ),
    }
}

fn resolve_funding_transaction(
    variables: &[Option<Variable>],
    index: usize,
) -> &FundingTransaction {
    match resolve(variables, index) {
        Variable::FundingTransaction(v) => v,
        other => panic!(
            "variable {index}: expected FundingTransaction, got {:?}",
            other.var_type(),
        ),
    }
}

fn consume_sent_open_channel(variables: &mut [Option<Variable>], index: usize) {
    match resolve(variables, index) {
        Variable::SentOpenChannel => {
            // Consume the affine `SentOpenChannel`.
            variables[index] = None;
        }
        other => panic!(
            "variable {index}: expected SentOpenChannel, got {:?}",
            other.var_type(),
        ),
    }
}

fn consume_sent_open_channel2(variables: &mut [Option<Variable>], index: usize) {
    match resolve(variables, index) {
        Variable::SentOpenChannel2 => {
            // Consume the affine `SentOpenChannel2`.
            variables[index] = None;
        }
        other => panic!(
            "variable {index}: expected SentOpenChannel2, got {:?}",
            other.var_type(),
        ),
    }
}

fn consume_sent_interactive_tx(variables: &mut [Option<Variable>], index: usize) {
    match resolve(variables, index) {
        Variable::SentInteractiveTx => {
            // Consume the affine `SentInteractiveTx`.
            variables[index] = None;
        }
        other => panic!(
            "variable {index}: expected SentInteractiveTx, got {:?}",
            other.var_type(),
        ),
    }
}

fn consume_sent_commitment_signed(variables: &mut [Option<Variable>], index: usize) {
    match resolve(variables, index) {
        Variable::SentCommitmentSigned => {
            // Consume the affine `SentCommitmentSigned`.
            variables[index] = None;
        }
        other => panic!(
            "variable {index}: expected SentCommitmentSigned, got {:?}",
            other.var_type(),
        ),
    }
}

fn consume_sent_funding_created(variables: &mut [Option<Variable>], index: usize) {
    match resolve(variables, index) {
        Variable::SentFundingCreated => {
            // Consume the affine `SentFundingCreated`.
            variables[index] = None;
        }
        other => panic!(
            "variable {index}: expected SentFundingCreated, got {:?}",
            other.var_type(),
        ),
    }
}

// -- Operation handlers --

/// Create a funding transaction by querying the bitcoind for UTXOs and a
/// change address, then calling [`build_funding_transaction`]. Locks the
/// selected inputs so a subsequently built transaction cannot reselect them.
fn create_funding_transaction(
    variables: &[Option<Variable>],
    inputs: &[usize],
    cli: &mut impl BitcoinRpc,
) -> Result<FundingTransaction, ExecuteError> {
    let opener_pubkey = resolve_pubkey(variables, inputs[0]);
    let acceptor_pubkey = resolve_pubkey(variables, inputs[1]);
    let funding_satoshis = resolve_amount(variables, inputs[2]);
    let feerate_per_kw = resolve_feerate(variables, inputs[3]);

    // Query wallet state from bitcoind for coin selection and change.
    let utxos = cli.get_utxos();
    let change_spk = cli.get_new_address_script_pubkey();

    // Create the funding transaction.
    let funding = build_funding_transaction(
        &opener_pubkey,
        &acceptor_pubkey,
        funding_satoshis,
        feerate_per_kw,
        utxos,
        change_spk,
    )?;

    // Lock the selected inputs so a subsequently built transaction does not
    // reselect the same UTXOs.
    let selected: Vec<OutPoint> = funding
        .tx
        .input
        .iter()
        .map(|txin| txin.previous_output)
        .collect();
    cli.lock_utxos(&selected);

    Ok(funding)
}

/// Builds an `OpenChannel` from 20 input variables (wire order).
fn build_open_channel(variables: &[Option<Variable>], inputs: &[usize]) -> OpenChannel {
    OpenChannel {
        chain_hash: resolve_chain_hash(variables, inputs[0]),
        temporary_channel_id: resolve_channel_id(variables, inputs[1]),
        funding_satoshis: resolve_amount(variables, inputs[2]),
        push_msat: resolve_amount(variables, inputs[3]),
        dust_limit_satoshis: resolve_amount(variables, inputs[4]),
        max_htlc_value_in_flight_msat: resolve_amount(variables, inputs[5]),
        channel_reserve_satoshis: resolve_amount(variables, inputs[6]),
        htlc_minimum_msat: resolve_amount(variables, inputs[7]),
        feerate_per_kw: resolve_feerate(variables, inputs[8]),
        to_self_delay: resolve_u16(variables, inputs[9]),
        max_accepted_htlcs: resolve_u16(variables, inputs[10]),
        funding_pubkey: resolve_pubkey(variables, inputs[11]),
        revocation_basepoint: resolve_pubkey(variables, inputs[12]),
        payment_basepoint: resolve_pubkey(variables, inputs[13]),
        delayed_payment_basepoint: resolve_pubkey(variables, inputs[14]),
        htlc_basepoint: resolve_pubkey(variables, inputs[15]),
        first_per_commitment_point: resolve_pubkey(variables, inputs[16]),
        channel_flags: resolve_u8(variables, inputs[17]),
        tlvs: OpenChannelTlvs {
            // Always send the TLV: a zero-length value is the BOLT 2 opt-out
            // signal when option_upfront_shutdown_script is negotiated.
            // Omitting it is a protocol violation in that case. Including if
            // not negotiated is not.
            upfront_shutdown_script: Some(resolve_bytes(variables, inputs[18]).to_vec()),
            channel_type: nonempty_or_none(resolve_features(variables, inputs[19])),
        },
    }
}

/// Builds an `OpenChannel2` from 21 input variables (wire order).
fn build_open_channel2(
    variables: &[Option<Variable>],
    inputs: &[usize],
    require_confirmed_inputs: bool,
) -> OpenChannel2 {
    OpenChannel2 {
        chain_hash: resolve_chain_hash(variables, inputs[0]),
        temporary_channel_id: resolve_channel_id(variables, inputs[1]),
        funding_feerate_perkw: resolve_feerate(variables, inputs[2]),
        commitment_feerate_perkw: resolve_feerate(variables, inputs[3]),
        funding_satoshis: resolve_amount(variables, inputs[4]),
        dust_limit_satoshis: resolve_amount(variables, inputs[5]),
        max_htlc_value_in_flight_msat: resolve_amount(variables, inputs[6]),
        htlc_minimum_msat: resolve_amount(variables, inputs[7]),
        to_self_delay: resolve_u16(variables, inputs[8]),
        max_accepted_htlcs: resolve_u16(variables, inputs[9]),
        locktime: resolve_block_height(variables, inputs[10]),
        funding_pubkey: resolve_pubkey(variables, inputs[11]),
        revocation_basepoint: resolve_pubkey(variables, inputs[12]),
        payment_basepoint: resolve_pubkey(variables, inputs[13]),
        delayed_payment_basepoint: resolve_pubkey(variables, inputs[14]),
        htlc_basepoint: resolve_pubkey(variables, inputs[15]),
        first_per_commitment_point: resolve_pubkey(variables, inputs[16]),
        second_per_commitment_point: resolve_pubkey(variables, inputs[17]),
        channel_flags: resolve_u8(variables, inputs[18]),
        tlvs: OpenChannel2Tlvs {
            // Always send the TLV: a zero-length value is the BOLT 2 opt-out
            // signal when option_upfront_shutdown_script is negotiated, so
            // omitting it would be a protocol violation in that case.
            upfront_shutdown_script: Some(resolve_bytes(variables, inputs[19]).to_vec()),
            // BOLT 2 requires `open_channel2` to set `channel_type`, but an
            // empty `Features` still omits the TLV so the receiver's "MUST fail
            // if channel_type is not set" path stays reachable.
            channel_type: nonempty_or_none(resolve_features(variables, inputs[20])),
            require_confirmed_inputs,
        },
    }
}

/// Resolves a v2 negotiation by either the derived `channel_id` every message
/// after `accept_channel2` carries, or the `temporary_channel_id` it is keyed
/// by.
///
/// Returns `None` when neither matches, which is what a mutated program that
/// dropped its `open_channel2`, or pointed a message at an unrelated channel,
/// looks like.
fn negotiation_v2_mut<'a>(
    negotiations: &'a mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
    channel_id: ChannelId,
) -> Option<&'a mut PendingChannelV2> {
    let key = if negotiations.contains_key(&channel_id) {
        channel_id
    } else {
        *v2_channel_ids.get(&channel_id)?
    };
    negotiations.get_mut(&key)
}

/// Truncates a variable-length message field to what the wire format can carry.
///
/// `Vec<u8>`'s BOLT encoding is a `u16` length followed by the bytes, so
/// anything longer panics in the encoder. A previous transaction can legally
/// exceed that, and truncating turns what would be a harness crash into a
/// message the peer rejects.
fn truncate_to_message_size(mut bytes: Vec<u8>, field: &str) -> Vec<u8> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        log::debug!(
            "truncating {field} from {} to {MAX_MESSAGE_SIZE} bytes",
            bytes.len(),
        );
        bytes.truncate(MAX_MESSAGE_SIZE);
    }
    bytes
}

/// Builds a `tx_add_input` proposing one of our wallet UTXOs, and records it in
/// the negotiation so the shared transaction can be rebuilt later.
///
/// `utxo_index` selects modulo the spendable set, so any index is meaningful
/// and reusing one proposes the same outpoint twice, which the peer must
/// reject. An empty wallet or a previous transaction the node does not know
/// yields an empty `prevtx`, which is likewise the peer's to reject.
#[allow(clippy::too_many_arguments)]
fn build_tx_add_input(
    variables: &[Option<Variable>],
    inputs: &[usize],
    serial_id: u64,
    utxo_index: u8,
    sequence: u32,
    cli: &mut impl BitcoinRpc,
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
) -> TxAddInput {
    let channel_id = resolve_channel_id(variables, inputs[0]);

    let utxos = cli.get_utxos();
    let selected = (!utxos.is_empty()).then(|| {
        let index = usize::from(utxo_index) % utxos.len();
        utxos[index].clone()
    });

    let (prevtx, prevtx_vout) = match &selected {
        Some(utxo) => (
            cli.get_raw_transaction(utxo.outpoint.txid)
                .unwrap_or_default(),
            utxo.outpoint.vout,
        ),
        None => (Vec::new(), 0),
    };
    let prevtx = truncate_to_message_size(prevtx, "tx_add_input.prevtx");

    if let Some(utxo) = &selected {
        // Locking keeps a later selection from proposing the same coin, which
        // the peer would reject as a duplicate input.
        cli.lock_utxos(&[utxo.outpoint]);
    }

    if let Some(pending) = negotiation_v2_mut(negotiations, v2_channel_ids, channel_id) {
        let mut input =
            SharedInput::from_prevtx(&prevtx, prevtx_vout, sequence, Contributor::Local);
        if let Some(utxo) = &selected {
            // Prefer what the wallet told us: a truncated or missing `prevtx`
            // still leaves us knowing exactly what we are spending.
            input.outpoint = utxo.outpoint;
            input.prevout = Some(TxOut {
                value: utxo.amount,
                script_pubkey: utxo.script_pubkey.clone(),
            });
        }
        pending.shared_tx.add_input(serial_id, input);
        pending.tx_negotiation.sent_tx_complete = false;
    }

    TxAddInput {
        channel_id,
        serial_id,
        prevtx,
        prevtx_vout,
        sequence,
        tlvs: TxAddInputTlvs::default(),
    }
}

/// Builds a `tx_add_output` and records it in the negotiation.
///
/// The funding and change roles derive their value and script from the
/// negotiation; without one to derive from they fall back to the value and
/// script inputs, so the message still goes out and the peer still gets to
/// judge it.
#[allow(clippy::too_many_arguments)]
fn build_tx_add_output(
    variables: &[Option<Variable>],
    inputs: &[usize],
    serial_id: u64,
    role: TxOutputRole,
    cli: &mut impl BitcoinRpc,
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
) -> TxAddOutput {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let explicit_sats = resolve_amount(variables, inputs[1]);
    let explicit_script = ScriptBuf::from(resolve_bytes(variables, inputs[2]).to_vec());

    let derived = match role {
        TxOutputRole::Explicit => None,
        TxOutputRole::Funding => negotiation_v2_mut(negotiations, v2_channel_ids, channel_id)
            .and_then(|pending| {
                let accept = pending.accept_channel2.as_ref()?;
                let script = build_funding_witness_script(
                    &pending.open_channel2.funding_pubkey,
                    &accept.funding_pubkey,
                )
                .to_p2wsh();
                Some((pending.total_funding_satoshis(), script))
            }),
        TxOutputRole::Change => {
            let change_script = cli.get_new_address_script_pubkey();
            negotiation_v2_mut(negotiations, v2_channel_ids, channel_id).map(|pending| {
                let feerate = pending.open_channel2.funding_feerate_perkw;
                let fee = pending
                    .shared_tx
                    .local_fee_sat(feerate, &[change_script.len()]);
                // Whatever our inputs cover beyond our funding contribution and
                // our share of the fee. Saturating: an under-funded selection
                // yields a zero-value output the peer rejects, rather than a
                // panic.
                let value = pending
                    .shared_tx
                    .contributed_input_value(Contributor::Local)
                    .saturating_sub(pending.open_channel2.funding_satoshis)
                    .saturating_sub(fee);
                (value, change_script)
            })
        }
    };

    let (sats, script) = derived.unwrap_or((explicit_sats, explicit_script));
    let script = truncate_to_message_size(script.into_bytes(), "tx_add_output.script");

    if let Some(pending) = negotiation_v2_mut(negotiations, v2_channel_ids, channel_id) {
        pending.shared_tx.add_output(
            serial_id,
            SharedOutput {
                value: sats,
                script_pubkey: ScriptBuf::from(script.clone()),
                contributor: Contributor::Local,
            },
        );
        pending.tx_negotiation.sent_tx_complete = false;
    }

    TxAddOutput {
        channel_id,
        serial_id,
        sats,
        script,
    }
}

/// Applies one received interactive transaction message to the negotiation it
/// names.
///
/// A message for an unknown negotiation, or one removing something we never
/// saw, is logged and dropped rather than reported: only the peer can tell
/// whether it is consistent with its own view, and it will fail the
/// negotiation if not.
fn apply_interactive_tx(
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
    msg: Message,
) -> Result<(), ExecuteError> {
    let channel_id = match &msg {
        Message::TxAddInput(m) => m.channel_id,
        Message::TxAddOutput(m) => m.channel_id,
        Message::TxRemoveInput(m) => m.channel_id,
        Message::TxRemoveOutput(m) => m.channel_id,
        Message::TxComplete(m) => m.channel_id,
        Message::TxAbort(m) => m.channel_id,
        other => {
            return Err(ExecuteError::UnexpectedMessage {
                expected: MessageType::TX_COMPLETE,
                got: other.msg_type(),
            });
        }
    };

    let Some(pending) = negotiation_v2_mut(negotiations, v2_channel_ids, channel_id) else {
        log::debug!("interactive tx message for unknown channel_id {channel_id}, ignoring");
        return Ok(());
    };

    // Only two consecutive `tx_complete`s conclude the negotiation, so any
    // other message from the peer clears its half of that pair.
    pending.tx_negotiation.peer_sent_tx_complete = matches!(msg, Message::TxComplete(_));

    match msg {
        Message::TxAddInput(m) => {
            pending.shared_tx.add_input(
                m.serial_id,
                SharedInput::from_prevtx(&m.prevtx, m.prevtx_vout, m.sequence, Contributor::Remote),
            );
        }
        Message::TxAddOutput(m) => {
            pending.shared_tx.add_output(
                m.serial_id,
                SharedOutput {
                    value: m.sats,
                    script_pubkey: ScriptBuf::from(m.script),
                    contributor: Contributor::Remote,
                },
            );
        }
        Message::TxRemoveInput(m) => {
            pending.shared_tx.remove_input(m.serial_id);
        }
        Message::TxRemoveOutput(m) => {
            pending.shared_tx.remove_output(m.serial_id);
        }
        Message::TxComplete(_) => {}
        Message::TxAbort(m) => {
            log::debug!(
                "peer aborted the negotiation: {}",
                m.message().unwrap_or("<non-utf8>"),
            );
            pending.tx_negotiation.aborted = true;
        }
        _ => unreachable!("message type checked above"),
    }

    Ok(())
}

/// Reconstructs the shared funding transaction from a negotiation.
///
/// An unknown `channel_id` yields an empty transaction rather than an error:
/// a mutated program may point this at a channel that was never opened, and
/// every consumer already has to cope with a funding output that does not
/// match.
fn build_funding_transaction_v2(
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
    channel_id: ChannelId,
) -> FundingTransaction {
    let Some(pending) = negotiation_v2_mut(negotiations, v2_channel_ids, channel_id) else {
        log::debug!("no v2 negotiation for channel_id {channel_id}, building an empty transaction");
        return FundingTransaction {
            tx: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: Vec::new(),
                output: Vec::new(),
            },
            vout: 0,
        };
    };

    let funding_script = pending.accept_channel2.as_ref().map(|accept| {
        build_funding_witness_script(
            &pending.open_channel2.funding_pubkey,
            &accept.funding_pubkey,
        )
        .to_p2wsh()
    });
    match funding_script {
        Some(script) => pending
            .shared_tx
            .build_funding(&script, pending.total_funding_satoshis()),
        // Without `accept_channel2` the funding script is unknown, so there is
        // nothing to locate; `vout` 0 keeps the result well-typed.
        None => FundingTransaction {
            tx: pending.shared_tx.build(),
            vout: 0,
        },
    }
}

/// Builds the v2 `commitment_signed` for the initial commitment and starts
/// tracking the channel.
///
/// Without both `open_channel2` and the peer's `accept_channel2` there is no
/// commitment to sign, so this falls back to an all-zero signature and leaves
/// `channel_states` untouched, mirroring the v1 `funding_created` path.
fn build_commitment_signed(
    variables: &[Option<Variable>],
    inputs: &[usize],
    channel_states: &mut HashMap<ChannelId, ChannelState>,
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
    mined_txids: &HashSet<Txid>,
) -> Result<CommitmentSigned, ExecuteError> {
    let funding_tx = resolve_funding_transaction(variables, inputs[0]).clone();
    let opener_funding_privkey_bytes = resolve_private_key(variables, inputs[1]);
    let channel_id = resolve_channel_id(variables, inputs[2]);

    let unsigned = |channel_id| CommitmentSigned {
        channel_id,
        signature: Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature"),
        htlc_signatures: Vec::new(),
        tlvs: CommitmentSignedTlvs::default(),
    };

    let Some(pending) = negotiation_v2_mut(negotiations, v2_channel_ids, channel_id) else {
        return Ok(unsigned(channel_id));
    };
    let Some(accept_channel2) = pending.accept_channel2.clone() else {
        return Ok(unsigned(channel_id));
    };
    let open_channel2 = pending.open_channel2.clone();
    let total_funding_satoshis = pending.total_funding_satoshis();
    let already_sent = pending.commitment_exchange.sent_commitment_signed;
    pending.commitment_exchange.sent_commitment_signed = true;

    let opener_funding_privkey =
        SecretKey::from_slice(&opener_funding_privkey_bytes).expect("valid private key");

    let funding_outpoint = OutPoint {
        txid: funding_tx.tx.compute_txid(),
        vout: funding_tx.vout,
    };
    let config = ChannelConfig {
        funding_outpoint,
        funding_satoshis: total_funding_satoshis,
        channel_type: open_channel2.tlvs.channel_type.clone().unwrap_or_default(),
        opener: ChannelPartyConfig {
            funding_pubkey: open_channel2.funding_pubkey,
            payment_basepoint: open_channel2.payment_basepoint,
            revocation_basepoint: open_channel2.revocation_basepoint,
            delayed_payment_basepoint: open_channel2.delayed_payment_basepoint,
            dust_limit_satoshis: open_channel2.dust_limit_satoshis,
            to_self_delay: open_channel2.to_self_delay,
        },
        acceptor: ChannelPartyConfig {
            funding_pubkey: accept_channel2.funding_pubkey,
            payment_basepoint: accept_channel2.payment_basepoint,
            revocation_basepoint: accept_channel2.revocation_basepoint,
            delayed_payment_basepoint: accept_channel2.delayed_payment_basepoint,
            dust_limit_satoshis: accept_channel2.dust_limit_satoshis,
            to_self_delay: accept_channel2.to_self_delay,
        },
        minimum_depth: accept_channel2.minimum_depth,
    };

    // v2 has no `push_msat`: each side's balance is simply what it contributed
    // to the funding output. Pushing the acceptor's contribution reproduces
    // exactly that split, since the total is the sum of the two.
    let push_msat = accept_channel2.funding_satoshis.saturating_mul(1000);
    let state = config.new_initial_commitment(
        push_msat,
        open_channel2.commitment_feerate_perkw,
        open_channel2.first_per_commitment_point,
        accept_channel2.first_per_commitment_point,
    )?;
    let holder = HolderIdentity {
        side: Side::Opener,
        funding_privkey: opener_funding_privkey,
    };
    let signature = config.sign_counterparty_commitment(&state, &holder);

    let is_funding_outpoint_valid = funding_tx.matches_funding_output(
        &open_channel2.funding_pubkey,
        &accept_channel2.funding_pubkey,
        total_funding_satoshis,
    );

    // Only track on the first `commitment_signed` for this negotiation, so a
    // resend cannot clobber state that has already advanced.
    if !already_sent {
        channel_states.entry(channel_id).or_insert_with(|| {
            ChannelState::new(
                config,
                holder,
                state,
                is_funding_outpoint_valid,
                mined_txids.contains(&funding_outpoint.txid),
            )
        });
    }

    Ok(CommitmentSigned {
        channel_id,
        signature,
        // BOLT 2: the first `commitment_signed` of a v2 open carries no HTLCs.
        htlc_signatures: Vec::new(),
        tlvs: CommitmentSignedTlvs::default(),
    })
}

/// Receives and decodes a `commitment_signed` message.
fn recv_commitment_signed(conn: &mut impl Connection) -> Result<CommitmentSigned, ExecuteError> {
    match recv_non_ping(conn, RECV_IDLE_TIMEOUT)? {
        Message::CommitmentSigned(cs) => Ok(cs),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: MessageType::COMMITMENT_SIGNED,
            got: other.msg_type(),
        }),
    }
}

/// Receives and decodes a `tx_signatures` message.
fn recv_tx_signatures(conn: &mut impl Connection) -> Result<TxSignatures, ExecuteError> {
    match recv_non_ping(conn, RECV_IDLE_TIMEOUT)? {
        Message::TxSignatures(ts) => Ok(ts),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: MessageType::TX_SIGNATURES,
            got: other.msg_type(),
        }),
    }
}

/// Verifies the counterparty's `commitment_signed` against the holder's
/// initial commitment.
///
/// # Errors
///
/// Returns [`Violation::UnknownChannel`] if the message names a channel we
/// established no state for, [`Violation::InvalidCounterpartySignature`] if the
/// signature does not verify, or [`Violation::UnexpectedHtlcSignatures`] if it
/// carries HTLC signatures, which BOLT 2 forbids for a v2 open.
///
/// A `commitment_signed` arriving when no v2 negotiation ever reached
/// `commitment_signed` is not reported: a mutated program may have dropped the
/// `accept_channel2` that would have established the state, and blaming the
/// target for that would be a false positive.
fn verify_commitment_signed(
    cs: &CommitmentSigned,
    channel_states: &HashMap<ChannelId, ChannelState>,
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
) -> Result<(), ExecuteError> {
    if !cs.htlc_signatures.is_empty() {
        return Err(Violation::UnexpectedHtlcSignatures(cs.channel_id).into());
    }

    let Some(state) = channel_states.get(&cs.channel_id) else {
        if negotiations
            .values()
            .any(|p| p.commitment_exchange.sent_commitment_signed)
        {
            return Err(Violation::UnknownChannel(cs.channel_id).into());
        }
        log::debug!(
            "commitment_signed for {} with no v2 commitment exchange in flight, ignoring",
            cs.channel_id,
        );
        return Ok(());
    };

    if !state
        .config
        .verify_counterparty_signature(&state.commitment, &state.holder, &cs.signature)
    {
        return Err(Violation::InvalidCounterpartySignature(cs.channel_id).into());
    }

    if let Some(pending) = negotiation_v2_mut(negotiations, v2_channel_ids, cs.channel_id) {
        pending.commitment_exchange.received_commitment_signed = true;
    }

    Ok(())
}

/// Returns whether the peer owes us a `tx_signatures` for this negotiation.
///
/// BOLT 2 has the peer contributing the least send first, so a program that
/// owes the first signature must not block waiting for a message the peer is
/// itself waiting on. Both `commitment_signed`s must also have been exchanged,
/// which is what entitles either peer to send at all.
fn is_tx_signatures_expected(
    negotiations: &HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
    channel_id: ChannelId,
    context: &ProgramContext,
) -> bool {
    let key = if negotiations.contains_key(&channel_id) {
        channel_id
    } else {
        match v2_channel_ids.get(&channel_id) {
            Some(key) => *key,
            None => return false,
        }
    };
    let Some(pending) = negotiations.get(&key) else {
        return false;
    };

    pending.commitment_exchange.sent_commitment_signed
        && pending.commitment_exchange.received_commitment_signed
        && !pending.commitment_exchange.received_tx_signatures
        && !pending.tx_negotiation.aborted
        && signs_first(
            pending
                .shared_tx
                .contributed_input_value(Contributor::Remote),
            pending
                .shared_tx
                .contributed_input_value(Contributor::Local),
            &context.target_pubkey,
            &context.local_pubkey,
        )
}

/// Signs the shared funding transaction and builds `tx_signatures` carrying one
/// witness per input we contributed, ordered by its `serial_id`.
///
/// The wallet signs only what it owns, so "the wallet could sign it" is exactly
/// "we contributed it". A transaction the wallet cannot sign at all yields an
/// empty witness list, which the peer rejects rather than the harness failing.
fn build_tx_signatures(
    variables: &[Option<Variable>],
    inputs: &[usize],
    cli: &mut impl BitcoinRpc,
    negotiations: &HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
) -> TxSignatures {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let funding_tx = resolve_funding_transaction(variables, inputs[1]);
    let txid = funding_tx.tx.compute_txid();

    let signed = cli.sign_tx(&funding_tx.tx);

    // The transaction was built from the negotiation's serial-id-ordered
    // contributions, so input position is serial order.
    let local_positions: Vec<usize> = negotiation_v2(negotiations, v2_channel_ids, channel_id)
        .map(|pending| {
            pending
                .shared_tx
                .inputs()
                .enumerate()
                .filter(|(_, (_, input))| input.contributor == Contributor::Local)
                .map(|(position, _)| position)
                .collect()
        })
        .unwrap_or_default();

    let witnesses = signed
        .as_ref()
        .map(|tx| {
            local_positions
                .iter()
                .filter_map(|&position| tx.input.get(position))
                .map(|txin| {
                    truncate_to_message_size(
                        bitcoin::consensus::encode::serialize(&txin.witness),
                        "tx_signatures.witness",
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    TxSignatures {
        channel_id,
        txid,
        witnesses,
        tlvs: TxSignaturesTlvs::default(),
    }
}

/// Shared-reference sibling of [`negotiation_v2_mut`].
fn negotiation_v2<'a>(
    negotiations: &'a HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &HashMap<ChannelId, ChannelId>,
    channel_id: ChannelId,
) -> Option<&'a PendingChannelV2> {
    let key = if negotiations.contains_key(&channel_id) {
        channel_id
    } else {
        *v2_channel_ids.get(&channel_id)?
    };
    negotiations.get(&key)
}

/// Builds a `funding_created` message from 3 input variables.
///
/// Channel parameters are read from the negotiated `open_channel` and
/// `accept_channel` messages recorded in `negotiations`, ensuring the
/// commitment is built from the negotiated values. `mined_txids` is used to
/// determine whether the funding transaction has already been mined.
///
/// If the negotiation for `temporary_channel_id` is incomplete, emits a
/// `funding_created` with the derived outpoint and an all-zero signature.
fn build_funding_created(
    variables: &[Option<Variable>],
    inputs: &[usize],
    channel_states: &mut HashMap<ChannelId, ChannelState>,
    negotiations: &mut HashMap<ChannelId, PendingChannel>,
    mined_txids: &HashSet<Txid>,
) -> Result<FundingCreated, ExecuteError> {
    let funding_tx = resolve_funding_transaction(variables, inputs[0]);
    let opener_funding_privkey_bytes = resolve_private_key(variables, inputs[1]);
    let temporary_channel_id = resolve_channel_id(variables, inputs[2]);

    let funding_outpoint = OutPoint {
        txid: funding_tx.tx.compute_txid(),
        vout: funding_tx.vout,
    };
    let funding_output_index = u16::try_from(funding_outpoint.vout)
        .expect("funding output index of a funding tx must fit in u16");

    // Without both the recorded `open_channel` and the peer's `accept_channel`
    // we cannot build the commitment to sign, so fall back to an unsigned
    // `funding_created` and leave `channel_states` untouched.
    let Some(pending) = negotiations.get(&temporary_channel_id) else {
        return Ok(FundingCreated {
            temporary_channel_id,
            funding_txid: funding_outpoint.txid,
            funding_output_index,
            signature: Signature::from_compact(&[0u8; 64])
                .expect("zero bytes parse as a signature"),
        });
    };
    let open_channel = &pending.open_channel;
    let Some(accept_channel) = pending.accept_channel.as_ref() else {
        return Ok(FundingCreated {
            temporary_channel_id,
            funding_txid: funding_outpoint.txid,
            funding_output_index,
            signature: Signature::from_compact(&[0u8; 64])
                .expect("zero bytes parse as a signature"),
        });
    };

    let opener_funding_privkey =
        SecretKey::from_slice(&opener_funding_privkey_bytes).expect("valid private key");
    let secp = Secp256k1::new();
    let opener_funding_pubkey = PublicKey::from_secret_key(&secp, &opener_funding_privkey);

    let opener = ChannelPartyConfig {
        funding_pubkey: opener_funding_pubkey,
        payment_basepoint: open_channel.payment_basepoint,
        revocation_basepoint: open_channel.revocation_basepoint,
        delayed_payment_basepoint: open_channel.delayed_payment_basepoint,
        dust_limit_satoshis: open_channel.dust_limit_satoshis,
        to_self_delay: open_channel.to_self_delay,
    };
    let acceptor = ChannelPartyConfig {
        funding_pubkey: accept_channel.funding_pubkey,
        payment_basepoint: accept_channel.payment_basepoint,
        revocation_basepoint: accept_channel.revocation_basepoint,
        delayed_payment_basepoint: accept_channel.delayed_payment_basepoint,
        dust_limit_satoshis: accept_channel.dust_limit_satoshis,
        to_self_delay: accept_channel.to_self_delay,
    };
    let config = ChannelConfig {
        funding_outpoint,
        funding_satoshis: open_channel.funding_satoshis,
        channel_type: open_channel.tlvs.channel_type.clone().unwrap_or_default(),
        opener,
        acceptor,
        minimum_depth: accept_channel.minimum_depth,
    };

    let state = config.new_initial_commitment(
        open_channel.push_msat,
        open_channel.feerate_per_kw,
        open_channel.first_per_commitment_point,
        accept_channel.first_per_commitment_point,
    )?;
    let holder = HolderIdentity {
        side: Side::Opener,
        funding_privkey: opener_funding_privkey,
    };
    let signature = config.sign_counterparty_commitment(&state, &holder);

    let channel_id = ChannelId::v1_from_funding_outpoint(config.funding_outpoint);

    // Check whether the funding outpoint is valid and contains the negotiated
    // amount and funding script. If not, there is a good chance the target will
    // neither complete the funding flow nor send an error message.
    let is_funding_outpoint_valid = funding_tx.matches_funding_output(
        &open_channel.funding_pubkey,
        &accept_channel.funding_pubkey,
        open_channel.funding_satoshis,
    );

    // Only track a new channel when this negotiation has not built a
    // `funding_created` yet. If it has, we are likely resending one for the
    // same `temporary_channel_id` with a different outpoint, which the target
    // may ignore (LND and Eclair currently do), leaving us tracking a channel
    // it never opened.
    //
    // This also means that building the same message again must not clobber a
    // channel whose state has already been established (and possibly advanced).
    if !pending.funding_built {
        channel_states.entry(channel_id).or_insert_with(|| {
            ChannelState::new(
                config,
                holder,
                state,
                is_funding_outpoint_valid,
                mined_txids.contains(&funding_outpoint.txid),
            )
        });
    }

    // Mark this negotiation as having built `funding_created`. It is retained
    // so repeated `funding_created` messages can still be built, but a later
    // `open_channel` reusing this `temporary_channel_id` starts a fresh
    // negotiation.
    if let Some(pending) = negotiations.get_mut(&temporary_channel_id) {
        pending.funding_built = true;
    }

    Ok(FundingCreated {
        temporary_channel_id,
        funding_txid: funding_outpoint.txid,
        funding_output_index,
        signature,
    })
}

/// Builds a `ChannelReady` from 3 input variables (wire order).
fn build_channel_ready(
    variables: &[Option<Variable>],
    inputs: &[usize],
    include_alias: bool,
    channel_states: &mut HashMap<ChannelId, ChannelState>,
) -> ChannelReady {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let second_per_commitment_point = resolve_pubkey(variables, inputs[1]);
    let short_channel_id = include_alias.then(|| resolve_short_channel_id(variables, inputs[2]));

    // Record the holder's next per-commitment point from the first locally-sent
    // `channel_ready`'s `second_per_commitment_point`. We only do so when the
    // channel is tracked, the commitment number is still 0, and the point is not
    // yet recorded: `channel_ready` may be resent, but BOLT peers ignore
    // redundant ones, so recording a resend would leave us with the wrong point
    // and make us reject a valid received commitment signature as invalid.
    if let Some(state) = channel_states.get_mut(&channel_id)
        && state.commitment.commitment_number == 0
    {
        let next_point = state.next_holder_per_commitment_point_mut();
        if next_point.is_none() {
            *next_point = Some(second_per_commitment_point);
        }
    }

    ChannelReady {
        channel_id,
        second_per_commitment_point,
        tlvs: ChannelReadyTlvs { short_channel_id },
    }
}

/// Builds a `Shutdown` message from 2 input variables (wire order).
fn build_shutdown(variables: &[Option<Variable>], inputs: &[usize]) -> Shutdown {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let scriptpubkey = resolve_bytes(variables, inputs[1]).to_vec();
    Shutdown::for_channel(channel_id, scriptpubkey)
}

/// Builds a signed `ChannelAnnouncement` from 7 input variables.
fn build_channel_announcement(
    variables: &[Option<Variable>],
    inputs: &[usize],
) -> ChannelAnnouncement {
    let features = resolve_features(variables, inputs[0]).to_vec();
    let chain_hash = resolve_chain_hash(variables, inputs[1]);
    let short_channel_id = resolve_short_channel_id(variables, inputs[2]);
    let node_sk_1_bytes = resolve_private_key(variables, inputs[3]);
    let node_sk_2_bytes = resolve_private_key(variables, inputs[4]);
    let bitcoin_sk_1_bytes = resolve_private_key(variables, inputs[5]);
    let bitcoin_sk_2_bytes = resolve_private_key(variables, inputs[6]);

    let node_sk_1 = SecretKey::from_slice(&node_sk_1_bytes).expect("valid private key");
    let node_sk_2 = SecretKey::from_slice(&node_sk_2_bytes).expect("valid private key");
    let bitcoin_sk_1 = SecretKey::from_slice(&bitcoin_sk_1_bytes).expect("valid private key");
    let bitcoin_sk_2 = SecretKey::from_slice(&bitcoin_sk_2_bytes).expect("valid private key");

    let secp = Secp256k1::new();
    let node_id_1 = PublicKey::from_secret_key(&secp, &node_sk_1);
    let node_id_2 = PublicKey::from_secret_key(&secp, &node_sk_2);
    let bitcoin_key_1 = PublicKey::from_secret_key(&secp, &bitcoin_sk_1);
    let bitcoin_key_2 = PublicKey::from_secret_key(&secp, &bitcoin_sk_2);

    let placeholder = Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature");
    let mut ca = ChannelAnnouncement {
        node_signature_1: placeholder,
        node_signature_2: placeholder,
        bitcoin_signature_1: placeholder,
        bitcoin_signature_2: placeholder,
        features,
        chain_hash,
        short_channel_id,
        node_id_1,
        node_id_2,
        bitcoin_key_1,
        bitcoin_key_2,
        extra: Vec::new(),
    };
    ca.sign(&node_sk_1, &node_sk_2, &bitcoin_sk_1, &bitcoin_sk_2);
    ca
}

/// Builds an `AnnouncementSignatures` message from 8 input variables.
///
/// Signs the `channel_announcement` body with our node and bitcoin secret keys
/// (inputs 4 and 6). The body is assembled with pubkeys sorted lexicographically
/// per BOLT 7 using the target's public keys (inputs 5 and 7) directly.
fn build_announcement_signatures(
    variables: &[Option<Variable>],
    inputs: &[usize],
) -> AnnouncementSignatures {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let features = resolve_features(variables, inputs[1]).to_vec();
    let chain_hash = resolve_chain_hash(variables, inputs[2]);
    let short_channel_id = resolve_short_channel_id(variables, inputs[3]);
    let node_sk_1_bytes = resolve_private_key(variables, inputs[4]);
    let node_id_2 = resolve_pubkey(variables, inputs[5]);
    let bitcoin_sk_1_bytes = resolve_private_key(variables, inputs[6]);
    let bitcoin_key_2 = resolve_pubkey(variables, inputs[7]);

    let node_sk_1 = SecretKey::from_slice(&node_sk_1_bytes).expect("valid private key");
    let bitcoin_sk_1 = SecretKey::from_slice(&bitcoin_sk_1_bytes).expect("valid private key");

    let secp = Secp256k1::new();
    let node_id_1 = PublicKey::from_secret_key(&secp, &node_sk_1);
    let bitcoin_key_1 = PublicKey::from_secret_key(&secp, &bitcoin_sk_1);

    // BOLT 7 requires node_id_1 < node_id_2 lexicographically (serialized
    // compressed form).  Sort the pubkeys so the body we sign is valid.
    let (n1, n2, bk1, bk2) = if node_id_1.serialize() <= node_id_2.serialize() {
        (node_id_1, node_id_2, bitcoin_key_1, bitcoin_key_2)
    } else {
        (node_id_2, node_id_1, bitcoin_key_2, bitcoin_key_1)
    };

    let placeholder = Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature");
    let ca = ChannelAnnouncement {
        node_signature_1: placeholder,
        node_signature_2: placeholder,
        bitcoin_signature_1: placeholder,
        bitcoin_signature_2: placeholder,
        features,
        chain_hash,
        short_channel_id,
        node_id_1: n1,
        node_id_2: n2,
        bitcoin_key_1: bk1,
        bitcoin_key_2: bk2,
        extra: Vec::new(),
    };

    // Sign the correctly-ordered body digest with our keys only.
    let digest = ca.signing_digest();
    let node_signature = secp.sign_ecdsa(&digest, &node_sk_1);
    let bitcoin_signature = secp.sign_ecdsa(&digest, &bitcoin_sk_1);

    AnnouncementSignatures {
        channel_id,
        short_channel_id,
        node_signature,
        bitcoin_signature,
    }
}

/// Builds a signed `NodeAnnouncement` from 4 input variables.
fn build_node_announcement(
    variables: &[Option<Variable>],
    inputs: &[usize],
    rgb_color: [u8; 3],
    alias: [u8; 32],
) -> NodeAnnouncement {
    let sk_bytes = resolve_private_key(variables, inputs[0]);
    let features = resolve_features(variables, inputs[1]).to_vec();
    let timestamp = resolve_timestamp(variables, inputs[2]);
    let addresses = resolve_bytes(variables, inputs[3]).to_vec();

    let sk = SecretKey::from_slice(&sk_bytes).expect("valid private key");
    let secp = Secp256k1::new();
    let node_id = PublicKey::from_secret_key(&secp, &sk);

    let mut na = NodeAnnouncement {
        signature: Signature::from_compact(&[0u8; 64]).expect("zero bytes parse as a signature"),
        features,
        timestamp,
        node_id,
        rgb_color,
        alias,
        addresses,
        extra: Vec::new(),
    };
    na.sign(&sk);
    na
}

/// Builds a signed `ChannelUpdate` from 11 input variables.
fn build_channel_update(variables: &[Option<Variable>], inputs: &[usize]) -> ChannelUpdate {
    let sk_bytes = resolve_private_key(variables, inputs[0]);
    let chain_hash = resolve_chain_hash(variables, inputs[1]);
    let short_channel_id = resolve_short_channel_id(variables, inputs[2]);
    let timestamp = resolve_timestamp(variables, inputs[3]);
    let message_flags = resolve_u8(variables, inputs[4]);
    let channel_flags = resolve_u8(variables, inputs[5]);
    let cltv_expiry_delta = resolve_u16(variables, inputs[6]);
    let htlc_minimum_msat = resolve_amount(variables, inputs[7]);
    let fee_base_msat = resolve_forwarding_fee(variables, inputs[8]);
    let fee_proportional_millionths = resolve_forwarding_fee(variables, inputs[9]);
    let htlc_maximum_msat = resolve_amount(variables, inputs[10]);

    let sk = SecretKey::from_slice(&sk_bytes).expect("valid private key");

    let mut cu = ChannelUpdate {
        signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0u8; 64])
            .expect("zero bytes parse as a signature"),
        chain_hash,
        short_channel_id,
        timestamp,
        message_flags,
        channel_flags,
        cltv_expiry_delta,
        htlc_minimum_msat,
        fee_base_msat,
        fee_proportional_millionths,
        htlc_maximum_msat,
        extra: Vec::new(),
    };
    cu.sign(&sk);
    cu
}

/// Receives the next message of interest, auto-responding to pings and silently
/// skipping unknown odd-type messages.
///
/// The read is bounded by `timeout`.
#[allow(clippy::similar_names)] // ping and pong are canonical names
fn recv_non_ping(conn: &mut impl Connection, timeout: Duration) -> Result<Message, ExecuteError> {
    let previous = conn.read_timeout()?;
    conn.set_read_timeout(Some(timeout))?;

    let result: Result<Message, ExecuteError> = (|| loop {
        let msg_bytes = conn.recv_message()?;
        let msg = Message::decode(&msg_bytes)?;
        match msg {
            Message::Ping(ping) => {
                let pong = Message::Pong(Pong::respond_to(&ping)).encode();
                conn.send_message(&pong)?;
            }
            Message::Unknown { .. } => {
                log::debug!("skipping message {msg}");
            }
            // TODO: Gossip messages are not currently consumed by any scenario,
            // so skip them for now. Revisit this once we want to extract their
            // fields.
            Message::ChannelAnnouncement(_)
            | Message::NodeAnnouncement(_)
            | Message::ChannelUpdate(_)
            | Message::AnnouncementSignatures(_)
            | Message::GossipTimestampFilter(_) => {
                log::debug!("skipping gossip message {msg}");
            }
            // Surface the received error message.
            Message::Error(e) => return Err(ExecuteError::PeerError(e)),
            other => return Ok(other),
        }
    })();

    // Ignore a restore failure so the receive's own result is surfaced.
    let _ = conn.set_read_timeout(previous);
    result
}

/// Receives and decodes an `accept_channel` message.
fn recv_accept_channel(conn: &mut impl Connection) -> Result<AcceptChannel, ExecuteError> {
    match recv_non_ping(conn, RECV_IDLE_TIMEOUT)? {
        Message::AcceptChannel(ac) => Ok(ac),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: MessageType::ACCEPT_CHANNEL,
            got: other.msg_type(),
        }),
    }
}

/// Receives and decodes an `accept_channel2` message.
fn recv_accept_channel2(conn: &mut impl Connection) -> Result<AcceptChannel2, ExecuteError> {
    match recv_non_ping(conn, RECV_IDLE_TIMEOUT)? {
        Message::AcceptChannel2(ac) => Ok(ac),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: MessageType::ACCEPT_CHANNEL2,
            got: other.msg_type(),
        }),
    }
}

/// Receives and decodes a `funding_signed` message.
fn recv_funding_signed(conn: &mut impl Connection) -> Result<FundingSigned, ExecuteError> {
    match recv_non_ping(conn, RECV_IDLE_TIMEOUT)? {
        Message::FundingSigned(fs) => Ok(fs),
        other => Err(ExecuteError::UnexpectedMessage {
            expected: MessageType::FUNDING_SIGNED,
            got: other.msg_type(),
        }),
    }
}

/// Receives and decodes a `channel_ready` message.
///
/// The `second_per_commitment_point` is recorded as the counterparty's next
/// per-commitment point on the channel it identifies.
///
/// # Errors
///
/// Returns [`ExecuteError::UnexpectedMessage`] if the received message is not a
/// `channel_ready`, or [`Violation::UnknownChannel`] if no channel state exists
/// for the message's `channel_id`.
fn recv_channel_ready(
    conn: &mut impl Connection,
    channel_states: &mut HashMap<ChannelId, ChannelState>,
) -> Result<(), ExecuteError> {
    let cr = match recv_non_ping(conn, RECV_CHANNEL_READY_TIMEOUT)? {
        Message::ChannelReady(cr) => cr,
        other => {
            return Err(ExecuteError::UnexpectedMessage {
                expected: MessageType::CHANNEL_READY,
                got: other.msg_type(),
            });
        }
    };

    let state = channel_states
        .get_mut(&cr.channel_id)
        .ok_or(Violation::UnknownChannel(cr.channel_id))?;
    *state.next_counterparty_per_commitment_point_mut() = Some(cr.second_per_commitment_point);

    Ok(())
}

/// Returns `true` if the target owes us a `channel_ready` message.
///
/// A `channel_ready` is expected when a tracked channel is still at commitment
/// number 0, the counterparty's next per-commitment point is unknown, the
/// advertised funding outpoint pays the negotiated funding output, the funding
/// transaction was mined only after we sent `funding_created`, and it has at
/// least `minimum_depth` confirmations (as specified in the received
/// `accept_channel`).
fn is_channel_ready_expected(
    channel_states: &HashMap<ChannelId, ChannelState>,
    bitcoin_cli: &mut impl BitcoinRpc,
) -> bool {
    channel_states.values().any(|state| {
        state.commitment.commitment_number == 0
            && state.next_counterparty_per_commitment_point().is_none()
            && state.is_funding_outpoint_valid
            && !state.was_funding_mined_prematurely
            && bitcoin_cli.get_transaction_confirmations(state.config.funding_outpoint.txid)
                >= state.config.minimum_depth
    })
}

/// Verifies the counterparty's signature from a `funding_signed` message using
/// the channel state associated with the message's `channel_id`.
///
/// # Errors
///
/// Returns [`Violation::UnknownChannel`] if no channel state exists for the
/// given `channel_id`, or [`Violation::InvalidCounterpartySignature`] if the
/// signature is invalid for the holder's initial commitment transaction.
fn verify_funding_signed(
    fs: &FundingSigned,
    channel_states: &HashMap<ChannelId, ChannelState>,
) -> Result<(), Violation> {
    let state = channel_states
        .get(&fs.channel_id)
        .ok_or(Violation::UnknownChannel(fs.channel_id))?;

    state
        .config
        .verify_counterparty_signature(&state.commitment, &state.holder, &fs.signature)
        .then_some(())
        .ok_or(Violation::InvalidCounterpartySignature(fs.channel_id))
}

/// Records a sent `open_channel`, keyed by `temporary_channel_id`, so the
/// funding flow can build commitments from the values actually put on the wire.
///
/// If a negotiation for the same `temporary_channel_id` is still in progress,
/// it is left untouched, preserving the first `open_channel`. Once a
/// `funding_created` has been built, it is overwritten, allowing the
/// `temporary_channel_id` to be reused for a new negotiation.
fn record_send_open_channel(
    negotiations: &mut HashMap<ChannelId, PendingChannel>,
    open_channel: &OpenChannel,
) {
    if negotiations
        .get(&open_channel.temporary_channel_id)
        .is_some_and(|pending| !pending.funding_built)
    {
        return;
    }

    negotiations.insert(
        open_channel.temporary_channel_id,
        PendingChannel {
            open_channel: open_channel.clone(),
            accept_channel: None,
            funding_built: false,
        },
    );
}

/// Pairs a received `accept_channel` with the recorded `open_channel` of the
/// same `temporary_channel_id`.
///
/// # Panics
///
/// Panics if no matching `open_channel` exists. This should be unreachable, as
/// `AcceptChannelOracle` reports such messages as a [`Violation`].
fn record_recv_accept_channel(
    negotiations: &mut HashMap<ChannelId, PendingChannel>,
    accept_channel: &AcceptChannel,
) {
    negotiations
        .get_mut(&accept_channel.temporary_channel_id)
        .expect("AcceptChannelOracle guaranteed this temporary_channel_id exists")
        .accept_channel = Some(accept_channel.clone());
}

/// Records a sent `open_channel2`, keyed by `temporary_channel_id`, so later
/// steps can build the funding transaction and commitment from the values
/// actually put on the wire.
///
/// A repeated `temporary_channel_id` starts a fresh negotiation, discarding the
/// previous one: unlike v1 there is no `funding_created` marking the point of no
/// return, and the id only has to stay unique until `accept_channel2` arrives.
fn record_send_open_channel2(
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    open_channel2: &OpenChannel2,
) {
    negotiations.insert(
        open_channel2.temporary_channel_id,
        PendingChannelV2::new(open_channel2.clone()),
    );
}

/// Pairs a received `accept_channel2` with the recorded `open_channel2` of the
/// same `temporary_channel_id`, and derives the v2 `channel_id` that every
/// subsequent message carries.
///
/// An `accept_channel2` for an unknown `temporary_channel_id` is ignored rather
/// than fatal: a mutated program may have dropped the `open_channel2` that
/// would have recorded it, and the message still decodes fine.
fn record_recv_accept_channel2(
    negotiations: &mut HashMap<ChannelId, PendingChannelV2>,
    v2_channel_ids: &mut HashMap<ChannelId, ChannelId>,
    accept_channel2: &AcceptChannel2,
) {
    let temporary_channel_id = accept_channel2.temporary_channel_id;
    let Some(pending) = negotiations.get_mut(&temporary_channel_id) else {
        log::debug!(
            "accept_channel2 for unknown temporary_channel_id {temporary_channel_id}, ignoring",
        );
        return;
    };

    let channel_id = ChannelId::v2_from_revocation_basepoints(
        &pending.open_channel2.revocation_basepoint,
        &accept_channel2.revocation_basepoint,
    );
    pending.accept_channel2 = Some(accept_channel2.clone());
    pending.channel_id = Some(channel_id);
    v2_channel_ids.insert(channel_id, temporary_channel_id);
}

/// Extracts a field from a parsed `accept_channel2` message.
fn extract_field_v2(ac: &AcceptChannel2, field: AcceptChannel2Field) -> Variable {
    match field {
        AcceptChannel2Field::TemporaryChannelId => Variable::ChannelId(ac.temporary_channel_id),
        AcceptChannel2Field::FundingSatoshis => Variable::Amount(ac.funding_satoshis),
        AcceptChannel2Field::DustLimitSatoshis => Variable::Amount(ac.dust_limit_satoshis),
        AcceptChannel2Field::MaxHtlcValueInFlightMsat => {
            Variable::Amount(ac.max_htlc_value_in_flight_msat)
        }
        AcceptChannel2Field::HtlcMinimumMsat => Variable::Amount(ac.htlc_minimum_msat),
        AcceptChannel2Field::MinimumDepth => Variable::BlockHeight(ac.minimum_depth),
        AcceptChannel2Field::ToSelfDelay => Variable::U16(ac.to_self_delay),
        AcceptChannel2Field::MaxAcceptedHtlcs => Variable::U16(ac.max_accepted_htlcs),
        AcceptChannel2Field::FundingPubkey => Variable::Point(ac.funding_pubkey),
        AcceptChannel2Field::RevocationBasepoint => Variable::Point(ac.revocation_basepoint),
        AcceptChannel2Field::PaymentBasepoint => Variable::Point(ac.payment_basepoint),
        AcceptChannel2Field::DelayedPaymentBasepoint => {
            Variable::Point(ac.delayed_payment_basepoint)
        }
        AcceptChannel2Field::HtlcBasepoint => Variable::Point(ac.htlc_basepoint),
        AcceptChannel2Field::FirstPerCommitmentPoint => {
            Variable::Point(ac.first_per_commitment_point)
        }
        AcceptChannel2Field::SecondPerCommitmentPoint => {
            Variable::Point(ac.second_per_commitment_point)
        }
        AcceptChannel2Field::UpfrontShutdownScript => {
            Variable::Bytes(ac.tlvs.upfront_shutdown_script.clone().unwrap_or_default())
        }
        AcceptChannel2Field::ChannelType => {
            Variable::Features(ac.tlvs.channel_type.clone().unwrap_or_default())
        }
    }
}

/// Extracts a field from a parsed `accept_channel` message.
fn extract_field(ac: &AcceptChannel, field: AcceptChannelField) -> Variable {
    match field {
        AcceptChannelField::TemporaryChannelId => Variable::ChannelId(ac.temporary_channel_id),
        AcceptChannelField::DustLimitSatoshis => Variable::Amount(ac.dust_limit_satoshis),
        AcceptChannelField::MaxHtlcValueInFlightMsat => {
            Variable::Amount(ac.max_htlc_value_in_flight_msat)
        }
        AcceptChannelField::ChannelReserveSatoshis => Variable::Amount(ac.channel_reserve_satoshis),
        AcceptChannelField::HtlcMinimumMsat => Variable::Amount(ac.htlc_minimum_msat),
        AcceptChannelField::MinimumDepth => Variable::BlockHeight(ac.minimum_depth),
        AcceptChannelField::ToSelfDelay => Variable::U16(ac.to_self_delay),
        AcceptChannelField::MaxAcceptedHtlcs => Variable::U16(ac.max_accepted_htlcs),
        AcceptChannelField::FundingPubkey => Variable::Point(ac.funding_pubkey),
        AcceptChannelField::RevocationBasepoint => Variable::Point(ac.revocation_basepoint),
        AcceptChannelField::PaymentBasepoint => Variable::Point(ac.payment_basepoint),
        AcceptChannelField::DelayedPaymentBasepoint => {
            Variable::Point(ac.delayed_payment_basepoint)
        }
        AcceptChannelField::HtlcBasepoint => Variable::Point(ac.htlc_basepoint),
        AcceptChannelField::FirstPerCommitmentPoint => {
            Variable::Point(ac.first_per_commitment_point)
        }
        AcceptChannelField::UpfrontShutdownScript => {
            Variable::Bytes(ac.tlvs.upfront_shutdown_script.clone().unwrap_or_default())
        }
        AcceptChannelField::ChannelType => {
            Variable::Features(ac.tlvs.channel_type.clone().unwrap_or_default())
        }
    }
}

/// Returns `None` for empty slices, `Some(vec)` otherwise.
fn nonempty_or_none(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::str::FromStr;

    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Amount, Transaction};
    use smite::bolt::{AcceptChannel2Tlvs, AcceptChannelTlvs, GossipTimestampFilter, Init, Ping};
    use smite_ir::Instruction;
    use smite_ir::operation::{ChannelTypeVariant, ShutdownScriptVariant};

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

        fn queue_recv(&mut self, msg_bytes: Vec<u8>) {
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
    struct MockBitcoinCli {
        mine_blocks_calls: Vec<u8>,
        mined_private_mempool: Vec<String>,
        broadcast_calls: Vec<Transaction>,
        block_position_lookups: Vec<Txid>,
        utxos: Vec<Utxo>,
        change_spk: ScriptBuf,
        confirmations: u32,
        /// Serialized transactions the node knows about, keyed by txid, as
        /// `getrawtransaction` would return them.
        raw_transactions: HashMap<Txid, Vec<u8>>,
        locked_outpoints: Vec<OutPoint>,
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

    // -- Helpers --

    /// Builds a private key with a single distinguishing byte, so
    /// `sample_pubkey(b)` is the point it derives.
    fn key(byte: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = byte;
        k
    }

    fn sample_pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = byte;
        let sk = SecretKey::from_slice(&key_bytes).expect("valid secret key");
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn sample_context() -> ProgramContext {
        ProgramContext {
            target_pubkey: sample_pubkey(1),
            local_pubkey: sample_pubkey(2),
            chain_hash: [0xcc; 32],
            block_height: 800_000,
            target_features: vec![],
        }
    }

    fn sample_utxo() -> Utxo {
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

    fn sample_change_spk() -> ScriptBuf {
        ScriptBuf::from(
            hex::decode("00142e532c12351a5c81e23c8a76d19345ca7b6de57a")
                .expect("valid P2WPKH scriptpubkey hex"),
        )
    }

    fn sample_accept_channel() -> AcceptChannel {
        AcceptChannel {
            temporary_channel_id: ChannelId::new([0xbb; 32]),
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

    /// Builds the 20 `open_channel` input instructions in wire order.
    fn open_channel_instructions() -> Vec<Instruction> {
        vec![
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChannelId([0xbb; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(100_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(0),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(546),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(100_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(10_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeeratePerKw(253),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU16(144),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU16(483),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTargetPubkeyFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU8(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadBytes(vec![]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![0x40, 0x10, 0x00]),
                inputs: vec![],
            },
        ]
    }

    fn create_and_broadcast_tx_instructions() -> Vec<Instruction> {
        let opener_privkey =
            SecretKey::from_str("30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749")
                .unwrap()
                .secret_bytes();
        let acceptor_privkey =
            SecretKey::from_str("1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13")
                .unwrap()
                .secret_bytes();

        vec![
            Instruction {
                operation: Operation::LoadPrivateKey(opener_privkey),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(acceptor_privkey),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![2],
            },
            Instruction {
                operation: Operation::LoadAmount(10_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeeratePerKw(15_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::CreateFundingTransaction,
                inputs: vec![1, 3, 4, 5],
            },
            Instruction {
                operation: Operation::BroadcastTransaction,
                inputs: vec![6],
            },
        ]
    }

    /// Builds instructions that construct and send a `channel_announcement`
    /// referencing the `ShortChannelId` produced at variable index `scid_var`.
    ///
    /// `base` is the variable index the first appended instruction will occupy
    /// (i.e. the current program length), used to wire up the inputs to
    /// `BuildChannelAnnouncement`.
    fn channel_announcement_from_scid_instructions(
        base: usize,
        scid_var: usize,
    ) -> Vec<Instruction> {
        vec![
            Instruction {
                operation: Operation::LoadFeatures(vec![0x01, 0x02]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x11; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x22; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x33; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([0x44; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildChannelAnnouncement,
                // features, chain_hash, short_channel_id, node_sk_1, node_sk_2,
                // bitcoin_sk_1, bitcoin_sk_2.
                inputs: vec![
                    base,
                    base + 1,
                    scid_var,
                    base + 2,
                    base + 3,
                    base + 4,
                    base + 5,
                ],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![base + 6],
            },
        ]
    }

    /// Decodes a sent message expected to be a `channel_announcement`.
    fn decode_sent_channel_announcement(bytes: &[u8]) -> ChannelAnnouncement {
        match Message::decode(bytes).expect("valid message") {
            Message::ChannelAnnouncement(ca) => ca,
            other => panic!("expected channel_announcement(256), got {other}"),
        }
    }

    fn decode_open_channel(bytes: &[u8]) -> OpenChannel {
        match Message::decode(bytes).expect("valid message") {
            Message::OpenChannel(oc) => oc,
            other => panic!("expected open_channel(32), got {other}"),
        }
    }

    fn send_open_channel_instructions() -> Vec<Instruction> {
        let mut instructions = open_channel_instructions();
        instructions.extend([
            Instruction {
                operation: Operation::BuildOpenChannel,
                inputs: (0..20).collect(),
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![20],
            },
        ]);
        instructions
    }

    // -- execute() tests --

    #[test]
    fn execute_load_build_send() {
        let pk = sample_pubkey(1);
        let mut instrs = open_channel_instructions();
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let oc = decode_open_channel(&executor.conn.sent[0]);
        assert_eq!(oc.chain_hash, [0xcc; 32]);
        assert_eq!(oc.temporary_channel_id, ChannelId::new([0xbb; 32]));
        assert_eq!(oc.funding_satoshis, 100_000);
        assert_eq!(oc.push_msat, 0);
        assert_eq!(oc.dust_limit_satoshis, 546);
        assert_eq!(oc.max_htlc_value_in_flight_msat, 100_000_000);
        assert_eq!(oc.channel_reserve_satoshis, 10_000);
        assert_eq!(oc.htlc_minimum_msat, 1_000);
        assert_eq!(oc.feerate_per_kw, 253);
        assert_eq!(oc.to_self_delay, 144);
        assert_eq!(oc.max_accepted_htlcs, 483);
        assert_eq!(oc.funding_pubkey, pk);
        assert_eq!(oc.revocation_basepoint, pk);
        assert_eq!(oc.payment_basepoint, pk);
        assert_eq!(oc.delayed_payment_basepoint, pk);
        assert_eq!(oc.htlc_basepoint, pk);
        assert_eq!(oc.first_per_commitment_point, pk);
        assert_eq!(oc.channel_flags, 1);
        assert_eq!(oc.tlvs.upfront_shutdown_script, Some(vec![]));
        assert_eq!(oc.tlvs.channel_type, Some(vec![0x40, 0x10, 0x00]));
    }

    #[test]
    fn execute_build_channel_announcement() {
        let node_sk_1_bytes = [0x11; 32];
        let node_sk_2_bytes = [0x22; 32];
        let bitcoin_sk_1_bytes = [0x33; 32];
        let bitcoin_sk_2_bytes = [0x44; 32];
        let scid = ShortChannelId::new(539_268, 845, 1);
        let features = vec![0x01, 0x02];

        let instrs = vec![
            Instruction {
                operation: Operation::LoadFeatures(features.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShortChannelId(scid.as_u64()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(node_sk_1_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(node_sk_2_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildChannelAnnouncement,
                inputs: vec![0, 1, 2, 3, 4, 5, 6],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![7],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let ca = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::ChannelAnnouncement(ca) => ca,
            other => panic!("expected channel_announcement(256), got {other}"),
        };

        let secp = Secp256k1::new();
        let pk =
            |b: &[u8; 32]| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(b).unwrap());
        assert_eq!(ca.features, features);
        assert_eq!(ca.chain_hash, sample_context().chain_hash);
        assert_eq!(ca.short_channel_id, scid);
        assert_eq!(ca.node_id_1, pk(&node_sk_1_bytes));
        assert_eq!(ca.node_id_2, pk(&node_sk_2_bytes));
        assert_eq!(ca.bitcoin_key_1, pk(&bitcoin_sk_1_bytes));
        assert_eq!(ca.bitcoin_key_2, pk(&bitcoin_sk_2_bytes));
        assert!(ca.extra.is_empty());
        assert!(ca.verify());
    }

    #[test]
    fn execute_build_node_announcement() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 0x42;
        let rgb_color = [0x11, 0x22, 0x33];
        let mut alias = [0u8; 32];
        alias[..5].copy_from_slice(b"smite");
        let addresses = vec![0xaa, 0xbb, 0xcc];

        let instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey(sk_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![0x01, 0x02]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTimestamp(1_700_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadBytes(addresses.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildNodeAnnouncement { rgb_color, alias },
                inputs: vec![0, 1, 2, 3],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![4],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let na = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::NodeAnnouncement(na) => na,
            other => panic!("expected node_announcement(257), got {other}"),
        };

        let secp = Secp256k1::new();
        let expected_node_id =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
        assert_eq!(na.node_id, expected_node_id);
        assert_eq!(na.features, vec![0x01, 0x02]);
        assert_eq!(na.timestamp, 1_700_000_000);
        assert_eq!(na.rgb_color, rgb_color);
        assert_eq!(na.alias, alias);
        assert_eq!(na.addresses, addresses);
        assert!(na.extra.is_empty());
        assert!(na.verify());
    }

    #[test]
    fn execute_build_channel_update() {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 0x42;
        let scid = ShortChannelId::new(538_532, 845, 1);

        let instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey(sk_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShortChannelId(scid.as_u64()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadTimestamp(1_715_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU8(0x01), // message_flags: must_be_one
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU8(0x00), // channel_flags
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadU16(144), // cltv_expiry_delta
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1_000), // htlc_minimum_msat
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadForwardingFee(1_000), // fee_base_msat
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadForwardingFee(100), // fee_proportional_millionths
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(99_000_000), // htlc_maximum_msat
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildChannelUpdate,
                inputs: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![11],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let cu = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::ChannelUpdate(cu) => cu,
            other => panic!("expected channel_update(258), got {other}"),
        };

        assert_eq!(cu.chain_hash, sample_context().chain_hash);
        assert_eq!(cu.short_channel_id, scid);
        assert_eq!(cu.timestamp, 1_715_000_000);
        assert_eq!(cu.message_flags, 0x01);
        assert_eq!(cu.channel_flags, 0x00);
        assert_eq!(cu.cltv_expiry_delta, 144);
        assert_eq!(cu.htlc_minimum_msat, 1_000);
        assert_eq!(cu.fee_base_msat, 1_000);
        assert_eq!(cu.fee_proportional_millionths, 100);
        assert_eq!(cu.htlc_maximum_msat, 99_000_000);
        assert!(cu.extra.is_empty());

        let secp = Secp256k1::new();
        let expected_node_id =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk_bytes).unwrap());
        assert!(cu.verify(&expected_node_id));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn execute_build_announcement_signatures() {
        let node_sk_1_bytes = [0x11; 32];
        let node_sk_2_bytes = [0x22; 32];
        let bitcoin_sk_1_bytes = [0x33; 32];
        let bitcoin_sk_2_bytes = [0x44; 32];
        let channel_id_bytes = [0xbb; 32];
        let scid = ShortChannelId::new(539_268, 845, 1);
        let features = vec![0x01, 0x02];

        // Instruction layout:
        //  v0 = LoadChannelId
        //  v1 = LoadFeatures
        //  v2 = LoadChainHashFromContext
        //  v3 = LoadShortChannelId
        //  v4 = LoadPrivateKey(node_sk_1)     -- our node signing key
        //  v5 = LoadPrivateKey(node_sk_2)     -- target's node key (derive pubkey from)
        //  v6 = DerivePoint(v5)               -- node_id_2 (target's node pubkey)
        //  v7 = LoadPrivateKey(bitcoin_sk_1)  -- our bitcoin signing key
        //  v8 = LoadPrivateKey(bitcoin_sk_2)  -- target's bitcoin key (derive pubkey from)
        //  v9 = DerivePoint(v8)               -- bitcoin_key_2 (target's bitcoin pubkey)
        // v10 = BuildAnnouncementSignatures(v0, v1, v2, v3, v4, v6, v7, v9)
        // v11 = SendMessage(v10)
        let instrs = vec![
            Instruction {
                operation: Operation::LoadChannelId(channel_id_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(features.clone()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadShortChannelId(scid.as_u64()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(node_sk_1_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(node_sk_2_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![5],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(bitcoin_sk_1_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(bitcoin_sk_2_bytes),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![8],
            },
            Instruction {
                operation: Operation::BuildAnnouncementSignatures,
                inputs: vec![0, 1, 2, 3, 4, 6, 7, 9],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![10],
            },
        ];

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let ann_sigs = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::AnnouncementSignatures(s) => s,
            other => panic!("expected announcement_signatures(259), got {other}"),
        };

        assert_eq!(ann_sigs.channel_id, ChannelId::new(channel_id_bytes));
        assert_eq!(ann_sigs.short_channel_id, scid);

        // Verify the signatures in announcement_signatures directly against
        // the channel_announcement body digest.
        let secp = Secp256k1::new();
        let node_sk_1 = SecretKey::from_slice(&node_sk_1_bytes).unwrap();
        let node_sk_2 = SecretKey::from_slice(&node_sk_2_bytes).unwrap();
        let bitcoin_sk_1 = SecretKey::from_slice(&bitcoin_sk_1_bytes).unwrap();
        let bitcoin_sk_2 = SecretKey::from_slice(&bitcoin_sk_2_bytes).unwrap();
        let node_id_ours = PublicKey::from_secret_key(&secp, &node_sk_1);
        let node_id_theirs = PublicKey::from_secret_key(&secp, &node_sk_2);
        let bitcoin_key_ours = PublicKey::from_secret_key(&secp, &bitcoin_sk_1);
        let bitcoin_key_theirs = PublicKey::from_secret_key(&secp, &bitcoin_sk_2);
        let (n1, n2, bk1, bk2) = if node_id_ours.serialize() <= node_id_theirs.serialize() {
            (
                node_id_ours,
                node_id_theirs,
                bitcoin_key_ours,
                bitcoin_key_theirs,
            )
        } else {
            (
                node_id_theirs,
                node_id_ours,
                bitcoin_key_theirs,
                bitcoin_key_ours,
            )
        };
        let placeholder = Signature::from_compact(&[0u8; 64]).unwrap();
        let ca = ChannelAnnouncement {
            node_signature_1: placeholder,
            node_signature_2: placeholder,
            bitcoin_signature_1: placeholder,
            bitcoin_signature_2: placeholder,
            features,
            chain_hash: sample_context().chain_hash,
            short_channel_id: scid,
            node_id_1: n1,
            node_id_2: n2,
            bitcoin_key_1: bk1,
            bitcoin_key_2: bk2,
            extra: Vec::new(),
        };
        let digest = ca.signing_digest();
        assert!(
            secp.verify_ecdsa(&digest, &ann_sigs.node_signature, &node_id_ours)
                .is_ok()
        );
        assert!(
            secp.verify_ecdsa(&digest, &ann_sigs.bitcoin_signature, &bitcoin_key_ours)
                .is_ok()
        );
    }

    #[test]
    fn execute_build_open_channel_with_tlvs() {
        let mut instrs = open_channel_instructions();
        instrs[18] = Instruction {
            operation: Operation::LoadBytes(vec![0x00, 0x14, 0xab]),
            inputs: vec![],
        };
        instrs[19] = Instruction {
            operation: Operation::LoadFeatures(vec![0x01, 0x02]),
            inputs: vec![],
        };
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: (0..20).collect(),
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        let oc = decode_open_channel(&executor.conn.sent[0]);
        assert_eq!(
            oc.tlvs.upfront_shutdown_script,
            Some(vec![0x00, 0x14, 0xab])
        );
        assert_eq!(oc.tlvs.channel_type, Some(vec![0x01, 0x02]));
    }

    #[test]
    fn execute_derive_point() {
        let mut instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey([0x11; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ];

        // Use the derived point in a BuildOpenChannel to verify it produced a
        // valid Point variable.
        let base = instrs.len();
        instrs.extend(open_channel_instructions());
        // Replace funding_pubkey (input 11) with the derived point (v1).
        let mut build_inputs: Vec<usize> = (base..base + 20).collect();
        build_inputs[11] = 1;
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: build_inputs,
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![base + 20],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        let oc = decode_open_channel(&executor.conn.sent[0]);
        let secp = Secp256k1::new();
        let expected =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
        assert_eq!(oc.funding_pubkey, expected);
    }

    #[test]
    fn execute_recv_and_extract_all_fields() {
        let ac = sample_accept_channel();
        let ac_bytes = Message::AcceptChannel(ac).encode();

        // Receive accept_channel (v0), then extract all 16 fields (v1..v16).
        let fields = [
            AcceptChannelField::TemporaryChannelId,
            AcceptChannelField::DustLimitSatoshis,
            AcceptChannelField::MaxHtlcValueInFlightMsat,
            AcceptChannelField::ChannelReserveSatoshis,
            AcceptChannelField::HtlcMinimumMsat,
            AcceptChannelField::MinimumDepth,
            AcceptChannelField::ToSelfDelay,
            AcceptChannelField::MaxAcceptedHtlcs,
            AcceptChannelField::FundingPubkey,
            AcceptChannelField::RevocationBasepoint,
            AcceptChannelField::PaymentBasepoint,
            AcceptChannelField::DelayedPaymentBasepoint,
            AcceptChannelField::HtlcBasepoint,
            AcceptChannelField::FirstPerCommitmentPoint,
            AcceptChannelField::UpfrontShutdownScript,
            AcceptChannelField::ChannelType,
        ];

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });
        let accept_channel_idx = instrs.len() - 1;
        for field in fields {
            instrs.push(Instruction {
                operation: Operation::ExtractAcceptChannel(field),
                inputs: vec![accept_channel_idx],
            });
        }

        // TODO: Once we add IR support for building accept_channel messages,
        // rebuild a message from the extracted fields and verify it matches the
        // original.

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ac_bytes);
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();
    }

    #[test]
    fn execute_recv_unexpected_message() {
        let init_bytes = Message::Init(Init::empty()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(init_bytes);
        let err = executor
            .execute(&program, std::time::Instant::now())
            .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::UnexpectedMessage {
                expected: MessageType::ACCEPT_CHANNEL,
                got: MessageType::INIT,
            }
        ));
    }

    #[test]
    fn execute_recv_peer_error() {
        let peer_error = smite::bolt::Error::all_channels("Wrong channel id in channel_ready");
        let error_bytes = Message::Error(peer_error.clone()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(error_bytes);
        let err = executor
            .execute(&program, std::time::Instant::now())
            .unwrap_err();
        assert!(matches!(err, ExecuteError::PeerError(e) if e == peer_error));
    }

    #[test]
    #[allow(clippy::similar_names)] // ping and pong are the canonical names
    fn execute_recv_auto_pong() {
        let ping = Ping {
            num_pong_bytes: 4,
            ignored: vec![0xaa],
        };
        let ping_bytes = Message::Ping(ping).encode();
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });

        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ping_bytes);
        executor.conn.queue_recv(ac_bytes);
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        // Verify exactly two messages were sent: `open_channel` and `pong`.
        assert_eq!(executor.conn.sent.len(), 2);

        // Verify the first message was `open_channel`.
        let oc = Message::decode(&executor.conn.sent[0]).unwrap();
        let Message::OpenChannel(_) = oc else {
            panic!("expected open_channel(32), got {oc}");
        };

        // Verify the second message was the pong.
        let pong = Message::decode(&executor.conn.sent[1]).unwrap();
        let Message::Pong(pong) = pong else {
            panic!("expected pong(19), got {pong}");
        };
        assert_eq!(pong.ignored.len(), 4);
    }

    #[test]
    fn execute_recv_skips_gossip() {
        let gossip = GossipTimestampFilter::new([0u8; 32], 0, 86400);
        let gossip_bytes = Message::GossipTimestampFilter(gossip).encode();
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(gossip_bytes);
        executor.conn.queue_recv(ac_bytes);
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        let accept_channel = executor
            .negotiations
            .values()
            .next()
            .and_then(|pending| pending.accept_channel.as_ref())
            .expect("accept_channel recorded");
        assert_eq!(accept_channel.clone(), sample_accept_channel());
    }

    #[test]
    fn execute_records_negotiation_for_open_and_accept() {
        let temporary_channel_id = ChannelId::new([0xbb; 32]);
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ac_bytes);
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        let pending = executor.negotiations.get(&temporary_channel_id).unwrap();
        assert_eq!(
            pending.open_channel.temporary_channel_id,
            temporary_channel_id
        );
        let accept_channel = pending.accept_channel.as_ref().unwrap();
        assert_eq!(accept_channel.clone(), sample_accept_channel());
        assert!(!pending.funding_built);
    }

    #[test]
    fn execute_recv_accept_channel_unknown_channel() {
        let unknown_id = ChannelId::new([0xcc; 32]);
        let ac_bytes = Message::AcceptChannel(AcceptChannel {
            temporary_channel_id: unknown_id,
            ..sample_accept_channel()
        })
        .encode();

        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ac_bytes);
        let err = executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap_err();

        let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
            panic!("unexpected error: {err:?}");
        };
        assert_eq!(*id, unknown_id);
        assert!(reason.contains(
            "unknown temporary_channel_id: no open_channel was sent for this negotiation"
        ));
    }

    #[test]
    fn execute_recv_accept_channel_opener_cannot_afford_fee() {
        let temporary_channel_id = ChannelId::new([0xbb; 32]);
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

        // Set `push_msat` so the opener cannot afford the commitment fee
        // requiring the peer to reject the `open_channel` per BOLT 2.
        let mut instrs = send_open_channel_instructions();
        instrs[3] = Instruction {
            operation: Operation::LoadAmount(99_900_000),
            inputs: vec![],
        };
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });

        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ac_bytes);
        let err = executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap_err();

        let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
            panic!("unexpected error: {err:?}");
        };
        assert_eq!(*id, temporary_channel_id);
        assert!(reason.contains(
            "invalid open_channel: opener balance 100 sat cannot cover the commitment fee"
        ));
    }

    #[test]
    fn execute_recv_accept_channel_rejects_reuse_before_funding() {
        let temporary_channel_id = ChannelId::new([0xbb; 32]);
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();

        let mut instrs = send_open_channel_instructions();
        let built_open_channel = instrs.len() - 2;
        let sent_open_channel = instrs.len() - 1;
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![sent_open_channel],
        });
        let resent_open_channel = instrs.len();
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![built_open_channel],
        });
        instrs.push(Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![resent_open_channel],
        });

        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ac_bytes.clone());
        executor.conn.queue_recv(ac_bytes.clone());
        let err = executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap_err();

        let ExecuteError::Violation(Violation::InvalidAcceptChannel(id, reason)) = &err else {
            panic!("unexpected error: {err:?}");
        };
        assert_eq!(*id, temporary_channel_id);
        assert!(reason.contains(
            "temporary_channel_id reuse: previous negotiation has not reached funding_created"
        ));
    }

    #[test]
    fn execute_records_only_first_open_channel_for_duplicate_id_before_funding() {
        let temporary_channel_id = ChannelId::new([0xbb; 32]);

        // First open_channel: funding_satoshis = 100_000.
        // Second open_channel: same temporary_channel_id, funding_satoshis = 200_000.
        let mut instrs = send_open_channel_instructions();

        // Override only funding_satoshis; reuse the first open_channel's other 19 inputs.
        let funding_satoshis = instrs.len();
        instrs.push(Instruction {
            operation: Operation::LoadAmount(200_000),
            inputs: vec![],
        });
        let mut build_inputs: Vec<usize> = (0..20).collect();
        build_inputs[2] = funding_satoshis;

        let built = instrs.len();
        instrs.push(Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: build_inputs,
        });
        instrs.push(Instruction {
            operation: Operation::SendOpenChannel,
            inputs: vec![built],
        });

        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        // Both open_channel messages went out on the wire, but only the first
        // negotiation is recorded for the shared id.
        assert_eq!(executor.conn.sent.len(), 2);
        assert_eq!(
            decode_open_channel(&executor.conn.sent[0]).funding_satoshis,
            100_000
        );
        assert_eq!(
            decode_open_channel(&executor.conn.sent[1]).funding_satoshis,
            200_000
        );
        let pending = executor.negotiations.get(&temporary_channel_id).unwrap();
        assert_eq!(pending.open_channel.funding_satoshis, 100_000);
    }

    #[test]
    fn execute_records_open_channel_for_duplicate_id_after_funding() {
        let temporary_channel_id = ChannelId::new([0xbb; 32]);
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        // Negotiated open_channel: funding_satoshis = 10_000_000.
        // Second open_channel: same temporary_channel_id, funding_satoshis = 100_000.
        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.
        // The second program's input indices are shifted past the funding
        // flow's variables.
        let offset = instrs.len();
        for mut instr in send_open_channel_instructions() {
            for input in &mut instr.inputs {
                *input += offset;
            }
            instrs.push(instr);
        }

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .negotiations
            .insert(temporary_channel_id, sample_funding_negotiation());
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        let pending = executor.negotiations.get(&temporary_channel_id).unwrap();
        assert_eq!(pending.open_channel.funding_satoshis, 100_000);
        assert!(pending.accept_channel.is_none());
        assert!(!pending.funding_built);
    }

    // -- Panic path tests --

    #[test]
    #[should_panic(expected = "expected 1 inputs, got 0")]
    fn execute_wrong_input_count_panics() {
        let program = Program {
            instructions: vec![Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![], // expects 1 input
            }],
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "expected PrivateKey, got Amount")]
    fn execute_type_mismatch_panics() {
        let program = Program {
            instructions: vec![
                Instruction {
                    operation: Operation::LoadAmount(42),
                    inputs: vec![],
                },
                Instruction {
                    operation: Operation::DerivePoint,
                    inputs: vec![0], // v0 is Amount, not PrivateKey
                },
            ],
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn execute_variable_out_of_bounds_panics() {
        let program = Program {
            instructions: vec![Instruction {
                operation: Operation::SendMessage,
                inputs: vec![99],
            }],
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn execute_forward_variable_reference_panics() {
        let program = Program {
            instructions: vec![
                Instruction {
                    operation: Operation::DerivePoint,
                    inputs: vec![1],
                },
                Instruction {
                    operation: Operation::LoadPrivateKey([0x11; 32]),
                    inputs: vec![],
                },
            ],
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "is void")]
    fn execute_void_variable_reference_panics() {
        let program = Program {
            instructions: vec![
                Instruction {
                    operation: Operation::MineBlocks(1),
                    inputs: vec![],
                },
                // Try to use the void variable.
                Instruction {
                    operation: Operation::SendMessage,
                    inputs: vec![0],
                },
            ],
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "valid private key")]
    fn execute_invalid_private_key_panics() {
        let program = Program {
            instructions: vec![
                Instruction {
                    operation: Operation::LoadPrivateKey([0; 32]),
                    inputs: vec![],
                },
                Instruction {
                    operation: Operation::DerivePoint,
                    inputs: vec![0],
                },
            ],
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "expected OpenChannelMessage, got Amount")]
    fn execute_send_open_channel_wrong_type_panics() {
        let instrs = vec![
            Instruction {
                operation: Operation::LoadAmount(42),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel,
                inputs: vec![0],
            },
        ];

        let program = Program {
            instructions: instrs,
        };

        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    #[should_panic(expected = "is void")]
    fn execute_affine_overuse_panics() {
        let mut instrs = send_open_channel_instructions();
        let sent_open_channel = instrs.len() - 1;
        instrs.extend([
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![sent_open_channel],
            },
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![sent_open_channel],
            },
        ]);
        let program = Program {
            instructions: instrs,
        };
        let ac_bytes = Message::AcceptChannel(sample_accept_channel()).encode();
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor.conn.queue_recv(ac_bytes);
        let _ = executor.execute(&program, std::time::Instant::now());
    }

    // MineBlocks should track calls to mine_blocks
    #[test]
    fn execute_mine_blocks_invokes_cli() {
        let instrs = vec![Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![],
        }];
        let program = Program {
            instructions: instrs,
        };
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        // Verify that mine_blocks was called with the correct number
        assert_eq!(executor.bitcoin_cli.mine_blocks_calls, vec![6]);
        assert!(executor.bitcoin_cli.mined_private_mempool.is_empty());
    }

    #[test]
    #[should_panic(expected = "expected 0 inputs, got 1")]
    fn execute_mine_blocks_wrong_input() {
        let instrs = vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::MineBlocks(6),
                inputs: vec![0],
            },
        ];
        let program = Program {
            instructions: instrs,
        };
        let _ = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        )
        .execute(&program, std::time::Instant::now());
    }

    #[test]
    fn execute_create_and_broadcast_tx() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .execute(
                &Program {
                    instructions: create_and_broadcast_tx_instructions(),
                },
                std::time::Instant::now(),
            )
            .expect("tx construction and broadcast should succeed");

        assert_eq!(executor.bitcoin_cli.broadcast_calls.len(), 1);
        let broadcast_tx = &executor.bitcoin_cli.broadcast_calls[0];
        assert_eq!(
            broadcast_tx.compute_txid().to_string(),
            "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
        );
    }

    // LookupShortChannelId should combine the confirmed block position with
    // the funding output's vout to produce the correct SCID, which we verify
    // by feeding it into a channel_announcement and decoding the sent message.
    #[test]
    fn execute_lookup_short_channel_id_confirmed() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let mut instrs = create_and_broadcast_tx_instructions();
        instrs.push(Instruction {
            operation: Operation::MineBlocks(6),
            inputs: vec![],
        });
        instrs.push(Instruction {
            // Feed the FundingTransaction produced by
            // CreateFundingTransaction (instruction 6) into the lookup. The
            // resulting ShortChannelId is variable 9.
            operation: Operation::LookupShortChannelId,
            inputs: vec![6],
        });
        // Build and send a channel_announcement carrying the looked-up SCID.
        instrs.extend(channel_announcement_from_scid_instructions(instrs.len(), 9));

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .expect("lookup after confirmation should succeed");

        assert_eq!(executor.bitcoin_cli.mine_blocks_calls, vec![6]);
        // The executor must have queried the mock with the broadcast
        // transaction's txid.
        assert_eq!(executor.bitcoin_cli.block_position_lookups.len(), 1);
        let broadcast_txid = executor.bitcoin_cli.broadcast_calls[0].compute_txid();
        assert_eq!(
            executor.bitcoin_cli.block_position_lookups[0],
            broadcast_txid,
        );

        // The mock returns block_height=800_042, tx_index=7 for a confirmed
        // tx, and the funding output is always at vout 0.
        let ca = decode_sent_channel_announcement(&executor.conn.sent[0]);
        assert_eq!(ca.short_channel_id, ShortChannelId::new(800_042, 7, 0));
    }

    // LookupShortChannelId should produce the sentinel SCID (0/0/0) when the
    // funding transaction is unknown to the node (e.g. never broadcast or
    // never confirmed), rather than panicking. We verify the sentinel value
    // via the SCID carried in a channel_announcement.
    #[test]
    fn execute_lookup_short_channel_id_unconfirmed_returns_sentinel() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        // No BroadcastTransaction and no MineBlocks: the mock reports zero
        // confirmations and get_transaction_block_position returns None.
        let mut instrs = vec![
            Instruction {
                operation: Operation::LoadPrivateKey([1u8; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadPrivateKey([2u8; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![2],
            },
            Instruction {
                operation: Operation::LoadAmount(10_000_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeeratePerKw(15_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::CreateFundingTransaction,
                inputs: vec![1, 3, 4, 5],
            },
            // The looked-up SCID is variable 7.
            Instruction {
                operation: Operation::LookupShortChannelId,
                inputs: vec![6],
            },
        ];
        instrs.extend(channel_announcement_from_scid_instructions(instrs.len(), 7));

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .expect("lookup on unconfirmed tx should not fail");
        // The mock was queried but returned None (zero confirmations), so the
        // executor took the sentinel path without panicking.
        assert!(executor.bitcoin_cli.mine_blocks_calls.is_empty());
        assert_eq!(executor.bitcoin_cli.block_position_lookups.len(), 1);

        let ca = decode_sent_channel_announcement(&executor.conn.sent[0]);
        assert_eq!(ca.short_channel_id, ShortChannelId::new(0, 0, 0));
    }

    #[test]
    fn execute_broadcast_dedupes_rejected_tx_in_private_mempool() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        // Fund with a dust amount so the built funding tx carries a below-dust
        // output.
        let mut instrs = create_and_broadcast_tx_instructions();
        instrs[4] = Instruction {
            operation: Operation::LoadAmount(200),
            inputs: vec![],
        };
        let funding_tx = instrs.len() - 2;
        instrs.push(Instruction {
            operation: Operation::BroadcastTransaction,
            inputs: vec![funding_tx],
        });
        instrs.push(Instruction {
            operation: Operation::MineBlocks(1),
            inputs: vec![],
        });

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        assert_eq!(executor.bitcoin_cli.broadcast_calls.len(), 2);
        assert_eq!(
            executor.bitcoin_cli.broadcast_calls[0].compute_txid(),
            executor.bitcoin_cli.broadcast_calls[1].compute_txid(),
        );

        let rejected_hex =
            bitcoin::consensus::encode::serialize_hex(&executor.bitcoin_cli.broadcast_calls[0]);
        assert!(executor.private_mempool.is_empty());
        assert_eq!(
            executor.bitcoin_cli.mined_private_mempool,
            vec![rejected_hex]
        );
    }

    #[test]
    fn execute_create_funding_transaction_insufficient_funds() {
        // UTXO too small to cover the funding amount and fees.
        let small_utxo = Utxo {
            amount: Amount::from_sat(1_000),
            ..sample_utxo()
        };
        let mock_cli = MockBitcoinCli {
            utxos: vec![small_utxo],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let err = Executor::new(MockConnection::new(), mock_cli, sample_context())
            .execute(
                &Program {
                    instructions: create_and_broadcast_tx_instructions(),
                },
                std::time::Instant::now(),
            )
            .unwrap_err();
        let ExecuteError::InsufficientFunds(funds_err) = err else {
            panic!("expected InsufficientFunds, got {err:?}");
        };
        assert_eq!(funds_err.available, Amount::from_sat(1_000));
        assert_eq!(funds_err.required, Amount::from_sat(10_007_290));
    }

    #[allow(clippy::similar_names)]
    fn sample_funding_negotiation() -> PendingChannel {
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
                temporary_channel_id: ChannelId::new([0xbb; 32]),
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
                temporary_channel_id: ChannelId::new([0xbb; 32]),
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

    fn send_funding_created_and_recv_funding_signed_instructions() -> Vec<Instruction> {
        let mut instrs = create_and_broadcast_tx_instructions();
        instrs.extend(vec![
            Instruction {
                operation: Operation::LoadChannelId([0xbb; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendFundingCreated,
                inputs: vec![6, 0, 8],
            },
            Instruction {
                operation: Operation::RecvFundingSigned,
                inputs: vec![9],
            },
        ]);
        instrs
    }

    #[test]
    fn execute_send_funding_created_and_recv_funding_signed() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        // The acceptor replies with funding_signed carrying its signature over
        // the opener's commitment.
        let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
            txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                .parse()
                .unwrap(),
            vout: 0,
        });

        // The expected signature here was computed using LDK as the source of
        // truth.
        let fs_bytes = Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        })
        .encode();

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor.conn.queue_recv(fs_bytes);
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), sample_funding_negotiation());
        executor
            .execute(
                &Program {
                    instructions: send_funding_created_and_recv_funding_signed_instructions(),
                },
                std::time::Instant::now(),
            )
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let fc = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::FundingCreated(fc) => fc,
            other => panic!("expected funding_created(34), got {other}"),
        };

        assert_eq!(fc.temporary_channel_id, ChannelId::new([0xbb; 32]));
        assert_eq!(
            fc.funding_txid.to_string(),
            "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
        );
        assert_eq!(fc.funding_output_index, 0);

        // Verify the signature sent by the opener on the acceptor side.
        let state = executor.channel_states.get(&channel_id).unwrap();
        let holder = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: SecretKey::from_str(
                "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13",
            )
            .unwrap(),
        };

        assert!(state.config.verify_counterparty_signature(
            &state.commitment,
            &holder,
            &fc.signature
        ));

        let pending = executor
            .negotiations
            .get(&ChannelId::new([0xbb; 32]))
            .unwrap();
        assert!(pending.funding_built);
    }

    #[test]
    fn execute_send_funding_created_after_funding_built_does_not_track_channel() {
        // A second UTXO so the program can build a second funding transaction.
        let second_utxo = Utxo {
            outpoint: OutPoint {
                vout: 1,
                ..sample_utxo().outpoint
            },
            ..sample_utxo()
        };
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo(), second_utxo],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        // Channel id derived from the first funding transaction's outpoint.
        let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
            txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                .parse()
                .unwrap(),
            vout: 0,
        });

        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.
        instrs.extend(vec![
            // Different funding spk, hence a different outpoint.
            Instruction {
                operation: Operation::CreateFundingTransaction,
                inputs: vec![1, 1, 4, 5],
            },
            Instruction {
                operation: Operation::SendFundingCreated,
                inputs: vec![10, 0, 8],
            },
        ]);

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), sample_funding_negotiation());
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        // The message still goes out, only the state tracking is suppressed.
        assert_eq!(executor.conn.sent.len(), 2);
        assert_eq!(executor.channel_states.len(), 1);
        assert!(executor.channel_states.contains_key(&channel_id));
    }

    #[test]
    fn execute_send_funding_created_push_exceeds_funding() {
        // A negotiated push_msat larger than the funding amount surfaces the
        // commitment construction error.
        let mut negotiation = sample_funding_negotiation();
        negotiation.open_channel.push_msat = 20_000_000_000;
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), negotiation);
        let err = executor
            .execute(
                &Program {
                    instructions: send_funding_created_and_recv_funding_signed_instructions(),
                },
                std::time::Instant::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::Commitment(smite::channel_tx::CommitmentError::PushExceedsFunding)
        ));
    }

    #[test]
    fn execute_send_funding_created_funding_msat_overflow() {
        // A negotiated funding_satoshis of u64::MAX overflows when converted to
        // millisatoshis.
        let mut negotiation = sample_funding_negotiation();
        negotiation.open_channel.funding_satoshis = u64::MAX;
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), negotiation);
        let err = executor
            .execute(
                &Program {
                    instructions: send_funding_created_and_recv_funding_signed_instructions(),
                },
                std::time::Instant::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::Commitment(smite::channel_tx::CommitmentError::FundingMsatOverflow)
        ));
    }

    #[test]
    fn execute_send_funding_created_no_open_channel() {
        // No negotiation exists for this temporary_channel_id, so we get a
        // `funding_created` with an all-zero signature and no recorded channel
        // state.
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        let fc = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::FundingCreated(fc) => fc,
            other => panic!("expected funding_created(34), got {other}"),
        };
        assert_eq!(fc.temporary_channel_id, ChannelId::new([0xbb; 32]));
        assert_eq!(
            fc.funding_txid.to_string(),
            "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
        );
        assert_eq!(fc.funding_output_index, 0);
        assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
        assert!(executor.channel_states.is_empty());
    }

    #[test]
    fn execute_send_funding_created_no_accept_channel() {
        // The `accept_channel` has not been received yet, so we get a
        // `funding_created` with an all-zero signature and no recorded channel
        // state.
        let mut negotiation = sample_funding_negotiation();
        negotiation.accept_channel = None;
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };
        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.pop(); // Drop the trailing `RecvFundingSigned` instruction.

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), negotiation);
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        let fc = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::FundingCreated(fc) => fc,
            other => panic!("expected funding_created(34), got {other}"),
        };
        assert_eq!(fc.temporary_channel_id, ChannelId::new([0xbb; 32]));
        assert_eq!(
            fc.funding_txid.to_string(),
            "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
        );
        assert_eq!(fc.funding_output_index, 0);
        assert_eq!(fc.signature, Signature::from_compact(&[0u8; 64]).unwrap());
        assert!(executor.channel_states.is_empty());
    }

    #[test]
    fn execute_recv_funding_signed_unknown_channel() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        let channel_id = ChannelId::new([0xbb; 32]);

        // The expected signature here was computed using LDK as the source of
        // truth.
        let fs_bytes = Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        })
        .encode();

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor.conn.queue_recv(fs_bytes);
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), sample_funding_negotiation());
        let err = executor
            .execute(
                &Program {
                    instructions: send_funding_created_and_recv_funding_signed_instructions(),
                },
                std::time::Instant::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::Violation(Violation::UnknownChannel(id)) if id == channel_id
        ));
    }

    #[test]
    fn execute_recv_funding_signed_invalid_signature() {
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
            txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                .parse()
                .unwrap(),
            vout: 0,
        });
        let fs_bytes = Message::FundingSigned(FundingSigned {
            channel_id,
            signature: Signature::from_compact(&[0u8; 64])
                .expect("zero bytes parse as a signature"),
        })
        .encode();

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor.conn.queue_recv(fs_bytes);
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), sample_funding_negotiation());
        let err = executor
            .execute(
                &Program {
                    instructions: send_funding_created_and_recv_funding_signed_instructions(),
                },
                std::time::Instant::now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ExecuteError::Violation(Violation::InvalidCounterpartySignature(id)) if id == channel_id
        ));
    }

    #[test]
    fn execute_send_channel_ready() {
        let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
            txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                .parse()
                .unwrap(),
            vout: 0,
        });
        let alias = ShortChannelId::new(538_532, 845, 1);
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.extend([
            Instruction {
                operation: Operation::LoadShortChannelId(alias.as_u64()),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendChannelReady {
                    include_alias: false,
                },
                inputs: vec![10, 1, 11],
            },
            Instruction {
                operation: Operation::SendChannelReady {
                    include_alias: true,
                },
                inputs: vec![10, 3, 11],
            },
        ]);

        let program = Program {
            instructions: instrs,
        };

        // We also need to send this `funding_signed`, since the instructions reused
        // by this test expect one to be present in the executor's receive queue.
        // The expected signature here was computed using LDK as the source of
        // truth.
        let fs_bytes = Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        })
        .encode();
        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor.conn.queue_recv(fs_bytes);
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), sample_funding_negotiation());
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        // The instructions send 1 `funding_created` and 2 `channel_ready` messages.
        assert_eq!(executor.conn.sent.len(), 3);

        // The first channel_ready was sent with include_alias = false, so it must
        // not carry the short_channel_id TLV.
        let cr1 = match Message::decode(&executor.conn.sent[1]).expect("valid message") {
            Message::ChannelReady(cr) => cr,
            other => panic!("expected channel_ready(36), got {other}"),
        };
        let expected_pcp1 = PublicKey::from_str(
            "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
        )
        .unwrap();
        assert_eq!(cr1.channel_id, channel_id);
        assert_eq!(cr1.second_per_commitment_point, expected_pcp1);
        assert!(cr1.tlvs.short_channel_id.is_none());

        // The second channel_ready was sent with include_alias = true, so it must
        // carry the alias SCID we loaded in its short_channel_id TLV.
        let cr2 = match Message::decode(&executor.conn.sent[2]).expect("valid message") {
            Message::ChannelReady(cr) => cr,
            other => panic!("expected channel_ready(36), got {other}"),
        };
        let expected_pcp2 = PublicKey::from_str(
            "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1",
        )
        .unwrap();
        assert_eq!(cr2.channel_id, channel_id);
        assert_eq!(cr2.second_per_commitment_point, expected_pcp2);
        assert_eq!(cr2.tlvs.short_channel_id, Some(alias));

        // The holder's next per-commitment point must hold the first
        // `channel_ready`'s point, not any subsequent one.
        let state = executor.channel_states.get_mut(&channel_id).unwrap();
        assert_eq!(
            *state.next_holder_per_commitment_point(),
            Some(expected_pcp1)
        );
    }

    #[test]
    fn execute_send_shutdown() {
        let channel_id = ChannelId::new([0x7a; 32]);
        let script = ShutdownScriptVariant::P2wpkh([0xab; 20]);
        let program = Program {
            instructions: vec![
                Instruction {
                    operation: Operation::LoadChannelId(channel_id.0),
                    inputs: vec![],
                },
                Instruction {
                    operation: Operation::LoadShutdownScript(script.clone()),
                    inputs: vec![],
                },
                Instruction {
                    operation: Operation::SendShutdown,
                    inputs: vec![0, 1],
                },
            ],
        };

        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let sd = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::Shutdown(sd) => sd,
            other => panic!("expected shutdown(38), got {other}"),
        };
        assert_eq!(sd.channel_id, channel_id);
        assert_eq!(sd.scriptpubkey, script.encode());
    }

    #[test]
    fn execute_send_shutdown_empty_scriptpubkey() {
        let channel_id = ChannelId::new([0x7a; 32]);
        // The fuzzer should allow an empty scriptpubkey in the shutdown message
        // to exercise the target's behavior even though it's protocol-invalid.
        let program = Program {
            instructions: vec![
                Instruction {
                    operation: Operation::LoadChannelId(channel_id.0),
                    inputs: vec![],
                },
                Instruction {
                    operation: Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
                    inputs: vec![],
                },
                Instruction {
                    operation: Operation::SendShutdown,
                    inputs: vec![0, 1],
                },
            ],
        };

        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&program, std::time::Instant::now())
            .unwrap();

        assert_eq!(executor.conn.sent.len(), 1);
        let sd = match Message::decode(&executor.conn.sent[0]).expect("valid message") {
            Message::Shutdown(sd) => sd,
            other => panic!("expected shutdown(38), got {other}"),
        };
        assert_eq!(sd.channel_id, channel_id);
        assert!(sd.scriptpubkey.is_empty());
    }

    fn recv_channel_ready_executor() -> (
        Executor<MockConnection, MockBitcoinCli>,
        ChannelId,
        PublicKey,
    ) {
        let channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
            txid: "09b0549b35f14ee862f63bd75811c6c27963c4dea6766ec6836952ec78df1e7e"
                .parse()
                .unwrap(),
            vout: 0,
        });
        let mock_cli = MockBitcoinCli {
            utxos: vec![sample_utxo()],
            change_spk: sample_change_spk(),
            ..Default::default()
        };

        // We also need to send this `funding_signed`, since the instructions reused
        // by this test expect one to be present in the executor's receive queue.
        // The expected signature here was computed using LDK as the source of
        // truth.
        let fs_bytes = Message::FundingSigned(FundingSigned {
            channel_id,
            signature: "304402203dbf3dbf337b042a72576488c1fb019086089d8d790a47f652346cff2511b6e70220395fdf700cb82b0abfcfe8e0b7c822181f2ee72409c82c3ff8e04e36593662c7".parse().unwrap(),
        })
        .encode();

        let target_pcp = sample_pubkey(1);
        let cr_bytes = Message::ChannelReady(ChannelReady {
            channel_id,
            second_per_commitment_point: target_pcp,
            tlvs: ChannelReadyTlvs::default(),
        })
        .encode();

        let mut executor = Executor::new(MockConnection::new(), mock_cli, sample_context());
        executor.conn.queue_recv(fs_bytes);
        executor.conn.queue_recv(cr_bytes);
        executor
            .negotiations
            .insert(ChannelId::new([0xbb; 32]), sample_funding_negotiation());

        (executor, channel_id, target_pcp)
    }

    #[test]
    fn execute_recv_channel_ready_invalid_funding_outpoint_is_noop() {
        let (mut executor, channel_id, _) = recv_channel_ready_executor();

        // Corrupt the negotiated opener funding pubkey so the broadcast funding
        // transaction's output no longer pays the negotiated 2-of-2 script,
        // marking the funding outpoint invalid.
        executor
            .negotiations
            .get_mut(&ChannelId::new([0xbb; 32]))
            .unwrap()
            .open_channel
            .funding_pubkey = sample_pubkey(1);

        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.extend([
            Instruction {
                operation: Operation::MineBlocks(8),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::RecvChannelReady,
                inputs: vec![],
            },
        ]);

        // With invalid funding outpoint the target does not owe us a
        // `channel_ready`, so `RecvChannelReady` must be a no-op.
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        // The target's next per-commitment point is still unknown and the queued
        // `channel_ready` remains untouched.
        let state = executor.channel_states.get_mut(&channel_id).unwrap();
        assert!(state.next_counterparty_per_commitment_point().is_none());
        assert_eq!(executor.conn.recv_queue.len(), 1);
    }

    #[test]
    fn execute_recv_channel_ready_below_minimum_depth_is_noop() {
        let (mut executor, channel_id, _) = recv_channel_ready_executor();

        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.extend([
            Instruction {
                // Mine one block fewer than the `minimum_depth` negotiated in
                // `accept_channel` by `sample_funding_negotiation()`.
                operation: Operation::MineBlocks(5),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::RecvChannelReady,
                inputs: vec![],
            },
        ]);

        // With fewer than the negotiated `minimum_depth` confirmations the target
        // does not yet owe us a `channel_ready`, so `RecvChannelReady` must be a
        // no-op.
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();
        assert!(executor.bitcoin_cli.mined_private_mempool.is_empty());

        // The target's next per-commitment point is still unknown and the queued
        // `channel_ready` remains untouched.
        let state = executor.channel_states.get_mut(&channel_id).unwrap();
        assert!(state.next_counterparty_per_commitment_point().is_none());
        assert_eq!(executor.conn.recv_queue.len(), 1);
    }

    #[test]
    fn execute_recv_channel_ready_at_minimum_depth_records_point() {
        let (mut executor, channel_id, target_pcp) = recv_channel_ready_executor();

        let mut instrs = send_funding_created_and_recv_funding_signed_instructions();
        instrs.extend([
            Instruction {
                // Mine exactly the `minimum_depth` negotiated in
                // `accept_channel` by `sample_funding_negotiation()`.
                operation: Operation::MineBlocks(6),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::RecvChannelReady,
                inputs: vec![],
            },
        ]);

        // At the negotiated `minimum_depth` confirmations the target owes us a
        // `channel_ready`, which `RecvChannelReady` receives and records.
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();
        assert!(executor.bitcoin_cli.mined_private_mempool.is_empty());

        // The `channel_ready` was consumed and the target's next per-commitment
        // point is now recorded.
        let state = executor.channel_states.get_mut(&channel_id).unwrap();
        assert_eq!(
            *state.next_counterparty_per_commitment_point(),
            Some(target_pcp)
        );
        assert!(executor.conn.recv_queue.is_empty());
    }

    #[test]
    fn execute_recv_channel_ready_funding_mined_prematurely_is_noop() {
        let (mut executor, channel_id, _) = recv_channel_ready_executor();

        let mut instrs = create_and_broadcast_tx_instructions();
        instrs.extend([
            Instruction {
                // Mine past the negotiated `minimum_depth` *before* sending
                // `funding_created`.
                operation: Operation::MineBlocks(8),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChannelId([0xbb; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendFundingCreated,
                inputs: vec![6, 0, 9],
            },
            Instruction {
                operation: Operation::RecvFundingSigned,
                inputs: vec![10],
            },
            Instruction {
                operation: Operation::RecvChannelReady,
                inputs: vec![],
            },
        ]);

        // The funding transaction confirmed before `funding_created`, so the
        // target may never observe the confirmation and `RecvChannelReady` must
        // be a no-op even though the confirmation count is sufficient.
        executor
            .execute(
                &Program {
                    instructions: instrs,
                },
                std::time::Instant::now(),
            )
            .unwrap();

        // The target's next per-commitment point is still unknown and the queued
        // `channel_ready` remains untouched.
        let state = executor.channel_states.get_mut(&channel_id).unwrap();
        assert!(state.was_funding_mined_prematurely);
        assert!(state.next_counterparty_per_commitment_point().is_none());
        assert_eq!(executor.conn.recv_queue.len(), 1);
    }

    // -- extract_field tests --

    // TODO: Once we can actually construct and send accept_channel messages, it
    // would be better to test field extraction through an IR program that
    // receives an accept_channel, extracts all fields, constructs a new
    // accept_channel from those fields, and sends the new accept_channel. Then
    // we'll have a full roundtrip test instead of testing the extract_field
    // helper function in isolation.

    #[test]
    fn extract_scalar_fields() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::DustLimitSatoshis),
            Variable::Amount(546)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::MaxHtlcValueInFlightMsat),
            Variable::Amount(100_000_000)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ChannelReserveSatoshis),
            Variable::Amount(10_000)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::HtlcMinimumMsat),
            Variable::Amount(1_000)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::MinimumDepth),
            Variable::BlockHeight(6)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ToSelfDelay),
            Variable::U16(144)
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::MaxAcceptedHtlcs),
            Variable::U16(483)
        );
    }

    #[test]
    fn extract_channel_id() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::TemporaryChannelId),
            Variable::ChannelId(ChannelId::new([0xbb; 32]))
        );
    }

    #[test]
    fn extract_pubkeys() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::FundingPubkey),
            Variable::Point(sample_pubkey(1))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::RevocationBasepoint),
            Variable::Point(sample_pubkey(2))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::PaymentBasepoint),
            Variable::Point(sample_pubkey(3))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::DelayedPaymentBasepoint),
            Variable::Point(sample_pubkey(4))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::HtlcBasepoint),
            Variable::Point(sample_pubkey(5))
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::FirstPerCommitmentPoint),
            Variable::Point(sample_pubkey(6))
        );
    }

    #[test]
    fn extract_tlvs_present() {
        let ac = sample_accept_channel();
        assert_eq!(
            extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
            Variable::Bytes(vec![0xde, 0xad])
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ChannelType),
            Variable::Features(vec![0x40, 0x10, 0x00])
        );
    }

    #[test]
    fn extract_tlvs_absent() {
        let ac = AcceptChannel {
            tlvs: AcceptChannelTlvs::default(),
            ..sample_accept_channel()
        };
        assert_eq!(
            extract_field(&ac, AcceptChannelField::UpfrontShutdownScript),
            Variable::Bytes(vec![])
        );
        assert_eq!(
            extract_field(&ac, AcceptChannelField::ChannelType),
            Variable::Features(vec![])
        );
    }

    // -- Channel establishment v2 --

    fn sample_accept_channel2(temporary_channel_id: ChannelId) -> AcceptChannel2 {
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

    /// The `open_channel2` that [`open_channel2_instructions`] puts on the
    /// wire.
    fn sample_open_channel2() -> OpenChannel2 {
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
            funding_pubkey: sample_pubkey(1),
            revocation_basepoint: sample_v2_revocation_basepoint(),
            payment_basepoint: sample_pubkey(4),
            delayed_payment_basepoint: sample_pubkey(5),
            htlc_basepoint: sample_pubkey(6),
            first_per_commitment_point: sample_pubkey(7),
            second_per_commitment_point: sample_pubkey(8),
            channel_flags: 0,
            tlvs: OpenChannel2Tlvs {
                upfront_shutdown_script: Some(vec![]),
                channel_type: Some(ChannelTypeVariant::Anchors.encode()),
                require_confirmed_inputs: false,
            },
        }
    }

    /// Our `revocation_basepoint`, and hence the `temporary_channel_id` that
    /// `open_channel2_instructions` derives from it.
    fn sample_v2_revocation_basepoint() -> PublicKey {
        sample_pubkey(3)
    }

    fn sample_v2_temporary_channel_id() -> ChannelId {
        ChannelId::v2_temporary_from_revocation_basepoint(&sample_v2_revocation_basepoint())
    }

    /// Builds the 21 `open_channel2` input instructions in wire order, deriving
    /// the `temporary_channel_id` from our revocation basepoint as BOLT 2
    /// requires. Instruction 21 is `DeriveTemporaryChannelIdV2`.
    fn open_channel2_instructions() -> Vec<Instruction> {
        let load = |op: Operation| Instruction {
            operation: op,
            inputs: vec![],
        };
        let derive = |sk_idx: usize| Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![sk_idx],
        };
        vec![
            load(Operation::LoadChainHashFromContext), // v0  chain_hash
            load(Operation::LoadFeeratePerKw(253)),    // v1  funding_feerate_perkw
            load(Operation::LoadFeeratePerKw(2500)),   // v2  commitment_feerate_perkw
            load(Operation::LoadAmount(200_000)),      // v3  funding_satoshis
            load(Operation::LoadAmount(546)),          // v4  dust_limit_satoshis
            load(Operation::LoadAmount(100_000_000)),  // v5  max_htlc_value_in_flight_msat
            load(Operation::LoadAmount(1_000)),        // v6  htlc_minimum_msat
            load(Operation::LoadU16(144)),             // v7  to_self_delay
            load(Operation::LoadU16(483)),             // v8  max_accepted_htlcs
            load(Operation::LoadBlockHeight(120)),     // v9  locktime
            load(Operation::LoadPrivateKey(key(1))),   // v10
            derive(10),                                // v11 funding_pubkey
            load(Operation::LoadPrivateKey(key(3))),   // v12
            derive(12),                                // v13 revocation_basepoint
            load(Operation::LoadPrivateKey(key(4))),   // v14
            derive(14),                                // v15 payment_basepoint
            load(Operation::LoadPrivateKey(key(5))),   // v16
            derive(16),                                // v17 delayed_payment_basepoint
            load(Operation::LoadPrivateKey(key(6))),   // v18
            derive(18),                                // v19 htlc_basepoint
            load(Operation::LoadPrivateKey(key(7))),   // v20
            derive(20),                                // v21 first_per_commitment_point
            load(Operation::LoadPrivateKey(key(8))),   // v22
            derive(22),                                // v23 second_per_commitment_point
            load(Operation::LoadU8(0)),                // v24 channel_flags
            load(Operation::LoadBytes(vec![])),        // v25 upfront_shutdown_script
            load(Operation::LoadChannelType(ChannelTypeVariant::Anchors)), // v26 channel_type
            Instruction {
                operation: Operation::DeriveTemporaryChannelIdV2,
                inputs: vec![13],
            }, // v27 temporary_channel_id
        ]
    }

    /// Indices into [`open_channel2_instructions`], in `BuildOpenChannel2`
    /// wire order.
    const OPEN_CHANNEL2_INPUTS: [usize; 21] = [
        0,  // chain_hash
        27, // temporary_channel_id
        1,  // funding_feerate_perkw
        2,  // commitment_feerate_perkw
        3,  // funding_satoshis
        4,  // dust_limit_satoshis
        5,  // max_htlc_value_in_flight_msat
        6,  // htlc_minimum_msat
        7,  // to_self_delay
        8,  // max_accepted_htlcs
        9,  // locktime
        11, // funding_pubkey
        13, // revocation_basepoint
        15, // payment_basepoint
        17, // delayed_payment_basepoint
        19, // htlc_basepoint
        21, // first_per_commitment_point
        23, // second_per_commitment_point
        24, // channel_flags
        25, // upfront_shutdown_script
        26, // channel_type
    ];

    fn decode_open_channel2(bytes: &[u8]) -> OpenChannel2 {
        match Message::decode(bytes).expect("valid open_channel2") {
            Message::OpenChannel2(oc) => oc,
            other => panic!("expected open_channel2, got {other}"),
        }
    }

    /// Emits the full `open_channel2` / `accept_channel2` exchange. The
    /// `AcceptChannel2` compound lands at the returned instruction index.
    fn send_open_channel2_instructions() -> (Vec<Instruction>, usize) {
        let mut instructions = open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::BuildOpenChannel2 {
                require_confirmed_inputs: false,
            },
            inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
        }); // v28
        instructions.push(Instruction {
            operation: Operation::SendOpenChannel2,
            inputs: vec![28],
        }); // v29
        instructions.push(Instruction {
            operation: Operation::RecvAcceptChannel2,
            inputs: vec![29],
        }); // v30
        (instructions, 30)
    }

    #[test]
    fn execute_build_and_send_open_channel2() {
        let mut instructions = open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::BuildOpenChannel2 {
                require_confirmed_inputs: true,
            },
            inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
        });
        instructions.push(Instruction {
            operation: Operation::SendOpenChannel2,
            inputs: vec![28],
        });
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        assert_eq!(executor.conn.sent.len(), 1);
        let sent = decode_open_channel2(&executor.conn.sent[0]);
        assert_eq!(sent.temporary_channel_id, sample_v2_temporary_channel_id());
        assert_eq!(sent.funding_feerate_perkw, 253);
        assert_eq!(sent.commitment_feerate_perkw, 2500);
        assert_eq!(sent.funding_satoshis, 200_000);
        assert_eq!(sent.locktime, 120);
        assert_eq!(sent.revocation_basepoint, sample_v2_revocation_basepoint());
        assert_eq!(sent.second_per_commitment_point, sample_pubkey(8));
        assert!(sent.tlvs.require_confirmed_inputs);
        assert_eq!(
            sent.tlvs.channel_type,
            Some(ChannelTypeVariant::Anchors.encode()),
        );
        // A zero-length upfront_shutdown_script is the BOLT 2 opt-out signal,
        // so the TLV is sent rather than omitted.
        assert_eq!(sent.tlvs.upfront_shutdown_script, Some(vec![]));

        // The negotiation is recorded so later steps can build from what we
        // actually put on the wire.
        let pending = executor
            .negotiations_v2
            .get(&sample_v2_temporary_channel_id())
            .expect("negotiation recorded");
        assert_eq!(pending.open_channel2, sent);
        assert!(pending.accept_channel2.is_none());
        assert!(pending.channel_id.is_none());
    }

    #[test]
    fn execute_build_open_channel2_omits_an_empty_channel_type() {
        let mut instructions = open_channel2_instructions();
        // Replace the channel type with an empty feature vector.
        instructions[26] = Instruction {
            operation: Operation::LoadFeatures(vec![]),
            inputs: vec![],
        };
        instructions.push(Instruction {
            operation: Operation::BuildOpenChannel2 {
                require_confirmed_inputs: false,
            },
            inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
        });
        instructions.push(Instruction {
            operation: Operation::SendOpenChannel2,
            inputs: vec![28],
        });
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        // BOLT 2 requires open_channel2 to set channel_type, so omitting it
        // must stay reachable for fuzzing the receiver's rejection path.
        assert_eq!(
            decode_open_channel2(&executor.conn.sent[0])
                .tlvs
                .channel_type,
            None
        );
    }

    #[test]
    fn execute_recv_accept_channel2_records_the_v2_channel_id() {
        let (instructions, _) = send_open_channel2_instructions();
        let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept.clone()).encode());
        let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        let expected_channel_id = ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &accept.revocation_basepoint,
        );
        let pending = executor
            .negotiations_v2
            .get(&sample_v2_temporary_channel_id())
            .expect("negotiation recorded");
        assert_eq!(pending.accept_channel2.as_ref(), Some(&accept));
        assert_eq!(pending.channel_id, Some(expected_channel_id));
        // The alias lets later messages, which carry the v2 channel_id, find
        // the negotiation keyed by its temporary_channel_id.
        assert_eq!(
            executor.v2_channel_ids.get(&expected_channel_id),
            Some(&sample_v2_temporary_channel_id()),
        );
    }

    #[test]
    fn execute_recv_accept_channel2_unknown_temporary_channel_id_is_ignored() {
        let (instructions, _) = send_open_channel2_instructions();
        // An accept_channel2 answering a temporary_channel_id we never opened,
        // as a mutated program that dropped its open_channel2 would see.
        let accept = sample_accept_channel2(ChannelId::new([0x77; 32]));
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept).encode());
        let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes without reporting a violation");

        // The unknown negotiation is not invented, and the one we did open is
        // left untouched.
        assert!(executor.v2_channel_ids.is_empty());
        let pending = executor
            .negotiations_v2
            .get(&sample_v2_temporary_channel_id())
            .expect("our own negotiation is still recorded");
        assert!(pending.accept_channel2.is_none());
    }

    #[test]
    fn execute_recv_accept_channel2_unexpected_message() {
        let (instructions, _) = send_open_channel2_instructions();
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel(sample_accept_channel()).encode());
        let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

        let err = executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect_err("v1 accept_channel does not answer an open_channel2");

        assert!(
            matches!(
                err,
                ExecuteError::UnexpectedMessage {
                    expected: MessageType::ACCEPT_CHANNEL2,
                    ..
                }
            ),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn execute_extract_all_accept_channel2_fields() {
        let (mut instructions, accept_idx) = send_open_channel2_instructions();
        for &field in AcceptChannel2Field::ALL {
            instructions.push(Instruction {
                operation: Operation::ExtractAcceptChannel2(field),
                inputs: vec![accept_idx],
            });
        }
        let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept.clone()).encode());
        let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        // Every field extracts, and each one produces the type it declares.
        for &field in AcceptChannel2Field::ALL {
            let extracted = extract_field_v2(&accept, field);
            assert_eq!(
                extracted.var_type(),
                field.output_type(),
                "{field} produced the wrong variable type",
            );
        }
        assert_eq!(
            extract_field_v2(&accept, AcceptChannel2Field::FundingSatoshis),
            Variable::Amount(0),
        );
        assert_eq!(
            extract_field_v2(&accept, AcceptChannel2Field::SecondPerCommitmentPoint),
            Variable::Point(sample_pubkey(17)),
        );
        assert_eq!(
            extract_field_v2(&accept, AcceptChannel2Field::MinimumDepth),
            Variable::BlockHeight(6),
        );
    }

    #[test]
    fn execute_derive_channel_id_v2_feeds_the_channel_id_on_the_wire() {
        // Runtime variables do not outlive execution, so observe
        // DeriveChannelIdV2 through the only field that carries a ChannelId
        // here: open_channel2's temporary_channel_id.
        let mut instructions = open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::LoadPrivateKey(key(12)),
            inputs: vec![],
        }); // v28
        instructions.push(Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![28],
        }); // v29 the peer's revocation basepoint
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 29],
        }); // v30
        let mut inputs = OPEN_CHANNEL2_INPUTS.to_vec();
        inputs[1] = 30;
        instructions.push(Instruction {
            operation: Operation::BuildOpenChannel2 {
                require_confirmed_inputs: false,
            },
            inputs,
        }); // v31
        instructions.push(Instruction {
            operation: Operation::SendOpenChannel2,
            inputs: vec![31],
        });
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        let sent = decode_open_channel2(&executor.conn.sent[0]);
        assert_eq!(
            sent.temporary_channel_id,
            ChannelId::v2_from_revocation_basepoints(
                &sample_v2_revocation_basepoint(),
                &sample_pubkey(12),
            ),
        );
        // Both basepoints are mixed in, so this is not the temporary id.
        assert_ne!(sent.temporary_channel_id, sample_v2_temporary_channel_id());
    }

    #[test]
    fn execute_send_open_channel2_wrong_type_panics() {
        let instructions = vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendOpenChannel2,
                inputs: vec![0],
            },
        ];
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.execute(&Program { instructions }, std::time::Instant::now())
        }));

        assert!(result.is_err(), "expected a panic on the type mismatch");
    }

    #[test]
    fn execute_recv_accept_channel2_affine_overuse_panics() {
        let (mut instructions, _) = send_open_channel2_instructions();
        // Receive twice against a single SendOpenChannel2.
        instructions.push(Instruction {
            operation: Operation::RecvAcceptChannel2,
            inputs: vec![29],
        });
        let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept.clone()).encode());
        conn.queue_recv(Message::AcceptChannel2(accept).encode());
        let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.execute(&Program { instructions }, std::time::Instant::now())
        }));

        assert!(
            result.is_err(),
            "expected a panic consuming SentOpenChannel2 twice"
        );
    }

    // -- Interactive transaction construction --

    /// A minimal previous transaction paying one 1 BTC P2WPKH output, used as
    /// the `prevtx` a `tx_add_input` carries.
    fn sample_prevtx() -> Transaction {
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

    /// A wallet holding a single spendable output of `sample_prevtx`, with that
    /// transaction available to `getrawtransaction`.
    fn sample_v2_wallet() -> MockBitcoinCli {
        let prevtx = sample_prevtx();
        let txid = prevtx.compute_txid();
        let mut cli = MockBitcoinCli {
            change_spk: sample_change_spk(),
            ..MockBitcoinCli::default()
        };
        cli.utxos.push(Utxo {
            amount: prevtx.output[0].value,
            outpoint: OutPoint { txid, vout: 0 },
            script_pubkey: prevtx.output[0].script_pubkey.clone(),
        });
        cli.raw_transactions
            .insert(txid, bitcoin::consensus::encode::serialize(&prevtx));
        cli
    }

    /// The `open_channel2` / `accept_channel2` exchange followed by
    /// `instructions`, all against a wallet with one spendable output.
    ///
    /// The `channel_id` for the interactive transaction messages is at index
    /// 31, derived from both revocation basepoints.
    fn run_v2_negotiation(extra: Vec<Instruction>) -> Executor<MockConnection, MockBitcoinCli> {
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            inputs: vec![30],
        }); // v31
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 31],
        }); // v32 channel_id
        instructions.extend(extra);

        let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept).encode());
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());
        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");
        executor
    }

    /// Index of the `channel_id` variable produced by [`run_v2_negotiation`].
    const V2_CHANNEL_ID_VAR: usize = 32;

    fn decode_sent<T>(bytes: &[u8], f: impl Fn(Message) -> Option<T>) -> T {
        let msg = Message::decode(bytes).expect("valid message");
        let name = msg.to_string();
        f(msg).unwrap_or_else(|| panic!("unexpected message {name}"))
    }

    fn sole_negotiation(executor: &Executor<MockConnection, MockBitcoinCli>) -> &PendingChannelV2 {
        executor
            .negotiations_v2
            .get(&sample_v2_temporary_channel_id())
            .expect("negotiation recorded")
    }

    #[test]
    fn execute_send_tx_add_input_proposes_a_wallet_utxo() {
        let executor = run_v2_negotiation(vec![Instruction {
            operation: Operation::SendTxAddInput {
                serial_id: 2,
                utxo_index: 0,
                sequence: 0xffff_fffd,
            },
            inputs: vec![V2_CHANNEL_ID_VAR],
        }]);

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxAddInput(m) => Some(m),
            _ => None,
        });
        let prevtx = sample_prevtx();
        assert_eq!(sent.serial_id, 2);
        assert_eq!(sent.sequence, 0xffff_fffd);
        assert_eq!(sent.prevtx_vout, 0);
        assert_eq!(sent.prevtx, bitcoin::consensus::encode::serialize(&prevtx));

        // The input is recorded with the value we know from the wallet, so the
        // change output can be computed from it.
        let pending = sole_negotiation(&executor);
        let (serial_id, input) = pending.shared_tx.inputs().next().expect("input recorded");
        assert_eq!(serial_id, 2);
        assert_eq!(input.contributor, Contributor::Local);
        assert_eq!(input.outpoint.txid, prevtx.compute_txid());
        assert_eq!(input.value(), 100_000_000);
    }

    #[test]
    fn execute_send_tx_add_input_locks_the_selected_utxo() {
        let executor = run_v2_negotiation(vec![Instruction {
            operation: Operation::SendTxAddInput {
                serial_id: 2,
                utxo_index: 0,
                sequence: 0xffff_fffd,
            },
            inputs: vec![V2_CHANNEL_ID_VAR],
        }]);

        // Locking is what stops a later selection proposing the same coin,
        // which the peer would reject as a duplicate input.
        assert_eq!(
            executor.bitcoin_cli.locked_outpoints,
            vec![OutPoint {
                txid: sample_prevtx().compute_txid(),
                vout: 0,
            }],
        );
    }

    #[test]
    fn execute_send_tx_add_input_with_an_empty_wallet_sends_an_empty_prevtx() {
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::SendTxAddInput {
                serial_id: 2,
                utxo_index: 0,
                sequence: 0xffff_fffd,
            },
            inputs: vec![27],
        });
        let accept = sample_accept_channel2(sample_v2_temporary_channel_id());
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept).encode());
        let mut executor = Executor::new(conn, MockBitcoinCli::default(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("an empty wallet is not a harness error");

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxAddInput(m) => Some(m),
            _ => None,
        });
        // Nothing to spend, so nothing to prove non-malleable. The message
        // still goes out for the peer to reject.
        assert!(sent.prevtx.is_empty());
    }

    #[test]
    fn execute_send_tx_add_output_derives_the_funding_output() {
        let executor = run_v2_negotiation(vec![Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 4,
                role: TxOutputRole::Funding,
            },
            inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
        }]);

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxAddOutput(m) => Some(m),
            _ => None,
        });
        // The acceptor contributes nothing, so the funding output is worth
        // exactly our open_channel2.funding_satoshis.
        assert_eq!(sent.sats, 200_000);
        let expected_script = build_funding_witness_script(
            &sample_pubkey(1),
            &sample_accept_channel2(sample_v2_temporary_channel_id()).funding_pubkey,
        )
        .to_p2wsh();
        assert_eq!(ScriptBuf::from(sent.script), expected_script);
    }

    #[test]
    fn execute_send_tx_add_output_change_covers_the_funding_and_the_fee() {
        let executor = run_v2_negotiation(vec![
            Instruction {
                operation: Operation::SendTxAddInput {
                    serial_id: 2,
                    utxo_index: 0,
                    sequence: 0xffff_fffd,
                },
                inputs: vec![V2_CHANNEL_ID_VAR],
            },
            Instruction {
                operation: Operation::SendTxAddOutput {
                    serial_id: 4,
                    role: TxOutputRole::Funding,
                },
                inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
            },
            Instruction {
                operation: Operation::SendTxAddOutput {
                    serial_id: 6,
                    role: TxOutputRole::Change,
                },
                inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
            },
        ]);

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxAddOutput(m) => Some(m),
            _ => None,
        });
        // One 1 BTC input, 200_000 sat to the funding output, and our share of
        // the fee at 253 sat/kw: weight 42 + 164 + 172 + 124 + 108 = 610,
        // giving ceil(610 * 253 / 1000) = 155 sat.
        assert_eq!(sent.sats, 100_000_000 - 200_000 - 155);
        assert_eq!(ScriptBuf::from(sent.script), sample_change_spk());
    }

    #[test]
    fn execute_send_tx_add_output_explicit_uses_its_inputs() {
        let executor = run_v2_negotiation(vec![Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 4,
                role: TxOutputRole::Explicit,
            },
            // v3 is funding_satoshis (200_000), v25 the empty script.
            inputs: vec![V2_CHANNEL_ID_VAR, 3, 25],
        }]);

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxAddOutput(m) => Some(m),
            _ => None,
        });
        assert_eq!(sent.sats, 200_000);
        assert!(sent.script.is_empty());
    }

    #[test]
    fn execute_send_tx_remove_input_keeps_the_peers_input() {
        let channel_id = ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
        );
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            inputs: vec![30],
        }); // v31
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 31],
        }); // v32
        instructions.push(Instruction {
            operation: Operation::SendTxAddInput {
                serial_id: 2,
                utxo_index: 0,
                sequence: 0xffff_fffd,
            },
            inputs: vec![32],
        }); // v33
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![33],
        }); // the peer contributes an input of its own
        instructions.push(Instruction {
            // BOLT 2 forbids removing an input the peer added. A peer that
            // receives one keeps its input, so we must keep it too or our
            // reconstruction of the shared transaction diverges from theirs.
            operation: Operation::SendTxRemoveInput { serial_id: 3 },
            inputs: vec![32],
        }); // v35
        instructions.push(Instruction {
            operation: Operation::SendTxRemoveInput { serial_id: 2 },
            inputs: vec![32],
        }); // v36

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(
            Message::TxAddInput(TxAddInput {
                channel_id,
                serial_id: 3,
                prevtx: bitcoin::consensus::encode::serialize(&sample_prevtx()),
                prevtx_vout: 0,
                sequence: 0xffff_fffd,
                tlvs: TxAddInputTlvs::default(),
            })
            .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        // Ours is gone, the peer's survives.
        let pending = sole_negotiation(&executor);
        let remaining: Vec<u64> = pending.shared_tx.inputs().map(|(id, _)| id).collect();
        assert_eq!(remaining, vec![3]);

        // Both removals still went on the wire; only our own changed local
        // state, so the peer gets to reject the illegal one.
        let removals = executor
            .conn
            .sent
            .iter()
            .filter(|bytes| {
                Message::decode(bytes).expect("valid").msg_type() == MessageType::TX_REMOVE_INPUT
            })
            .count();
        assert_eq!(removals, 2);
    }

    #[test]
    fn execute_send_tx_remove_output_keeps_the_peers_output() {
        let channel_id = ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
        );
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            inputs: vec![30],
        });
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 31],
        });
        instructions.push(Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 4,
                role: TxOutputRole::Funding,
            },
            inputs: vec![32, 3, 25],
        }); // v33
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![33],
        });
        instructions.push(Instruction {
            operation: Operation::SendTxRemoveOutput { serial_id: 5 },
            inputs: vec![32],
        });
        instructions.push(Instruction {
            operation: Operation::SendTxRemoveOutput { serial_id: 4 },
            inputs: vec![32],
        });

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(
            Message::TxAddOutput(TxAddOutput {
                channel_id,
                serial_id: 5,
                sats: 50_000,
                script: sample_change_spk().into_bytes(),
            })
            .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        let pending = sole_negotiation(&executor);
        let remaining: Vec<u64> = pending.shared_tx.outputs().map(|(id, _)| id).collect();
        assert_eq!(remaining, vec![5]);
    }

    #[test]
    fn execute_recv_interactive_tx_records_peer_contributions() {
        let prevtx = sample_prevtx();
        let channel_id = ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
        );
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            inputs: vec![30],
        }); // v31
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 31],
        }); // v32
        instructions.push(Instruction {
            operation: Operation::SendTxComplete,
            inputs: vec![32],
        }); // v33
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![33],
        });

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(
            Message::TxAddInput(TxAddInput {
                channel_id,
                // The non-initiator uses odd serial ids.
                serial_id: 3,
                prevtx: bitcoin::consensus::encode::serialize(&prevtx),
                prevtx_vout: 0,
                sequence: 0xffff_fffd,
                tlvs: TxAddInputTlvs::default(),
            })
            .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        let pending = sole_negotiation(&executor);
        let (serial_id, input) = pending.shared_tx.inputs().next().expect("input recorded");
        assert_eq!(serial_id, 3);
        assert_eq!(input.contributor, Contributor::Remote);
        assert_eq!(input.value(), 100_000_000);
        // A contribution is not a tx_complete, so the negotiation has not
        // concluded even though we sent ours.
        assert!(pending.tx_negotiation.sent_tx_complete);
        assert!(!pending.tx_negotiation.peer_sent_tx_complete);
        assert!(!pending.tx_negotiation_complete());
    }

    #[test]
    fn execute_recv_interactive_tx_completes_on_consecutive_tx_completes() {
        let channel_id = ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
        );
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            inputs: vec![30],
        });
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 31],
        });
        instructions.push(Instruction {
            operation: Operation::SendTxComplete,
            inputs: vec![32],
        });
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![33],
        });

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(Message::TxComplete(TxComplete { channel_id }).encode());
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        assert!(sole_negotiation(&executor).tx_negotiation_complete());
    }

    #[test]
    fn execute_recv_interactive_tx_for_an_unknown_channel_is_ignored() {
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::SendTxComplete,
            inputs: vec![27],
        }); // v31
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![31],
        });

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(
            Message::TxComplete(TxComplete {
                channel_id: ChannelId::new([0x99; 32]),
            })
            .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("an unknown channel_id is not a harness error");

        // Only the peer can tell whether that message is consistent with its
        // own view, so nothing is invented on our side.
        assert!(
            !sole_negotiation(&executor)
                .tx_negotiation
                .peer_sent_tx_complete
        );
    }

    #[test]
    fn execute_recv_interactive_tx_unexpected_message() {
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::SendTxComplete,
            inputs: vec![27],
        });
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![31],
        });

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(Message::AcceptChannel(sample_accept_channel()).encode());
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        let err = executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect_err("accept_channel does not belong in an interactive tx exchange");

        assert!(
            matches!(err, ExecuteError::UnexpectedMessage { .. }),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn execute_recv_interactive_tx_affine_overuse_panics() {
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::SendTxComplete,
            inputs: vec![27],
        });
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![31],
        });
        instructions.push(Instruction {
            operation: Operation::RecvInteractiveTx,
            inputs: vec![31],
        });

        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        // Enough for the first receive to succeed, so the second one fails on
        // the consumed token rather than on an empty queue.
        conn.queue_recv(
            Message::TxComplete(TxComplete {
                channel_id: sample_v2_temporary_channel_id(),
            })
            .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.execute(&Program { instructions }, std::time::Instant::now())
        }));

        assert!(
            result.is_err(),
            "the turn-based protocol earns one receive per send",
        );
    }

    // -- Commitment and signature exchange --

    /// Drives the full v2 flow through `tx_complete`, then appends `extra`.
    ///
    /// Variable indices of interest: 32 is the v2 `channel_id`, 36 the funding
    /// transaction, 10 our funding private key.
    fn v2_flow_instructions(extra: Vec<Instruction>) -> Vec<Instruction> {
        let (mut instructions, _) = send_open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel2(AcceptChannel2Field::RevocationBasepoint),
            inputs: vec![30],
        }); // v31
        instructions.push(Instruction {
            operation: Operation::DeriveChannelIdV2,
            inputs: vec![13, 31],
        }); // v32 channel_id
        instructions.push(Instruction {
            operation: Operation::SendTxAddInput {
                serial_id: 2,
                utxo_index: 0,
                sequence: 0xffff_fffd,
            },
            inputs: vec![32],
        }); // v33
        instructions.push(Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 4,
                role: TxOutputRole::Funding,
            },
            inputs: vec![32, 3, 25],
        }); // v34
        instructions.push(Instruction {
            operation: Operation::SendTxAddOutput {
                serial_id: 6,
                role: TxOutputRole::Change,
            },
            inputs: vec![32, 3, 25],
        }); // v35
        instructions.push(Instruction {
            operation: Operation::BuildFundingTransactionV2,
            inputs: vec![32],
        }); // v36 funding transaction
        instructions.extend(extra);
        instructions
    }

    /// A wallet whose single output is also signable, so `tx_signatures` has a
    /// witness to carry.
    fn sample_v2_signing_wallet() -> MockBitcoinCli {
        let mut cli = sample_v2_wallet();
        cli.signable_outpoints = cli.utxos.iter().map(|u| u.outpoint).collect();
        cli
    }

    fn v2_channel_id() -> ChannelId {
        ChannelId::v2_from_revocation_basepoints(
            &sample_v2_revocation_basepoint(),
            &sample_accept_channel2(sample_v2_temporary_channel_id()).revocation_basepoint,
        )
    }

    /// A `commitment_signed` the acceptor would send for our initial
    /// commitment, signed with the acceptor's funding key.
    fn counterparty_commitment_signed(
        executor: &Executor<MockConnection, MockBitcoinCli>,
        channel_id: ChannelId,
        acceptor_funding_privkey: &SecretKey,
    ) -> CommitmentSigned {
        let state = executor
            .channel_states
            .get(&channel_id)
            .expect("channel tracked");
        let holder = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: *acceptor_funding_privkey,
        };
        CommitmentSigned {
            channel_id,
            signature: state
                .config
                .sign_counterparty_commitment(&state.commitment, &holder),
            htlc_signatures: Vec::new(),
            tlvs: CommitmentSignedTlvs::default(),
        }
    }

    #[test]
    fn execute_build_funding_transaction_v2_locates_the_funding_output() {
        let mut executor = Executor::new(
            {
                let mut conn = MockConnection::new();
                conn.queue_recv(
                    Message::AcceptChannel2(sample_accept_channel2(
                        sample_v2_temporary_channel_id(),
                    ))
                    .encode(),
                );
                conn
            },
            sample_v2_wallet(),
            sample_context(),
        );
        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let pending = sole_negotiation(&executor);
        let funding = pending.shared_tx.build_funding(
            &build_funding_witness_script(
                &sample_pubkey(1),
                &sample_accept_channel2(sample_v2_temporary_channel_id()).funding_pubkey,
            )
            .to_p2wsh(),
            200_000,
        );
        // Serial 4 (funding) sorts before serial 6 (change).
        assert_eq!(funding.vout, 0);
        assert_eq!(funding.tx.input.len(), 1);
        assert_eq!(funding.tx.output.len(), 2);
        assert_eq!(funding.tx.output[0].value.to_sat(), 200_000);
        assert_eq!(funding.tx.lock_time.to_consensus_u32(), 120);
    }

    #[test]
    fn execute_build_funding_transaction_v2_unknown_channel_is_empty() {
        let instructions = vec![
            Instruction {
                operation: Operation::LoadChannelId([0x99; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::BuildFundingTransactionV2,
                inputs: vec![0],
            },
            // The empty sentinel must flow into its consumers without panicking.
            Instruction {
                operation: Operation::BroadcastTransaction,
                inputs: vec![1],
            },
        ];
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("an unknown channel_id is not a harness error");
    }

    #[test]
    fn execute_send_commitment_signed_tracks_the_channel() {
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());
        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendCommitmentSigned,
                        inputs: vec![36, 10, 32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::CommitmentSigned(m) => Some(m),
            _ => None,
        });
        assert_eq!(sent.channel_id, v2_channel_id());
        // BOLT 2: the first commitment of a v2 open carries no HTLCs.
        assert!(sent.htlc_signatures.is_empty());

        let state = executor
            .channel_states
            .get(&v2_channel_id())
            .expect("channel tracked under the v2 channel_id");
        assert_eq!(state.config.funding_satoshis, 200_000);
        assert_eq!(state.config.minimum_depth, 6);
        // The acceptor contributes nothing, so the whole balance is ours.
        assert_eq!(state.commitment.opener.balance_msat, 200_000_000);
        assert_eq!(state.commitment.acceptor.balance_msat, 0);
        assert!(state.is_funding_outpoint_valid);
        // The signature we sent is over the acceptor's commitment, so it must
        // verify the way the acceptor would verify it. The holder's private
        // key plays no part in verification, only its side does.
        assert!(
            state.config.verify_counterparty_signature(
                &state.commitment,
                &HolderIdentity {
                    side: Side::Acceptor,
                    funding_privkey: SecretKey::from_slice(&key(99)).expect("valid secret key"),
                },
                &sent.signature,
            ),
            "the commitment signature we sent does not verify",
        );
    }

    #[test]
    fn execute_send_commitment_signed_splits_the_balance_by_contribution() {
        let mut accept = sample_accept_channel2(sample_v2_temporary_channel_id());
        // The acceptor contributes half the channel.
        accept.funding_satoshis = 200_000;
        let mut conn = MockConnection::new();
        conn.queue_recv(Message::AcceptChannel2(accept).encode());
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendCommitmentSigned,
                        inputs: vec![36, 10, 32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let state = executor
            .channel_states
            .get(&v2_channel_id())
            .expect("channel tracked");
        // v2 has no push_msat: each side's balance is what it contributed.
        assert_eq!(state.config.funding_satoshis, 400_000);
        assert_eq!(state.commitment.opener.balance_msat, 200_000_000);
        assert_eq!(state.commitment.acceptor.balance_msat, 200_000_000);
    }

    #[test]
    fn execute_send_commitment_signed_without_accept_channel2_is_unsigned() {
        // No accept_channel2 queued, so RecvAcceptChannel2 fails and the
        // negotiation never learns the peer's keys. Drive commitment_signed
        // straight off the temporary channel id instead.
        let mut instructions = open_channel2_instructions();
        instructions.push(Instruction {
            operation: Operation::BuildOpenChannel2 {
                require_confirmed_inputs: false,
            },
            inputs: OPEN_CHANNEL2_INPUTS.to_vec(),
        }); // v28
        instructions.push(Instruction {
            operation: Operation::SendOpenChannel2,
            inputs: vec![28],
        }); // v29
        instructions.push(Instruction {
            operation: Operation::BuildFundingTransactionV2,
            inputs: vec![27],
        }); // v30
        instructions.push(Instruction {
            operation: Operation::SendCommitmentSigned,
            inputs: vec![30, 10, 27],
        });
        let mut executor =
            Executor::new(MockConnection::new(), sample_v2_wallet(), sample_context());

        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("a missing accept_channel2 is not a harness error");

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::CommitmentSigned(m) => Some(m),
            _ => None,
        });
        // Nothing to sign without the peer's keys, so an all-zero signature
        // goes out and no channel is tracked.
        assert_eq!(sent.signature.serialize_compact(), [0u8; 64]);
        assert!(executor.channel_states.is_empty());
    }

    #[test]
    fn execute_send_commitment_signed_commits_to_the_advertised_funding_pubkey() {
        // A mutated program can hand `SendCommitmentSigned` a key unrelated to
        // the `funding_pubkey` the open advertised. The peer signs the
        // commitment we announced, so the commitment we track has to follow the
        // advertised key; deriving it from the signing key instead would leave
        // us verifying a different transaction and reporting the peer's correct
        // signature as invalid.
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(
                &Program {
                    // v12 is the revocation private key, not the funding one
                    // behind the advertised v11 `funding_pubkey`.
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendCommitmentSigned,
                        inputs: vec![36, 12, 32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("a mismatched funding key is not a harness error");

        let state = executor
            .channel_states
            .get(&v2_channel_id())
            .expect("channel tracked");
        assert_eq!(
            state.config.opener.funding_pubkey,
            PublicKey::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&key(1)).expect("valid secret key"),
            ),
        );
        // The commitment and the on-chain funding output therefore agree on the
        // 2-of-2 script.
        assert!(state.is_funding_outpoint_valid);
    }

    #[test]
    fn execute_recv_commitment_signed_accepts_a_valid_signature() {
        let acceptor_key = SecretKey::from_slice(&key(11)).expect("valid secret key");
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        // First run establishes the channel state we need to sign against.
        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendCommitmentSigned,
                        inputs: vec![36, 10, 32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let reply = counterparty_commitment_signed(&executor, v2_channel_id(), &acceptor_key);
        executor.conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        executor
            .conn
            .queue_recv(Message::CommitmentSigned(reply).encode());

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![
                        Instruction {
                            operation: Operation::SendCommitmentSigned,
                            inputs: vec![36, 10, 32],
                        }, // v37
                        Instruction {
                            operation: Operation::RecvCommitmentSigned,
                            inputs: vec![37],
                        },
                    ]),
                },
                std::time::Instant::now(),
            )
            .expect("a valid counterparty signature verifies");

        assert!(
            sole_negotiation(&executor)
                .commitment_exchange
                .received_commitment_signed
        );
    }

    #[test]
    fn execute_recv_commitment_signed_rejects_an_invalid_signature() {
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        conn.queue_recv(
            Message::CommitmentSigned(CommitmentSigned {
                channel_id: v2_channel_id(),
                // A well-formed signature over the wrong digest, which is what
                // a target signing the wrong commitment would produce.
                signature: Secp256k1::new().sign_ecdsa(
                    &bitcoin::secp256k1::Message::from_digest([0x7c; 32]),
                    &SecretKey::from_slice(&key(11)).expect("valid secret key"),
                ),
                htlc_signatures: Vec::new(),
                tlvs: CommitmentSignedTlvs::default(),
            })
            .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        let err = executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![
                        Instruction {
                            operation: Operation::SendCommitmentSigned,
                            inputs: vec![36, 10, 32],
                        },
                        Instruction {
                            operation: Operation::RecvCommitmentSigned,
                            inputs: vec![37],
                        },
                    ]),
                },
                std::time::Instant::now(),
            )
            .expect_err("an invalid counterparty signature is a target bug");

        assert!(
            matches!(
                err,
                ExecuteError::Violation(Violation::InvalidCounterpartySignature(_)),
            ),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn execute_recv_commitment_signed_rejects_htlc_signatures() {
        let acceptor_key = SecretKey::from_slice(&key(11)).expect("valid secret key");
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());
        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendCommitmentSigned,
                        inputs: vec![36, 10, 32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let mut reply = counterparty_commitment_signed(&executor, v2_channel_id(), &acceptor_key);
        // BOLT 2 forbids HTLCs in the first commitment of a v2 open.
        reply.htlc_signatures = vec![reply.signature];
        executor.conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        executor
            .conn
            .queue_recv(Message::CommitmentSigned(reply).encode());

        let err = executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![
                        Instruction {
                            operation: Operation::SendCommitmentSigned,
                            inputs: vec![36, 10, 32],
                        },
                        Instruction {
                            operation: Operation::RecvCommitmentSigned,
                            inputs: vec![37],
                        },
                    ]),
                },
                std::time::Instant::now(),
            )
            .expect_err("htlc signatures in a v2 open are a target bug");

        assert!(
            matches!(
                err,
                ExecuteError::Violation(Violation::UnexpectedHtlcSignatures(_)),
            ),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn execute_recv_commitment_signed_without_any_v2_exchange_is_ignored() {
        // A commitment_signed arriving when no v2 negotiation ever reached
        // commitment_signed is a harness artifact, not a target bug.
        let instructions = vec![
            Instruction {
                operation: Operation::LoadChannelId([0x55; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
        ];
        let mut executor = Executor::new(
            MockConnection::new(),
            MockBitcoinCli::default(),
            sample_context(),
        );
        executor
            .execute(&Program { instructions }, std::time::Instant::now())
            .expect("program executes");

        let cs = CommitmentSigned {
            channel_id: ChannelId::new([0x55; 32]),
            signature: Signature::from_compact(&[0u8; 64]).expect("zero signature"),
            htlc_signatures: Vec::new(),
            tlvs: CommitmentSignedTlvs::default(),
        };
        let result = verify_commitment_signed(
            &cs,
            &executor.channel_states,
            &mut executor.negotiations_v2,
            &executor.v2_channel_ids,
        );

        assert!(result.is_ok(), "expected no violation, got {result:?}");
    }

    #[test]
    fn execute_send_tx_signatures_carries_our_witnesses() {
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_signing_wallet(), sample_context());

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendTxSignatures,
                        inputs: vec![32, 36],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxSignatures(m) => Some(m),
            _ => None,
        });
        assert_eq!(sent.channel_id, v2_channel_id());
        // One witness for the single input we contributed. The txid is the
        // unsigned one, since witnesses do not affect it.
        assert_eq!(sent.witnesses.len(), 1);
        assert!(!sent.witnesses[0].is_empty());
        assert_eq!(
            sent.txid,
            sole_negotiation(&executor).shared_tx.build().compute_txid()
        );
    }

    #[test]
    fn execute_send_tx_signatures_skips_inputs_the_wallet_cannot_sign() {
        let mut wallet = sample_v2_wallet();
        // The wallet holds the coin but cannot sign it, as it could not sign a
        // peer-contributed input.
        wallet.signable_outpoints.clear();
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, wallet, sample_context());

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendTxSignatures,
                        inputs: vec![32, 36],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxSignatures(m) => Some(m),
            _ => None,
        });
        // An empty witness is the peer's to reject, not a harness failure.
        assert_eq!(sent.witnesses.len(), 1);
        assert_eq!(sent.witnesses[0], vec![0x00]);
    }

    #[test]
    fn execute_send_tx_signatures_with_signing_failure_sends_no_witnesses() {
        let mut wallet = sample_v2_signing_wallet();
        wallet.signing_fails = true;
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, wallet, sample_context());

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendTxSignatures,
                        inputs: vec![32, 36],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("a signing failure is not a harness error");

        let sent = decode_sent(executor.conn.sent.last().unwrap(), |m| match m {
            Message::TxSignatures(m) => Some(m),
            _ => None,
        });
        assert!(sent.witnesses.is_empty());
    }

    #[test]
    fn execute_recv_tx_signatures_is_a_noop_before_the_commitment_exchange() {
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_wallet(), sample_context());

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::RecvTxSignatures,
                        inputs: vec![32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("no commitment_signed has been exchanged, so nothing is owed");

        // Nothing was read, so no message was consumed from an empty queue.
        assert!(executor.conn.recv_queue.is_empty());
        assert!(
            !sole_negotiation(&executor)
                .commitment_exchange
                .received_tx_signatures
        );
    }

    /// A negotiation that has exchanged both `commitment_signed`s, with the
    /// given input values contributed by each side.
    fn negotiation_awaiting_tx_signatures(
        local_value: u64,
        remote_value: u64,
    ) -> (
        HashMap<ChannelId, PendingChannelV2>,
        HashMap<ChannelId, ChannelId>,
    ) {
        let temporary_channel_id = sample_v2_temporary_channel_id();
        let mut pending = PendingChannelV2::new(sample_open_channel2());
        pending.accept_channel2 = Some(sample_accept_channel2(temporary_channel_id));
        pending.channel_id = Some(v2_channel_id());
        pending.commitment_exchange.sent_commitment_signed = true;
        pending.commitment_exchange.received_commitment_signed = true;

        let prevtx = sample_prevtx();
        let mut add = |serial_id: u64, value: u64, contributor| {
            pending.shared_tx.add_input(
                serial_id,
                SharedInput {
                    outpoint: OutPoint {
                        txid: prevtx.compute_txid(),
                        vout: u32::try_from(serial_id).expect("small"),
                    },
                    sequence: 0xffff_fffd,
                    contributor,
                    prevout: Some(TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: sample_change_spk(),
                    }),
                },
            );
        };
        if local_value > 0 {
            add(2, local_value, Contributor::Local);
        }
        if remote_value > 0 {
            add(3, remote_value, Contributor::Remote);
        }

        let mut negotiations = HashMap::new();
        negotiations.insert(temporary_channel_id, pending);
        let mut v2_channel_ids = HashMap::new();
        v2_channel_ids.insert(v2_channel_id(), temporary_channel_id);
        (negotiations, v2_channel_ids)
    }

    #[test]
    fn tx_signatures_expected_only_when_the_peer_contributed_less() {
        let context = sample_context();

        // We contributed everything, so BOLT 2 has the peer sign first and we
        // are owed a tx_signatures.
        let (negotiations, ids) = negotiation_awaiting_tx_signatures(100_000_000, 0);
        assert!(is_tx_signatures_expected(
            &negotiations,
            &ids,
            v2_channel_id(),
            &context,
        ));

        // The peer contributed more, so we must sign first: waiting here would
        // deadlock against a peer waiting on us.
        let (negotiations, ids) = negotiation_awaiting_tx_signatures(1, 100_000_000);
        assert!(!is_tx_signatures_expected(
            &negotiations,
            &ids,
            v2_channel_id(),
            &context,
        ));
    }

    #[test]
    fn tx_signatures_expected_breaks_an_equal_contribution_by_node_id() {
        let (negotiations, ids) = negotiation_awaiting_tx_signatures(50_000, 50_000);

        // Equal contributions, so the lower node_id signs first. sample_context
        // uses target_pubkey = sample_pubkey(1) and local_pubkey =
        // sample_pubkey(2).
        let expected = signs_first(50_000, 50_000, &sample_pubkey(1), &sample_pubkey(2));
        assert_eq!(
            is_tx_signatures_expected(&negotiations, &ids, v2_channel_id(), &sample_context()),
            expected,
        );

        // Swapping the two node ids swaps who signs first.
        let swapped = ProgramContext {
            target_pubkey: sample_pubkey(2),
            local_pubkey: sample_pubkey(1),
            ..sample_context()
        };
        assert_eq!(
            is_tx_signatures_expected(&negotiations, &ids, v2_channel_id(), &swapped),
            !expected,
        );
    }

    #[test]
    fn tx_signatures_not_expected_once_received() {
        let (mut negotiations, ids) = negotiation_awaiting_tx_signatures(100_000_000, 0);
        negotiations
            .get_mut(&sample_v2_temporary_channel_id())
            .expect("negotiation")
            .commitment_exchange
            .received_tx_signatures = true;

        assert!(!is_tx_signatures_expected(
            &negotiations,
            &ids,
            v2_channel_id(),
            &sample_context(),
        ));
    }

    #[test]
    fn tx_signatures_not_expected_after_an_abort() {
        let (mut negotiations, ids) = negotiation_awaiting_tx_signatures(100_000_000, 0);
        negotiations
            .get_mut(&sample_v2_temporary_channel_id())
            .expect("negotiation")
            .tx_negotiation
            .aborted = true;

        assert!(!is_tx_signatures_expected(
            &negotiations,
            &ids,
            v2_channel_id(),
            &sample_context(),
        ));
    }

    #[test]
    fn execute_recv_tx_signatures_reads_when_the_peer_signs_first() {
        let acceptor_key = SecretKey::from_slice(&key(11)).expect("valid secret key");
        let mut conn = MockConnection::new();
        conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        let mut executor = Executor::new(conn, sample_v2_signing_wallet(), sample_context());
        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![Instruction {
                        operation: Operation::SendCommitmentSigned,
                        inputs: vec![36, 10, 32],
                    }]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        let reply = counterparty_commitment_signed(&executor, v2_channel_id(), &acceptor_key);
        executor.conn.queue_recv(
            Message::AcceptChannel2(sample_accept_channel2(sample_v2_temporary_channel_id()))
                .encode(),
        );
        executor
            .conn
            .queue_recv(Message::CommitmentSigned(reply).encode());
        executor.conn.queue_recv(
            Message::TxSignatures(TxSignatures {
                channel_id: v2_channel_id(),
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .expect("valid txid"),
                witnesses: Vec::new(),
                tlvs: TxSignaturesTlvs::default(),
            })
            .encode(),
        );

        executor
            .execute(
                &Program {
                    instructions: v2_flow_instructions(vec![
                        Instruction {
                            operation: Operation::SendCommitmentSigned,
                            inputs: vec![36, 10, 32],
                        }, // v37
                        Instruction {
                            operation: Operation::RecvCommitmentSigned,
                            inputs: vec![37],
                        }, // v38
                        Instruction {
                            operation: Operation::RecvTxSignatures,
                            inputs: vec![32],
                        },
                    ]),
                },
                std::time::Instant::now(),
            )
            .expect("program executes");

        // We contributed every input, so BOLT 2 has the peer sign first and
        // the receive is expected rather than skipped.
        assert!(
            sole_negotiation(&executor)
                .commitment_exchange
                .received_tx_signatures
        );
    }
}
