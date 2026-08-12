//! IR program executor.
//!
//! Executes an IR program against a target node over an established connection,
//! producing side effects (sending/receiving messages).

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use smite::bitcoin::{BitcoinCli, TxBlockPosition, Utxo};
use smite::bolt::{
    AcceptChannel, AnnouncementSignatures, ChannelAnnouncement, ChannelId, ChannelReady,
    ChannelReadyTlvs, ChannelUpdate, FundingCreated, FundingSigned, Message, MessageType,
    NodeAnnouncement, OpenChannel, OpenChannelTlvs, Pong, ShortChannelId, Shutdown,
};
use smite::channel_tx::{
    ChannelConfig, ChannelPartyConfig, ChannelState, FundingTransaction, HolderIdentity, Side,
    build_funding_transaction,
};
use smite::noise::{ConnectionError, NoiseConnection};
use smite::oracles::{AcceptChannelContext, AcceptChannelOracle, Oracle};
use smite::pending_channel::PendingChannel;
use smite::violation::Violation;
use smite_ir::operation::AcceptChannelField;
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

    /// Signs and broadcasts a transaction. Returns hex-encoded raw transaction
    /// if it is consensus-valid but rejected by mempool policy, so it can be
    /// added to the `private_mempool`; returns `None` if it was broadcast or is
    /// already confirmed.
    #[must_use]
    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) -> Option<String>;

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

    fn sign_and_broadcast_tx(&mut self, tx: &bitcoin::Transaction) -> Option<String> {
        BitcoinCli::sign_and_broadcast_tx(self, tx)
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
                    let msg_type = bytes.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
                    log::debug!(
                        "[{:?}] SendMessage: type {msg_type:?}, {} bytes",
                        start.elapsed(),
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

    // Building the same message again must not clobber a channel whose state
    // has already been established (and possibly advanced).
    channel_states.entry(channel_id).or_insert_with(|| {
        ChannelState::new(
            config,
            holder,
            state,
            is_funding_outpoint_valid,
            mined_txids.contains(&funding_outpoint.txid),
        )
    });

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
            Message::Unknown { msg_type, .. } => {
                log::debug!("skipping unknown message type {msg_type}");
            }
            // TODO: Gossip messages are not currently consumed by any scenario,
            // so skip them for now. Revisit this once we want to extract their
            // fields.
            Message::ChannelAnnouncement(_)
            | Message::NodeAnnouncement(_)
            | Message::ChannelUpdate(_)
            | Message::AnnouncementSignatures(_)
            | Message::GossipTimestampFilter(_) => {
                log::debug!("skipping gossip message type {}", msg.msg_type());
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
    use smite::bolt::{AcceptChannelTlvs, GossipTimestampFilter, Init, Ping};
    use smite_ir::Instruction;
    use smite_ir::operation::ShutdownScriptVariant;

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
            other => panic!(
                "expected ChannelAnnouncement, got type {}",
                other.msg_type()
            ),
        }
    }

    fn decode_open_channel(bytes: &[u8]) -> OpenChannel {
        match Message::decode(bytes).expect("valid message") {
            Message::OpenChannel(oc) => oc,
            other => panic!("expected OpenChannel, got type {}", other.msg_type()),
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
            other => panic!(
                "expected ChannelAnnouncement, got type {}",
                other.msg_type()
            ),
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
            other => panic!("expected NodeAnnouncement, got type {}", other.msg_type()),
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
            other => panic!("expected ChannelUpdate, got type {}", other.msg_type()),
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
            other => panic!(
                "expected AnnouncementSignatures, got type {}",
                other.msg_type()
            ),
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
            panic!("expected OpenChannel, got {:?}", oc.msg_type());
        };

        // Verify the second message was the pong.
        let pong = Message::decode(&executor.conn.sent[1]).unwrap();
        let Message::Pong(pong) = pong else {
            panic!("expected Pong, got {:?}", pong.msg_type());
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
            other => panic!("expected FundingCreated, got type {}", other.msg_type()),
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
            other => panic!("expected FundingCreated, got type {}", other.msg_type()),
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
            other => panic!("expected FundingCreated, got type {}", other.msg_type()),
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
            other => panic!("expected ChannelReady, got type {}", other.msg_type()),
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
            other => panic!("expected ChannelReady, got type {}", other.msg_type()),
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
            other => panic!("expected Shutdown, got type {}", other.msg_type()),
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
            other => panic!("expected Shutdown, got type {}", other.msg_type()),
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
}
