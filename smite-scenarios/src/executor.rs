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
    ChannelReadyTlvs, ChannelUpdate, Features, FundingCreated, FundingSigned, Message, MessageType,
    NodeAnnouncement, OpenChannel, OpenChannelTlvs, Pong, ShortChannelId, Shutdown,
    TemporaryChannelId,
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
    /// Features negotiated between the target node and Smite.
    pub negotiated_features: Features,
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
    negotiations: HashMap<TemporaryChannelId, PendingChannel>,
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
                        negotiated_features: &self.context.negotiated_features,
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
    negotiations: &mut HashMap<TemporaryChannelId, PendingChannel>,
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

    let opener = ChannelPartyConfig {
        funding_pubkey: open_channel.funding_pubkey,
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
        channel_type: Features::from(open_channel.tlvs.channel_type.clone().unwrap_or_default()),
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
    negotiations: &mut HashMap<TemporaryChannelId, PendingChannel>,
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
    negotiations: &mut HashMap<TemporaryChannelId, PendingChannel>,
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
mod tests;
