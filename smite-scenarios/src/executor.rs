//! IR program executor.
//!
//! Executes an IR program against a target node over an established connection,
//! producing side effects (sending/receiving messages).

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, TxOut, Txid, Witness};
use smite::bitcoin::{BitcoinCli, TxBlockPosition, Utxo};
use smite::bolt::{
    AcceptChannel, AcceptChannel2, AnnouncementSignatures, ChannelAnnouncement, ChannelId,
    ChannelReady, ChannelReadyTlvs, ChannelUpdate, CommitmentSigned, CommitmentSignedTlvs,
    Features, FromMessage, FundingCreated, FundingSigned, Message, MessageType, NodeAnnouncement,
    OpenChannel, OpenChannel2, OpenChannel2Tlvs, OpenChannelTlvs, Pong, ShortChannelId, Shutdown,
    TemporaryChannelId, TxAddInput, TxAddInputTlvs, TxAddOutput, TxComplete, TxRemoveInput,
    TxRemoveOutput, TxSignatures, TxSignaturesTlvs,
};
use smite::channel_tx::{
    ChannelConfig, ChannelPartyConfig, ChannelState, Contributor, FundingTransaction,
    HolderIdentity, SharedInput, SharedOutput, Side, Step, build_funding_transaction, signs_first,
};
use smite::noise::{ConnectionError, NoiseConnection};
use smite::oracles::{
    AcceptChannelContext, AcceptChannelOracle, FundingSignedContext, FundingSignedOracle, Oracle,
};
use smite::pending_channel::{PendingChannel, V2Negotiations};
use smite::violation::Violation;

use super::targets::TargetRpc;
use smite_ir::operation::{AcceptChannel2Field, AcceptChannelField, TxOutputRole};
use smite_ir::{Operation, Program, Variable, VariableType};
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
    /// Features negotiated between the target node and Smite. Even and odd
    /// feature bits are treated equivalently, and the distinction carries no
    /// meaning here.
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
pub struct Executor<C, B, R> {
    /// Connection used to send and receive Lightning messages.
    conn: C,
    /// Interface to bitcoind for wallet and chain operations.
    bitcoin_cli: B,
    /// Interface for interacting with the target node through RPC.
    rpc: R,
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
    /// Channel establishment v2 negotiation state, addressable by either the
    /// `temporary_channel_id` or the derived `channel_id` a message carries.
    negotiations_v2: V2Negotiations,
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

impl<C: Connection, B: BitcoinRpc, R: TargetRpc> Executor<C, B, R> {
    /// Creates an executor with the given connection, bitcoin-cli handle,
    /// program context, and target RPC handle. Channel state and negotiations
    /// start empty.
    pub fn new(conn: C, bitcoin_cli: B, rpc: R, context: ProgramContext) -> Self {
        Self {
            conn,
            bitcoin_cli,
            rpc,
            context,
            channel_states: HashMap::new(),
            negotiations: HashMap::new(),
            negotiations_v2: V2Negotiations::default(),
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
    ///   order. Program producers keep keys in range: the builder draws them
    ///   uniformly (out of range with probability ~2^-128) and the mutator
    ///   repairs any out-of-range result.
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
                    consume_affine(
                        &mut variables,
                        instr.inputs[0],
                        instr.operation.input_types()[0],
                    );
                    log::debug!("[{:?}] RecvAcceptChannel: waiting", start.elapsed());
                    let ac: AcceptChannel = recv_bolt(&mut self.conn, RECV_IDLE_TIMEOUT)?;
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
                    consume_affine(
                        &mut variables,
                        instr.inputs[0],
                        instr.operation.input_types()[0],
                    );
                    log::debug!("[{:?}] RecvFundingSigned: waiting", start.elapsed());
                    let fs: FundingSigned = recv_bolt(&mut self.conn, RECV_IDLE_TIMEOUT)?;
                    log::debug!("[{:?}] RecvFundingSigned: received", start.elapsed());
                    FundingSignedOracle.evaluate(&FundingSignedContext {
                        funding_signed: &fs,
                        channel: self.channel_states.get(&fs.channel_id),
                    })?;
                    record_recv_funding_signed(&mut self.channel_states, &fs);
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
                    self.rpc.chain_sync();
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
                    // A channel establishment v2 funding transaction carries the
                    // peer's inputs, which our wallet cannot sign. Its
                    // `tx_signatures` is the only thing that can witness them.
                    let tx = apply_peer_witnesses(&self.negotiations_v2, &ft.tx);
                    // Queue transactions rejected by the mempool in the private
                    // mempool so they can be mined later. Dedup on txid so the
                    // same transaction broadcast again before then is queued
                    // once, regardless of any change to its signed hex.
                    if let Some(hex) = self.bitcoin_cli.sign_and_broadcast_tx(&tx)
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
                    self.negotiations_v2.record_open(oc);
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
                    consume_affine(
                        &mut variables,
                        instr.inputs[0],
                        instr.operation.input_types()[0],
                    );
                    log::debug!("[{:?}] RecvAcceptChannel2: waiting", start.elapsed());
                    let ac: AcceptChannel2 = recv_bolt(&mut self.conn, RECV_IDLE_TIMEOUT)?;
                    log::debug!("[{:?}] RecvAcceptChannel2: received", start.elapsed());
                    self.negotiations_v2.record_accept(&ac);
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
                    );
                    let channel_id = msg.channel_id;
                    let encoded = Message::TxAddInput(msg).encode();
                    log::debug!(
                        "[{:?}] SendTxAddInput: serial_id={serial_id}, {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx(channel_id))
                }

                Operation::SendTxAddOutput { serial_id, role } => {
                    let msg = build_tx_add_output(
                        &variables,
                        &instr.inputs,
                        *serial_id,
                        *role,
                        &mut self.bitcoin_cli,
                        &mut self.negotiations_v2,
                    );
                    let channel_id = msg.channel_id;
                    let encoded = Message::TxAddOutput(msg).encode();
                    log::debug!(
                        "[{:?}] SendTxAddOutput: serial_id={serial_id}, role={role}, {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx(channel_id))
                }

                Operation::SendTxRemoveInput { serial_id } => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    record_sent_step(
                        &mut self.negotiations_v2,
                        channel_id,
                        Step::RemoveInput(*serial_id),
                    );
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
                    Some(Variable::SentInteractiveTx(channel_id))
                }

                Operation::SendTxRemoveOutput { serial_id } => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    record_sent_step(
                        &mut self.negotiations_v2,
                        channel_id,
                        Step::RemoveOutput(*serial_id),
                    );
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
                    Some(Variable::SentInteractiveTx(channel_id))
                }

                Operation::SendTxComplete => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    record_sent_step(&mut self.negotiations_v2, channel_id, Step::Complete);
                    let encoded = Message::TxComplete(TxComplete { channel_id }).encode();
                    log::debug!("[{:?}] SendTxComplete", start.elapsed());
                    self.conn.send_message(&encoded)?;
                    Some(Variable::SentInteractiveTx(channel_id))
                }

                Operation::RecvInteractiveTx => {
                    let channel_id = consume_sent_interactive_tx(&mut variables, instr.inputs[0]);
                    if is_interactive_tx_expected(&self.negotiations_v2, channel_id) {
                        log::debug!("[{:?}] RecvInteractiveTx: waiting", start.elapsed());
                        let msg = self.recv_interactive_tx()?;
                        log::debug!("[{:?}] RecvInteractiveTx: got {msg}", start.elapsed());
                    } else {
                        log::debug!(
                            "[{:?}] RecvInteractiveTx: negotiation concluded, nothing to receive",
                            start.elapsed(),
                        );
                    }
                    None
                }

                Operation::BuildFundingTransactionV2 => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    self.settle_negotiation(channel_id)?;
                    let ft = build_funding_transaction_v2(&self.negotiations_v2, channel_id);
                    log::debug!(
                        "[{:?}] BuildFundingTransactionV2: txid={} vout={}",
                        start.elapsed(),
                        ft.tx.compute_txid(),
                        ft.vout,
                    );
                    Some(Variable::FundingTransaction(ft))
                }

                Operation::SendCommitmentSigned => {
                    self.settle_negotiation(resolve_channel_id(&variables, instr.inputs[2]))?;
                    let cs = build_commitment_signed(
                        &variables,
                        &instr.inputs,
                        &mut self.channel_states,
                        &mut self.negotiations_v2,
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
                    consume_affine(
                        &mut variables,
                        instr.inputs[0],
                        instr.operation.input_types()[0],
                    );
                    log::debug!("[{:?}] RecvCommitmentSigned: waiting", start.elapsed());
                    let cs: CommitmentSigned = recv_bolt(&mut self.conn, RECV_IDLE_TIMEOUT)?;
                    log::debug!("[{:?}] RecvCommitmentSigned: received", start.elapsed());
                    verify_commitment_signed(&cs, &self.channel_states, &mut self.negotiations_v2)?;
                    Some(Variable::ChannelId(cs.channel_id))
                }

                Operation::RecvTxSignatures => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    if is_tx_signatures_expected(&self.negotiations_v2, channel_id, &self.context) {
                        log::debug!("[{:?}] RecvTxSignatures: waiting", start.elapsed());
                        let ts: TxSignatures = recv_bolt(&mut self.conn, RECV_IDLE_TIMEOUT)?;
                        log::debug!(
                            "[{:?}] RecvTxSignatures: received {} witness(es)",
                            start.elapsed(),
                            ts.witnesses.len(),
                        );
                        let contributed = self.negotiations_v2.get(ts.channel_id).map(|pending| {
                            pending
                                .tx_exchange
                                .shared_tx()
                                .input_positions(Contributor::Remote)
                                .len()
                        });
                        let witnesses = validate_peer_witnesses(&ts, contributed)?;
                        if let Some(pending) = self.negotiations_v2.get_mut(ts.channel_id) {
                            pending.commitment_exchange.tx_signatures.received = true;
                            pending.peer_witnesses = witnesses;
                        }
                    }
                    None
                }

                Operation::SendTxSignatures => {
                    let channel_id = resolve_channel_id(&variables, instr.inputs[0]);
                    self.settle_negotiation(channel_id)?;
                    let ts = build_tx_signatures(
                        &variables,
                        &instr.inputs,
                        &mut self.bitcoin_cli,
                        &self.negotiations_v2,
                    );
                    let encoded = Message::TxSignatures(ts).encode();
                    log::debug!(
                        "[{:?}] SendTxSignatures: {} bytes",
                        start.elapsed(),
                        encoded.len(),
                    );
                    self.conn.send_message(&encoded)?;
                    // BOLT 2 has the peer reply with its own once it has ours,
                    // so this is what makes a later receive expect one.
                    if let Some(pending) = self.negotiations_v2.get_mut(channel_id) {
                        pending.commitment_exchange.tx_signatures.sent = true;
                    }
                    None
                }
            };

            variables.push(result);
        }

        Ok(())
    }

    /// Reads the peer's next interactive transaction message and applies it
    /// to the negotiation it names.
    fn recv_interactive_tx(&mut self) -> Result<Message, ExecuteError> {
        let msg = recv_non_ping(&mut self.conn, RECV_IDLE_TIMEOUT)?;
        apply_interactive_tx(&mut self.negotiations_v2, &msg)?;
        Ok(msg)
    }

    /// Reads every reply the peer still owes on `channel_id`, so what is
    /// built from the negotiation next is what the peer negotiated.
    ///
    /// A program may send several messages before reading any reply, and
    /// whether our `tx_complete` concluded the exchange is only known from
    /// the reply to the message before it. Building the funding transaction
    /// or signing over it while replies are owed would use a transaction the
    /// peer may never have agreed to, and its perfectly good signatures
    /// would then read as invalid. The replies are already on their way, so
    /// reading them costs nothing, and a later `RecvInteractiveTx` finds
    /// nothing owed and reads nothing.
    ///
    /// The count of owed replies is exact, so this never reads into whatever
    /// the peer moved on to after the exchange.
    fn settle_negotiation(&mut self, channel_id: ChannelId) -> Result<(), ExecuteError> {
        while self
            .negotiations_v2
            .get(channel_id)
            .is_some_and(|pending| pending.tx_exchange.expects_reply())
        {
            let msg = self.recv_interactive_tx()?;
            log::debug!("settling negotiation {channel_id}: got {msg}");
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

/// Panics with a diagnostic naming the variable slot, the [`VariableType`] an
/// operation required, and the type actually found there.
fn type_mismatch(index: usize, expected: VariableType, actual: VariableType) -> ! {
    panic!("variable {index}: expected {expected:?}, got {actual:?}")
}

/// Defines a resolver for a single [`Variable`] variant, panicking on a type
/// mismatch. A `&T` return type borrows the payload from the variable slice;
/// any other return type copies it out.
macro_rules! define_resolver {
    ($name:ident, $variant:ident, &$ret:ty) => {
        fn $name(variables: &[Option<Variable>], index: usize) -> &$ret {
            match resolve(variables, index) {
                Variable::$variant(v) => v,
                other => type_mismatch(index, VariableType::$variant, other.var_type()),
            }
        }
    };
    ($name:ident, $variant:ident, $ret:ty) => {
        fn $name(variables: &[Option<Variable>], index: usize) -> $ret {
            match resolve(variables, index) {
                Variable::$variant(v) => *v,
                other => type_mismatch(index, VariableType::$variant, other.var_type()),
            }
        }
    };
}

define_resolver!(resolve_amount, Amount, u64);
define_resolver!(resolve_feerate, FeeratePerKw, u32);
define_resolver!(resolve_forwarding_fee, ForwardingFee, u32);
define_resolver!(resolve_timestamp, Timestamp, u32);
define_resolver!(resolve_block_height, BlockHeight, u32);
define_resolver!(resolve_u16, U16, u16);
define_resolver!(resolve_u8, U8, u8);
define_resolver!(resolve_bytes, Bytes, &[u8]);
define_resolver!(resolve_features, Features, &[u8]);
define_resolver!(resolve_chain_hash, ChainHash, [u8; 32]);
define_resolver!(resolve_channel_id, ChannelId, ChannelId);
define_resolver!(resolve_pubkey, Point, PublicKey);
define_resolver!(resolve_short_channel_id, ShortChannelId, ShortChannelId);
define_resolver!(resolve_private_key, PrivateKey, [u8; 32]);
define_resolver!(resolve_message, Message, &[u8]);
define_resolver!(
    resolve_open_channel_message,
    OpenChannelMessage,
    &OpenChannel
);
define_resolver!(resolve_accept_channel, AcceptChannel, &AcceptChannel);
define_resolver!(
    resolve_open_channel2_message,
    OpenChannel2Message,
    &OpenChannel2
);
define_resolver!(resolve_accept_channel2, AcceptChannel2, &AcceptChannel2);
define_resolver!(
    resolve_funding_transaction,
    FundingTransaction,
    &FundingTransaction
);

/// Consumes an affine variable, leaving its slot void so it cannot be used
/// again.
fn consume_affine(variables: &mut [Option<Variable>], index: usize, expected: VariableType) {
    assert!(
        expected.is_affine(),
        "consume_affine called with non-affine type {expected:?}; voiding the slot would break later reads"
    );
    let actual = resolve(variables, index).var_type();
    if actual != expected {
        type_mismatch(index, expected, actual);
    }
    variables[index] = None;
}

/// Consumes the affine `SentInteractiveTx`, returning the `channel_id` the
/// message it stands for was sent on.
fn consume_sent_interactive_tx(variables: &mut [Option<Variable>], index: usize) -> ChannelId {
    let channel_id = match resolve(variables, index) {
        Variable::SentInteractiveTx(channel_id) => *channel_id,
        other => type_mismatch(index, VariableType::SentInteractiveTx, other.var_type()),
    };
    variables[index] = None;
    channel_id
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

/// Records a step we sent on `channel_id` in its negotiation.
///
/// A negotiation we do not track records nothing: the message still goes out
/// for the peer to judge, as does anything sent after the exchange concluded.
fn record_sent_step(negotiations: &mut V2Negotiations, channel_id: ChannelId, step: Step) {
    if let Some(pending) = negotiations.get_mut(channel_id) {
        pending.tx_exchange.send(step);
    }
}

/// Builds a `tx_add_input` proposing one of our wallet UTXOs, and records it in
/// the negotiation so the shared transaction can be rebuilt later.
///
/// `utxo_index` selects modulo the spendable set, so any index is meaningful
/// and reusing one proposes the same outpoint twice, which the peer must
/// reject. An empty wallet or a previous transaction the node does not know
/// yields an empty `prevtx`, which is likewise the peer's to reject.
fn build_tx_add_input(
    variables: &[Option<Variable>],
    inputs: &[usize],
    serial_id: u64,
    utxo_index: u8,
    sequence: u32,
    cli: &mut impl BitcoinRpc,
    negotiations: &mut V2Negotiations,
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

    if let Some(utxo) = &selected {
        // Locking keeps a later selection from proposing the same coin, which
        // the peer would reject as a duplicate input.
        cli.lock_utxos(&[utxo.outpoint]);
    }

    let mut input = SharedInput::from_prevtx(&prevtx, prevtx_vout, sequence, Contributor::Local);
    if let Some(utxo) = &selected {
        // Prefer what the wallet told us: a missing `prevtx` still leaves
        // us knowing exactly what we are spending.
        input.outpoint = utxo.outpoint;
        input.prevout = Some(TxOut {
            value: utxo.amount,
            script_pubkey: utxo.script_pubkey.clone(),
        });
    }
    record_sent_step(
        negotiations,
        channel_id,
        Step::AddInput { serial_id, input },
    );

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
fn build_tx_add_output(
    variables: &[Option<Variable>],
    inputs: &[usize],
    serial_id: u64,
    role: TxOutputRole,
    cli: &mut impl BitcoinRpc,
    negotiations: &mut V2Negotiations,
) -> TxAddOutput {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let explicit_sats = resolve_amount(variables, inputs[1]);
    let explicit_script = ScriptBuf::from(resolve_bytes(variables, inputs[2]).to_vec());

    let derived = match role {
        TxOutputRole::Explicit => None,
        TxOutputRole::Funding => negotiations.get(channel_id).and_then(|pending| {
            Some((pending.total_funding_satoshis(), pending.funding_script()?))
        }),
        TxOutputRole::Change => {
            let change_script = cli.get_new_address_script_pubkey();
            negotiations.get(channel_id).map(|pending| {
                let feerate = pending.open_channel2.funding_feerate_perkw;
                let fee = pending
                    .tx_exchange
                    .shared_tx()
                    .local_fee_sat(feerate, &[change_script.len()]);
                // Whatever our inputs cover beyond our funding contribution and
                // our share of the fee. Saturating: an under-funded selection
                // yields a zero-value output the peer rejects, rather than a
                // panic.
                let value = pending
                    .tx_exchange
                    .shared_tx()
                    .contributed_input_value(Contributor::Local)
                    .saturating_sub(pending.open_channel2.funding_satoshis)
                    .saturating_sub(fee);
                (value, change_script)
            })
        }
    };

    let (sats, script) = derived.unwrap_or((explicit_sats, explicit_script));
    let script = script.into_bytes();

    record_sent_step(
        negotiations,
        channel_id,
        Step::AddOutput {
            serial_id,
            output: SharedOutput {
                value: sats,
                script_pubkey: ScriptBuf::from(script.clone()),
                contributor: Contributor::Local,
            },
        },
    );

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
/// A message for an unknown negotiation is logged and dropped rather than
/// reported: only the peer can tell whether it is consistent with its own
/// view, and it will fail the negotiation if not.
fn apply_interactive_tx(
    negotiations: &mut V2Negotiations,
    msg: &Message,
) -> Result<(), ExecuteError> {
    let (channel_id, step) = match msg {
        Message::TxAddInput(m) => (
            m.channel_id,
            Step::AddInput {
                serial_id: m.serial_id,
                input: SharedInput::from_prevtx(
                    &m.prevtx,
                    m.prevtx_vout,
                    m.sequence,
                    Contributor::Remote,
                ),
            },
        ),
        Message::TxAddOutput(m) => (
            m.channel_id,
            Step::AddOutput {
                serial_id: m.serial_id,
                output: SharedOutput {
                    value: m.sats,
                    script_pubkey: ScriptBuf::from(m.script.clone()),
                    contributor: Contributor::Remote,
                },
            },
        ),
        Message::TxRemoveInput(m) => (m.channel_id, Step::RemoveInput(m.serial_id)),
        Message::TxRemoveOutput(m) => (m.channel_id, Step::RemoveOutput(m.serial_id)),
        Message::TxComplete(m) => (m.channel_id, Step::Complete),
        Message::TxAbort(m) => {
            log::debug!(
                "peer aborted the negotiation: {}",
                m.message().unwrap_or("<non-utf8>"),
            );
            if let Some(pending) = negotiations.get_mut(m.channel_id) {
                pending.tx_exchange.abort();
            }
            return Ok(());
        }
        other => {
            return Err(ExecuteError::UnexpectedMessage {
                expected: MessageType::TX_COMPLETE,
                got: other.msg_type(),
            });
        }
    };

    match negotiations.get_mut(channel_id) {
        Some(pending) => pending.tx_exchange.receive(step),
        None => {
            log::debug!("interactive tx message for unknown channel_id {channel_id}, ignoring");
        }
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
    negotiations: &V2Negotiations,
    channel_id: ChannelId,
) -> FundingTransaction {
    let Some(pending) = negotiations.get(channel_id) else {
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

    match pending.funding_script() {
        Some(script) => pending
            .tx_exchange
            .shared_tx()
            .build_funding(&script, pending.total_funding_satoshis()),
        // Without `accept_channel2` the funding script is unknown, so there is
        // nothing to locate; `vout` 0 keeps the result well-typed.
        None => FundingTransaction {
            tx: pending.tx_exchange.shared_tx().build(),
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
///
/// The negotiation is found by either of its ids, but the peer only answers on
/// the derived `channel_id`. A message sent on the `temporary_channel_id`
/// still goes out signed, so the peer gets to judge it, but it neither counts
/// as our side of the commitment exchange nor tracks a channel: the peer's own
/// `commitment_signed` arrives on the derived id regardless, and reading it as
/// the answer to ours would blame the target for the program's confusion.
fn build_commitment_signed(
    variables: &[Option<Variable>],
    inputs: &[usize],
    channel_states: &mut HashMap<ChannelId, ChannelState>,
    negotiations: &mut V2Negotiations,
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

    let Some(pending) = negotiations.get_mut(channel_id) else {
        return Ok(unsigned(channel_id));
    };
    let Some(accept_channel2) = pending.accept_channel2.clone() else {
        return Ok(unsigned(channel_id));
    };
    let open_channel2 = pending.open_channel2.clone();
    let total_funding_satoshis = pending.total_funding_satoshis();
    let on_derived_channel_id = pending.channel_id == Some(channel_id);
    let already_sent = pending.commitment_exchange.commitment_signed.sent;
    if on_derived_channel_id {
        pending.commitment_exchange.commitment_signed.sent = true;
    }
    let negotiated_txid = pending.tx_exchange.shared_tx().build().compute_txid();

    let opener_funding_privkey =
        SecretKey::from_slice(&opener_funding_privkey_bytes).expect("valid private key");

    let funding_outpoint = OutPoint {
        txid: funding_tx.tx.compute_txid(),
        vout: funding_tx.vout,
    };
    let config = ChannelConfig {
        funding_outpoint,
        funding_satoshis: total_funding_satoshis,
        channel_type: Features::from(open_channel2.tlvs.channel_type.clone().unwrap_or_default()),
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

    // The peer signs over the transaction it negotiated, so a funding output
    // with the right script and value is not enough: the transaction holding
    // it must be the negotiated one too. A funding transaction built before
    // the negotiation concluded carries the same output under another txid.
    let is_funding_outpoint_valid = funding_outpoint.txid == negotiated_txid
        && funding_tx.matches_funding_output(
            &open_channel2.funding_pubkey,
            &accept_channel2.funding_pubkey,
            total_funding_satoshis,
        );

    // The peer must reject a signature made with a key other than the funding
    // key we announced in `open_channel2`.
    let opener_funding_pubkey =
        PublicKey::from_secret_key(&Secp256k1::new(), &opener_funding_privkey);
    let sent_invalid_signature = opener_funding_pubkey != open_channel2.funding_pubkey;

    // Only track on the first `commitment_signed` for this negotiation, so a
    // resend cannot clobber state that has already advanced.
    if on_derived_channel_id && !already_sent {
        channel_states.entry(channel_id).or_insert_with(|| {
            ChannelState::new(
                config,
                holder,
                state,
                is_funding_outpoint_valid,
                mined_txids.contains(&funding_outpoint.txid),
                sent_invalid_signature,
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
/// A `commitment_signed` we have no state for is only reported when the
/// negotiation it names is one we sent our own `commitment_signed` on. Anything
/// else is our own doing rather than the target's: a mutated program may have
/// dropped the `accept_channel2` that would have established the state, or
/// pointed `SendCommitmentSigned` at a different `channel_id` than the one the
/// peer answers on, and blaming the target for either would be a false
/// positive.
///
/// The signature itself is checked only when our commitment was built over the
/// negotiated funding outpoint. `SendCommitmentSigned` takes the funding
/// transaction as an operand, so a mutated program can point it at one from an
/// unrelated negotiation, or at one built from this negotiation before every
/// output was added; the peer then signs the outpoint it actually negotiated,
/// we verify against a different one, and every signature would fail to verify
/// no matter what the target did.
fn verify_commitment_signed(
    cs: &CommitmentSigned,
    channel_states: &HashMap<ChannelId, ChannelState>,
    negotiations: &mut V2Negotiations,
) -> Result<(), ExecuteError> {
    if !cs.htlc_signatures.is_empty() {
        return Err(Violation::UnexpectedHtlcSignatures(cs.channel_id).into());
    }

    let Some(state) = channel_states.get(&cs.channel_id) else {
        if negotiations
            .get(cs.channel_id)
            .is_some_and(|pending| pending.commitment_exchange.commitment_signed.sent)
        {
            return Err(Violation::UnknownChannel(cs.channel_id).into());
        }
        log::debug!(
            "commitment_signed for {} with no v2 commitment exchange in flight, ignoring",
            cs.channel_id,
        );
        return Ok(());
    };

    if !state.is_funding_outpoint_valid {
        log::debug!(
            "commitment_signed for {} was built over a funding output the negotiation never \
             produced, not checking the signature",
            cs.channel_id,
        );
    } else if !state.config.verify_counterparty_signature(
        &state.commitment,
        &state.holder,
        &cs.signature,
    ) {
        return Err(Violation::InvalidCounterpartySignature(cs.channel_id).into());
    }

    if let Some(pending) = negotiations.get_mut(cs.channel_id) {
        pending.commitment_exchange.commitment_signed.received = true;
    }

    Ok(())
}

/// Returns whether the peer owes us a reply in the interactive transaction
/// exchange.
///
/// The exchange is turn-based, so the peer answers every message we send until
/// the one that concludes it on two consecutive `tx_complete`s. Reading when
/// nothing is owed would consume whatever the peer moved on to, usually its
/// `commitment_signed`, and leave every later operation a message behind.
///
/// This counts what is owed rather than asking whether the exchange concluded.
/// A mutator that drops one receive leaves the program permanently short of a
/// reply, and the count lets the next receive settle the backlog instead of
/// stranding it.
///
/// A negotiation we do not track still reads. A mutated program may have sent
/// on a channel we never opened, and the peer's rejection of it is worth
/// surfacing.
fn is_interactive_tx_expected(negotiations: &V2Negotiations, channel_id: ChannelId) -> bool {
    negotiations
        .get(channel_id)
        .is_none_or(|pending| pending.tx_exchange.expects_reply())
}

/// Returns whether the peer owes us a `tx_signatures` for this negotiation.
///
/// Both `commitment_signed`s must have been exchanged, which is what entitles
/// either peer to send at all. After that BOLT 2 gives two ways for the peer to
/// owe one: it contributed the least, so it signs first, or it received ours
/// and "MUST reply with their `tx_signatures` if not already transmitted".
/// Waiting outside those two cases would block on a message the peer is itself
/// waiting on us to send.
fn is_tx_signatures_expected(
    negotiations: &V2Negotiations,
    channel_id: ChannelId,
    context: &ProgramContext,
) -> bool {
    let Some(pending) = negotiations.get(channel_id) else {
        return false;
    };

    let peer_signs_first = signs_first(
        pending
            .tx_exchange
            .shared_tx()
            .contributed_input_value(Contributor::Remote),
        pending
            .tx_exchange
            .shared_tx()
            .contributed_input_value(Contributor::Local),
        &context.target_pubkey,
        &context.local_pubkey,
    );

    pending.commitment_exchange.commitment_signed.sent
        && pending.commitment_exchange.commitment_signed.received
        && !pending.commitment_exchange.tx_signatures.received
        && !pending.tx_exchange.aborted()
        && (peer_signs_first || pending.commitment_exchange.tx_signatures.sent)
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
    negotiations: &V2Negotiations,
) -> TxSignatures {
    let channel_id = resolve_channel_id(variables, inputs[0]);
    let funding_tx = resolve_funding_transaction(variables, inputs[1]);
    let txid = funding_tx.tx.compute_txid();

    let signed = cli.sign_tx(&funding_tx.tx);

    let local_positions = negotiations
        .get(channel_id)
        .map(|pending| {
            pending
                .tx_exchange
                .shared_tx()
                .input_positions(Contributor::Local)
        })
        .unwrap_or_default();

    let witnesses = signed
        .as_ref()
        .map(|tx| {
            local_positions
                .iter()
                .filter_map(|&position| tx.input.get(position))
                .map(|txin| bitcoin::consensus::encode::serialize(&txin.witness))
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

/// Validates and decodes the witnesses of a received `tx_signatures`.
///
/// `contributed` is how many inputs we recorded the peer adding, or `None` when
/// the message names a negotiation we track no state for and there is nothing
/// to count against.
///
/// # Errors
///
/// Returns [`Violation::InvalidTxSignatures`] for each condition BOLT 2 has the
/// receiver fail the negotiation over:
/// - an empty `witness`, named outright as a MUST-fail;
/// - a `witness_data` that is not the bitcoin wire encoding the spec's
///   rationale prescribes, so no conformant target emits it;
/// - a `num_witnesses` that does not equal the number of inputs the sender
///   added, which the sending node's own requirements forbid.
///
/// The remaining two MUST-fail conditions, non-standard witnesses and a
/// signature flag other than `SIGHASH_ALL`, need the witness scripts and
/// signatures parsed, and are not checked yet.
fn validate_peer_witnesses(
    ts: &TxSignatures,
    contributed: Option<usize>,
) -> Result<Vec<Witness>, Violation> {
    if let Some(contributed) = contributed
        && ts.witnesses.len() != contributed
    {
        return Err(Violation::InvalidTxSignatures(
            ts.channel_id,
            format!(
                "{} witness(es) for the {contributed} input(s) the peer added",
                ts.witnesses.len(),
            ),
        ));
    }

    ts.witnesses
        .iter()
        .enumerate()
        .map(|(index, encoded)| {
            let witness =
                bitcoin::consensus::encode::deserialize::<Witness>(encoded).map_err(|e| {
                    Violation::InvalidTxSignatures(
                        ts.channel_id,
                        format!("witness {index} does not decode: {e}"),
                    )
                })?;
            if witness.is_empty() {
                return Err(Violation::InvalidTxSignatures(
                    ts.channel_id,
                    format!("witness {index} is empty"),
                ));
            }
            Ok(witness)
        })
        .collect()
}

/// Attaches the witnesses from the peer's `tx_signatures` to a channel
/// establishment v2 funding transaction.
///
/// The negotiation is found by txid, since `BroadcastTransaction` carries only
/// the transaction. Witnesses do not change a txid, so the match is exact, and
/// a v1 funding transaction matches nothing and comes back unchanged.
///
/// Applying the peer's witnesses is what makes the shared transaction
/// broadcastable at all: our wallet owns only the inputs we contributed, so
/// without them `signrawtransactionwithwallet` can never complete it. Per BOLT
/// 2 the witnesses arrive ordered by the `serial_id` of the input they
/// correspond to, which is the order [`SharedTransaction::input_positions`]
/// returns.
///
/// [`validate_peer_witnesses`] already rejected anything BOLT 2 fails the
/// negotiation over when the message arrived, so every witness held here is
/// well-formed and there is one per input the peer added.
fn apply_peer_witnesses(
    negotiations: &V2Negotiations,
    tx: &bitcoin::Transaction,
) -> bitcoin::Transaction {
    let txid = tx.compute_txid();
    let mut tx = tx.clone();
    let Some(pending) = negotiations.iter().find(|pending| {
        !pending.peer_witnesses.is_empty()
            && pending.tx_exchange.shared_tx().build().compute_txid() == txid
    }) else {
        return tx;
    };

    let positions = pending
        .tx_exchange
        .shared_tx()
        .input_positions(Contributor::Remote);
    let mut applied = 0usize;
    for (&position, witness) in positions.iter().zip(&pending.peer_witnesses) {
        let Some(txin) = tx.input.get_mut(position) else {
            continue;
        };
        txin.witness = witness.clone();
        applied += 1;
    }
    log::debug!(
        "applied {applied} of {} peer witness(es) to {txid}",
        pending.peer_witnesses.len(),
    );
    tx
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

    // Only track a new channel when this negotiation has not built a
    // `funding_created` yet. If it has, we are likely resending one for the
    // same `temporary_channel_id` with a different outpoint, which the target
    // may ignore (LND and Eclair currently do), leaving us tracking a channel
    // it never opened.
    //
    // This also means that building the same message again must not clobber a
    // channel whose state has already been established (and possibly advanced).
    if !pending.funding_built {
        let channel_id = ChannelId::v1_from_funding_outpoint(config.funding_outpoint);

        // Check whether the funding outpoint is valid and contains the
        // negotiated amount and funding script. If not, there is a good chance
        // the target will neither complete the funding flow nor send an error
        // message.
        let is_funding_outpoint_valid = funding_tx.matches_funding_output(
            &open_channel.funding_pubkey,
            &accept_channel.funding_pubkey,
            open_channel.funding_satoshis,
        );
        // TODO: Once we support sending malformed signatures, update this state
        // when constructing one so that the peer's acceptance can be detected
        // as a violation.
        let opener_funding_pubkey =
            PublicKey::from_secret_key(&Secp256k1::new(), &opener_funding_privkey);
        let sent_invalid_signature = opener_funding_pubkey != open_channel.funding_pubkey;

        channel_states.entry(channel_id).or_insert_with(|| {
            ChannelState::new(
                config,
                holder,
                state,
                is_funding_outpoint_valid,
                mined_txids.contains(&funding_outpoint.txid),
                sent_invalid_signature,
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
            // Log the human-readable data before handing the message to the
            // caller, which typically only inspects the message type.
            Message::Warning(ref w) => {
                log::debug!(
                    "received warning on {}: {}",
                    w.channel_id,
                    String::from_utf8_lossy(&w.data)
                );
                return Ok(msg);
            }
            Message::TxAbort(ref a) => {
                log::debug!(
                    "received tx_abort on {}: {}",
                    a.channel_id,
                    String::from_utf8_lossy(&a.data)
                );
                return Ok(msg);
            }
            other => return Ok(other),
        }
    })();

    // Ignore a restore failure so the receive's own result is surfaced.
    let _ = conn.set_read_timeout(previous);
    result
}

/// Receives and decodes the next message, requiring it to be an `M`.
///
/// # Errors
///
/// Returns [`ExecuteError::UnexpectedMessage`] if the received message is not
/// an `M`.
fn recv_bolt<M: FromMessage>(
    conn: &mut impl Connection,
    timeout: Duration,
) -> Result<M, ExecuteError> {
    let msg = recv_non_ping(conn, timeout)?;
    let got = msg.msg_type();
    M::from_message(msg).ok_or(ExecuteError::UnexpectedMessage {
        expected: M::TYPE,
        got,
    })
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
    let cr: ChannelReady = recv_bolt(conn, RECV_CHANNEL_READY_TIMEOUT)?;

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
/// transaction was mined only after we sent `funding_created`, we have not sent
/// a signature the peer is required to reject, and it has at least
/// `minimum_depth` confirmations (as specified in the received `accept_channel`).
fn is_channel_ready_expected(
    channel_states: &HashMap<ChannelId, ChannelState>,
    bitcoin_cli: &mut impl BitcoinRpc,
) -> bool {
    channel_states.values().any(|state| {
        state.commitment.commitment_number == 0
            && state.next_counterparty_per_commitment_point().is_none()
            && state.is_funding_outpoint_valid
            && !state.was_funding_mined_prematurely
            && !state.sent_invalid_signature
            && bitcoin_cli.get_transaction_confirmations(state.config.funding_outpoint.txid)
                >= state.config.minimum_depth
    })
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

/// Records that a `funding_signed` has been accepted for its channel.
///
/// # Panics
///
/// Panics if no matching channel exists. This should be unreachable, as
/// `FundingSignedOracle` reports such messages as a [`Violation`].
fn record_recv_funding_signed(
    channel_states: &mut HashMap<ChannelId, ChannelState>,
    funding_signed: &FundingSigned,
) {
    channel_states
        .get_mut(&funding_signed.channel_id)
        .expect("FundingSignedOracle guaranteed this channel_id exists")
        .funding_signed_received = true;
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
mod tests;
