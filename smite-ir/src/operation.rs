//! IR operations that load, compute, build or act.
//!
//! Each [`Operation`] falls into one of four categories:
//!
//! - `Load` - Produce a variable from an embedded literal or from the
//!   `ProgramContext`.
//! - `Compute` - Derive a new variable from existing ones.
//! - `Build` - Construct a BOLT message from input variables.
//! - `Act` - Perform a side effect against the target.

use std::fmt;
use std::fmt::Write;

use bitcoin::{opcodes::all as opcodes, script::Builder, script::PushBytes};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use smite::bolt::{FeatureBit, Features, ShortChannelId};

use super::VariableType;

/// An IR operation.  Each instruction in a program contains one operation plus
/// input variable indices.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    // -- Load: produce a variable from an embedded literal or the context --
    /// Load a satoshi or millisatoshi amount.
    LoadAmount(u64),
    /// Load a BOLT 7 `short_channel_id` in its packed `u64` form
    /// (`(block << 40) | (tx_index << 16) | output_index`).
    LoadShortChannelId(u64),
    /// Load a fee rate in sat/kw.
    LoadFeeratePerKw(u32),
    /// Load a block height or count.
    LoadBlockHeight(u32),
    /// Load a Unix timestamp in seconds.
    LoadTimestamp(u32),
    /// Load a BOLT 7 `channel_update` fee parameter (`fee_base_msat` in
    /// millisatoshi or `fee_proportional_millionths` in millionths).
    LoadForwardingFee(u32),
    /// Load a u16 protocol parameter (e.g., `to_self_delay`).
    LoadU16(u16),
    /// Load a u8 protocol parameter (e.g., `channel_flags`).
    LoadU8(u8),
    /// Load raw bytes.
    LoadBytes(Vec<u8>),
    /// Load feature bits.
    LoadFeatures(Vec<u8>),
    /// Load a secp256k1 private key.
    LoadPrivateKey([u8; 32]),
    /// Load a 32-byte channel identifier.
    LoadChannelId([u8; 32]),
    /// Load a BOLT 2 compliant `upfront_shutdown_script`.
    ///
    /// Produces a [`VariableType::Bytes`] value whose contents match one of the
    /// standard script templates required by BOLT 2.
    LoadShutdownScript(ShutdownScriptVariant),
    /// Load a valid `channel_type` feature vector.
    ///
    /// Produces a [`VariableType::Features`] value encoding one of a set of
    /// channel types known to be accepted by at least one target.
    LoadChannelType(ChannelTypeVariant),
    /// Load the target node's public key from the program context.
    LoadTargetPubkeyFromContext,
    /// Load the chain hash from the program context.
    LoadChainHashFromContext,

    // -- Compute: derive a variable from inputs --
    /// Derive a compressed public key from a private key. The executor
    /// validates that the bytes are in range `[1, curve_order)` and errors if
    /// not.
    /// Input: `PrivateKey`.
    DerivePoint,
    /// Extract a field from a parsed `accept_channel` response.
    /// Input: `AcceptChannel`.
    ExtractAcceptChannel(AcceptChannelField),
    /// Create a BOLT 3 funding transaction for the channel funding flow.
    ///
    /// Inputs (4):
    ///   0: `opener_funding_pubkey` (`Point`)
    ///   1: `acceptor_funding_pubkey` (`Point`)
    ///   2: `funding_satoshis` (`Amount`)
    ///   3: `feerate_per_kw` (`FeeratePerKw`)
    CreateFundingTransaction,

    // -- Build: construct a BOLT message from inputs --
    /// Build an `open_channel` message (BOLT 2, type 32).
    ///
    /// Inputs (20, matching wire order):
    ///   0: `chain_hash` (`ChainHash`)
    ///   1: `temporary_channel_id` (`ChannelId`)
    ///   2: `funding_satoshis` (`Amount`)
    ///   3: `push_msat` (`Amount`)
    ///   4: `dust_limit_satoshis` (`Amount`)
    ///   5: `max_htlc_value_in_flight_msat` (`Amount`)
    ///   6: `channel_reserve_satoshis` (`Amount`)
    ///   7: `htlc_minimum_msat` (`Amount`)
    ///   8: `feerate_per_kw` (`FeeratePerKw`)
    ///   9: `to_self_delay` (`U16`)
    ///  10: `max_accepted_htlcs` (`U16`)
    ///  11: `funding_pubkey` (`Point`)
    ///  12: `revocation_basepoint` (`Point`)
    ///  13: `payment_basepoint` (`Point`)
    ///  14: `delayed_payment_basepoint` (`Point`)
    ///  15: `htlc_basepoint` (`Point`)
    ///  16: `first_per_commitment_point` (`Point`)
    ///  17: `channel_flags` (`U8`)
    ///  18: `upfront_shutdown_script` (`Bytes`, empty = omit TLV)
    ///  19: `channel_type` (`Features`, empty = omit TLV)
    BuildOpenChannel,
    /// Build a `channel_announcement` message (BOLT 7, type 256).
    ///
    /// All four `PrivateKey` inputs are used to sign the body.
    ///
    /// Inputs (7):
    ///   0: `features`         (`Features`)
    ///   1: `chain_hash`       (`ChainHash`)
    ///   2: `short_channel_id` (`ShortChannelId`)
    ///   3: `node_sk_1`        (`PrivateKey`) -- derives `node_id_1`
    ///   4: `node_sk_2`        (`PrivateKey`) -- derives `node_id_2`
    ///   5: `bitcoin_sk_1`     (`PrivateKey`) -- derives `bitcoin_key_1`
    ///   6: `bitcoin_sk_2`     (`PrivateKey`) -- derives `bitcoin_key_2`
    BuildChannelAnnouncement,
    /// Build a `node_announcement` message (BOLT 7, type 257).
    ///
    /// `rgb_color` and `alias` are op-level params (not variable inputs) so the
    /// mutator can flip bits inside them but cannot change their lengths.
    ///
    /// Inputs (4):
    ///   0: `node_sk` (`PrivateKey`) -- derives `node_id` and signs the body
    ///   1: `features` (`Features`)
    ///   2: `timestamp` (`Timestamp`)
    ///   3: `addresses` (`Bytes`, raw network address descriptor bytes)
    BuildNodeAnnouncement {
        /// 3-byte RGB color for UI display.
        rgb_color: [u8; 3],
        /// 32-byte node alias, zero-padded.
        alias: [u8; 32],
    },
    /// Build a `channel_update` message (BOLT 7, type 258).
    ///
    /// The signature is computed internally over the double-SHA256 of the
    /// message body following the signature field, using the supplied node
    /// secret key (per BOLT 7).
    ///
    /// Inputs (11):
    ///   0: `node_sk` (`PrivateKey`) -- signs the body
    ///   1: `chain_hash` (`ChainHash`)
    ///   2: `short_channel_id` (`ShortChannelId`)
    ///   3: `timestamp` (`Timestamp`)
    ///   4: `message_flags` (`U8`)
    ///   5: `channel_flags` (`U8`)
    ///   6: `cltv_expiry_delta` (`U16`)
    ///   7: `htlc_minimum_msat` (`Amount`)
    ///   8: `fee_base_msat` (`ForwardingFee`)
    ///   9: `fee_proportional_millionths` (`ForwardingFee`)
    ///  10: `htlc_maximum_msat` (`Amount`)
    BuildChannelUpdate,
    /// Build an `announcement_signatures` message (BOLT 7, type 259).
    ///
    /// Signs the `channel_announcement` body with our node and bitcoin secret
    /// keys. The body is constructed with pubkeys sorted in the lexicographic
    /// order required by BOLT 7, using the target's public keys (inputs 5 and
    /// 7) directly — we do not need the target's secret keys.
    ///
    /// Inputs (8):
    ///   0: `channel_id`       (`ChannelId`)
    ///   1: `features`         (`Features`)
    ///   2: `chain_hash`       (`ChainHash`)
    ///   3: `short_channel_id` (`ShortChannelId`)
    ///   4: `node_sk_1`        (`PrivateKey`) -- our node signing key
    ///   5: `node_id_2`        (`Point`)      -- target's node public key
    ///   6: `bitcoin_sk_1`     (`PrivateKey`) -- our bitcoin signing key
    ///   7: `bitcoin_key_2`    (`Point`)      -- target's bitcoin public key
    BuildAnnouncementSignatures,

    // -- Act: side effects against the target --
    /// Send an encoded message over the connection.
    /// Input: `Message`.
    SendMessage,
    /// Send an `open_channel` message over the connection.
    /// Produces a `SentOpenChannel` variable.
    /// Input: `OpenChannelMessage`.
    SendOpenChannel,
    /// Build and send a `funding_created` message (BOLT 2, type 34).
    /// Produces a `SentFundingCreated` variable.
    ///
    /// Inputs (3):
    ///   0: `funding_transaction` (`FundingTransaction`)
    ///   1: `opener_funding_privkey` (`PrivateKey`)
    ///   2: `temporary_channel_id` (`ChannelId`)
    SendFundingCreated,
    /// Build and send a `channel_ready` message (BOLT 2, type 36).
    ///
    /// The alias TLV is optional in `channel_ready`. Since every `u64` is a
    /// valid `ShortChannelId`, presence is controlled by `include_alias`
    /// rather than a sentinel value. When `false`, the alias TLV is omitted
    /// and input 2 is ignored. The `ShortChannelId` is used directly by
    /// `channel_update`, so the alias type must match it in order to exercise
    /// both valid and invalid alias SCID cases.
    ///
    /// Inputs (3):
    ///   0: `channel_id` (`ChannelId`)
    ///   1: `second_per_commitment_point` (`Point`)
    ///   2: `short_channel_id` (`ShortChannelId`) -- the alias SCID
    SendChannelReady {
        /// Whether to include the alias `short_channel_id` TLV from input 2.
        /// If `false`, the TLV is omitted and input 2 is ignored.
        include_alias: bool,
    },
    /// Build and send a `shutdown` message (BOLT 2, type 38).
    /// Produces a `SentShutdown` variable.
    ///
    /// Inputs (2):
    ///   0: `channel_id`   (`ChannelId`)
    ///   1: `scriptpubkey` (`Bytes`)
    SendShutdown,
    /// Receive and parse an `accept_channel` response.
    /// Produces an `AcceptChannel` compound variable.
    RecvAcceptChannel,
    /// Receive and parse a `funding_signed` response.
    /// Produces the `ChannelId` carried in the message.
    /// TODO: Add `ExtractFundingSigned` when implementing force-close scenarios.
    RecvFundingSigned,
    /// Receive and parse a `channel_ready` response.
    ///
    /// This is a no-op unless some tracked channel is awaiting `channel_ready`
    /// (still at commitment number 0 with the counterparty's next per-commitment
    /// point unknown) and its funding transaction has enough confirmations for
    /// the target to have sent `channel_ready`.
    RecvChannelReady,
    /// Mines the given number of blocks on the Bitcoin network.
    MineBlocks(u8),
    /// Sign wallet inputs of the transaction and broadcast it via `bitcoin-cli`.
    /// Input: `FundingTransaction`.
    BroadcastTransaction,
    /// Look up the confirmed block position of a broadcast funding transaction
    /// and produce the corresponding BOLT 7 `short_channel_id`.
    ///
    /// This is the bridge between an on-chain funding output and the gossip
    /// layer: the resulting `ShortChannelId` can be fed into
    /// `BuildChannelAnnouncement`, `BuildChannelUpdate`, and
    /// `BuildAnnouncementSignatures` so that gossip messages reference a real
    /// UTXO and can pass the on-chain validation performed by CLN and LND.
    ///
    /// The typical program shape is:
    ///
    /// ```text
    /// ft   = CreateFundingTransaction(...)
    /// _    = BroadcastTransaction(ft)
    /// _    = MineBlocks(k)          // k >= 1 for the tx to be confirmed
    /// scid = LookupShortChannelId(ft)
    /// ```
    ///
    /// If the funding transaction is unknown to the node or still in the
    /// mempool (e.g. `MineBlocks` was dropped by a mutator), the sentinel
    /// `ShortChannelId::new(0, 0, 0)` is produced. This keeps downstream
    /// consumers well-typed without introducing a target- or program-side
    /// error: any resulting gossip message simply fails on-chain validation.
    ///
    /// Input: `FundingTransaction`.
    LookupShortChannelId,
}

/// A BOLT 2 compliant `upfront_shutdown_script` template.
///
/// Each variant encodes to a script matching one of the formats required by
/// BOLT 2 for the upfront shutdown TLV. `Empty` opts out of upfront shutdown
/// entirely and is accepted regardless of feature negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShutdownScriptVariant {
    /// Zero-length script. Opts out of upfront shutdown.
    Empty,
    /// `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
    P2pkh([u8; 20]),
    /// `OP_HASH160 <20-byte hash> OP_EQUAL`.
    P2sh([u8; 20]),
    /// `OP_0 <20-byte hash>`.
    P2wpkh([u8; 20]),
    /// `OP_0 <32-byte hash>`.
    P2wsh([u8; 32]),
    /// `OP_<version> <program>` for witness program versions 1..=16 with a
    /// 2..=40 byte program. Requires the counterparty to signal
    /// `option_shutdown_anysegwit`.
    AnySegwit {
        /// Witness program version, in `1..=16`.
        version: u8,
        /// Witness program bytes, length in `2..=40`.
        program: Vec<u8>,
    },
    /// `OP_RETURN <data>` where `data` is 6..=80 bytes. Requires the
    /// counterparty to signal `option_simple_close`.
    OpReturn(Vec<u8>),
}

impl ShutdownScriptVariant {
    /// Number of variants, used for uniform random sampling. Keep in sync with
    /// `random` and the enum definition.
    pub const VARIANT_COUNT: usize = 7;

    /// `AnySegwit` witness program version bounds (BOLT 2 / BIP 141).
    pub const ANYSEGWIT_MIN_VERSION: u8 = 1;
    pub const ANYSEGWIT_MAX_VERSION: u8 = 16;

    /// `AnySegwit` witness program length bounds (BOLT 2 / BIP 141).
    pub const ANYSEGWIT_MIN_PROGRAM_LEN: usize = 2;
    pub const ANYSEGWIT_MAX_PROGRAM_LEN: usize = 40;

    /// `OP_RETURN` payload length bounds (BOLT 2 `option_simple_close`).
    pub const OP_RETURN_MIN_DATA_LEN: usize = 6;
    pub const OP_RETURN_MAX_DATA_LEN: usize = 80;

    /// Generates a random variant with random embedded data. Variants are
    /// chosen uniformly. Embedded hashes / programs are filled with random
    /// bytes; lengths are drawn uniformly from the BOLT-permitted range for
    /// variable-length variants.
    pub fn random(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..Self::VARIANT_COUNT) {
            0 => Self::Empty,
            1 => Self::P2pkh(rng.random()),
            2 => Self::P2sh(rng.random()),
            3 => Self::P2wpkh(rng.random()),
            4 => Self::P2wsh(rng.random()),
            5 => {
                let version =
                    rng.random_range(Self::ANYSEGWIT_MIN_VERSION..=Self::ANYSEGWIT_MAX_VERSION);
                let len = rng.random_range(
                    Self::ANYSEGWIT_MIN_PROGRAM_LEN..=Self::ANYSEGWIT_MAX_PROGRAM_LEN,
                );
                let mut program = vec![0u8; len];
                rng.fill(&mut program[..]);
                Self::AnySegwit { version, program }
            }
            6 => {
                let len =
                    rng.random_range(Self::OP_RETURN_MIN_DATA_LEN..=Self::OP_RETURN_MAX_DATA_LEN);
                let mut data = vec![0u8; len];
                rng.fill(&mut data[..]);
                Self::OpReturn(data)
            }
            _ => unreachable!("ShutdownScriptVariant::random doesn't generate all variants"),
        }
    }

    /// Encodes the variant as raw scriptpubkey bytes.
    ///
    /// # Panics
    ///
    /// Panics if `AnySegwit.version` is outside
    /// `ANYSEGWIT_MIN_VERSION..=ANYSEGWIT_MAX_VERSION`, if the program is
    /// outside `ANYSEGWIT_MIN_PROGRAM_LEN..=ANYSEGWIT_MAX_PROGRAM_LEN` bytes,
    /// or if `OpReturn` data is outside
    /// `OP_RETURN_MIN_DATA_LEN..=OP_RETURN_MAX_DATA_LEN` bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::P2pkh(h) => Builder::new()
                .push_opcode(opcodes::OP_DUP)
                .push_opcode(opcodes::OP_HASH160)
                .push_slice(h)
                .push_opcode(opcodes::OP_EQUALVERIFY)
                .push_opcode(opcodes::OP_CHECKSIG)
                .into_bytes(),
            Self::P2sh(h) => Builder::new()
                .push_opcode(opcodes::OP_HASH160)
                .push_slice(h)
                .push_opcode(opcodes::OP_EQUAL)
                .into_bytes(),
            Self::P2wpkh(h) => Builder::new().push_int(0).push_slice(h).into_bytes(),
            Self::P2wsh(h) => Builder::new().push_int(0).push_slice(h).into_bytes(),
            Self::AnySegwit { version, program } => {
                assert!(
                    (Self::ANYSEGWIT_MIN_VERSION..=Self::ANYSEGWIT_MAX_VERSION).contains(version),
                    "AnySegwit version {version} out of range",
                );
                assert!(
                    (Self::ANYSEGWIT_MIN_PROGRAM_LEN..=Self::ANYSEGWIT_MAX_PROGRAM_LEN)
                        .contains(&program.len()),
                    "AnySegwit program length {} out of range",
                    program.len(),
                );
                Builder::new()
                    .push_int(i64::from(*version))
                    .push_slice(
                        <&PushBytes>::try_from(program.as_slice())
                            .expect("AnySegwit program length checked above"),
                    )
                    .into_bytes()
            }
            Self::OpReturn(data) => {
                assert!(
                    (Self::OP_RETURN_MIN_DATA_LEN..=Self::OP_RETURN_MAX_DATA_LEN)
                        .contains(&data.len()),
                    "OpReturn data length {} out of range",
                    data.len(),
                );
                Builder::new()
                    .push_opcode(opcodes::OP_RETURN)
                    .push_slice(
                        <&PushBytes>::try_from(data.as_slice())
                            .expect("OpReturn data length checked above"),
                    )
                    .into_bytes()
            }
        }
    }
}

impl fmt::Display for ShutdownScriptVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::P2pkh(h) => write!(f, "P2pkh({})", format_hex(h)),
            Self::P2sh(h) => write!(f, "P2sh({})", format_hex(h)),
            Self::P2wpkh(h) => write!(f, "P2wpkh({})", format_hex(h)),
            Self::P2wsh(h) => write!(f, "P2wsh({})", format_hex(h)),
            Self::AnySegwit { version, program } => {
                write!(f, "AnySegwit(v{version}, {})", format_hex(program))
            }
            Self::OpReturn(data) => write!(f, "OpReturn({})", format_hex(data)),
        }
    }
}

/// A specific BOLT 2 `channel_type` feature-bit combination.
///
/// Each variant corresponds to a channel type accepted by at least one target
/// implementation:
///
/// - `option_static_remotekey` (bit 12)
/// - `option_anchors` (bits 22 and 12)
/// - `zero_fee_commitments` (bit 40)
/// - `option_simple_taproot` (bit 80)
/// - `option_simple_taproot_staging` (bit 180)
/// - `option_script_enforced_lease` (bits 2022, 22, 12)
///
/// Additionally, the following bits can be added to any channel type:
/// - `option_scid_alias` (bit 46)
/// - `option_zeroconf` (bit 50)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelTypeVariant {
    /// bit 12
    StaticRemoteKey,
    /// bits 12, 46
    StaticRemoteKeyScidAlias,
    /// bits 12, 50
    StaticRemoteKeyZeroConf,
    /// bits 12, 46, 50
    StaticRemoteKeyScidAliasZeroConf,
    /// bits 12, 22
    Anchors,
    /// bits 12, 22, 46
    AnchorsScidAlias,
    /// bits 12, 22, 50
    AnchorsZeroConf,
    /// bits 12, 22, 46, 50
    AnchorsScidAliasZeroConf,
    /// bit 40
    ZeroFeeCommitments,
    /// bits 40, 46
    ZeroFeeCommitmentsScidAlias,
    /// bits 40, 50
    ZeroFeeCommitmentsZeroConf,
    /// bits 40, 46, 50
    ZeroFeeCommitmentsScidAliasZeroConf,
    /// bit 80
    SimpleTaproot,
    /// bits 80, 46
    SimpleTaprootScidAlias,
    /// bits 80, 50
    SimpleTaprootZeroConf,
    /// bits 80, 46, 50
    SimpleTaprootScidAliasZeroConf,
    /// bit 180
    SimpleTaprootStaging,
    /// bits 180, 46
    SimpleTaprootStagingScidAlias,
    /// bits 180, 50
    SimpleTaprootStagingZeroConf,
    /// bits 180, 46, 50
    SimpleTaprootStagingScidAliasZeroConf,
    /// bits 12, 22, 2022
    ScriptEnforcedLease,
    /// bits 12, 22, 2022, 46
    ScriptEnforcedLeaseScidAlias,
    /// bits 12, 22, 2022, 50
    ScriptEnforcedLeaseZeroConf,
    /// bits 12, 22, 2022, 46, 50
    ScriptEnforcedLeaseScidAliasZeroConf,
}

impl ChannelTypeVariant {
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::StaticRemoteKey,
        Self::StaticRemoteKeyScidAlias,
        Self::StaticRemoteKeyZeroConf,
        Self::StaticRemoteKeyScidAliasZeroConf,
        Self::Anchors,
        Self::AnchorsScidAlias,
        Self::AnchorsZeroConf,
        Self::AnchorsScidAliasZeroConf,
        Self::ZeroFeeCommitments,
        Self::ZeroFeeCommitmentsScidAlias,
        Self::ZeroFeeCommitmentsZeroConf,
        Self::ZeroFeeCommitmentsScidAliasZeroConf,
        Self::SimpleTaproot,
        Self::SimpleTaprootScidAlias,
        Self::SimpleTaprootZeroConf,
        Self::SimpleTaprootScidAliasZeroConf,
        Self::SimpleTaprootStaging,
        Self::SimpleTaprootStagingScidAlias,
        Self::SimpleTaprootStagingZeroConf,
        Self::SimpleTaprootStagingScidAliasZeroConf,
        Self::ScriptEnforcedLease,
        Self::ScriptEnforcedLeaseScidAlias,
        Self::ScriptEnforcedLeaseZeroConf,
        Self::ScriptEnforcedLeaseScidAliasZeroConf,
    ];

    /// The feature bits (even/required) contained in this channel type.
    #[must_use]
    pub fn bits(self) -> &'static [FeatureBit] {
        use Features as F;
        match self {
            Self::StaticRemoteKey => &[F::OPTION_STATIC_REMOTEKEY],
            Self::StaticRemoteKeyScidAlias => &[F::OPTION_STATIC_REMOTEKEY, F::OPTION_SCID_ALIAS],
            Self::StaticRemoteKeyZeroConf => &[F::OPTION_STATIC_REMOTEKEY, F::OPTION_ZEROCONF],
            Self::StaticRemoteKeyScidAliasZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::Anchors => &[F::OPTION_STATIC_REMOTEKEY, F::OPTION_ANCHORS],
            Self::AnchorsScidAlias => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCID_ALIAS,
            ],
            Self::AnchorsZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_ZEROCONF,
            ],
            Self::AnchorsScidAliasZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::ZeroFeeCommitments => &[F::ZERO_FEE_COMMITMENTS],
            Self::ZeroFeeCommitmentsScidAlias => &[F::ZERO_FEE_COMMITMENTS, F::OPTION_SCID_ALIAS],
            Self::ZeroFeeCommitmentsZeroConf => &[F::ZERO_FEE_COMMITMENTS, F::OPTION_ZEROCONF],
            Self::ZeroFeeCommitmentsScidAliasZeroConf => &[
                F::ZERO_FEE_COMMITMENTS,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::SimpleTaproot => &[F::OPTION_SIMPLE_TAPROOT],
            Self::SimpleTaprootScidAlias => &[F::OPTION_SIMPLE_TAPROOT, F::OPTION_SCID_ALIAS],
            Self::SimpleTaprootZeroConf => &[F::OPTION_SIMPLE_TAPROOT, F::OPTION_ZEROCONF],
            Self::SimpleTaprootScidAliasZeroConf => &[
                F::OPTION_SIMPLE_TAPROOT,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::SimpleTaprootStaging => &[F::OPTION_SIMPLE_TAPROOT_STAGING],
            Self::SimpleTaprootStagingScidAlias => {
                &[F::OPTION_SIMPLE_TAPROOT_STAGING, F::OPTION_SCID_ALIAS]
            }
            Self::SimpleTaprootStagingZeroConf => {
                &[F::OPTION_SIMPLE_TAPROOT_STAGING, F::OPTION_ZEROCONF]
            }
            Self::SimpleTaprootStagingScidAliasZeroConf => &[
                F::OPTION_SIMPLE_TAPROOT_STAGING,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::ScriptEnforcedLease => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
            ],
            Self::ScriptEnforcedLeaseScidAlias => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
                F::OPTION_SCID_ALIAS,
            ],
            Self::ScriptEnforcedLeaseZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
                F::OPTION_ZEROCONF,
            ],
            Self::ScriptEnforcedLeaseScidAliasZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
        }
    }

    /// Encodes the channel type as a BOLT feature bitmap (big-endian bytes).
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        Features::from_bits(self.bits()).into_bytes()
    }
}

impl fmt::Display for ChannelTypeVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Fields that can be extracted from an `AcceptChannel` compound variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcceptChannelField {
    TemporaryChannelId,
    DustLimitSatoshis,
    MaxHtlcValueInFlightMsat,
    ChannelReserveSatoshis,
    HtlcMinimumMsat,
    MinimumDepth,
    ToSelfDelay,
    MaxAcceptedHtlcs,
    FundingPubkey,
    RevocationBasepoint,
    PaymentBasepoint,
    DelayedPaymentBasepoint,
    HtlcBasepoint,
    FirstPerCommitmentPoint,
    UpfrontShutdownScript,
    ChannelType,
}

impl fmt::Display for AcceptChannelField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl AcceptChannelField {
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::TemporaryChannelId,
        Self::DustLimitSatoshis,
        Self::MaxHtlcValueInFlightMsat,
        Self::ChannelReserveSatoshis,
        Self::HtlcMinimumMsat,
        Self::MinimumDepth,
        Self::ToSelfDelay,
        Self::MaxAcceptedHtlcs,
        Self::FundingPubkey,
        Self::RevocationBasepoint,
        Self::PaymentBasepoint,
        Self::DelayedPaymentBasepoint,
        Self::HtlcBasepoint,
        Self::FirstPerCommitmentPoint,
        Self::UpfrontShutdownScript,
        Self::ChannelType,
    ];

    /// Returns the variable type produced by extracting this field.
    #[must_use]
    pub fn output_type(self) -> VariableType {
        match self {
            Self::TemporaryChannelId => VariableType::ChannelId,
            Self::DustLimitSatoshis
            | Self::MaxHtlcValueInFlightMsat
            | Self::ChannelReserveSatoshis
            | Self::HtlcMinimumMsat => VariableType::Amount,
            Self::MinimumDepth => VariableType::BlockHeight,
            Self::ToSelfDelay | Self::MaxAcceptedHtlcs => VariableType::U16,
            Self::FundingPubkey
            | Self::RevocationBasepoint
            | Self::PaymentBasepoint
            | Self::DelayedPaymentBasepoint
            | Self::HtlcBasepoint
            | Self::FirstPerCommitmentPoint => VariableType::Point,
            Self::UpfrontShutdownScript => VariableType::Bytes,
            Self::ChannelType => VariableType::Features,
        }
    }
}

/// Format a byte slice as a hex string. Returns an empty string for empty
/// input.
fn format_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        write!(s, "{b:02x}").expect("write to string");
    }
    s
}

/// Print an Operation. Operations that take no variable inputs include parens
/// (e.g., `LoadAmount(100000)`, `LoadChainHashFromContext()`). Operations that do take
/// inputs omit parens so `Program::Display` can append them `(v0, v1, ...)`.
impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadAmount(v) => write!(f, "LoadAmount({v})"),
            Self::LoadShortChannelId(v) => {
                write!(f, "LoadShortChannelId({})", ShortChannelId::from_u64(*v))
            }
            Self::LoadFeeratePerKw(v) => write!(f, "LoadFeeratePerKw({v})"),
            Self::LoadBlockHeight(v) => write!(f, "LoadBlockHeight({v})"),
            Self::LoadTimestamp(v) => write!(f, "LoadTimestamp({v})"),
            Self::LoadForwardingFee(v) => write!(f, "LoadForwardingFee({v})"),
            Self::LoadU16(v) => write!(f, "LoadU16({v})"),
            Self::LoadU8(v) => write!(f, "LoadU8({v})"),
            Self::LoadBytes(b) => write!(f, "LoadBytes({})", format_hex(b)),
            Self::LoadFeatures(b) => write!(f, "LoadFeatures({})", format_hex(b)),
            Self::LoadPrivateKey(b) => write!(f, "LoadPrivateKey({})", format_hex(b)),
            Self::LoadChannelId(b) => write!(f, "LoadChannelId({})", format_hex(b)),
            Self::LoadShutdownScript(v) => write!(f, "LoadShutdownScript({v})"),
            Self::LoadChannelType(v) => write!(f, "LoadChannelType({v})"),
            Self::LoadTargetPubkeyFromContext => write!(f, "LoadTargetPubkeyFromContext()"),
            Self::LoadChainHashFromContext => write!(f, "LoadChainHashFromContext()"),
            Self::MineBlocks(v) => write!(f, "MineBlocks({v})"),
            // Operations with inputs: parens added by Program::Display.
            Self::DerivePoint => write!(f, "DerivePoint"),
            Self::ExtractAcceptChannel(field) => write!(f, "Extract{field}"),
            Self::CreateFundingTransaction => write!(f, "CreateFundingTransaction"),
            Self::BuildOpenChannel => write!(f, "BuildOpenChannel"),
            Self::BuildChannelAnnouncement => write!(f, "BuildChannelAnnouncement"),
            Self::BuildNodeAnnouncement { rgb_color, alias } => write!(
                f,
                "BuildNodeAnnouncement{{rgb={}, alias={}}}",
                format_hex(rgb_color),
                format_hex(alias),
            ),
            Self::BuildChannelUpdate => write!(f, "BuildChannelUpdate"),
            Self::BuildAnnouncementSignatures => write!(f, "BuildAnnouncementSignatures"),
            Self::SendMessage => write!(f, "SendMessage"),
            Self::SendOpenChannel => write!(f, "SendOpenChannel"),
            Self::SendFundingCreated => write!(f, "SendFundingCreated"),
            Self::SendChannelReady { include_alias } => {
                write!(f, "SendChannelReady{{include_alias={include_alias}}}")
            }
            Self::SendShutdown => write!(f, "SendShutdown"),
            Self::RecvAcceptChannel => write!(f, "RecvAcceptChannel"),
            Self::RecvFundingSigned => write!(f, "RecvFundingSigned"),
            Self::RecvChannelReady => write!(f, "RecvChannelReady()"),
            Self::BroadcastTransaction => write!(f, "BroadcastTransaction"),
            Self::LookupShortChannelId => write!(f, "LookupShortChannelId"),
        }
    }
}

impl Operation {
    /// Returns the variable type produced by this operation, or `None` for void
    /// operations (e.g., `SendMessage`).
    #[must_use]
    pub fn output_type(&self) -> Option<VariableType> {
        match self {
            Self::LoadAmount(_) => Some(VariableType::Amount),
            Self::LoadShortChannelId(_) | Self::LookupShortChannelId => {
                Some(VariableType::ShortChannelId)
            }
            Self::LoadFeeratePerKw(_) => Some(VariableType::FeeratePerKw),
            Self::LoadBlockHeight(_) => Some(VariableType::BlockHeight),
            Self::LoadTimestamp(_) => Some(VariableType::Timestamp),
            Self::LoadForwardingFee(_) => Some(VariableType::ForwardingFee),
            Self::LoadU16(_) => Some(VariableType::U16),
            Self::LoadU8(_) => Some(VariableType::U8),
            Self::LoadBytes(_) | Self::LoadShutdownScript(_) => Some(VariableType::Bytes),
            Self::LoadFeatures(_) | Self::LoadChannelType(_) => Some(VariableType::Features),
            Self::LoadPrivateKey(_) => Some(VariableType::PrivateKey),
            Self::LoadChannelId(_) | Self::RecvFundingSigned => Some(VariableType::ChannelId),
            Self::LoadTargetPubkeyFromContext | Self::DerivePoint => Some(VariableType::Point),
            Self::LoadChainHashFromContext => Some(VariableType::ChainHash),
            Self::ExtractAcceptChannel(field) => Some(field.output_type()),
            Self::CreateFundingTransaction => Some(VariableType::FundingTransaction),
            Self::BuildOpenChannel => Some(VariableType::OpenChannelMessage),
            Self::BuildChannelAnnouncement
            | Self::BuildNodeAnnouncement { .. }
            | Self::BuildChannelUpdate
            | Self::BuildAnnouncementSignatures => Some(VariableType::Message),
            Self::SendMessage
            | Self::SendChannelReady { .. }
            | Self::RecvChannelReady
            | Self::MineBlocks(_)
            | Self::BroadcastTransaction => None,
            Self::SendOpenChannel => Some(VariableType::SentOpenChannel),
            Self::SendFundingCreated => Some(VariableType::SentFundingCreated),
            Self::SendShutdown => Some(VariableType::SentShutdown),
            Self::RecvAcceptChannel => Some(VariableType::AcceptChannel),
        }
    }

    /// Returns the expected variable types for each input position.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn input_types(&self) -> Vec<VariableType> {
        match self {
            Self::LoadAmount(_)
            | Self::LoadShortChannelId(_)
            | Self::LoadFeeratePerKw(_)
            | Self::LoadBlockHeight(_)
            | Self::LoadTimestamp(_)
            | Self::LoadForwardingFee(_)
            | Self::LoadU16(_)
            | Self::LoadU8(_)
            | Self::LoadBytes(_)
            | Self::LoadFeatures(_)
            | Self::LoadPrivateKey(_)
            | Self::LoadChannelId(_)
            | Self::LoadShutdownScript(_)
            | Self::LoadChannelType(_)
            | Self::LoadTargetPubkeyFromContext
            | Self::LoadChainHashFromContext
            | Self::RecvChannelReady
            | Self::MineBlocks(_) => vec![],

            Self::DerivePoint => vec![VariableType::PrivateKey],
            Self::ExtractAcceptChannel(_) => vec![VariableType::AcceptChannel],
            Self::CreateFundingTransaction => vec![
                VariableType::Point,        // opener_funding_pubkey
                VariableType::Point,        // acceptor_funding_pubkey
                VariableType::Amount,       // funding_satoshis
                VariableType::FeeratePerKw, // feerate_per_kw
            ],
            Self::SendMessage => vec![VariableType::Message],
            Self::SendOpenChannel => vec![VariableType::OpenChannelMessage],
            Self::SendFundingCreated => vec![
                VariableType::FundingTransaction, // funding_transaction
                VariableType::PrivateKey,         // opener_funding_privkey
                VariableType::ChannelId,          // temporary_channel_id
            ],
            Self::SendChannelReady { .. } => vec![
                VariableType::ChannelId,      // channel_id
                VariableType::Point,          // second_per_commitment_point
                VariableType::ShortChannelId, // short_channel_id (alias)
            ],
            Self::SendShutdown => vec![
                VariableType::ChannelId, // channel_id
                VariableType::Bytes,     // scriptpubkey
            ],
            Self::RecvAcceptChannel => vec![VariableType::SentOpenChannel],
            Self::RecvFundingSigned => vec![VariableType::SentFundingCreated],
            Self::BroadcastTransaction | Self::LookupShortChannelId => {
                vec![VariableType::FundingTransaction]
            }

            Self::BuildOpenChannel => vec![
                VariableType::ChainHash,    // chain_hash
                VariableType::ChannelId,    // temporary_channel_id
                VariableType::Amount,       // funding_satoshis
                VariableType::Amount,       // push_msat
                VariableType::Amount,       // dust_limit_satoshis
                VariableType::Amount,       // max_htlc_value_in_flight_msat
                VariableType::Amount,       // channel_reserve_satoshis
                VariableType::Amount,       // htlc_minimum_msat
                VariableType::FeeratePerKw, // feerate_per_kw
                VariableType::U16,          // to_self_delay
                VariableType::U16,          // max_accepted_htlcs
                VariableType::Point,        // funding_pubkey
                VariableType::Point,        // revocation_basepoint
                VariableType::Point,        // payment_basepoint
                VariableType::Point,        // delayed_payment_basepoint
                VariableType::Point,        // htlc_basepoint
                VariableType::Point,        // first_per_commitment_point
                VariableType::U8,           // channel_flags
                VariableType::Bytes,        // upfront_shutdown_script
                VariableType::Features,     // channel_type
            ],

            Self::BuildChannelAnnouncement => vec![
                VariableType::Features,       // features
                VariableType::ChainHash,      // chain_hash
                VariableType::ShortChannelId, // short_channel_id
                VariableType::PrivateKey,     // node_sk_1
                VariableType::PrivateKey,     // node_sk_2
                VariableType::PrivateKey,     // bitcoin_sk_1
                VariableType::PrivateKey,     // bitcoin_sk_2
            ],

            Self::BuildNodeAnnouncement { .. } => vec![
                VariableType::PrivateKey, // node_sk
                VariableType::Features,   // features
                VariableType::Timestamp,  // timestamp
                VariableType::Bytes,      // addresses
            ],

            Self::BuildChannelUpdate => vec![
                VariableType::PrivateKey,     // node_sk
                VariableType::ChainHash,      // chain_hash
                VariableType::ShortChannelId, // short_channel_id
                VariableType::Timestamp,      // timestamp
                VariableType::U8,             // message_flags
                VariableType::U8,             // channel_flags
                VariableType::U16,            // cltv_expiry_delta
                VariableType::Amount,         // htlc_minimum_msat
                VariableType::ForwardingFee,  // fee_base_msat
                VariableType::ForwardingFee,  // fee_proportional_millionths
                VariableType::Amount,         // htlc_maximum_msat
            ],

            Self::BuildAnnouncementSignatures => vec![
                VariableType::ChannelId,      // channel_id
                VariableType::Features,       // features
                VariableType::ChainHash,      // chain_hash
                VariableType::ShortChannelId, // short_channel_id
                VariableType::PrivateKey,     // node_sk_1 (our node signing key)
                VariableType::Point,          // node_id_2 (target's node public key)
                VariableType::PrivateKey,     // bitcoin_sk_1 (our bitcoin signing key)
                VariableType::Point,          // bitcoin_key_2 (target's bitcoin public key)
            ],
        }
    }

    /// Returns extraction operations for compound variable types.
    ///
    /// For example, `RecvAcceptChannel` produces an `AcceptChannel` compound
    /// variable, so this returns `ExtractAcceptChannel` operations for each
    /// field.  Non-compound operations return an empty vec.
    #[must_use]
    pub fn extractable_fields(&self) -> Vec<(Operation, VariableType)> {
        match self {
            Self::LoadAmount(_)
            | Self::LoadShortChannelId(_)
            | Self::LoadFeeratePerKw(_)
            | Self::LoadBlockHeight(_)
            | Self::LoadTimestamp(_)
            | Self::LoadForwardingFee(_)
            | Self::LoadU16(_)
            | Self::LoadU8(_)
            | Self::LoadBytes(_)
            | Self::LoadFeatures(_)
            | Self::LoadPrivateKey(_)
            | Self::LoadChannelId(_)
            | Self::LoadShutdownScript(_)
            | Self::LoadChannelType(_)
            | Self::LoadTargetPubkeyFromContext
            | Self::LoadChainHashFromContext
            | Self::DerivePoint
            | Self::ExtractAcceptChannel(_)
            | Self::CreateFundingTransaction
            | Self::BuildOpenChannel
            | Self::BuildChannelAnnouncement
            | Self::BuildNodeAnnouncement { .. }
            | Self::BuildChannelUpdate
            | Self::BuildAnnouncementSignatures
            | Self::SendMessage
            | Self::SendOpenChannel
            | Self::SendFundingCreated
            | Self::SendChannelReady { .. }
            | Self::SendShutdown
            | Self::RecvFundingSigned
            | Self::RecvChannelReady
            | Self::MineBlocks(_)
            | Self::BroadcastTransaction
            | Self::LookupShortChannelId => vec![],

            Self::RecvAcceptChannel => AcceptChannelField::ALL
                .iter()
                .map(|&f| (Self::ExtractAcceptChannel(f), f.output_type()))
                .collect(),
        }
    }

    /// Returns `true` if this operation has I/O side effects and therefore
    /// cannot be dropped by DCE or deduplicated by CSE.
    #[must_use]
    pub fn has_side_effects(&self) -> bool {
        match self {
            Self::SendMessage
            | Self::SendOpenChannel
            | Self::SendFundingCreated
            | Self::SendChannelReady { .. }
            | Self::SendShutdown
            | Self::RecvAcceptChannel
            | Self::RecvFundingSigned
            | Self::RecvChannelReady
            | Self::MineBlocks(_)
            | Self::CreateFundingTransaction
            | Self::BroadcastTransaction
            | Self::LookupShortChannelId => true,
            Self::LoadAmount(_)
            | Self::LoadShortChannelId(_)
            | Self::BuildChannelAnnouncement
            | Self::LoadFeeratePerKw(_)
            | Self::LoadForwardingFee(_)
            | Self::LoadBlockHeight(_)
            | Self::LoadTimestamp(_)
            | Self::LoadU16(_)
            | Self::LoadU8(_)
            | Self::LoadBytes(_)
            | Self::LoadFeatures(_)
            | Self::LoadPrivateKey(_)
            | Self::LoadChannelId(_)
            | Self::LoadShutdownScript(_)
            | Self::LoadChannelType(_)
            | Self::LoadTargetPubkeyFromContext
            | Self::LoadChainHashFromContext
            | Self::DerivePoint
            | Self::ExtractAcceptChannel(_)
            | Self::BuildOpenChannel
            | Self::BuildNodeAnnouncement { .. }
            | Self::BuildChannelUpdate
            | Self::BuildAnnouncementSignatures => false,
        }
    }

    /// Returns true if this operation has parameters that can be mutated
    /// by `OperationParamMutator`.
    #[must_use]
    pub fn is_param_mutable(&self) -> bool {
        match self {
            Self::LoadAmount(_)
            | Self::LoadShortChannelId(_)
            | Self::LoadFeeratePerKw(_)
            | Self::LoadBlockHeight(_)
            | Self::LoadTimestamp(_)
            | Self::LoadForwardingFee(_)
            | Self::LoadU16(_)
            | Self::LoadU8(_)
            | Self::LoadBytes(_)
            | Self::LoadFeatures(_)
            | Self::LoadPrivateKey(_)
            | Self::LoadChannelId(_)
            | Self::LoadShutdownScript(_)
            | Self::LoadChannelType(_)
            | Self::ExtractAcceptChannel(_)
            | Self::BuildNodeAnnouncement { .. }
            | Self::SendChannelReady { .. }
            | Self::MineBlocks(_) => true,

            Self::LoadTargetPubkeyFromContext
            | Self::LoadChainHashFromContext
            | Self::DerivePoint
            | Self::CreateFundingTransaction
            | Self::BuildOpenChannel
            | Self::BuildChannelAnnouncement
            | Self::BuildChannelUpdate
            | Self::BuildAnnouncementSignatures
            | Self::SendMessage
            | Self::SendOpenChannel
            | Self::SendFundingCreated
            | Self::SendShutdown
            | Self::RecvAcceptChannel
            | Self::RecvFundingSigned
            | Self::RecvChannelReady
            | Self::BroadcastTransaction
            | Self::LookupShortChannelId => false,
        }
    }
}
