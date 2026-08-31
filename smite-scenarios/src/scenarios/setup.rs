//! Snapshot setup: procedural pre-snapshot state preparation for IR fuzzing.

use std::time::Duration;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bolt::{
    ChannelId, Error as ErrorMessage, Init, InitTlvs, Message, OpenChannel, OpenChannelTlvs,
};
use smite::noise::NoiseConnection;
use smite::scenarios::ScenarioError;
use smite_ir::operation::ChannelTypeVariant;

use super::{handshake_with_target, ping_pong};
use crate::executor::ProgramContext;
use crate::targets::{EclairTarget, INITIAL_BLOCKS, Target};

/// Bitcoin regtest genesis hash (in BOLT 2 network byte order).
pub const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

const TIMEOUT: Duration = Duration::from_secs(5);

/// Pre-snapshot setup that establishes a ready-to-use connection and produces
/// the [`ProgramContext`] an IR program will read at execution time. Called
/// once from `IrScenario::new()` before the Nyx snapshot is taken.
pub trait SnapshotSetup<T: Target> {
    /// Execute the setup and return the connection and context.
    ///
    /// # Errors
    ///
    /// Setup-specific; propagated to the scenario's `new()`.
    fn setup(target: &T) -> Result<(NoiseConnection, ProgramContext), ScenarioError>;
}

/// Clears a feature bit from a feature vector.
///
/// Feature vectors are encoded as big-endian byte arrays where bit N lives in
/// byte `features[len - 1 - N/8]` at position `N % 8`.
fn clear_feature_bit(features: &mut [u8], bit: usize) {
    let byte_index = features.len().checked_sub(1 + bit / 8);
    if let Some(i) = byte_index {
        features[i] &= !(1 << (bit % 8));
    }
}

/// Gossip-related feature bits (BOLT 9): `gossip_queries` (6/7),
/// `gossip_queries_ex` (10/11). Stripped so the target doesn't send
/// `gossip_timestamp_filter` or other gossip noise during execution.
const GOSSIP_FEATURE_BITS: &[usize] = &[6, 7, 10, 11];

/// Feature bits that force a dual-funded flow when both peers support them:
/// `option_dual_fund` (28/29). Eclair in particular will not allow
/// single-funded flows if either of these feature bits is set, so we strip them
/// when fuzzing the single-funded flow.
const DUAL_FUNDING_FEATURE_BITS: &[usize] = &[28, 29];

/// Peer storage feature bits: `option_provide_storage` (42/43). When enabled,
/// peers may send `peer_storage` and `peer_storage_retrieval` messages at
/// arbitrary times. Disabling these bits eliminates peer storage noise.
const PEER_STORAGE_FEATURE_BITS: &[usize] = &[42, 43];

/// Creates an `init` that echoes the received features with bits stripped that
/// would steer the target away from the single-funded `open_channel` flow.
fn init_for_single_funded(received: &Init) -> Init {
    let mut globalfeatures = received.globalfeatures.clone();
    let mut features = received.features.clone();
    for &bit in GOSSIP_FEATURE_BITS
        .iter()
        .chain(DUAL_FUNDING_FEATURE_BITS)
        .chain(PEER_STORAGE_FEATURE_BITS)
    {
        clear_feature_bit(&mut globalfeatures, bit);
        clear_feature_bit(&mut features, bit);
    }
    Init {
        globalfeatures,
        features,
        tlvs: InitTlvs::default(),
    }
}

/// Fixed feerate (sat/kW) for warmup `open_channel` messages. 2500 sat/kW
/// (~10 sat/vB) is comfortably inside every target's accepted range.
const WARMUP_FEERATE_PER_KW: u32 = 2500;

/// Fixed funding amount (sat) for warmup `open_channel` messages.
const WARMUP_FUNDING_SATOSHIS: u64 = 100_000;

/// Derives the six public keys an `open_channel` requires from fixed secrets.
fn warmup_channel_keys() -> [PublicKey; 6] {
    let secp = Secp256k1::new();
    let secrets: [[u8; 32]; 6] = [
        [0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32], [0x25; 32], [0x26; 32],
    ];
    secrets.map(|s| {
        let sk = SecretKey::from_slice(&s).expect("valid warmup secret");
        PublicKey::from_secret_key(&secp, &sk)
    })
}

/// Builds a spec-valid single-funded `open_channel` for warmup traffic.
///
/// The parameters are fixed and known-good; only `temporary_channel_id` changes
/// per iteration.
fn warmup_open_channel(temporary_channel_id: ChannelId, keys: &[PublicKey; 6]) -> OpenChannel {
    OpenChannel {
        chain_hash: REGTEST_CHAIN_HASH,
        temporary_channel_id,
        funding_satoshis: WARMUP_FUNDING_SATOSHIS,
        push_msat: 0,
        dust_limit_satoshis: 546,
        max_htlc_value_in_flight_msat: WARMUP_FUNDING_SATOSHIS * 1000,
        channel_reserve_satoshis: 1000,
        htlc_minimum_msat: 1,
        feerate_per_kw: WARMUP_FEERATE_PER_KW,
        to_self_delay: 144,
        max_accepted_htlcs: 483,
        funding_pubkey: keys[0],
        revocation_basepoint: keys[1],
        payment_basepoint: keys[2],
        delayed_payment_basepoint: keys[3],
        htlc_basepoint: keys[4],
        first_per_commitment_point: keys[5],
        channel_flags: 0x00,
        tlvs: OpenChannelTlvs {
            // Always send the TLV: a zero-length value is the BOLT 2 opt-out
            // signal when option_upfront_shutdown_script is negotiated (which
            // Eclair advertises and we echo). Omitting it is a protocol
            // violation that makes Eclair drop the connection.
            upfront_shutdown_script: Some(Vec::new()),
            channel_type: Some(ChannelTypeVariant::Anchors.encode()),
        },
    }
}

/// Derives a distinct, non-zero `temporary_channel_id` for warmup open `seed`.
///
/// Each open needs a distinct id or Eclair rejects the duplicate. The `0x01`
/// fill keeps it non-zero: BOLT 1 reserves the all-zero channel id for "fail
/// all channels", which would make our per-channel abort drop the connection.
fn warmup_temp_channel_id(seed: u64) -> ChannelId {
    let mut bytes = [0x01u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    ChannelId::new(bytes)
}

/// Establishes a Noise connection and completes the `init` exchange for the
/// single-funded `open_channel` flow, returning a connection ready to carry
/// channel messages along with the target's `Init`.
fn establish_connection<T: Target>(target: &T) -> Result<(NoiseConnection, Init), ScenarioError> {
    let (mut conn, target_init) = handshake_with_target(target, TIMEOUT)?;

    // Echo features but strip the bits that would take us off the single-funded
    // `open_channel` path this setup is built for.
    let our_init = init_for_single_funded(&target_init);
    conn.send_message(&Message::Init(our_init).encode())?;

    // Drain any post-init noise so the caller starts from a clean connection.
    ping_pong(&mut conn)?;

    Ok((conn, target_init))
}

/// Reason string in the `error` that retires a warmup channel.
const WARMUP_ABORT_REASON: &str = "warmup done";

/// Sends one warmup `open_channel` and waits for the target to accept it.
///
/// Both halves are required. Waiting: Eclair handles opens in one
/// `OpenChannelInterceptor` actor per peer and answers anything arriving while
/// it is busy with `error("concurrent request rejected")`, so pipelined opens
/// warm nothing. Replying `error` on `accept_channel`: that closes the channel
/// actor and frees the pending-channel slot, which is otherwise only released
/// on disconnect, so a long-lived connection would hit Eclair's limit
/// (`max-total-pending-channels-private-nodes`, default 99).
///
/// A rejection is fatal rather than retried: it means the channel path never
/// ran, and the cause (channel type, feature bits, a limit) is not transient.
fn warmup_open(
    conn: &mut NoiseConnection,
    temp_id: ChannelId,
    keys: &[PublicKey; 6],
) -> Result<(), ScenarioError> {
    let open = warmup_open_channel(temp_id, keys);
    conn.send_message(&Message::OpenChannel(open).encode())?;

    loop {
        match Message::decode(&conn.recv_message()?)? {
            Message::AcceptChannel(accept) if accept.temporary_channel_id == temp_id => {
                let abort = ErrorMessage::for_channel(temp_id, WARMUP_ABORT_REASON);
                conn.send_message(&Message::Error(abort).encode())?;
                return Ok(());
            }
            Message::Error(err) if err.channel_id == temp_id => {
                return Err(ScenarioError::Protocol(format!(
                    "target rejected a warmup open_channel: {}",
                    String::from_utf8_lossy(&err.data)
                )));
            }
            // A connection-level error tears down every channel, so there is
            // nothing left to warm on this connection.
            Message::Error(err) if err.channel_id == ChannelId::ALL => {
                return Err(ScenarioError::Protocol(format!(
                    "target sent a connection-level error during warmup: {}",
                    String::from_utf8_lossy(&err.data)
                )));
            }
            // Warnings, gossip and replies for retired channels are noise here.
            _ => {}
        }
    }
}

/// Drives `iterations` `open_channel` -> `accept_channel` exchanges to warm up a
/// JVM target before the snapshot, so `HotSpot` JIT-compiles the channel path.
///
/// Runs on a throwaway connection, never the snapshot connection. Exchanges are
/// sequential and each is retired with an `error`; see [`warmup_open`] for why.
fn warmup<T: Target>(target: &T, iterations: usize) -> Result<(), ScenarioError> {
    log::info!("Warming up target with {iterations} open_channel exchanges");
    let keys = warmup_channel_keys();
    let (mut conn, _) = establish_connection(target)?;

    for seed in 0..iterations as u64 {
        warmup_open(&mut conn, warmup_temp_channel_id(seed), &keys)?;
    }

    // Flush the last abort so every warmup channel is retired before the
    // connection goes away.
    ping_pong(&mut conn)?;
    drop(conn);

    log::info!("Warmup complete: {iterations} open_channel exchanges");
    Ok(())
}

/// Setup that snapshots just after the Noise handshake and init exchange are
/// complete.
pub struct PostInitSetup;

impl<T: Target> SnapshotSetup<T> for PostInitSetup {
    fn setup(target: &T) -> Result<(NoiseConnection, ProgramContext), ScenarioError> {
        // Establish the pristine connection the fuzzer reuses across runs.
        let (conn, target_init) = establish_connection(target)?;

        let context = ProgramContext {
            target_pubkey: *target.pubkey(),
            chain_hash: REGTEST_CHAIN_HASH,
            // All targets gate startup on `INITIAL_BLOCKS` being mined, so
            // this is the floor. Dynamic per-target queries can replace it
            // later.
            block_height: u32::try_from(INITIAL_BLOCKS).expect("fits in u32"),
            target_features: target_init.features,
        };

        Ok((conn, context))
    }
}

/// Default number of warmup `open_channel` exchanges for [`EclairWarmupSetup`].
///
/// Overridable via `SMITE_WARMUP_ITERATIONS`; zero skips warmup entirely.
const ECLAIR_WARMUP_ITERATIONS: usize = 200;

/// [`PostInitSetup`] preceded by a JVM warmup pass; used for Eclair.
///
/// Before the snapshot it drives `open_channel` exchanges so `HotSpot`
/// JIT-compiles Eclair's channel path, then freezes the JIT so no compiler
/// threads run during fuzzing.
pub struct EclairWarmupSetup;

impl SnapshotSetup<EclairTarget> for EclairWarmupSetup {
    fn setup(target: &EclairTarget) -> Result<(NoiseConnection, ProgramContext), ScenarioError> {
        // `SMITE_WARMUP_ITERATIONS` overrides the default without recompiling.
        let iterations = std::env::var("SMITE_WARMUP_ITERATIONS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(ECLAIR_WARMUP_ITERATIONS);
        if iterations > 0 {
            warmup(target, iterations)?;
            target.freeze_jit()?;
        }

        // Reuse the generic post-init setup for the snapshot connection + context.
        PostInitSetup::setup(target)
    }
}
