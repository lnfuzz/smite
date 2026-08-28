//! Shared bitcoind management for all targets.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;

use super::TargetError;

/// Blocks a coinbase output must be buried under before it can be spent.
const COINBASE_MATURITY: u64 = 100;

/// Mature coinbase outputs the wallet holds once startup is done.
///
/// Every block mined at startup pays its coinbase to the wallet, so this is
/// also the number of separate UTXOs a program has to spend. It needs to cover
/// more than one: channel establishment v2 has a program contribute several
/// inputs to one funding transaction, and each `tx_add_input` locks the coin it
/// selects so the next one cannot propose the same outpoint. A program may also
/// open more than one channel. Sixteen leaves room for both, and mining the
/// extra blocks costs nothing measurable, since it happens once before the
/// snapshot is taken.
const SPENDABLE_UTXOS: u64 = 16;

/// Number of blocks to generate at startup.
///
/// Only outputs buried under [`COINBASE_MATURITY`] blocks are spendable, so the
/// wallet ends up with [`SPENDABLE_UTXOS`] of them.
pub const INITIAL_BLOCKS: u64 = COINBASE_MATURITY + SPENDABLE_UTXOS;

/// Bitcoind configuration.
pub struct BitcoindConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub p2p_port: u16,
    /// Optional ZMQ raw block notification port (`zmqpubrawblock`).
    pub zmq_block_port: Option<u16>,
    /// Optional ZMQ hash block notification port (`zmqpubhashblock`).
    pub zmq_hashblock_port: Option<u16>,
    /// Optional ZMQ transaction notification port (`zmqpubrawtx`).
    pub zmq_tx_port: Option<u16>,
    /// Additional bitcoind arguments (e.g. `-addresstype=bech32`).
    pub extra_args: Vec<String>,
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
            rpc_port: 18443,
            p2p_port: 18444,
            zmq_block_port: None,
            zmq_hashblock_port: None,
            zmq_tx_port: None,
            extra_args: Vec::new(),
        }
    }
}

/// Resolves the data directory: uses `SMITE_DATA_DIR` if set, otherwise creates a temp dir.
///
/// Returns `(path, temp_dir)` where `temp_dir` is `Some` if a temp directory was created
/// (it will be cleaned up when dropped).
pub fn resolve_data_dir() -> Result<(PathBuf, Option<tempfile::TempDir>), TargetError> {
    if let Ok(dir) = std::env::var("SMITE_DATA_DIR") {
        let path = PathBuf::from(dir);
        fs::create_dir_all(&path)?;
        log::info!("Preserving data directory: {}", path.display());
        Ok((path, None))
    } else {
        let temp = tempfile::tempdir()?;
        let path = temp.path().to_path_buf();
        Ok((path, Some(temp)))
    }
}

/// Starts bitcoind and waits for it to be ready.
pub fn start(
    config: &BitcoindConfig,
    data_dir: &Path,
) -> Result<(ManagedProcess, BitcoinCli), TargetError> {
    log::info!("Starting bitcoind...");

    let bitcoind_dir = data_dir.join("bitcoind");
    fs::create_dir_all(&bitcoind_dir)?;

    let mut cmd = Command::new("bitcoind");
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", bitcoind_dir.display()))
        .arg(format!("-port={}", config.p2p_port))
        .arg(format!("-rpcport={}", config.rpc_port))
        .arg("-rpcuser=rpcuser")
        .arg("-rpcpassword=rpcpass")
        .arg("-fallbackfee=0.00001")
        .arg("-txindex=1")
        .arg("-server=1")
        .arg("-rest=1")
        .arg("-printtoconsole=0")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Add ZMQ args if configured
    if let Some(port) = config.zmq_block_port {
        cmd.arg(format!("-zmqpubrawblock=tcp://127.0.0.1:{port}"));
    }
    if let Some(port) = config.zmq_hashblock_port {
        cmd.arg(format!("-zmqpubhashblock=tcp://127.0.0.1:{port}"));
    }
    if let Some(port) = config.zmq_tx_port {
        cmd.arg(format!("-zmqpubrawtx=tcp://127.0.0.1:{port}"));
    }

    // Add any extra args
    for arg in &config.extra_args {
        cmd.arg(arg);
    }

    let bitcoind = ManagedProcess::spawn(&mut cmd, "bitcoind")?;
    let cli = BitcoinCli {
        rpc_port: config.rpc_port,
        bitcoind_dir,
    };

    // Wait for bitcoind to be ready
    log::info!("Waiting for bitcoind to be ready...");
    for _ in 0..30 {
        let status = cli
            .run()
            .arg("getblockchaininfo")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if status.is_ok_and(|s| s.success()) {
            log::info!("bitcoind is ready");
            setup_wallet(&cli)?;
            return Ok((bitcoind, cli));
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    Err(TargetError::StartFailed(
        "bitcoind failed to become ready".into(),
    ))
}

/// Creates wallet and generates initial blocks.
fn setup_wallet(cli: &BitcoinCli) -> Result<(), TargetError> {
    // Create wallet
    let _ = cli
        .run()
        .arg("createwallet")
        .arg("default")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // Generate initial blocks
    let status = cli
        .run()
        .arg("-generate")
        .arg(INITIAL_BLOCKS.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if !status.success() {
        return Err(TargetError::StartFailed(
            "failed to generate initial blocks".into(),
        ));
    }

    Ok(())
}
