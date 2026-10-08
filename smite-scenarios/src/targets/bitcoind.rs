//! Shared bitcoind management for all targets.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;

use super::TargetError;

/// Number of blocks to generate at startup for coinbase maturity.
pub const INITIAL_BLOCKS: u64 = 101;

/// Blocks [`fund_wallet`] mines to confirm a target's funding.
const FUNDING_BLOCKS: u64 = 1;

/// Chain height once the target's wallet is funded.
pub const FUNDED_HEIGHT: u64 = INITIAL_BLOCKS + FUNDING_BLOCKS;

/// Wallet the fuzzer funds its own transactions from.
const FUZZER_WALLET: &str = "default";

/// Confirmed UTXOs each target's wallet starts with.
///
/// Targets need them to fee-bump and sweep on chain, and LDK rejects inbound
/// anchor channels without an on-chain reserve. Separate coins let concurrent
/// claims (e.g. anchor CPFP and HTLC claims) each find a confirmed input.
const FUNDING_UTXOS: usize = 4;

/// Value of each funding UTXO in BTC, well above LDK's default 25k sat
/// per-channel anchor reserve.
const FUNDING_UTXO_BTC: &str = "0.1";

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
        wallet: FUZZER_WALLET.into(),
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

/// Creates the fuzzer's wallet and generates initial blocks.
fn setup_wallet(cli: &BitcoinCli) -> Result<(), TargetError> {
    // Fails if the wallet already exists (i.e. SMITE_DATA_DIR was mounted).
    cli.call(&["createwallet", &cli.wallet])?;
    cli.call(&["-generate", &INITIAL_BLOCKS.to_string()])?;
    Ok(())
}

/// Pays [`FUNDING_UTXOS`] outputs to a target's `address` from the fuzzer's
/// wallet and mines [`FUNDING_BLOCKS`] to confirm them.
pub fn fund_wallet(cli: &BitcoinCli, address: &str) -> Result<(), TargetError> {
    log::info!("Funding target wallet at {address}");
    // One payment per UTXO, as `sendmany` rejects repeated addresses.
    for _ in 0..FUNDING_UTXOS {
        cli.call(&["sendtoaddress", address, FUNDING_UTXO_BTC])?;
    }
    cli.call(&["-generate", &FUNDING_BLOCKS.to_string()])?;
    Ok(())
}
