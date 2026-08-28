//! CLN (Core Lightning) target implementation.
//!
//! CLN is written in C, so AFL instrumentation (via `afl-clang-fast`) writes
//! directly to shared memory. No coverage pipes are needed.
//!
//! CLN uses a subdaemon architecture: `lightningd` spawns separate binaries
//! (`lightning_connectd`, `lightning_gossipd`, etc.). Global subdaemons have
//! `must_not_exit = true`, so if any of them crash, lightningd itself exits.
//! This means checking lightningd's liveness is sufficient for crash detection.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use bitcoin::secp256k1;
use serde::Deserialize;
use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;

use super::bitcoind;
use super::{Target, TargetError, check_crash_log};

/// Configuration for the CLN target.
pub struct ClnConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// CLN P2P listen port (default: 9735).
    pub cln_p2p_port: u16,
}

impl Default for ClnConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            cln_p2p_port: 9735,
        }
    }
}

impl ClnConfig {
    fn bitcoind_config(&self, data_dir: &Path) -> bitcoind::BitcoindConfig {
        bitcoind::BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            extra_args: vec![format!(
                "-blocknotify=lightning-cli --lightning-dir='{}' --network=regtest syncblocks",
                data_dir.join("cln").display()
            )],
            ..bitcoind::BitcoindConfig::default()
        }
    }
}

/// CLN (Core Lightning) node target.
///
/// Field order matters: `cln` is declared before `bitcoind` so it drops first,
/// which allows CLN to exit cleanly before bitcoind shuts down.
pub struct ClnTarget {
    cln: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    cln_dir: PathBuf,
    bitcoin_cli: BitcoinCli,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl ClnTarget {
    /// Starts lightningd and waits for it to be ready.
    /// Returns the process, CLN's identity pubkey, and the lightning-dir path.
    fn start_cln(
        config: &ClnConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey, PathBuf), TargetError> {
        log::info!("Starting lightningd...");

        let cln_dir = data_dir.join("cln");
        fs::create_dir_all(&cln_dir)?;

        // Run lightningd in foreground mode (no --daemon) so ManagedProcess
        // can track the PID for liveness checks and signal delivery.
        let mut cmd = Command::new("lightningd");

        // LD_PRELOAD the crash handler into lightningd and its subdaemons.
        // Set only on lightningd (not lightning-cli/bitcoin-cli) to avoid
        // interfering with helper processes.
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler);
        }

        cmd.arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg(format!(
                "--bitcoin-rpcconnect=127.0.0.1:{}",
                config.bitcoind_rpc_port
            ))
            .arg("--bitcoin-rpcuser=rpcuser")
            .arg("--bitcoin-rpcpassword=rpcpass")
            .arg(format!("--addr=0.0.0.0:{}", config.cln_p2p_port))
            // Advertise option_dual_fund so the channel establishment v2
            // scenarios can negotiate it. The v1 scenarios strip the bit from
            // our own `init`, so enabling it here does not affect them.
            .arg("--experimental-dual-fund")
            .arg("--log-level=info")
            .arg(format!("--log-file={}/cln.log", cln_dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let cln = ManagedProcess::spawn(&mut cmd, "lightningd")?;

        // Wait for CLN to be ready and fully synced. We poll getinfo until
        // blockheight matches the initial blocks we generated.
        log::info!("Waiting for lightningd to be ready and synced...");
        for _ in 0..120 {
            if let Ok((pubkey, blockheight)) = Self::query_info(&cln_dir) {
                if blockheight >= bitcoind::INITIAL_BLOCKS {
                    log::info!("lightningd synced (blockheight={blockheight})");
                    return Ok((cln, pubkey, cln_dir));
                }
                log::debug!("lightningd not yet synced (blockheight={blockheight})");
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "lightningd failed to sync chain".into(),
        ))
    }

    /// Queries CLN's identity public key and blockheight via lightning-cli.
    fn query_info(cln_dir: &Path) -> Result<(secp256k1::PublicKey, u64), TargetError> {
        #[derive(Deserialize)]
        struct GetInfoResponse {
            id: String,
            blockheight: u64,
        }

        let output = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg("getinfo")
            .output()?;

        if !output.status.success() {
            return Err(TargetError::StartFailed(format!(
                "lightning-cli getinfo failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let info: GetInfoResponse = serde_json::from_slice(&output.stdout).map_err(|e| {
            TargetError::StartFailed(format!("failed to parse lightning-cli output: {e}"))
        })?;

        log::info!(
            "CLN identity pubkey: {}, blockheight: {}",
            info.id,
            info.blockheight
        );

        let pubkey_bytes = hex::decode(&info.id)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))?;

        Ok((pubkey, info.blockheight))
    }
}

impl Drop for ClnTarget {
    fn drop(&mut self) {
        // Use `lightning-cli stop` for graceful shutdown instead of SIGTERM.
        // lightningd's SIGTERM handler calls _exit(), which skips atexit handlers
        // and prevents LLVM coverage profraw data from being written. The `stop`
        // RPC triggers a clean exit through the event loop, running atexit handlers.
        log::debug!("lightningd: requesting graceful shutdown via lightning-cli stop");
        let result = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", self.cln_dir.display()))
            .arg("--network=regtest")
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if result.is_ok_and(|s| s.success()) {
            // Wait for lightningd to fully exit with a timeout. The RPC response
            // is sent just before `return` from main(), so there's a small window
            // where the CLI has returned but lightningd hasn't exited yet.
            log::debug!("lightningd: waiting for process to exit");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.cln.is_running() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            log::debug!("lightningd: lightning-cli stop failed, falling back to SIGTERM");
        }
        // ManagedProcess::drop handles cleanup. If lightningd already exited,
        // is_running() returns false and no signal is sent. If the timeout
        // expired, ManagedProcess sends SIGTERM as a fallback and targets the
        // whole process group so any lingering subdaemons are cleaned up too.
    }
}

impl Target for ClnTarget {
    type Config = ClnConfig;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let bitcoind_config = config.bitcoind_config(&data_path);
        let (bitcoind, bitcoin_cli) = bitcoind::start(&bitcoind_config, &data_path)?;
        let (cln, pubkey, cln_dir) = Self::start_cln(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.cln_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            cln,
            bitcoind,
            pubkey,
            addr,
            cln_dir,
            bitcoin_cli,
            temp_dir,
        })
    }

    fn pubkey(&self) -> &secp256k1::PublicKey {
        &self.pubkey
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn bitcoin_cli(&self) -> &BitcoinCli {
        &self.bitcoin_cli
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        check_crash_log()?;
        if !self.cln.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }

    /// Known violations suppressed until fixed upstream:
    ///
    /// - CLN currently allows `funding_satoshis` values above the total Bitcoin
    ///   supply during `open_channel` and `accept_channel` negotiation. These
    ///   values should be rejected early, as they cannot result in a valid
    ///   channel. See: <https://github.com/ElementsProject/lightning/pull/9368>
    ///
    /// - CLN currently allows `dust_limit_satoshis` values below 354 during
    ///   `open_channel` negotiation. These values should be rejected early, as
    ///   required by BOLT 2.
    ///   See: <https://github.com/ElementsProject/lightning/issues/9403>
    fn known_violations() -> &'static [&'static [&'static str]] {
        &[
            &[
                "accepted invalid open_channel: funding_satoshis",
                "exceeds maximum funding of 2100000000000000 sat",
            ],
            &[
                "accepted invalid open_channel: dust_limit_satoshis",
                "is below the minimum of 354 sat",
            ],
        ]
    }
}
