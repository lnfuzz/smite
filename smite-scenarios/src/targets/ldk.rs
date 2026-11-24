//! LDK target implementation.
//!
//! LDK is written in Rust, so AFL instrumentation writes directly to shared
//! memory.

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use bitcoin::secp256k1;
use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;
use smite::rpc::unix_rpc;

use super::bitcoind;
use super::{Target, TargetError, TargetRpc, check_crash_log};

/// Configuration for the LDK target.
pub struct LdkConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// LDK P2P listen port (default: 9735).
    pub ldk_p2p_port: u16,
}

impl Default for LdkConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            ldk_p2p_port: 9735,
        }
    }
}

impl LdkConfig {
    fn bitcoind_config(&self) -> bitcoind::BitcoindConfig {
        bitcoind::BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            ..bitcoind::BitcoindConfig::default()
        }
    }
}

/// RPC handle for interacting with LDK node target.
///
/// ldk-node has no RPC server, so the wrapper exposes its APIs as JSON-RPC
/// over a Unix socket. The wrapper serves one connection at a time with no
/// read timeout, which is safe because each call sends its request right
/// after connecting.
#[derive(Debug, Clone)]
pub struct LdkRpc {
    /// Path to the wrapper's Unix RPC socket.
    rpc_socket: PathBuf,
}

impl LdkRpc {
    /// Calls a wrapper JSON-RPC method over its Unix socket.
    fn run(&self, method: &str, params: impl serde::Serialize) -> io::Result<serde_json::Value> {
        unix_rpc(&self.rpc_socket, method, params)
    }
}

impl TargetRpc for LdkRpc {
    /// RPC to make LDK sync its wallets with the chain immediately instead of
    /// waiting for its regular poll interval, allowing it to sync faster.
    ///
    /// # Panics
    ///
    /// - If the wrapper answers with an error, which means the call itself is
    ///   at fault rather than the target having crashed/hanged.
    fn chain_sync(&mut self) {
        if let Err(e) = self.run("sync_wallets", serde_json::json!({})) {
            // The wrapper is unreachable, indicating that LDK has already
            // crashed/hanged, check_alive/ping-pong will report the crash/hang
            // at the end.
            log::warn!("sync_wallets could not reach ldk: {e}");
        }
    }
}

/// LDK Lightning node target.
///
/// Field order matters: `ldk` is declared before `bitcoind` so it drops first,
/// which allows LDK to exit cleanly.
pub struct LdkTarget {
    ldk: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    bitcoin_cli: BitcoinCli,
    rpc_socket: PathBuf,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl LdkTarget {
    /// Starts ldk-node-wrapper, funds its on-chain wallet, and waits for it to
    /// be ready. Returns the process and LDK's identity pubkey.
    fn start_ldk(
        config: &LdkConfig,
        ldk_dir: &Path,
        rpc_socket: &Path,
        bitcoin_cli: &BitcoinCli,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting ldk-node-wrapper...");

        fs::create_dir_all(ldk_dir)?;

        let mut cmd = Command::new("ldk-node-wrapper");
        cmd.arg(ldk_dir.to_str().expect("valid UTF-8 path"))
            .arg(config.ldk_p2p_port.to_string())
            .arg(config.bitcoind_rpc_port.to_string())
            .arg(bitcoind::INITIAL_BLOCKS.to_string())
            .arg(rpc_socket.to_str().expect("valid UTF-8 path"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // LD_PRELOAD the crash handler to report crashes immediately (before
        // process teardown closes TCP sockets).
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler);
        }

        let mut ldk = ManagedProcess::spawn(&mut cmd, "ldk-node-wrapper")?;

        // Parse pubkey from stdout and fund the wallet address. The wrapper
        // prints READY once the funding confirms:
        //   PUBKEY:<hex>
        //   ADDRESS:<address>
        //   READY
        let stdout = ldk.inner().stdout.take().ok_or_else(|| {
            TargetError::StartFailed("ldk-node-wrapper stdout not captured".into())
        })?;

        let reader = BufReader::new(stdout);
        let mut pubkey = None;

        for line in reader.lines() {
            let line = line.map_err(|e| TargetError::StartFailed(format!("read error: {e}")))?;

            if let Some(hex) = line.strip_prefix("PUBKEY:") {
                let bytes = hex::decode(hex).map_err(|e| {
                    TargetError::StartFailed(format!("failed to decode pubkey hex: {e}"))
                })?;
                pubkey = Some(secp256k1::PublicKey::from_slice(&bytes).map_err(|e| {
                    TargetError::StartFailed(format!("failed to parse pubkey: {e}"))
                })?);
                log::info!("LDK identity pubkey: {hex}");
            } else if let Some(address) = line.strip_prefix("ADDRESS:") {
                bitcoind::fund_wallet(bitcoin_cli, address)?;
            } else if line == "READY" {
                break;
            }
        }

        let pubkey =
            pubkey.ok_or_else(|| TargetError::StartFailed("no PUBKEY line received".into()))?;

        log::info!("ldk-node-wrapper is ready, synced, and funded");
        Ok((ldk, pubkey))
    }
}

impl Drop for LdkTarget {
    fn drop(&mut self) {
        // Use the `stop` RPC for graceful shutdown instead of SIGTERM. The
        // wrapper doesn't handle SIGTERM, so SIGTERM ends it without running
        // `node.stop()` or the exit-time hook that writes LLVM coverage profraw
        // data. The `stop` RPC makes the wrapper stop the node and return from
        // main(), so the profraw data is written.
        log::debug!("ldk-node-wrapper: requesting graceful shutdown via stop RPC");
        match self.rpc().run("stop", serde_json::json!({})) {
            Ok(_) => {
                // Wait for the wrapper to fully exit with a timeout. The RPC
                // response is sent before `node.stop()` runs, so the wrapper is
                // still shutting down when the RPC returns.
                log::debug!("ldk-node-wrapper: waiting for process to exit");
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !self.ldk.has_exited() && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(e) => {
                log::debug!("ldk-node-wrapper: stop RPC failed ({e}), falling back to SIGTERM");
            }
        }
        // ManagedProcess::drop handles cleanup. If the wrapper already exited,
        // has_exited() returns true and no signal is sent. If the stop RPC
        // failed or the timeout expired, ManagedProcess sends SIGTERM as a
        // fallback, which kills the wrapper.
    }
}

impl Target for LdkTarget {
    type Config = LdkConfig;
    type Rpc = LdkRpc;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let (bitcoind, bitcoin_cli) = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let ldk_dir = data_path.join("ldk");
        let rpc_socket = ldk_dir.join("smite-ldk-rpc.sock");
        let (ldk, pubkey) = Self::start_ldk(&config, &ldk_dir, &rpc_socket, &bitcoin_cli)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.ldk_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            ldk,
            bitcoind,
            pubkey,
            addr,
            bitcoin_cli,
            rpc_socket,
            temp_dir,
        })
    }

    fn pubkey(&self) -> &secp256k1::PublicKey {
        &self.pubkey
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn rpc(&self) -> Self::Rpc {
        LdkRpc {
            rpc_socket: self.rpc_socket.clone(),
        }
    }

    fn bitcoin_cli(&self) -> &BitcoinCli {
        &self.bitcoin_cli
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        check_crash_log()?;
        if !self.ldk.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }

    /// Known violations suppressed until fixed upstream:
    ///
    /// - LDK doesn't fail the channel when both initial commitment balances are
    ///   at or below `channel_reserve_satoshis`, as BOLT 2 requires.
    ///   See: <https://git.rust-bitcoin.org/lightningdevkit/rust-lightning/issues/4931>
    fn known_violations() -> &'static [&'static [&'static str]] {
        &[
            &["accepted invalid open_channel: neither side exceeds channel reserve"],
            &["invalid accept_channel: neither side exceeds channel reserve"],
        ]
    }
}
