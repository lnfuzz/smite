//! LDK target implementation.
//!
//! Unlike LND, LDK is written in Rust so AFL instrumentation writes directly
//! to shared memory. No coverage pipes are needed.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};

use bitcoin::secp256k1;
use smite::bitcoin::BitcoinCli;
use smite::process::{ManagedProcess, send_sigusr1};

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
/// LDK currently has no RPC socket, so commands are delivered through signals
/// that invoke the corresponding APIs directly.
#[derive(Debug, Clone)]
pub struct LdkRpc {
    /// PID of the LDK node's wrapper process, which receives the signals.
    pid: u32,
}

impl TargetRpc for LdkRpc {
    /// Signals the wrapper (SIGUSR1) to sync on new blocks immediately instead
    /// of waiting for its regular poll interval, allowing it to sync faster.
    ///
    /// # Panics
    ///
    /// Panics if the signal cannot be sent, which means the call itself is at
    /// fault rather than the target having crashed.
    fn chain_sync(&mut self) {
        // A crashed wrapper remains an unreaped zombie, so the signal is sent
        // but discarded. check_alive will report the crash at the end.
        if let Err(e) = send_sigusr1(self.pid) {
            panic!(
                "failed to send SIGUSR1 to ldk-node-wrapper (pid {}): {e}",
                self.pid
            );
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
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl LdkTarget {
    /// Starts ldk-node-wrapper and waits for it to be ready.
    /// Returns the process and LDK's identity pubkey.
    fn start_ldk(
        config: &LdkConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting ldk-node-wrapper...");

        let ldk_dir = data_dir.join("ldk");
        fs::create_dir_all(&ldk_dir)?;

        let mut cmd = Command::new("ldk-node-wrapper");
        cmd.arg(ldk_dir.to_str().expect("valid UTF-8 path"))
            .arg(config.ldk_p2p_port.to_string())
            .arg(config.bitcoind_rpc_port.to_string())
            .arg(bitcoind::INITIAL_BLOCKS.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // LD_PRELOAD the crash handler to report crashes immediately (before
        // process teardown closes TCP sockets).
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler);
        }

        let mut ldk = ManagedProcess::spawn(&mut cmd, "ldk-node-wrapper")?;

        // Parse pubkey from stdout. The wrapper prints:
        //   PUBKEY:<hex>
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
            } else if line == "READY" {
                break;
            }
        }

        let pubkey =
            pubkey.ok_or_else(|| TargetError::StartFailed("no PUBKEY line received".into()))?;

        log::info!("ldk-node-wrapper is ready and synced");
        Ok((ldk, pubkey))
    }
}

impl Target for LdkTarget {
    type Config = LdkConfig;
    type Rpc = LdkRpc;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let (bitcoind, bitcoin_cli) = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let (ldk, pubkey) = Self::start_ldk(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.ldk_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            ldk,
            bitcoind,
            pubkey,
            addr,
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

    fn rpc(&self) -> Self::Rpc {
        LdkRpc {
            pid: self.ldk.pid(),
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
}
