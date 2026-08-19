//! LND target implementation.

use std::fs;
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use bitcoin::secp256k1;
use serde::Deserialize;
use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;

use super::bitcoind;
use super::{Target, TargetError, TargetRpc};

/// Configuration for the LND target.
pub struct LndConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// LND P2P listen port (default: 9735).
    pub lnd_p2p_port: u16,
    /// LND RPC port (default: 10009).
    pub lnd_rpc_port: u16,
    /// ZMQ block notification port (default: 28332).
    pub zmq_block_port: u16,
    /// ZMQ transaction notification port (default: 28333).
    pub zmq_tx_port: u16,
}

impl Default for LndConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            lnd_p2p_port: 9735,
            lnd_rpc_port: 10009,
            zmq_block_port: 28332,
            zmq_tx_port: 28333,
        }
    }
}

impl LndConfig {
    fn bitcoind_config(&self) -> bitcoind::BitcoindConfig {
        bitcoind::BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            zmq_block_port: Some(self.zmq_block_port),
            zmq_tx_port: Some(self.zmq_tx_port),
            ..bitcoind::BitcoindConfig::default()
        }
    }
}

/// Pipes for LND coverage synchronization.
///
/// Go can't write directly to AFL's shared memory, so we use pipes:
/// 1. Scenario writes trigger byte
/// 2. LND copies coverage to AFL shared memory
/// 3. LND writes ack byte
/// 4. If scenario's ack read fails (EOF), LND crashed
struct CoveragePipes {
    trigger_write: PipeWriter,
    ack_read: PipeReader,
}

impl CoveragePipes {
    /// Triggers LND to copy coverage counters to AFL shared memory.
    fn sync(&mut self) -> std::io::Result<()> {
        let mut buf = [0u8; 1];
        // Write 1 byte to trigger coverage copy
        self.trigger_write.write_all(&buf)?;
        // Wait for coverage copy to finish (EOF = crash)
        self.ack_read.read_exact(&mut buf)?;
        Ok(())
    }
}

/// RPC handle for interacting with LND node target.
#[derive(Debug, Clone)]
pub struct LndCli;

impl TargetRpc for LndCli {
    /// LND receives new blocks directly from bitcoind over ZMQ, so no manual
    /// chain synchronization is required.
    fn chain_sync(&mut self) {}
}

/// LND Lightning node target.
///
/// Field order matters: `lnd` is declared before `bitcoind` so it drops first,
/// which allows LND to exit cleanly.
pub struct LndTarget {
    lnd: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    coverage_pipes: Option<CoveragePipes>,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    bitcoin_cli: BitcoinCli,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl LndTarget {
    /// Starts LND and waits for it to be ready. Returns the process, coverage
    /// pipes (if in fuzzing mode), and LND's identity pubkey.
    fn start_lnd(
        config: &LndConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, Option<CoveragePipes>, secp256k1::PublicKey), TargetError> {
        log::info!("Starting lnd...");

        let lnd_dir = data_dir.join("lnd");
        fs::create_dir_all(&lnd_dir)?;

        let mut cmd = Command::new("lnd");
        cmd.arg("--noseedbackup")
            .arg("--debuglevel=info")
            .arg("--bitcoin.active")
            .arg("--bitcoin.regtest")
            .arg("--bitcoin.node=bitcoind")
            .arg(format!(
                "--bitcoind.rpchost=127.0.0.1:{}",
                config.bitcoind_rpc_port
            ))
            .arg("--bitcoind.rpcuser=rpcuser")
            .arg("--bitcoind.rpcpass=rpcpass")
            .arg(format!(
                "--bitcoind.zmqpubrawblock=tcp://127.0.0.1:{}",
                config.zmq_block_port
            ))
            .arg(format!(
                "--bitcoind.zmqpubrawtx=tcp://127.0.0.1:{}",
                config.zmq_tx_port
            ))
            .arg(format!("--lnddir={}", lnd_dir.display()))
            .arg(format!("--listen=127.0.0.1:{}", config.lnd_p2p_port))
            .arg(format!("--rpclisten=127.0.0.1:{}", config.lnd_rpc_port))
            .arg("--restlisten=127.0.0.1:8080")
            .arg("--tlsextradomain=127.0.0.1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // Set up coverage pipes if in fuzzing mode. We keep all four pipe ends alive
        // until after spawn so the FDs are valid when the child forks.
        let pipe_ends = if std::env::var("__AFL_SHM_ID").is_ok() {
            let (trigger_read, trigger_write) = std::io::pipe()?;
            let (ack_read, ack_write) = std::io::pipe()?;

            let trigger_fd = trigger_read.as_raw_fd();
            let ack_fd = ack_write.as_raw_fd();

            // SAFETY: This closure runs in the child process after fork, before exec.
            // We only call async-signal-safe libc functions (fcntl, dup2, close) and
            // create io::Error from last_os_error() which just stores an i32 errno.
            unsafe {
                use std::os::unix::process::CommandExt;

                cmd.pre_exec(move || {
                    let mut t = trigger_fd;
                    let mut a = ack_fd;

                    // Move FDs to safe range (>= 10) to avoid conflicts with targets 3 and 4.
                    // For example, if ack_fd were 3, dup2(trigger_fd, 3) would close it.
                    if t < 10 {
                        let new_t = libc::fcntl(t, libc::F_DUPFD, 10);
                        if new_t == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        libc::close(t);
                        t = new_t;
                    }
                    if a < 10 {
                        let new_a = libc::fcntl(a, libc::F_DUPFD, 10);
                        if new_a == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        libc::close(a);
                        a = new_a;
                    }

                    // Assign to fixed FD numbers that LND's sancov.go expects
                    if libc::dup2(t, 3) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(a, 4) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Close the intermediate FDs (dup2 doesn't close the source)
                    libc::close(t);
                    libc::close(a);

                    Ok(())
                });
            }

            Some((trigger_read, trigger_write, ack_read, ack_write))
        } else {
            None
        };

        let lnd = ManagedProcess::spawn(&mut cmd, "lnd")?;

        // Extract parent-side pipe ends; child-side ends are dropped (closed) here
        let coverage_pipes = pipe_ends.map(|(_, trigger_write, ack_read, _)| CoveragePipes {
            trigger_write,
            ack_read,
        });

        // Wait for LND to be ready and fully synced. We poll getinfo until
        // block_height matches the initial blocks we generated.
        log::info!("Waiting for lnd to be ready and synced...");
        for _ in 0..120 {
            if let Ok((pubkey, blockheight, synced_to_chain)) = Self::query_info(config, &lnd_dir) {
                if blockheight >= bitcoind::INITIAL_BLOCKS && synced_to_chain {
                    log::info!("lnd synced (blockheight={blockheight})");
                    return Ok((lnd, coverage_pipes, pubkey));
                }
                log::debug!(
                    "lnd not yet synced (blockheight={blockheight}, synced_to_chain={synced_to_chain})"
                );
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed("lnd failed to sync chain".into()))
    }

    /// Queries LND's identity public key and blockheight via lncli.
    fn query_info(
        config: &LndConfig,
        lnd_dir: &Path,
    ) -> Result<(secp256k1::PublicKey, u64, bool), TargetError> {
        #[derive(Deserialize)]
        struct GetInfoResponse {
            identity_pubkey: String,
            block_height: u64,
            synced_to_chain: bool,
        }

        let output = Command::new("lncli")
            .arg(format!("--lnddir={}", lnd_dir.display()))
            .arg(format!("--rpcserver=127.0.0.1:{}", config.lnd_rpc_port))
            .arg("--network=regtest")
            .arg("getinfo")
            .output()?;

        if !output.status.success() {
            return Err(TargetError::StartFailed(format!(
                "lncli getinfo failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let info: GetInfoResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse lncli output: {e}")))?;

        log::info!(
            "LND identity pubkey: {}, blockheight: {}, synced_to_chain: {}",
            info.identity_pubkey,
            info.block_height,
            info.synced_to_chain
        );

        let pubkey_bytes = hex::decode(&info.identity_pubkey)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))?;

        Ok((pubkey, info.block_height, info.synced_to_chain))
    }
}

impl Target for LndTarget {
    type Config = LndConfig;
    type Rpc = LndCli;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let (bitcoind, bitcoin_cli) = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let (lnd, coverage_pipes, pubkey) = Self::start_lnd(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.lnd_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            lnd,
            bitcoind,
            coverage_pipes,
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
        LndCli
    }

    fn bitcoin_cli(&self) -> &BitcoinCli {
        &self.bitcoin_cli
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        // If we have coverage pipes, sync triggers coverage copy AND detects crashes
        if let Some(pipes) = &mut self.coverage_pipes {
            pipes.sync().map_err(|_| TargetError::Crashed)?;
        } else {
            // No pipes (local mode) - just check process is running
            if !self.lnd.is_running() {
                return Err(TargetError::Crashed);
            }
        }
        Ok(())
    }

    /// Known violations suppressed until fixed upstream:
    ///
    /// - LND allows `open_channel` with an omitted `channel_type`, violating
    ///   BOLT 2 even though it signals the required `option_channel_type` feature.
    ///   See: <https://github.com/lightningnetwork/lnd/pull/11064>
    fn known_violations() -> &'static [&'static [&'static str]] {
        &[&["accepted invalid open_channel: open_channel does not include a channel_type"]]
    }
}
