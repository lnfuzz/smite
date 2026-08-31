//! Eclair target implementation.
//!
//! Eclair is written in Scala (JVM), so instrumentation is provided by a custom
//! Java bytecode agent that writes coverage directly to AFL shared memory via
//! JNI.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::secp256k1;
use serde::Deserialize;
use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;

use super::bitcoind;
use super::{Target, TargetError, check_crash_log};

/// API password for Eclair's REST API.
const API_PASSWORD: &str = "fuzzpass";

/// Upper bound on how long to wait for the JVM's JIT compile queue to drain
/// after warmup before giving up and freezing anyway.
const JIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

/// How often to poll `jcmd Compiler.queue` while waiting for it to drain.
const JIT_DRAIN_POLL: Duration = Duration::from_millis(150);

/// Number of consecutive idle polls required before declaring the compile queue
/// drained, so we don't stop during a transient lull while Eclair is still
/// feeding the compiler.
const JIT_DRAIN_CONFIRMATIONS: u32 = 3;

/// Configuration for the Eclair target.
pub struct EclairConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// Eclair P2P listen port (default: 9735).
    pub eclair_p2p_port: u16,
    /// Eclair REST API port (default: 8080).
    pub eclair_api_port: u16,
    /// ZMQ block notification port (default: 29000).
    pub zmq_block_port: u16,
    /// ZMQ transaction notification port (default: 29001).
    pub zmq_tx_port: u16,
}

impl Default for EclairConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            eclair_p2p_port: 9735,
            eclair_api_port: 8080,
            zmq_block_port: 29000,
            zmq_tx_port: 29001,
        }
    }
}

impl EclairConfig {
    fn bitcoind_config(&self) -> bitcoind::BitcoindConfig {
        bitcoind::BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            zmq_hashblock_port: Some(self.zmq_block_port),
            zmq_tx_port: Some(self.zmq_tx_port),
            // Eclair requires bech32 address/change types for proper segwit wallet behavior
            extra_args: vec!["-addresstype=bech32".into(), "-changetype=bech32".into()],
            ..bitcoind::BitcoindConfig::default()
        }
    }
}

/// Eclair Lightning node target.
///
/// Field order matters: `eclair` is declared before `bitcoind` so it drops first,
/// which allows Eclair to exit cleanly.
pub struct EclairTarget {
    eclair: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    bitcoin_cli: BitcoinCli,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl EclairTarget {
    /// Writes eclair.conf to the eclair data directory.
    fn write_config(config: &EclairConfig, eclair_dir: &Path) -> Result<(), TargetError> {
        let conf = format!(
            "eclair.chain=regtest\n\
             eclair.server.port={eclair_p2p_port}\n\
             eclair.api.enabled=true\n\
             eclair.api.port={eclair_api_port}\n\
             eclair.api.password={api_password}\n\
             eclair.bitcoind.rpcuser=rpcuser\n\
             eclair.bitcoind.rpcpassword=rpcpass\n\
             eclair.bitcoind.rpcport={bitcoind_rpc_port}\n\
             eclair.bitcoind.zmqblock=\"tcp://127.0.0.1:{zmq_block_port}\"\n\
             eclair.bitcoind.zmqtx=\"tcp://127.0.0.1:{zmq_tx_port}\"\n",
            eclair_p2p_port = config.eclair_p2p_port,
            eclair_api_port = config.eclair_api_port,
            api_password = API_PASSWORD,
            bitcoind_rpc_port = config.bitcoind_rpc_port,
            zmq_block_port = config.zmq_block_port,
            zmq_tx_port = config.zmq_tx_port,
        );
        fs::write(eclair_dir.join("eclair.conf"), conf)?;
        Ok(())
    }

    /// Starts Eclair and waits for it to be ready and synced.
    /// Returns the process and Eclair's identity pubkey.
    fn start_eclair(
        config: &EclairConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting eclair...");

        let eclair_dir = data_dir.join("eclair");
        fs::create_dir_all(&eclair_dir)?;

        Self::write_config(config, &eclair_dir)?;

        let mut cmd = Command::new("eclair-node.sh");

        // LD_PRELOAD the crash handler to report crashes immediately (before
        // process teardown closes TCP sockets).
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler);
        }

        // JVM tuning options for eclair-node.sh, applied for the lifetime of the
        // Eclair process. Replaces JAVA_OPTS outright, so it must restate any
        // defaults from the workload's init.sh it still wants.
        if let Ok(opts) = std::env::var("SMITE_ECLAIR_JAVA_OPTS") {
            cmd.env("JAVA_OPTS", opts);
        }

        cmd.arg(format!("-Declair.datadir={}", eclair_dir.display()));

        // Silence Eclair by default; inherit its stdio when we need to see JVM
        // diagnostics such as -XX:+PrintCompilation output.
        if std::env::var("SMITE_ECLAIR_LOG").is_ok() {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        let eclair = ManagedProcess::spawn(&mut cmd, "eclair")?;

        // Wait for Eclair to be ready and fully synced. We poll the REST API
        // until blockHeight matches the initial blocks we generated.
        log::info!("Waiting for eclair to be ready and synced...");
        for _ in 0..120 {
            if let Ok((pubkey, blockheight)) = Self::query_info(config) {
                if blockheight >= bitcoind::INITIAL_BLOCKS {
                    log::info!("eclair synced (blockheight={blockheight})");
                    return Ok((eclair, pubkey));
                }
                log::debug!("eclair not yet synced (blockheight={blockheight})");
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "eclair failed to sync chain".into(),
        ))
    }

    /// Queries Eclair's identity public key and block height via the REST API.
    fn query_info(config: &EclairConfig) -> Result<(secp256k1::PublicKey, u64), TargetError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct GetInfoResponse {
            node_id: String,
            block_height: u64,
        }

        let output = Command::new("curl")
            .arg("-s")
            .arg("-X")
            .arg("POST")
            .arg("-u")
            .arg(format!(":{API_PASSWORD}"))
            .arg(format!(
                "http://127.0.0.1:{}/getinfo",
                config.eclair_api_port
            ))
            .output()?;

        if !output.status.success() || output.stdout.is_empty() {
            return Err(TargetError::StartFailed("curl getinfo failed".into()));
        }

        let info: GetInfoResponse = serde_json::from_slice(&output.stdout).map_err(|e| {
            TargetError::StartFailed(format!("failed to parse getinfo output: {e}"))
        })?;

        log::info!(
            "Eclair nodeId: {}, blockHeight: {}",
            info.node_id,
            info.block_height
        );

        let pubkey_bytes = hex::decode(&info.node_id)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))?;

        Ok((pubkey, info.block_height))
    }

    /// Runs `jcmd <eclair-jvm-pid> <args...>` and returns its stdout on success.
    fn run_jcmd(&self, args: &[&str]) -> Result<String, String> {
        let java_home = std::env::var("JAVA_HOME").unwrap_or_else(|_| "/opt/java/openjdk".into());
        let out = Command::new(format!("{java_home}/bin/jcmd"))
            .arg(self.eclair.pid().to_string())
            .args(args)
            .output()
            .map_err(|e| format!("failed to run jcmd: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "jcmd {} failed (status {}): {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Polls `jcmd Compiler.queue` until the compiler is idle for
    /// [`JIT_DRAIN_CONFIRMATIONS`] consecutive polls, or [`JIT_DRAIN_TIMEOUT`]
    /// elapses. Idle = the output lists no in-flight `CompilerThread` and no
    /// queued `Class::method` (`::`).
    fn wait_for_compiler_idle(&self) {
        let deadline = Instant::now() + JIT_DRAIN_TIMEOUT;
        let mut consecutive_idle = 0u32;
        loop {
            let idle = match self.run_jcmd(&["Compiler.queue"]) {
                Ok(out) => !out.contains("CompilerThread") && !out.contains("::"),
                // If we can't query the queue we can't confirm idle; keep trying
                // until the timeout rather than freezing a possibly-busy compiler.
                Err(e) => {
                    log::debug!("Compiler.queue poll failed: {e}");
                    false
                }
            };

            if idle {
                consecutive_idle += 1;
                if consecutive_idle >= JIT_DRAIN_CONFIRMATIONS {
                    log::info!("JIT compile queue drained");
                    return;
                }
            } else {
                consecutive_idle = 0;
            }

            if Instant::now() >= deadline {
                log::warn!("timed out waiting for JIT compile queue to drain; freezing anyway");
                return;
            }
            std::thread::sleep(JIT_DRAIN_POLL);
        }
    }

    /// Waits for the compile queue to drain, then freezes the JIT via a catch-all
    /// `Exclude` compiler directive (`jcmd`). This blocks further compilation
    /// while keeping warmed code installed (verified: no deopt), so no compiler
    /// threads run during fuzzing. Draining first is essential — freezing with
    /// methods still queued would leave them interpreted.
    ///
    /// `eclair-node.sh` `exec`s the JVM, so `self.eclair.pid()` is the JVM pid.
    /// Best-effort: jcmd failures are logged, not propagated.
    ///
    /// # Errors
    ///
    /// Returns an error only if writing the directive file fails.
    pub fn freeze_jit(&self) -> Result<(), TargetError> {
        self.wait_for_compiler_idle();

        // Catch-all exclude: block future JIT compilation of every method.
        let directive = std::env::temp_dir().join("smite-jit-exclude-all.json");
        fs::write(&directive, "[ { match: [\"*.*\"], Exclude: true } ]\n")?;
        match self.run_jcmd(&["Compiler.directives_add", &directive.to_string_lossy()]) {
            Ok(out) => log::info!("Froze JIT via jcmd: {}", out.trim()),
            Err(e) => log::warn!("could not freeze JIT: {e}"),
        }
        Ok(())
    }
}

impl Target for EclairTarget {
    type Config = EclairConfig;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let (bitcoind, bitcoin_cli) = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let (eclair, pubkey) = Self::start_eclair(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.eclair_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            eclair,
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

    fn bitcoin_cli(&self) -> &BitcoinCli {
        &self.bitcoin_cli
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        check_crash_log()?;
        if !self.eclair.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }

    /// Known violations suppressed until fixed upstream:
    ///
    /// - Eclair currently allows `funding_satoshis` values above the total Bitcoin
    ///   supply during `open_channel` and `accept_channel` negotiation. These
    ///   values should be rejected early, as they cannot result in a valid
    ///   channel. See: <https://github.com/ACINQ/eclair/issues/3349>
    ///
    /// - Eclair currently does not properly validate `channel_reserve_satoshis`
    ///   against the `dust_limit_satoshis` from `open_channel` in `accept_channel`,
    ///   as required by BOLT 2. See: <https://github.com/ACINQ/eclair/issues/3350>
    fn known_violations() -> &'static [&'static [&'static str]] {
        &[
            &[
                "accepted invalid open_channel: funding_satoshis",
                "exceeds maximum funding of 2100000000000000 sat",
            ],
            &[
                "invalid accept_channel: channel_reserve_satoshis",
                "is below the open_channel dust_limit_satoshis",
            ],
        ]
    }
}
