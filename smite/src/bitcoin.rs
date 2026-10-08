//! This module implements utilities for interacting with regtest
//! `bitcoind` instances via `bitcoin-cli`.

use std::cmp::Ordering;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};

/// A spendable UTXO used as a transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// The value of the UTXO.
    pub amount: Amount,
    /// The transaction outpoint identifying the UTXO.
    pub outpoint: OutPoint,
    /// The script pubkey of the UTXO being spent.
    pub script_pubkey: ScriptBuf,
}

impl Ord for Utxo {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort in decreasing order of amount to support largest-first coin
        // selection (as used in `bdk_wallet`) and ensure deterministic ordering.
        other
            .amount
            .cmp(&self.amount)
            .then_with(|| other.script_pubkey.cmp(&self.script_pubkey))
            .then_with(|| other.outpoint.cmp(&self.outpoint))
    }
}

impl PartialOrd for Utxo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The confirmed position of a transaction within the block chain, used to
/// derive a BOLT 7 `short_channel_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBlockPosition {
    /// The height of the block containing the transaction.
    pub block_height: u32,
    /// The transaction's index within its block.
    pub tx_index: u32,
}

/// Parsed response from `getrawtransaction <txid> 1`.
#[derive(Deserialize)]
struct RawTransactionInfo {
    /// Omitted while the transaction is unconfirmed (in the mempool), so
    /// defaults to zero.
    #[serde(default)]
    confirmations: u32,
    /// Omitted while the transaction is unconfirmed (in the mempool).
    blockhash: Option<String>,
}

/// Connection info for invoking `bitcoin-cli` against the regtest `bitcoind`
/// started by a target.
#[derive(Debug, Clone)]
pub struct BitcoinCli {
    /// RPC port exposed by the regtest `bitcoind` instance.
    pub rpc_port: u16,
    /// Path passed to `bitcoin-cli -datadir`.
    pub bitcoind_dir: PathBuf,
    /// Wallet that wallet RPCs act on, required once `bitcoind` has more than
    /// one wallet loaded.
    pub wallet: String,
}

impl BitcoinCli {
    /// Creates a `bitcoin-cli` command preconfigured with the connection
    /// arguments for this regtest node.
    #[must_use]
    pub fn run(&self) -> Command {
        let mut cmd = Command::new("bitcoin-cli");
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", self.bitcoind_dir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcwallet={}", self.wallet))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass");
        cmd
    }

    /// Runs `bitcoin-cli` with `args` and returns its trimmed stdout.
    ///
    /// # Errors
    ///
    /// Returns an error if `bitcoin-cli` fails to execute or exits non-zero,
    /// carrying its stderr in the latter case.
    pub fn call(&self, args: &[&str]) -> io::Result<String> {
        let output = self.run().args(args).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "bitcoin-cli {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Mines the given number of blocks.
    ///
    /// Any transactions stored in `private_mempool` are included in the first
    /// block. Any remaining blocks are then mined normally. If
    /// `private_mempool` is empty, the current mempool is mined as usual.
    ///
    /// # Panics
    ///
    /// If the `bitcoin-cli -generate` or `generateblock` command fails to
    /// execute or exits non-zero.
    pub fn mine_blocks(&self, num_blocks: u8, private_mempool: &[String]) {
        if private_mempool.is_empty() {
            self.generate(num_blocks);
            return;
        }

        // Include the private mempool in the first block, then mine the
        // remaining blocks normally.
        self.mine_block_including(private_mempool);
        if num_blocks > 1 {
            self.generate(num_blocks - 1);
        }
    }

    /// Mines `num_blocks` blocks from the node's mempool via
    /// `bitcoin-cli -generate`.
    fn generate(&self, num_blocks: u8) {
        let mine_out = self
            .run()
            .arg("-generate")
            .arg(num_blocks.to_string())
            .output()
            .expect("bitcoin-cli -generate should not fail");
        assert!(
            mine_out.status.success(),
            "bitcoin-cli -generate {} failed: {}",
            num_blocks,
            String::from_utf8_lossy(&mine_out.stderr)
        );
    }

    /// Mines a single block containing the current mempool together with the
    /// transactions stored in `private_mempool`.
    ///
    /// Since `generateblock` only includes the transactions it is given, the
    /// current mempool (fetched via `getrawmempool`) is included as well so
    /// already-broadcast transactions are not omitted from the block.
    ///
    /// If the target RBF fee-bumps one of its transactions (e.g. a sweep), the
    /// replacement may land between the `getrawmempool` snapshot and
    /// `generateblock`. In that case, the snapshot contains a txid that is no
    /// longer in the mempool, causing `generateblock` to fail. The snapshot is
    /// then retaken and the block retried, up to `MAX_ATTEMPTS` times. If all
    /// attempts fail, that means the target is replacing its transactions far
    /// more often than expected.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getrawmempool`, `getnewaddress`, or `generateblock`
    ///   fails to execute or exits non-zero.
    /// - If `generateblock` reports a transaction not in mempool on all
    ///   `MAX_ATTEMPTS` attempts.
    /// - If `getrawmempool` does not return valid JSON.
    /// - If `getnewaddress` does not return a valid regtest address.
    /// - If any transaction in `private_mempool` is consensus-invalid.
    /// - If the combined transaction list contains a duplicate rawtx/txid or is
    ///   not topologically ordered.
    fn mine_block_including(&self, private_mempool: &[String]) {
        // RBF replacement is atomic in the mempool, so the replacement is
        // already present when `generateblock` fails. Targets fee-bump on new
        // blocks or on timers tens of seconds apart, so a single retry should
        // succeed. The remaining attempt is kept as a buffer.
        const MAX_ATTEMPTS: usize = 3;

        let address = self.get_new_address();
        for attempt in 1..=MAX_ATTEMPTS {
            let mut txs = self.get_raw_mempool();
            txs.extend_from_slice(private_mempool);
            let txs_json = serde_json::to_string(&txs).expect("tx list serializes to valid JSON");

            let gen_out = self
                .run()
                .arg("generateblock")
                .arg(address.to_string())
                .arg(&txs_json)
                .output()
                .expect("bitcoin-cli generateblock should not fail");
            if gen_out.status.success() {
                return;
            }

            // Only retry if a snapshotted transaction left the mempool (e.g.
            // replaced by an RBF fee bump) before the block was generated.
            let stderr = String::from_utf8_lossy(&gen_out.stderr);
            assert!(
                stderr.contains("not in mempool") && attempt < MAX_ATTEMPTS,
                "bitcoin-cli generateblock failed: {stderr}"
            );
        }
    }

    /// Returns the txids currently in the node's mempool.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getrawmempool` fails to execute or exits non-zero.
    /// - If the output is not valid JSON.
    fn get_raw_mempool(&self) -> Vec<String> {
        let out = self
            .run()
            .arg("getrawmempool")
            .output()
            .expect("bitcoin-cli getrawmempool should not fail");
        assert!(
            out.status.success(),
            "bitcoin-cli getrawmempool failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("getrawmempool should return valid JSON")
    }

    /// Returns the wallet's spendable UTXOs, sorted deterministically.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli listunspent` fails to execute or exits non-zero.
    /// - If the output is not valid JSON, or any entry has an invalid amount,
    ///   txid, or hex scriptPubKey.
    #[must_use]
    pub fn get_utxos(&self) -> Vec<Utxo> {
        #[derive(Deserialize)]
        struct UnspentOutput {
            txid: String,
            vout: u32,
            amount: f64,
            #[serde(rename = "scriptPubKey")]
            script_pubkey: String,
            spendable: bool,
        }

        let utxo_out = self
            .run()
            .arg("listunspent")
            .output()
            .expect("bitcoin-cli listunspent should not fail");
        assert!(
            utxo_out.status.success(),
            "bitcoin-cli listunspent failed: {}",
            String::from_utf8_lossy(&utxo_out.stderr)
        );

        let utxos: Vec<UnspentOutput> =
            serde_json::from_slice(&utxo_out.stdout).expect("listunspent should return valid JSON");

        let mut spendable: Vec<Utxo> = utxos
            .into_iter()
            .filter(|u| u.spendable)
            .map(|u| Utxo {
                amount: Amount::from_btc(u.amount).expect("listunspent amount should be valid BTC"),
                outpoint: OutPoint::new(
                    Txid::from_str(&u.txid).expect("listunspent should return valid txid"),
                    u.vout,
                ),
                script_pubkey: ScriptBuf::from(
                    hex::decode(&u.script_pubkey)
                        .expect("listunspent should return valid hex scriptPubKey"),
                ),
            })
            .collect();
        // Sorted for determinism and to support largest-first coin selection
        // during transaction construction.
        spendable.sort();

        spendable
    }

    /// Returns the scriptPubKey for a newly generated wallet address.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getnewaddress` fails to execute or exits non-zero.
    /// - If the output is not valid UTF-8 or not a valid regtest address.
    #[must_use]
    pub fn get_new_address_script_pubkey(&self) -> ScriptBuf {
        self.get_new_address().script_pubkey()
    }

    /// Returns a newly generated wallet address.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getnewaddress` fails to execute or exits non-zero.
    /// - If the output is not valid UTF-8 or not a valid regtest address.
    fn get_new_address(&self) -> Address {
        let addr_out = self
            .run()
            .arg("getnewaddress")
            .output()
            .expect("bitcoin-cli getnewaddress should not fail");
        assert!(
            addr_out.status.success(),
            "bitcoin-cli getnewaddress failed: {}",
            String::from_utf8_lossy(&addr_out.stderr)
        );

        let addr_str = String::from_utf8(addr_out.stdout).expect("bitcoin address is valid UTF-8");
        Address::from_str(addr_str.trim())
            .and_then(|a| a.require_network(Network::Regtest))
            .expect("getnewaddress should return a valid address")
    }

    /// Signs and broadcasts a transaction, unless it is already confirmed.
    ///
    /// If the signed transaction is accepted by the mempool, it is broadcast
    /// normally. If the mempool rejects it (for example, because it is below
    /// the minimum relay feerate or creates a dust output), it is returned
    /// instead so the caller can mine it later, bypassing mempool policy.
    ///
    /// Returns `None` if the transaction was already confirmed or was broadcast
    /// successfully, or hex-encoded raw transaction if it was rejected by the
    /// mempool.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli signrawtransactionwithwallet` fails to execute or
    ///   exits non-zero.
    /// - If the sign output is not valid JSON.
    /// - If signing returns `complete=false`.
    /// - If `bitcoin-cli sendrawtransaction` fails to execute.
    /// - If the broadcast is rejected for any reason other than a below-dust
    ///   output or a below-minimum relay feerate.
    /// - If a successful broadcast does not return a valid UTF-8 txid.
    /// - If the broadcasted txid does not match the given transaction's txid.
    #[must_use]
    pub fn sign_and_broadcast_tx(&self, tx: &Transaction) -> Option<String> {
        #[derive(Deserialize)]
        struct SignRawTransactionResponse {
            hex: String,
            complete: bool,
        }

        // A confirmed transaction may be broadcast again by the fuzzer. Its
        // inputs are spent, so the wallet can no longer fully sign it, skip
        // signing and broadcasting it again.
        let txid = tx.compute_txid();
        if self.get_transaction_confirmations(txid) > 0 {
            return None;
        }

        let tx_hex = serialize_hex(tx);

        let signed_out = self
            .run()
            .arg("signrawtransactionwithwallet")
            .arg(&tx_hex)
            .output()
            .expect("bitcoin-cli signrawtransactionwithwallet should not fail");
        assert!(
            signed_out.status.success(),
            "bitcoin-cli signrawtransactionwithwallet failed: {}",
            String::from_utf8_lossy(&signed_out.stderr)
        );

        let signed_tx: SignRawTransactionResponse = serde_json::from_slice(&signed_out.stdout)
            .expect("signrawtransactionwithwallet should return valid JSON");
        assert!(
            signed_tx.complete,
            "signrawtransactionwithwallet returned complete=false"
        );

        let broadcast_out = self
            .run()
            .arg("sendrawtransaction")
            .arg(&signed_tx.hex)
            // Disable the high-feerate cap and accept any fee rate for broadcast.
            .arg("0")
            .output()
            .expect("bitcoin-cli sendrawtransaction should not fail");

        if !broadcast_out.status.success() {
            let stderr = String::from_utf8_lossy(&broadcast_out.stderr);
            // If the feerate is below the default minimum relay feerate, or any
            // output is below its dust threshold, return the transactions so
            // they can be mined directly, bypassing mempool policy.
            if stderr.contains("tx with dust output") || stderr.contains("min relay fee not met") {
                return Some(signed_tx.hex);
            }
            panic!("bitcoin-cli sendrawtransaction failed: {stderr}");
        }

        // Safe because bitcoind descriptor wallets currently default to native
        // SegWit, so signing does not alter the txid computed from the unsigned
        // Transaction.
        let broadcast_txid = String::from_utf8(broadcast_out.stdout)
            .expect("sendrawtransaction should return a valid UTF-8 txid");
        assert_eq!(
            broadcast_txid.trim(),
            txid.to_string(),
            "sendrawtransaction returned unexpected txid"
        );

        None
    }

    /// Locks the given outpoints in the wallet so they are excluded from
    /// `listunspent` and automatic coin selection.
    ///
    /// Prevents independently built transactions from selecting the same UTXO.
    /// `listunspent` only excludes an output once its spending transaction
    /// reaches the mempool, so transactions built beforehand can share an input.
    /// The second transaction then either fails broadcast as a non-fee-bumping
    /// RBF replacement, or later fails signing because the prevout has left the
    /// UTXO set.
    ///
    /// # Panics
    ///
    /// If the `bitcoin-cli lockunspent` command fails to execute or exits
    /// non-zero.
    pub fn lock_utxos(&self, outpoints: &[OutPoint]) {
        #[derive(Serialize)]
        struct LockOutpoint {
            txid: String,
            vout: u32,
        }

        if outpoints.is_empty() {
            return;
        }

        let locks: Vec<LockOutpoint> = outpoints
            .iter()
            .map(|o| LockOutpoint {
                txid: o.txid.to_string(),
                vout: o.vout,
            })
            .collect();
        let locks_json = serde_json::to_string(&locks).expect("outpoints serialize to valid JSON");

        let lock_out = self
            .run()
            .arg("lockunspent")
            .arg("false")
            .arg(&locks_json)
            .output()
            .expect("bitcoin-cli lockunspent should not fail");
        assert!(
            lock_out.status.success(),
            "bitcoin-cli lockunspent failed: {}",
            String::from_utf8_lossy(&lock_out.stderr)
        );
    }

    /// Calls `getrawtransaction <txid> 1` and returns the parsed response, or
    /// `None` if the transaction is unknown to the node (non-zero exit code).
    ///
    /// # Panics
    ///
    /// - If the command fails to execute.
    /// - If the command succeeds but its output is not valid JSON.
    fn get_raw_transaction_info(&self, txid: Txid) -> Option<RawTransactionInfo> {
        let tx_out = self
            .run()
            .arg("getrawtransaction")
            .arg(txid.to_string())
            .arg("1")
            .output()
            .expect("bitcoin-cli getrawtransaction should not fail");

        // A non-zero exit means the transaction is unknown to the node.
        if !tx_out.status.success() {
            return None;
        }

        let tx_info: RawTransactionInfo = serde_json::from_slice(&tx_out.stdout)
            .expect("getrawtransaction should return valid JSON");

        Some(tx_info)
    }

    /// Returns the number of confirmations for the transaction with the given
    /// txid, or `0` if it is unconfirmed (in the mempool) or unknown to the node
    /// (e.g. not broadcast yet).
    ///
    /// # Panics
    ///
    /// - If the `bitcoin-cli getrawtransaction` command fails to execute.
    /// - If the command succeeds but its output is not valid JSON.
    #[must_use]
    pub fn get_transaction_confirmations(&self, txid: Txid) -> u32 {
        self.get_raw_transaction_info(txid)
            .map_or(0, |info| info.confirmations)
    }

    /// Returns the position of the confirmed transaction with the given txid,
    /// or `None` if it is unconfirmed (in the mempool) or unknown to the node
    /// (e.g. not broadcast yet).
    ///
    /// The returned position is the pair required to derive a BOLT 7
    /// `short_channel_id` from the funding transaction.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getrawtransaction` or `getblock` fails to execute.
    /// - If either command succeeds but its output is not valid JSON.
    /// - If `getblock` returns a block whose transaction list does not contain
    ///   the queried txid (would indicate an inconsistent bitcoind state).
    #[must_use]
    pub fn get_transaction_block_position(&self, txid: Txid) -> Option<TxBlockPosition> {
        #[derive(Deserialize)]
        struct GetBlockResponse {
            height: u32,
            // Transaction ids in the order they appear in the block. The index
            // within this list is the `tx_index` used by `short_channel_id`.
            tx: Vec<String>,
        }

        // No `blockhash` means the transaction is in the mempool but not yet
        // confirmed.
        let blockhash = self.get_raw_transaction_info(txid)?.blockhash?;

        let block_out = self
            .run()
            .arg("getblock")
            .arg(&blockhash)
            .arg("1")
            .output()
            .expect("bitcoin-cli getblock should not fail");
        assert!(
            block_out.status.success(),
            "bitcoin-cli getblock {} failed: {}",
            blockhash,
            String::from_utf8_lossy(&block_out.stderr)
        );

        let block: GetBlockResponse =
            serde_json::from_slice(&block_out.stdout).expect("getblock should return valid JSON");

        let txid_str = txid.to_string();
        let tx_index = block
            .tx
            .iter()
            .position(|id| id == &txid_str)
            .expect("getblock tx list should contain the queried txid");
        let tx_index = u32::try_from(tx_index).expect("tx_index fits in u32");

        Some(TxBlockPosition {
            block_height: block.height,
            tx_index,
        })
    }
}
