//! This module implements utilities for interacting with regtest
//! `bitcoind` instances via `bitcoin-cli`.

use std::cmp::Ordering;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use bitcoin::consensus::encode::{deserialize, serialize_hex};
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

/// Parsed response from `signrawtransactionwithwallet <hex>`.
#[derive(Deserialize)]
struct SignRawTransactionResponse {
    /// Consensus-serialized transaction with every signable input signed.
    hex: String,
    /// Whether every input now has a complete signature set.
    complete: bool,
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
    /// Consensus-serialized transaction, always present.
    hex: String,
}

/// What a `sendrawtransaction` rejection means for a transaction the fuzzer
/// negotiated, as read from the command's stderr.
enum BroadcastRejection {
    /// Already in the mempool or a block, so already where we want it. The
    /// fuzzer can broadcast the same transaction twice before mining, and in
    /// channel establishment v2 the peer broadcasts the funding transaction
    /// as well.
    AlreadyKnown,
    /// Locked until a later block, absolutely or relative to its inputs. A
    /// channel establishment v2 funding transaction takes its `nLockTime`
    /// from `open_channel2.locktime` and each input's `nSequence` from
    /// `tx_add_input`, both of which the fuzzer picks freely.
    NotFinal,
    /// Breaks a consensus rule, so no block will ever take it.
    ConsensusInvalid,
    /// Turned down before consensus was checked: by a mempool policy rule, or
    /// by the burn cap. `tx_add_output` sends whatever script and value the
    /// fuzzer picked, so a non-standard script, a dust output, a feerate below
    /// the relay minimum, a transaction under 65 bytes or an unspendable
    /// output worth more than the money supply are all routine.
    BeforeConsensus,
}

impl BroadcastRejection {
    fn from_stderr(stderr: &str) -> Self {
        if stderr.contains("txn-already-in-mempool")
            || stderr.contains("txn-already-known")
            || stderr.contains("Transaction already in block chain")
        {
            Self::AlreadyKnown
        } else if stderr.contains("non-final") || stderr.contains("non-BIP68-final") {
            Self::NotFinal
        } else if stderr.contains("bad-txns-") {
            Self::ConsensusInvalid
        } else {
            Self::BeforeConsensus
        }
    }
}

/// Connection info for invoking `bitcoin-cli` against the regtest `bitcoind`
/// started by a target.
#[derive(Debug, Clone)]
pub struct BitcoinCli {
    /// RPC port exposed by the regtest `bitcoind` instance.
    pub rpc_port: u16,
    /// Path passed to `bitcoin-cli -datadir`.
    pub bitcoind_dir: PathBuf,
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
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass");
        cmd
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
    /// # Panics
    ///
    /// - If `bitcoin-cli getrawmempool`, `getnewaddress`, or `generateblock`
    ///   fails to execute or exits non-zero.
    /// - If `getrawmempool` does not return valid JSON.
    /// - If `getnewaddress` does not return a valid regtest address.
    /// - If any transaction in `private_mempool` is consensus-invalid.
    /// - If the combined transaction list contains a duplicate rawtx/txid or is
    ///   not topologically ordered.
    fn mine_block_including(&self, private_mempool: &[String]) {
        self.generate_block_with_mempool(private_mempool, true)
            .unwrap_or_else(|stderr| panic!("bitcoin-cli generateblock failed: {stderr}"));
    }

    /// Runs `generateblock` over the current mempool together with `extra`,
    /// either submitting the block or, with `submit` false, only checking that
    /// it would be valid. Returns the command's stderr if it exits non-zero.
    ///
    /// Since `generateblock` only includes the transactions it is given, the
    /// current mempool (fetched via `getrawmempool`) is included as well, so
    /// already-broadcast transactions are neither omitted from the block nor
    /// missing as parents of `extra`.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getrawmempool`, `getnewaddress`, or `generateblock`
    ///   fails to execute.
    /// - If `getrawmempool` does not return valid JSON.
    /// - If `getnewaddress` does not return a valid regtest address.
    fn generate_block_with_mempool(&self, extra: &[String], submit: bool) -> Result<(), String> {
        let mut txs = self.get_raw_mempool();
        txs.extend_from_slice(extra);
        let txs_json = serde_json::to_string(&txs).expect("tx list serializes to valid JSON");

        let address = self.get_new_address();
        let gen_out = self
            .run()
            .arg("generateblock")
            .arg(address.to_string())
            .arg(&txs_json)
            .arg(submit.to_string())
            .output()
            .expect("bitcoin-cli generateblock should not fail");
        if gen_out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&gen_out.stderr).into_owned())
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

    /// Signs the wallet-owned inputs of `tx`, returning the partially or fully
    /// signed transaction, or `None` if the node does not know how to sign any
    /// of them.
    ///
    /// Unlike [`Self::sign_and_broadcast_tx`], this does not require signing to
    /// be complete. A channel establishment v2 funding transaction also carries
    /// the peer's inputs, which our wallet cannot sign; the partially signed
    /// result still carries our own witnesses, which is what `tx_signatures`
    /// needs. Signing does not alter the txid, since every input we can sign is
    /// a segwit input.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli signrawtransactionwithwallet` fails to execute.
    /// - If the command succeeds but its output is not valid JSON, or its `hex`
    ///   field does not decode as a transaction.
    #[must_use]
    pub fn sign_tx(&self, tx: &Transaction) -> Option<Transaction> {
        let signed = self
            .sign_raw_transaction_with_wallet(tx)
            .inspect_err(|stderr| {
                log::debug!("bitcoin-cli signrawtransactionwithwallet failed: {stderr}");
            })
            .ok()?;
        Some(
            deserialize(&hex::decode(&signed.hex).expect("signing should return valid hex"))
                .expect("signing should return a valid transaction"),
        )
    }

    /// Runs `signrawtransactionwithwallet`, returning the raw response, or the
    /// command's stderr if it exits non-zero.
    ///
    /// Whether a non-zero exit is fatal is the caller's to decide, so the
    /// stderr is handed back rather than logged here: [`Self::sign_tx`] treats
    /// it as a transaction the wallet cannot sign, while
    /// [`Self::sign_and_broadcast_tx`] panics and needs it in the message.
    fn sign_raw_transaction_with_wallet(
        &self,
        tx: &Transaction,
    ) -> Result<SignRawTransactionResponse, String> {
        let signed_out = self
            .run()
            .arg("signrawtransactionwithwallet")
            .arg(serialize_hex(tx))
            .output()
            .expect("bitcoin-cli signrawtransactionwithwallet should not fail");

        if !signed_out.status.success() {
            return Err(String::from_utf8_lossy(&signed_out.stderr).into_owned());
        }

        Ok(serde_json::from_slice(&signed_out.stdout)
            .expect("signrawtransactionwithwallet should return valid JSON"))
    }

    /// Signs and broadcasts a transaction, unless it is already confirmed.
    ///
    /// If the signed transaction is accepted by the mempool, it is broadcast
    /// normally. If the mempool rejects it (for example, because it is below
    /// the minimum relay feerate or creates a dust output), it is returned
    /// instead so the caller can mine it later, bypassing mempool policy.
    ///
    /// Returns `None` if the transaction has no inputs, was already confirmed,
    /// could not be fully signed, could not go in a block, or was broadcast
    /// successfully; or the hex-encoded raw transaction if it was rejected by
    /// mempool policy alone.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli signrawtransactionwithwallet` fails to execute or
    ///   exits non-zero.
    /// - If the sign output is not valid JSON.
    /// - If `bitcoin-cli sendrawtransaction` fails to execute.
    /// - If a successful broadcast does not return a valid UTF-8 txid, or one
    ///   that does not match the given transaction's txid.
    /// - If a broadcast rejected before consensus was checked then fails the
    ///   block validity check for a reason other than a consensus rule.
    #[must_use]
    pub fn sign_and_broadcast_tx(&self, tx: &Transaction) -> Option<String> {
        let txid = tx.compute_txid();
        // A channel establishment v2 funding transaction holds whatever the
        // fuzzer negotiated, which may be no inputs at all. Consensus forbids
        // that, and bitcoind cannot even decode the segwit serialization of
        // it, so there is nothing to sign or broadcast.
        if tx.input.is_empty() {
            log::debug!("{txid} has no inputs, not broadcasting");
            return None;
        }

        // A confirmed transaction may be broadcast again by the fuzzer. Its
        // inputs are spent, so the wallet can no longer fully sign it, skip
        // signing and broadcasting it again.
        if self.get_transaction_confirmations(txid) > 0 {
            return None;
        }

        let signed_tx = self
            .sign_raw_transaction_with_wallet(tx)
            .unwrap_or_else(|stderr| {
                panic!("bitcoin-cli signrawtransactionwithwallet failed: {stderr}")
            });
        if !signed_tx.complete {
            log::debug!(
                "signrawtransactionwithwallet could not fully sign {txid}, not broadcasting"
            );
            return None;
        }

        let rejection = match self.send_raw_transaction(&signed_tx.hex) {
            Ok(broadcast_txid) => {
                assert_eq!(
                    broadcast_txid,
                    txid.to_string(),
                    "sendrawtransaction returned unexpected txid"
                );
                return None;
            }
            Err(stderr) => stderr,
        };

        match BroadcastRejection::from_stderr(&rejection) {
            BroadcastRejection::AlreadyKnown => None,
            BroadcastRejection::NotFinal => {
                log::debug!("{txid} is not final yet, not broadcasting");
                None
            }
            BroadcastRejection::ConsensusInvalid => {
                log::debug!(
                    "{txid} is consensus invalid, not broadcasting: {}",
                    rejection.trim()
                );
                None
            }
            BroadcastRejection::BeforeConsensus => {
                self.keep_if_mineable(txid, signed_tx.hex, &rejection)
            }
        }
    }

    /// Runs `sendrawtransaction` with the fee and burn caps lifted, returning
    /// the txid it reports, or the command's stderr if it exits non-zero.
    ///
    /// # Panics
    ///
    /// If the command fails to execute, or succeeds without printing a valid
    /// UTF-8 txid.
    fn send_raw_transaction(&self, hex: &str) -> Result<String, String> {
        let out = self
            .run()
            .arg("sendrawtransaction")
            .arg(hex)
            // Disable the high-feerate cap and accept any fee rate for broadcast.
            .arg("0")
            // Lift the burn cap (`maxburnamount`, in BTC) as well: an output
            // the fuzzer made provably unspendable, such as an `OP_RETURN`
            // script in `tx_add_output`, is still a mineable transaction. The
            // cap stops at the money supply, so such an output worth more than
            // that still trips it, ahead of the consensus check that rejects
            // the value whatever the script.
            .arg("21000000")
            .output()
            .expect("bitcoin-cli sendrawtransaction should not fail");

        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned());
        }
        let txid = String::from_utf8(out.stdout)
            .expect("sendrawtransaction should return a valid UTF-8 txid");
        Ok(txid.trim().to_owned())
    }

    /// Returns `hex` if a block would accept the transaction `sendrawtransaction`
    /// turned down for `rejection`, so the caller can mine it later, or `None`
    /// if it breaks a consensus rule.
    ///
    /// A rejection before consensus says nothing about the checks bitcoind
    /// never got to. Standardness runs before finality and input values, so a
    /// non-standard script or a second dust output hides a lock time still in
    /// the future or outputs worth more than the inputs, both of which a
    /// funding transaction the fuzzer negotiated has as readily. Only a
    /// transaction a block would accept is worth mining later, so ask bitcoind
    /// to assemble one without submitting it.
    ///
    /// # Panics
    ///
    /// If the block validity check fails for a reason other than a consensus
    /// rule.
    fn keep_if_mineable(&self, txid: Txid, hex: String, rejection: &str) -> Option<String> {
        match self.generate_block_with_mempool(std::slice::from_ref(&hex), false) {
            Ok(()) => Some(hex),
            Err(stderr) if stderr.contains("bad-txns-") => {
                log::debug!(
                    "{txid} cannot go in a block either, not broadcasting: {}",
                    stderr.trim()
                );
                None
            }
            Err(stderr) => panic!(
                "bitcoin-cli sendrawtransaction failed: {}\nbitcoin-cli generateblock failed: {}",
                rejection.trim(),
                stderr.trim()
            ),
        }
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

    /// Returns the consensus-serialized transaction with the given txid, or
    /// `None` if it is unknown to the node.
    ///
    /// Channel establishment v2 needs these bytes for `tx_add_input`'s
    /// `prevtx` field, which lets the peer verify that the input being spent
    /// is non-malleable.
    ///
    /// # Panics
    ///
    /// - If the `bitcoin-cli getrawtransaction` command fails to execute.
    /// - If the command succeeds but its output is not valid JSON or its `hex`
    ///   field is not valid hex.
    #[must_use]
    pub fn get_raw_transaction(&self, txid: Txid) -> Option<Vec<u8>> {
        let info = self.get_raw_transaction_info(txid)?;
        Some(hex::decode(&info.hex).expect("getrawtransaction should return valid hex"))
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
