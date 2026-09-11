//! JSON-RPC client for the regtest `bitcoind` instances started by targets.

use std::cmp::Ordering;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
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

/// `rpcuser:rpcpassword` credentials every target starts `bitcoind` with.
const RPC_CREDENTIALS: &str = "rpcuser:rpcpass";

/// `getrawtransaction` error code for a transaction unknown to the node.
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;

/// A JSON-RPC error returned by `bitcoind`.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error code: {}, message: {}", self.code, self.message)
    }
}

/// Why a JSON-RPC request produced no result.
enum RequestError {
    /// `bitcoind` could not be reached or did not answer with JSON-RPC.
    Transport(std::io::Error),
    /// `bitcoind` answered with a JSON-RPC error.
    Rpc(RpcError),
}

/// Client for the regtest `bitcoind` started by a target.
///
/// All calls go over a single HTTP/1.1 keep-alive connection to the JSON-RPC
/// server, so no process is spawned in the fuzzing loop.
#[derive(Debug)]
pub struct BitcoindClient {
    /// RPC port exposed by the regtest `bitcoind` instance.
    pub rpc_port: u16,
    /// Keep-alive connection to the JSON-RPC server, opened on first use and
    /// reopened after `bitcoind` closes it (it drops idle connections after
    /// `-rpcservertimeout`).
    conn: Option<BufReader<TcpStream>>,
}

impl Clone for BitcoindClient {
    /// Clones the connection info only; the clone opens its own connection.
    fn clone(&self) -> Self {
        Self::new(self.rpc_port)
    }
}

impl BitcoindClient {
    #[must_use]
    pub fn new(rpc_port: u16) -> Self {
        Self {
            rpc_port,
            conn: None,
        }
    }

    /// Returns `true` once `bitcoind` answers RPCs, i.e. it is up and past
    /// its warmup (during which every RPC is rejected with `-28`).
    pub fn is_ready(&mut self) -> bool {
        self.request("getblockchaininfo", &serde_json::json!([]))
            .is_ok()
    }

    /// Creates a wallet named `name`, which `bitcoind` then keeps loaded.
    ///
    /// # Errors
    ///
    /// Returns the JSON-RPC error, e.g. when a wallet of that name already
    /// exists in the data directory.
    pub fn create_wallet(&mut self, name: &str) -> Result<(), RpcError> {
        self.call("createwallet", &serde_json::json!([name]))
            .map(|_| ())
    }

    /// Sends one JSON-RPC request over the keep-alive connection, treating a
    /// transport failure as a programmer or environment error.
    ///
    /// # Panics
    ///
    /// If `bitcoind` cannot be reached or answers with something that is not
    /// a JSON-RPC response. Startup code that expects that uses
    /// [`BitcoindClient::is_ready`] instead.
    fn call(
        &mut self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        match self.request(method, params) {
            Ok(result) => Ok(result),
            Err(RequestError::Rpc(e)) => Err(e),
            Err(RequestError::Transport(e)) => panic!("bitcoind {method} request failed: {e}"),
        }
    }

    /// Sends one JSON-RPC request over the keep-alive connection.
    ///
    /// Returns the `result` field, or the server's JSON-RPC error. A
    /// connection that `bitcoind` has closed in the meantime is reopened and
    /// the request retried once.
    fn request(
        &mut self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RequestError> {
        #[derive(Deserialize)]
        struct RpcResponse {
            #[serde(default)]
            result: serde_json::Value,
            error: Option<RpcError>,
        }

        let request = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "smite",
            "method": method,
            "params": params,
        })
        .to_string();

        let body = match self.http_post(&request) {
            Ok(body) => body,
            Err(e) => {
                // The server closes idle keep-alive connections; reconnect once.
                log::debug!("bitcoind {method} failed ({e}), retrying on a fresh connection");
                self.conn = None;
                match self.http_post(&request) {
                    Ok(body) => body,
                    Err(e) => {
                        self.conn = None;
                        return Err(RequestError::Transport(e));
                    }
                }
            }
        };

        let response: RpcResponse = serde_json::from_slice(&body).map_err(|e| {
            self.conn = None;
            RequestError::Transport(std::io::Error::other(format!(
                "invalid JSON-RPC response: {e}"
            )))
        })?;
        match response.error {
            Some(error) => Err(RequestError::Rpc(error)),
            None => Ok(response.result),
        }
    }

    /// Posts `body` to the JSON-RPC endpoint and returns the response body,
    /// whatever the HTTP status: `bitcoind` reports JSON-RPC errors as HTTP
    /// 500 with the JSON-RPC error in the body.
    fn http_post(&mut self, body: &str) -> std::io::Result<Vec<u8>> {
        let conn = if let Some(conn) = self.conn.as_mut() {
            conn
        } else {
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.rpc_port));
            let stream = TcpStream::connect(addr)?;
            stream.set_nodelay(true)?;
            self.conn.insert(BufReader::new(stream))
        };

        let request = format!(
            "POST / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Authorization: Basic {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n{body}",
            base64(RPC_CREDENTIALS.as_bytes()),
            body.len(),
        );
        conn.get_mut().write_all(request.as_bytes())?;

        // Status line, then headers up to the blank line. Only
        // `Content-Length` matters: bitcoind never chunks its responses.
        let mut line = String::new();
        let mut content_length = None;
        loop {
            line.clear();
            if conn.read_line(&mut line)? == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            let trimmed = line.trim_end_matches("\r\n");
            if trimmed.is_empty() {
                break;
            }
            if let Some(value) = trimmed
                .split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim())
            {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|e| std::io::Error::other(format!("bad Content-Length: {e}")))?,
                );
            }
        }

        let len = content_length
            .ok_or_else(|| std::io::Error::other("bitcoind response without Content-Length"))?;
        let mut body = vec![0u8; len];
        conn.read_exact(&mut body)?;
        Ok(body)
    }

    /// Mines the given number of blocks.
    ///
    /// Any transactions stored in `private_mempool` are included in the first
    /// block. Any remaining blocks are then mined normally. If
    /// `private_mempool` is empty, the current mempool is mined as usual.
    ///
    /// # Panics
    ///
    /// If `generatetoaddress` or `generateblock` fails, e.g. `MineBlocks(0)`.
    pub fn mine_blocks(&mut self, num_blocks: u8, private_mempool: &[String]) {
        let mine = |this: &mut Self, n: u8| {
            this.generate(u32::from(n))
                .unwrap_or_else(|e| panic!("generatetoaddress {n} failed: {e}"));
        };

        if private_mempool.is_empty() {
            mine(self, num_blocks);
            return;
        }

        // Include the private mempool in the first block, then mine the
        // remaining blocks normally.
        self.mine_block_including(private_mempool);
        if num_blocks > 1 {
            mine(self, num_blocks - 1);
        }
    }

    /// Mines `num_blocks` blocks from the node's mempool to a fresh wallet
    /// address.
    ///
    /// # Errors
    ///
    /// Returns the JSON-RPC error, e.g. for `num_blocks == 0`.
    pub fn generate(&mut self, num_blocks: u32) -> Result<(), RpcError> {
        let address = self.get_new_address();
        self.call(
            "generatetoaddress",
            &serde_json::json!([num_blocks, address.to_string()]),
        )
        .map(|_| ())
    }

    /// Mines a single block containing the current mempool together with the
    /// transactions stored in `private_mempool`.
    ///
    /// Since `generateblock` only includes the transactions it is given, the
    /// current mempool (fetched via `getrawmempool`) is included as well so
    /// already-broadcast transactions are not omitted from the block.
    ///
    /// # Panics
    ///
    /// - If `getrawmempool`, `getnewaddress`, or `generateblock` fails.
    /// - If `getnewaddress` does not return a valid regtest address.
    /// - If any transaction in `private_mempool` is consensus-invalid.
    /// - If the combined transaction list contains a duplicate rawtx/txid or is
    ///   not topologically ordered.
    fn mine_block_including(&mut self, private_mempool: &[String]) {
        let mut txs = self.get_raw_mempool();
        txs.extend_from_slice(private_mempool);

        let address = self.get_new_address();
        self.call(
            "generateblock",
            &serde_json::json!([address.to_string(), txs]),
        )
        .unwrap_or_else(|e| panic!("generateblock failed: {e}"));
    }

    /// Returns the txids currently in the node's mempool.
    ///
    /// # Panics
    ///
    /// If `getrawmempool` fails or does not return a txid list.
    fn get_raw_mempool(&mut self) -> Vec<String> {
        let result = self
            .call("getrawmempool", &serde_json::json!([]))
            .unwrap_or_else(|e| panic!("getrawmempool failed: {e}"));
        serde_json::from_value(result).expect("getrawmempool should return a txid list")
    }

    /// Returns the wallet's spendable UTXOs, sorted deterministically.
    ///
    /// # Panics
    ///
    /// - If `listunspent` fails.
    /// - If any entry has an invalid amount, txid, or hex scriptPubKey.
    #[must_use]
    pub fn get_utxos(&mut self) -> Vec<Utxo> {
        #[derive(Deserialize)]
        struct UnspentOutput {
            txid: String,
            vout: u32,
            amount: f64,
            #[serde(rename = "scriptPubKey")]
            script_pubkey: String,
            spendable: bool,
        }

        let result = self
            .call("listunspent", &serde_json::json!([]))
            .unwrap_or_else(|e| panic!("listunspent failed: {e}"));
        let utxos: Vec<UnspentOutput> =
            serde_json::from_value(result).expect("listunspent should return a UTXO list");

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
    /// - If `getnewaddress` fails.
    /// - If the result is not a valid regtest address.
    #[must_use]
    pub fn get_new_address_script_pubkey(&mut self) -> ScriptBuf {
        self.get_new_address().script_pubkey()
    }

    /// Returns a newly generated wallet address.
    ///
    /// # Panics
    ///
    /// - If `getnewaddress` fails.
    /// - If the result is not a valid regtest address.
    fn get_new_address(&mut self) -> Address {
        let result = self
            .call("getnewaddress", &serde_json::json!([]))
            .unwrap_or_else(|e| panic!("getnewaddress failed: {e}"));
        let addr_str = result
            .as_str()
            .expect("getnewaddress should return a string");
        Address::from_str(addr_str)
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
    /// - If `signrawtransactionwithwallet` fails or returns `complete=false`.
    /// - If the broadcast is rejected for any reason other than a below-dust
    ///   output or a below-minimum relay feerate.
    /// - If the broadcasted txid does not match the given transaction's txid.
    #[must_use]
    pub fn sign_and_broadcast_tx(&mut self, tx: &Transaction) -> Option<String> {
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

        let result = self
            .call("signrawtransactionwithwallet", &serde_json::json!([tx_hex]))
            .unwrap_or_else(|e| panic!("signrawtransactionwithwallet failed: {e}"));
        let signed_tx: SignRawTransactionResponse = serde_json::from_value(result)
            .expect("signrawtransactionwithwallet should return hex and complete");
        assert!(
            signed_tx.complete,
            "signrawtransactionwithwallet returned complete=false"
        );

        // The `0` disables the high-feerate cap so any fee rate is broadcast.
        let broadcast = self.call("sendrawtransaction", &serde_json::json!([signed_tx.hex, 0]));
        let broadcast_txid = match broadcast {
            Ok(result) => result,
            // If the feerate is below the default minimum relay feerate, or any
            // output is below its dust threshold, return the transactions so
            // they can be mined directly, bypassing mempool policy.
            Err(e) if e.message.contains("dust") || e.message.contains("min relay fee not met") => {
                return Some(signed_tx.hex);
            }
            Err(e) => panic!("sendrawtransaction failed: {e}"),
        };

        // Safe because bitcoind descriptor wallets currently default to native
        // SegWit, so signing does not alter the txid computed from the unsigned
        // Transaction.
        assert_eq!(
            broadcast_txid.as_str(),
            Some(txid.to_string().as_str()),
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
    /// If `lockunspent` fails.
    pub fn lock_utxos(&mut self, outpoints: &[OutPoint]) {
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
        self.call("lockunspent", &serde_json::json!([false, locks]))
            .unwrap_or_else(|e| panic!("lockunspent failed: {e}"));
    }

    /// Calls `getrawtransaction <txid> 1` and returns the parsed response, or
    /// `None` if the transaction is unknown to the node (non-zero exit code).
    ///
    /// # Panics
    ///
    /// - If the command fails to execute.
    /// - If the command succeeds but its output is not valid JSON.
    fn get_raw_transaction_info(&mut self, txid: Txid) -> Option<RawTransactionInfo> {
        let result = match self.call(
            "getrawtransaction",
            &serde_json::json!([txid.to_string(), 1]),
        ) {
            Ok(result) => result,
            Err(e) if e.code == RPC_INVALID_ADDRESS_OR_KEY => return None,
            Err(e) => panic!("getrawtransaction failed: {e}"),
        };
        Some(serde_json::from_value(result).expect("getrawtransaction should return tx info"))
    }

    /// Returns the number of confirmations for the transaction with the given
    /// txid, or `0` if it is unconfirmed (in the mempool) or unknown to the node
    /// (e.g. not broadcast yet).
    ///
    /// # Panics
    ///
    /// If `getrawtransaction` fails for any reason other than an unknown txid.
    #[must_use]
    pub fn get_transaction_confirmations(&mut self, txid: Txid) -> u32 {
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
    /// - If `getrawtransaction` or `getblock` fails.
    /// - If `getblock` returns a block whose transaction list does not contain
    ///   the queried txid (would indicate an inconsistent bitcoind state).
    #[must_use]
    pub fn get_transaction_block_position(&mut self, txid: Txid) -> Option<TxBlockPosition> {
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

        let result = self
            .call("getblock", &serde_json::json!([blockhash, 1]))
            .unwrap_or_else(|e| panic!("getblock {blockhash} failed: {e}"));
        let block: GetBlockResponse =
            serde_json::from_value(result).expect("getblock should return height and tx list");

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

/// Standard base64 with padding, enough for the `Authorization: Basic` header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> (18 - 6 * i)) & 0x3f).expect("6-bit index");
                out.push(char::from(ALPHABET[idx]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"rpcuser:rpcpass"), "cnBjdXNlcjpycGNwYXNz");
    }
}
