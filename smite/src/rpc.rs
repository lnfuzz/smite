//! Client for target node JSON-RPC over a Unix socket.
//!
//! An unreachable target is returned as an [`io::Error`]. Any other failure
//! means the call itself is wrong and panics.

use std::io::{self, ErrorKind};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Read/write timeout for RPC I/O, so a hung target cannot block forever.
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(1);

/// Passes through errors caused by an unreachable target.
///
/// # Panics
///
/// Panics on any other error, i.e., a malformed request or response.
fn unreachable(e: io::Error, request: &str) -> io::Error {
    match e.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::WouldBlock
        | ErrorKind::TimedOut
        | ErrorKind::UnexpectedEof => e,
        _ => panic!("malformed {request} request or response: {e}"),
    }
}

/// Sends a JSON-RPC request over the Unix socket at `socket` and returns the
/// response's `result`.
///
/// # Errors
///
/// Returns an error if the target is unreachable: the connection fails, or the
/// response times out or is cut short.
///
/// # Panics
///
/// - If `params` cannot be serialized or the response is not valid JSON-RPC.
/// - If the target answers with a JSON-RPC `error`.
pub fn unix_rpc(socket: &Path, method: &str, params: impl Serialize) -> io::Result<Value> {
    /// A JSON-RPC response from target. `jsonrpc` and `id` are echoed
    /// back but unused, and exactly one of `result` or `error` is set.
    #[derive(Deserialize)]
    struct RpcResponse {
        #[serde(default)]
        result: Value,
        error: Option<Value>,
    }

    let response = (|| -> io::Result<RpcResponse> {
        // Connect to target's RPC socket.
        let mut sock = UnixStream::connect(socket)?;
        sock.set_read_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");
        sock.set_write_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");

        // Write the request to the socket.
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "smite",
            "method": method,
            "params": params,
        });
        serde_json::to_writer(&mut sock, &request)?;

        // Read the response.
        serde_json::Deserializer::from_reader(&mut sock)
            .into_iter()
            .next()
            .transpose()?
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("target closed the socket without answering {method}"),
                )
            })
    })()
    .map_err(|e| unreachable(e, method))?;

    if let Some(error) = response.error {
        panic!("target rejected {method}: {error}");
    }

    Ok(response.result)
}
