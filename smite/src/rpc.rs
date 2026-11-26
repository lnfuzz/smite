//! Client for target node JSON-RPC over a Unix socket.
//!
//! An unreachable target is returned as an [`io::Error`]. Any other failure
//! means the call itself is wrong and panics.

use std::io::{self, BufReader, ErrorKind, Write};
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
        sock.write_all(&serde_json::to_vec(&request)?)?;

        // Read the response.
        serde_json::Deserializer::from_reader(BufReader::new(&mut sock))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::Shutdown;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread::{self, JoinHandle};

    use serde_json::json;
    use tempfile::TempDir;

    /// Spawns an RPC server for one connection: it reads the request, runs
    /// `reply` on the stream, then keeps the connection open until the client
    /// closes it. The thread returns the request it read, if any.
    fn serve_unix(
        reply: impl FnOnce(&mut UnixStream) + Send + 'static,
    ) -> (TempDir, PathBuf, JoinHandle<Option<Value>>) {
        let temp_dir = TempDir::new().unwrap();
        let socket = temp_dir.path().join("rpc.sock");
        let listener = UnixListener::bind(&socket).unwrap();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = serde_json::Deserializer::from_reader(BufReader::new(&mut stream))
                .into_iter::<Value>()
                .next()
                .and_then(Result::ok);
            reply(&mut stream);
            let _ = stream.read_to_end(&mut Vec::new());
            request
        });

        (temp_dir, socket, handle)
    }

    #[test]
    fn unix_rpc_target_answers() {
        // A target may follow the response with whitespace (e.g., CLN ends
        // every response with "\n\n").
        let (_temp_dir, socket, handle) = serve_unix(|stream| {
            stream
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"smite\",\"result\":101}\n\n")
                .unwrap();
        });

        let result = unix_rpc(&socket, "getblockcount", json!([])).unwrap();
        assert_eq!(result, json!(101));

        let request = handle.join().unwrap();
        assert_eq!(
            request,
            Some(json!({
                "jsonrpc": "2.0",
                "id": "smite",
                "method": "getblockcount",
                "params": [],
            }))
        );
    }

    #[test]
    fn unix_rpc_target_down() {
        // A socket file with no listener behind it, as left by a crashed target.
        let temp_dir = TempDir::new().unwrap();
        let socket = temp_dir.path().join("rpc.sock");
        drop(UnixListener::bind(&socket).unwrap());

        let err = unix_rpc(&socket, "getblockcount", json!([])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    }

    #[test]
    fn unix_rpc_target_hangs_during_request() {
        // A hung target stops reading, so a request larger than the socket
        // buffer cannot be written in full. The thread returns the stream
        // rather than dropping it, keeping the connection open.
        let temp_dir = TempDir::new().unwrap();
        let socket = temp_dir.path().join("rpc.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let _handle = thread::spawn(move || listener.accept().unwrap().0);

        let err = unix_rpc(
            &socket,
            "sendrawtransaction",
            json!({ "hexstring": "00".repeat(2 << 20) }),
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn unix_rpc_target_dies_during_request() {
        // The target crashes while a request larger than the socket buffer is
        // still being written, so the rest of the write fails.
        let temp_dir = TempDir::new().unwrap();
        let socket = temp_dir.path().join("rpc.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.read_exact(&mut [0]).unwrap();
        });

        let err = unix_rpc(
            &socket,
            "sendrawtransaction",
            json!({ "hexstring": "00".repeat(2 << 20) }),
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn unix_rpc_target_dies_before_reading_request() {
        // The target crashes before reading the request, closing with it
        // unread, which resets the connection.
        let temp_dir = TempDir::new().unwrap();
        let socket = temp_dir.path().join("rpc.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.read_exact(&mut [0]).unwrap();
        });

        let err = unix_rpc(&socket, "getblockcount", json!([])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    }

    #[test]
    fn unix_rpc_target_dies_after_reading_request() {
        // The target crashes after reading the whole request, before
        // answering.
        let (_temp_dir, socket, _handle) =
            serve_unix(|stream| stream.shutdown(Shutdown::Both).unwrap());

        let err = unix_rpc(&socket, "getblockcount", json!([])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn unix_rpc_target_hangs_before_answering() {
        // A hung target reads the request but never answers.
        let (_temp_dir, socket, _handle) = serve_unix(|_| {});

        let err = unix_rpc(&socket, "getblockcount", json!([])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn unix_rpc_target_dies_during_answer() {
        // The target crashes partway through writing its response.
        let (_temp_dir, socket, _handle) = serve_unix(|stream| {
            stream.write_all(br#"{"jsonrpc":"2.0","id":"#).unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
        });

        let err = unix_rpc(&socket, "getblockcount", json!([])).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    #[should_panic(expected = "malformed getblockcount request or response: expected ident")]
    fn unix_rpc_target_answers_invalid_json_panics() {
        // A target bug: the response is not JSON.
        let (_temp_dir, socket, _handle) =
            serve_unix(|stream| stream.write_all(b"not json").unwrap());

        let _ = unix_rpc(&socket, "getblockcount", json!([]));
    }

    #[test]
    #[should_panic(
        expected = "malformed getblockcount request or response: invalid length 1, expected struct RpcResponse with 2 elements"
    )]
    fn unix_rpc_target_answers_non_object_panics() {
        // A target bug: the response is JSON but not a JSON-RPC object.
        let (_temp_dir, socket, _handle) = serve_unix(|stream| stream.write_all(b"[]").unwrap());

        let _ = unix_rpc(&socket, "getblockcount", json!([]));
    }

    #[test]
    #[should_panic(
        expected = r#"target rejected getblockhash: {"code":-8,"message":"Block height out of range"}"#
    )]
    fn unix_rpc_target_rejects_request_panics() {
        // The target rejects a bad call, e.g., invalid params.
        let (_temp_dir, socket, _handle) = serve_unix(|stream| {
            stream
                .write_all(
                    br#"{"jsonrpc":"2.0","id":"smite","error":{"code":-8,"message":"Block height out of range"}}"#,
                )
                .unwrap();
        });

        let _ = unix_rpc(&socket, "getblockhash", json!({ "height": 102 }));
    }
}
