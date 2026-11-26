//! Clients for target node RPC (JSON-RPC over Unix socket, JSON over HTTP).
//!
//! An unreachable target is returned as an [`io::Error`]. Any other failure
//! means the call itself is wrong and panics.

use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
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

/// Sends an HTTP POST to `localhost:{port}{path}` and returns the JSON response
/// body.
///
/// # Errors
///
/// Returns an error if the target is unreachable: the connection fails, or the
/// response times out or is cut short.
///
/// # Panics
///
/// - If the response lacks a valid `Content-Length` or its body is not valid JSON.
/// - If the response status code is missing or not 2xx.
pub fn http_post(port: u16, path: &str, headers: &[(&str, &str)], body: &str) -> io::Result<Value> {
    let (status, response) = (|| -> io::Result<(String, Vec<u8>)> {
        // Connect to target's HTTP port.
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let sock = TcpStream::connect_timeout(&addr, RPC_IO_TIMEOUT)?;
        sock.set_read_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");
        sock.set_write_timeout(Some(RPC_IO_TIMEOUT))
            .expect("valid timeout");
        let mut conn = BufReader::new(sock);

        // Write the request to the socket.
        let mut request = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\n").into_bytes();
        for (name, value) in headers {
            write!(request, "{name}: {value}\r\n")?;
        }
        write!(request, "Content-Length: {}\r\n\r\n{body}", body.len())?;
        conn.get_mut().write_all(&request)?;

        // Read the response length.
        let mut lines = conn.by_ref().lines();
        let status = lines.next().ok_or(ErrorKind::UnexpectedEof)??;
        let mut content_length = None;
        loop {
            let line = lines.next().ok_or(ErrorKind::UnexpectedEof)??;
            if line.is_empty() {
                break;
            }

            if let Some(value) = line.strip_prefix("Content-Length:") {
                content_length =
                    Some(value.trim().parse().map_err(|_| {
                        io::Error::other(format!("invalid Content-Length:{value}"))
                    })?);
            }
        }

        // Read the response.
        let len = content_length.ok_or_else(|| io::Error::other("no Content-Length"))?;
        let mut response = vec![0; len];
        conn.read_exact(&mut response)?;

        Ok((status, response))
    })()
    .map_err(|e| unreachable(e, path))?;

    // Check status after reading the body to surface rejections as panics.
    assert!(
        status
            .split_whitespace()
            .nth(1)
            .is_some_and(|code| code.starts_with('2')),
        "target rejected {path}: {}",
        String::from_utf8_lossy(&response)
    );

    Ok(serde_json::from_slice(&response).expect("valid JSON response"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{Shutdown, TcpListener};
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

    /// Spawns an HTTP server for one connection: it reads the request (head and
    /// `Content-Length` body), runs `reply` on the stream, then keeps the
    /// connection open until the client closes it. The thread returns the request
    /// it read, if any.
    fn serve_http(
        reply: impl FnOnce(&mut TcpStream) + Send + 'static,
    ) -> (u16, JoinHandle<Option<String>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = (|| -> Option<String> {
                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                let mut content_length = 0;
                loop {
                    let start = request.len();
                    if reader.read_line(&mut request).ok()? == 0 {
                        return None;
                    }
                    let line = &request[start..];
                    // A blank line ends the head, and the body has no line ending.
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.strip_prefix("Content-Length:") {
                        content_length = value.trim().parse().ok()?;
                    }
                }
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).ok()?;
                request.push_str(&String::from_utf8(body).ok()?);
                Some(request)
            })();
            reply(&mut stream);
            let _ = stream.read_to_end(&mut Vec::new());
            request
        });

        (port, handle)
    }

    #[test]
    fn http_post_target_answers() {
        // Every caller header is sent. The target keeps the connection alive,
        // so the body ends at Content-Length, which follows other headers.
        let (port, handle) = serve_http(|stream| {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: Thu, 26 Nov 2026 00:00:00 GMT\r\nContent-Length: 3\r\n\r\n101",
                )
                .unwrap();
        });

        let result = http_post(
            port,
            "/getblockcount",
            &[
                ("Authorization", "Basic OmZ1enpwYXNz"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            "[]",
        )
        .unwrap();
        assert_eq!(result, json!(101));

        let request = handle.join().unwrap();
        assert_eq!(
            request.as_deref(),
            Some(
                "POST /getblockcount HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Authorization: Basic OmZ1enpwYXNz\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 2\r\n\
                 \r\n\
                 []"
            )
        );
    }

    #[test]
    fn http_post_target_down() {
        // A port with no listener behind it, as left by a crashed target.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let err = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    }

    #[test]
    fn http_post_target_hangs_during_request() {
        // A hung target stops reading, so a request larger than the socket
        // buffers cannot be written in full. The thread returns the stream
        // rather than dropping it, keeping the connection open.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let _handle = thread::spawn(move || listener.accept().unwrap().0);

        let err = http_post(
            port,
            "/sendrawtransaction",
            &[("Grpc-Metadata-macaroon", "0201")],
            &format!(r#"{{"hexstring":"{}"}}"#, "00".repeat(32 << 20)),
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn http_post_target_dies_during_request() {
        // The target crashes while a request larger than the socket buffers is
        // still being written, so the rest of the write fails.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.read_exact(&mut [0]).unwrap();
        });

        let err = http_post(
            port,
            "/sendrawtransaction",
            &[("Grpc-Metadata-macaroon", "0201")],
            &format!(r#"{{"hexstring":"{}"}}"#, "00".repeat(32 << 20)),
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    }

    #[test]
    fn http_post_target_dies_before_reading_request() {
        // The target crashes before reading the request, closing with it
        // unread, which resets the connection.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.read_exact(&mut [0]).unwrap();
        });

        let err = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    }

    #[test]
    fn http_post_target_dies_after_reading_request() {
        // The target crashes after reading the whole request, before
        // answering.
        let (port, _handle) = serve_http(|stream| stream.shutdown(Shutdown::Both).unwrap());

        let err = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn http_post_target_hangs_before_answering() {
        // A hung target reads the request but never answers.
        let (port, _handle) = serve_http(|_| {});

        let err = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn http_post_target_dies_during_answer_head() {
        // The target crashes partway through writing the response head.
        let (port, _handle) = serve_http(|stream| {
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-").unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
        });

        let err = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn http_post_target_dies_during_answer_body() {
        // The target crashes partway through writing the response body.
        let (port, _handle) = serve_http(|stream| {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n10")
                .unwrap();
            stream.shutdown(Shutdown::Both).unwrap();
        });

        let err = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    #[should_panic(expected = "target rejected /getblockcount: 101")]
    fn http_post_target_answers_without_status_code_panics() {
        // A target bug: the status line has no status code.
        let (port, _handle) = serve_http(|stream| {
            stream
                .write_all(b"HTTP/1.1\r\nContent-Length: 3\r\n\r\n101")
                .unwrap();
        });

        let _ = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        );
    }

    #[test]
    #[should_panic(expected = "malformed /getblockcount request or response: no Content-Length")]
    fn http_post_target_answers_without_content_length_panics() {
        // Chunked encoding (no Content-Length) is valid HTTP but unsupported.
        // LND's Go net/http sends it for a body over 2048 bytes.
        let (port, _handle) = serve_http(|stream| {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n101\r\n0\r\n\r\n",
                )
                .unwrap();
        });

        let _ = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        );
    }

    #[test]
    #[should_panic(
        expected = "malformed /getblockcount request or response: invalid Content-Length: abc"
    )]
    fn http_post_target_answers_invalid_content_length_panics() {
        // A target bug: the Content-Length is not a number.
        let (port, _handle) = serve_http(|stream| {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n101")
                .unwrap();
        });

        let _ = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        );
    }

    #[test]
    #[should_panic(expected = "valid JSON response")]
    fn http_post_target_answers_invalid_json_panics() {
        // A target bug: the response body is not JSON.
        let (port, _handle) = serve_http(|stream| {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot json")
                .unwrap();
        });

        let _ = http_post(
            port,
            "/getblockcount",
            &[("Grpc-Metadata-macaroon", "0201")],
            "[]",
        );
    }

    #[test]
    #[should_panic(
        expected = r#"target rejected /getblockhash: {"code":-8,"message":"Block height out of range"}"#
    )]
    fn http_post_target_rejects_request_panics() {
        // The target rejects a bad call, e.g., invalid params.
        let (port, _handle) = serve_http(|stream| {
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 49\r\n\r\n{\"code\":-8,\"message\":\"Block height out of range\"}",
                )
                .unwrap();
        });

        let _ = http_post(
            port,
            "/getblockhash",
            &[("Grpc-Metadata-macaroon", "0201")],
            r#"{"height":102}"#,
        );
    }
}
