//! Noise handshake scenario - fuzzes the BOLT 8 handshake at each act.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use bitcoin::secp256k1::SecretKey;
use smite::bolt::{Init, Message};
use smite::noise::{
    ACT_TWO_SIZE, ENCRYPTED_LENGTH_SIZE, MAC_SIZE, NoiseCipher, NoiseConnection, NoiseHandshake,
};
use smite::scenarios::{Scenario, ScenarioError, ScenarioResult};
use smite::violation::Violation;

use super::{EPHEMERAL_KEY, handshake_with_target, ping_pong};
use crate::targets::Target;

/// Timeout for normal TCP operations during handshake setup (Act 2 recv, etc.).
const TIMEOUT: Duration = Duration::from_secs(5);

/// Short timeout for checking if the target disconnected after fuzz injection.
const DISCONNECT_TIMEOUT: Duration = Duration::from_millis(5);

/// Static key for the fuzzed handshake. This key is intentionally different
/// from the default sync connection key to keep the target from disconnecting
/// due to a duplicate peer connection.
const FUZZ_STATIC_KEY: [u8; 32] = [
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
];

/// A scenario that fuzzes the Noise protocol handshake (BOLT 8).
///
/// Uses the first byte of fuzz input to select the injection point:
/// - Act 1: sends fuzz bytes instead of a valid Act 1
/// - Act 3: performs valid Acts 1 & 2, then sends fuzz bytes instead of Act 3
/// - Post-handshake: completes the full handshake, then sends unencrypted fuzz
///   bytes
/// - Post-init header: completes handshake and init exchange, then sends
///   unencrypted fuzz bytes
/// - Post-init body: completes handshake and init exchange, sends a valid
///   encrypted length header, then sends raw fuzz bytes as the message body
///
/// A separate encrypted "sync" connection is established pre-snapshot for
/// synchronization. If the target doesn't disconnect after fuzz injection, a
/// ping-pong on the sync connection ensures the target has some time to process
/// the fuzz data before we check for crashes.
pub struct NoiseScenario<T: Target> {
    target: T,
    stream: TcpStream,
    sync_conn: NoiseConnection,
}

impl<T: Target> NoiseScenario<T> {
    /// Create a fresh initiator handshake using fixed keys.
    fn new_handshake(&self) -> NoiseHandshake {
        let local_static = SecretKey::from_slice(&FUZZ_STATIC_KEY).expect("valid static key");
        let local_ephemeral = SecretKey::from_slice(&EPHEMERAL_KEY).expect("valid ephemeral key");
        NoiseHandshake::new_initiator(local_static, local_ephemeral, *self.target.pubkey())
    }

    /// Complete the full Noise handshake (Acts 1-3) and derive the cipher.
    fn complete_handshake(&mut self) -> NoiseCipher {
        let mut handshake = self.new_handshake();
        let act_one = handshake.get_act_one().expect("act one successful");
        self.stream
            .write_all(&act_one)
            .expect("act one send successful");
        let mut act_two = [0u8; ACT_TWO_SIZE];
        self.stream
            .read_exact(&mut act_two)
            .expect("act two recv successful");
        let act_three = handshake
            .process_act_two(&act_two)
            .expect("act two processing successful");
        self.stream
            .write_all(&act_three)
            .expect("act three send successful");
        handshake
            .into_cipher()
            .expect("cipher derivation successful")
    }

    /// Complete the init exchange: receive the target's init and echo it back.
    fn complete_init_exchange(&mut self, cipher: &mut NoiseCipher) {
        log::debug!("Waiting for target init message");
        let init_bytes = recv_message(&mut self.stream, cipher);
        let init = match Message::decode(&init_bytes).expect("valid init message") {
            Message::Init(init) => init,
            other => panic!("expected init(16), got {other}"),
        };
        let echo_init = Init::echo(&init);
        let encoded = Message::Init(echo_init).encode();
        let encrypted = cipher.encrypt(&encoded);
        self.stream
            .write_all(&encrypted)
            .expect("init echo send successful");
        log::debug!("Init exchange complete");
    }

    /// Check if the target disconnected after fuzz injection.
    ///
    /// Returns true if the target disconnected.
    fn target_disconnected(&mut self) -> bool {
        self.stream
            .set_read_timeout(Some(DISCONNECT_TIMEOUT))
            .expect("valid timeout");
        let mut buf = [0u8; 1024];
        let disconnected = match self.stream.read(&mut buf) {
            Ok(0) => {
                log::debug!("Target disconnected (EOF)");
                true
            }
            Ok(n) => {
                log::debug!("Target sent {n} bytes (still connected)");
                false
            }
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                log::debug!("Target silent (still connected)");
                false
            }
            Err(e) => {
                log::debug!("Target disconnected ({e})");
                true
            }
        };
        self.stream
            .set_read_timeout(Some(TIMEOUT))
            .expect("valid timeout");
        disconnected
    }

    /// Send fuzz data, ignoring connection resets from the target.
    ///
    /// For large inputs, the kernel may need multiple sends to transmit all
    /// the data. The target can process and reject the initial bytes (e.g.
    /// invalid Act 1) and send a TCP RST before transmission completes,
    /// causing `write_all` to fail with `ConnectionReset`.
    fn send_fuzz_data(&mut self, data: &[u8]) {
        match self.stream.write_all(data) {
            Ok(()) => {}
            Err(e)
                if e.kind() == ErrorKind::ConnectionReset || e.kind() == ErrorKind::BrokenPipe =>
            {
                log::debug!("Target closed connection during write: {e}");
            }
            Err(e) => panic!("fuzz data send failed: {e}"),
        }
    }

    /// Send fuzz bytes instead of a valid Act 1.
    fn fuzz_act_one(&mut self, data: &[u8]) {
        self.send_fuzz_data(data);
    }

    /// Perform valid Acts 1 & 2, then send fuzz bytes instead of Act 3.
    fn fuzz_act_three(&mut self, data: &[u8]) {
        let mut handshake = self.new_handshake();
        let act_one = handshake.get_act_one().expect("act one successful");
        self.stream
            .write_all(&act_one)
            .expect("act one send successful");
        let mut act_two = [0u8; ACT_TWO_SIZE];
        self.stream
            .read_exact(&mut act_two)
            .expect("act two recv successful");
        handshake
            .process_act_two(&act_two)
            .expect("act two processing successful");

        self.send_fuzz_data(data);
    }

    /// Complete the full handshake, then send raw fuzz bytes.
    fn fuzz_post_handshake(&mut self, data: &[u8]) {
        self.complete_handshake();
        self.send_fuzz_data(data);
    }

    /// Complete handshake and init exchange, then send raw fuzz bytes.
    fn fuzz_post_init_header(&mut self, data: &[u8]) {
        let mut cipher = self.complete_handshake();
        self.complete_init_exchange(&mut cipher);
        self.send_fuzz_data(data);
    }

    /// Complete handshake and init exchange, send a valid encrypted length
    /// header derived from the fuzz data, then send raw fuzz bytes as the
    /// message body.
    ///
    /// Requires that `data.len()` is at least 2.
    fn fuzz_post_init_body(&mut self, data: &[u8]) {
        let mut cipher = self.complete_handshake();
        self.complete_init_exchange(&mut cipher);

        // First two bytes of data choose the body length; remaining bytes are
        // the raw body. This lets the fuzzer explore length/body mismatches.
        let body_len = u16::from_be_bytes([data[0], data[1]]);
        let encrypted_len = cipher.encrypt_length(body_len);
        let mut packet = Vec::with_capacity(encrypted_len.len() + data.len() - 2);
        packet.extend_from_slice(&encrypted_len);
        packet.extend_from_slice(&data[2..]);
        self.send_fuzz_data(&packet);
    }
}

/// Receive and decrypt a message from a raw stream + cipher.
fn recv_message(stream: &mut TcpStream, cipher: &mut NoiseCipher) -> Vec<u8> {
    let mut encrypted_len = [0u8; ENCRYPTED_LENGTH_SIZE];
    stream
        .read_exact(&mut encrypted_len)
        .expect("length read successful");
    let msg_len = cipher
        .decrypt_length(&encrypted_len)
        .expect("length decryption successful");

    let encrypted_msg_len = usize::from(msg_len) + MAC_SIZE;
    let mut encrypted_msg = vec![0u8; encrypted_msg_len];
    stream
        .read_exact(&mut encrypted_msg)
        .expect("message read successful");
    cipher
        .decrypt_message(&encrypted_msg)
        .expect("message decryption successful")
}

impl<T: Target> Scenario for NoiseScenario<T> {
    fn new(_args: &[String]) -> Result<Self, ScenarioError> {
        let config = T::Config::default();
        let target = T::start(config)?;

        // Establish a connection for ping-pong synchronization. This also warms
        // up the target's message handling code paths before the Nyx snapshot,
        // improving fuzzing efficiency for JVM targets.
        let (mut sync_conn, target_init) = handshake_with_target(&target, TIMEOUT)?;
        let echo = Message::Init(Init::echo(&target_init)).encode();
        sync_conn.send_message(&echo)?;
        ping_pong(&mut sync_conn)?;

        // Establish the fuzz connection that will be snapshotted in its
        // pre-handshake state.
        let stream = TcpStream::connect_timeout(&target.addr(), TIMEOUT)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        Ok(Self {
            target,
            stream,
            sync_conn,
        })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        if input.is_empty() {
            return ScenarioResult::Skip;
        }

        let start = std::time::Instant::now();
        let mode = input[0] % 5;
        let data = &input[1..];

        match mode {
            0 => {
                log::debug!(
                    "[{:?}] Fuzzing Act 1 ({} bytes)",
                    start.elapsed(),
                    data.len()
                );
                self.fuzz_act_one(data);
            }
            1 => {
                log::debug!(
                    "[{:?}] Fuzzing Act 3 ({} bytes)",
                    start.elapsed(),
                    data.len()
                );
                self.fuzz_act_three(data);
            }
            2 => {
                log::debug!(
                    "[{:?}] Fuzzing post-handshake ({} bytes)",
                    start.elapsed(),
                    data.len()
                );
                self.fuzz_post_handshake(data);
            }
            3 => {
                log::debug!(
                    "[{:?}] Fuzzing post-init header ({} bytes)",
                    start.elapsed(),
                    data.len()
                );
                self.fuzz_post_init_header(data);
            }
            4 => {
                // Two bytes are needed to derive a valid header.
                if data.len() < 2 {
                    return ScenarioResult::Skip;
                }
                log::debug!(
                    "[{:?}] Fuzzing post-init body ({} bytes)",
                    start.elapsed(),
                    data.len()
                );
                self.fuzz_post_init_body(data);
            }
            _ => unreachable!(),
        }

        // If the target didn't disconnect, sync via ping-pong on the side
        // connection to ensure it has processed the fuzz data.
        if !self.target_disconnected() {
            log::debug!("[{:?}] Syncing via ping-pong", start.elapsed());
            if let Err(e) = ping_pong(&mut self.sync_conn) {
                log::debug!("[{:?}] Sync ping-pong failed: {e}", start.elapsed());
                let violation = if e.is_timeout() {
                    Violation::Hung
                } else {
                    Violation::UnexpectedDisconnect
                };
                return ScenarioResult::Fail(violation.to_string());
            }
        }

        log::debug!("[{:?}] Fuzz injection complete", start.elapsed());

        if let Err(e) = self.target.check_alive() {
            log::debug!("[{:?}] check_alive: {e}", start.elapsed());
            return ScenarioResult::Fail(Violation::Crashed.to_string());
        }

        log::debug!("[{:?}] Target still alive", start.elapsed());
        ScenarioResult::Ok
    }
}
