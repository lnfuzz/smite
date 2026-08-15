//! BOLT 4 payment onion packet construction and decryption.

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use super::OnionError;
use super::keys::{KeyType, apply_stream, derive_key, hmac};
use super::payload::HopPayload;
use crate::bolt::{BigSize, BoltError, PUBLIC_KEY_SIZE, WireFormat};

/// The only onion packet version defined by BOLT 4.
pub const ONION_VERSION: u8 = 0;

/// Size of a payment onion's fixed-length `hop_payloads` field in bytes.
///
/// Onion messages size this field differently, so it is not a property of
/// onion packets in general.
pub const PAYMENT_HOP_PAYLOADS_SIZE: usize = 1300;

/// Size of the packet HMAC in bytes.
pub const HMAC_SIZE: usize = 32;

/// Total serialized size of a payment onion packet in bytes.
pub const PAYMENT_ONION_PACKET_SIZE: usize =
    1 + PUBLIC_KEY_SIZE + PAYMENT_HOP_PAYLOADS_SIZE + HMAC_SIZE;

/// Size of the working buffer a hop deobfuscates into: `hop_payloads` plus the
/// zero padding appended before decryption.
const STREAM_SIZE: usize = 2 * PAYMENT_HOP_PAYLOADS_SIZE;

/// [`PAYMENT_HOP_PAYLOADS_SIZE`] as a `u64`, to compare against wire-declared
/// lengths.
const PAYMENT_HOP_PAYLOADS_CAPACITY: u64 = PAYMENT_HOP_PAYLOADS_SIZE as u64;

/// A BOLT 4 payment onion packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPacket {
    /// Packet version, 0 for this specification.
    pub version: u8,
    /// Ephemeral public key used to derive the receiving hop's shared secret.
    pub public_key: PublicKey,
    /// The obfuscated per-hop routing information.
    pub hop_payloads: [u8; PAYMENT_HOP_PAYLOADS_SIZE],
    /// HMAC over `hop_payloads` and the associated data.
    pub hmac: [u8; HMAC_SIZE],
}

impl OnionPacket {
    /// Encodes the packet to its 1366-byte wire representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYMENT_ONION_PACKET_SIZE);
        self.write(&mut out);
        out
    }

    /// Decodes a packet from exactly 1366 bytes.
    ///
    /// # Errors
    ///
    /// Returns `Bolt(Truncated)` unless the input is exactly
    /// [`PAYMENT_ONION_PACKET_SIZE`] bytes, or `Bolt(InvalidPublicKey)` if the
    /// ephemeral key is not a valid point.
    pub fn decode(data: &[u8]) -> Result<Self, OnionError> {
        if data.len() != PAYMENT_ONION_PACKET_SIZE {
            return Err(BoltError::Truncated {
                expected: PAYMENT_ONION_PACKET_SIZE,
                actual: data.len(),
            }
            .into());
        }
        let mut cursor = data;
        Ok(Self::read(&mut cursor)?)
    }
}

impl WireFormat for OnionPacket {
    fn read(data: &mut &[u8]) -> Result<Self, crate::bolt::BoltError> {
        let version = u8::read(data)?;
        let public_key = PublicKey::read(data)?;
        let hop_payloads: [u8; PAYMENT_HOP_PAYLOADS_SIZE] = WireFormat::read(data)?;
        let hmac: [u8; HMAC_SIZE] = WireFormat::read(data)?;
        Ok(Self {
            version,
            public_key,
            hop_payloads,
            hmac,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.version.write(out);
        self.public_key.write(out);
        self.hop_payloads.write(out);
        self.hmac.write(out);
    }
}

/// One hop of a route, with the payload bytes destined for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    /// The hop's node ID (or its blinded node ID inside a blinded path).
    pub node_id: PublicKey,
    /// The payload bytes, excluding the `bigsize` length prefix and the HMAC.
    pub payload: Vec<u8>,
}

/// A constructed onion packet and the shared secrets used to build it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltOnion {
    /// The packet, ready to be placed in `update_add_htlc`.
    pub packet: OnionPacket,
    /// One shared secret per hop, in route order.
    ///
    /// Keep these: they are what decrypts an error returned along the route,
    /// and they identify which hop sent it.
    pub shared_secrets: Vec<SharedSecret>,
}

/// Builds payment onions for a route.
///
/// The builder is reusable: [`build`](Self::build) borrows it, so variations
/// of the same route can be produced from one instance.
#[derive(Debug, Clone)]
pub struct OnionBuilder {
    session_key: SecretKey,
    associated_data: Vec<u8>,
    version: u8,
    hops: Vec<Hop>,
}

impl OnionBuilder {
    /// Starts a route with the given single-use session key.
    #[must_use]
    pub fn new(session_key: SecretKey) -> Self {
        Self {
            session_key,
            associated_data: Vec::new(),
            version: ONION_VERSION,
            hops: Vec::new(),
        }
    }

    /// Sets the associated data committed to by every hop's HMAC.
    ///
    /// For payment onions this is the `payment_hash`.
    #[must_use]
    pub fn associated_data(mut self, associated_data: impl Into<Vec<u8>>) -> Self {
        self.associated_data = associated_data.into();
        self
    }

    /// Overrides the `version` byte, which readers must reject unless it is 0.
    #[must_use]
    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Appends a hop carrying an encoded [`HopPayload`].
    #[must_use]
    pub fn hop(self, node_id: PublicKey, payload: &HopPayload) -> Self {
        self.raw_hop(node_id, payload.encode())
    }

    /// Appends a hop carrying arbitrary payload bytes.
    ///
    /// Nothing about `payload` is validated, so this can produce the reserved
    /// lengths 0 and 1, malformed TLV streams, and payloads that overflow the
    /// packet (which [`build`](Self::build) reports as
    /// [`OnionError::PayloadsTooLong`]).
    #[must_use]
    pub fn raw_hop(mut self, node_id: PublicKey, payload: Vec<u8>) -> Self {
        self.hops.push(Hop { node_id, payload });
        self
    }

    /// Constructs the packet.
    ///
    /// # Errors
    ///
    /// Returns [`OnionError::NoHops`] for an empty route,
    /// [`OnionError::PayloadsTooLong`] if the payloads exceed 1300 bytes, and
    /// [`OnionError::KeyBlindingFailed`] if key blinding yields an invalid key.
    pub fn build(&self) -> Result<BuiltOnion, OnionError> {
        if self.hops.is_empty() {
            return Err(OnionError::NoHops);
        }

        let mut needed = 0usize;
        for hop in &self.hops {
            needed = needed.saturating_add(shift_size(hop.payload.len()));
        }
        if needed > PAYMENT_HOP_PAYLOADS_SIZE {
            return Err(OnionError::PayloadsTooLong {
                needed: needed as u64,
                capacity: PAYMENT_HOP_PAYLOADS_CAPACITY,
            });
        }

        let node_ids: Vec<PublicKey> = self.hops.iter().map(|hop| hop.node_id).collect();
        let shared_secrets = derive_shared_secrets(&self.session_key, &node_ids)?;

        // The packet starts as pseudo-random bytes derived from the session
        // key, so unused space is indistinguishable from real payloads.
        let pad_key = derive_key(KeyType::Pad, &self.session_key.secret_bytes());
        let mut hop_payloads = [0u8; PAYMENT_HOP_PAYLOADS_SIZE];
        apply_stream(&pad_key, &mut hop_payloads);

        let filler = generate_filler(&shared_secrets, &self.hops);

        let mut next_hmac = [0u8; HMAC_SIZE];
        for (i, hop) in self.hops.iter().enumerate().rev() {
            let secret = shared_secrets[i].secret_bytes();
            let rho = derive_key(KeyType::Rho, &secret);
            let mu = derive_key(KeyType::Mu, &secret);
            let shift = shift_size(hop.payload.len());

            hop_payloads.copy_within(..PAYMENT_HOP_PAYLOADS_SIZE - shift, shift);
            let mut header = Vec::with_capacity(shift);
            BigSize::new(hop.payload.len() as u64).write(&mut header);
            header.extend_from_slice(&hop.payload);
            header.extend_from_slice(&next_hmac);
            hop_payloads[..shift].copy_from_slice(&header);

            apply_stream(&rho, &mut hop_payloads);

            // The last hop's tail must equal the padding the earlier hops will
            // generate as they peel, or their HMACs will not match.
            if i == self.hops.len() - 1 {
                hop_payloads[PAYMENT_HOP_PAYLOADS_SIZE - filler.len()..].copy_from_slice(&filler);
            }

            next_hmac = hmac(&mu, &[&hop_payloads, &self.associated_data]);
        }

        let secp = Secp256k1::new();
        Ok(BuiltOnion {
            packet: OnionPacket {
                version: self.version,
                public_key: PublicKey::from_secret_key(&secp, &self.session_key),
                hop_payloads,
                hmac: next_hmac,
            },
            shared_secrets,
        })
    }
}

/// The result of peeling one layer off an onion packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Peeled {
    /// This node is an intermediate hop and should forward `next`.
    Forward {
        /// The payload destined for this node.
        payload: Vec<u8>,
        /// The packet to forward to the next hop.
        next: OnionPacket,
        /// The shared secret with the origin node.
        shared_secret: SharedSecret,
    },
    /// This node is the final recipient.
    Final {
        /// The payload destined for this node.
        payload: Vec<u8>,
        /// The shared secret with the origin node.
        shared_secret: SharedSecret,
    },
}

impl Peeled {
    /// Returns the payload destined for this node.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Forward { payload, .. } | Self::Final { payload, .. } => payload,
        }
    }

    /// Returns the shared secret with the origin node.
    #[must_use]
    pub fn shared_secret(&self) -> &SharedSecret {
        match self {
            Self::Forward { shared_secret, .. } | Self::Final { shared_secret, .. } => {
                shared_secret
            }
        }
    }
}

/// Peels one layer off a packet addressed to `node_key`.
///
/// `path_key` is the `current_path_key` of a blinded path, which tweaks the
/// node key before the shared secret is derived.
///
/// # Errors
///
/// Returns [`OnionError::InvalidVersion`] for a non-zero version,
/// [`OnionError::HmacMismatch`] if the packet is not authentic,
/// [`OnionError::PayloadTooShort`] for the reserved lengths 0 and 1,
/// [`OnionError::PayloadsTooLong`] if the declared payload does not fit,
/// [`OnionError::KeyBlindingFailed`] if tweaking the node key or deriving the
/// next ephemeral key yields an invalid key, and [`OnionError::Bolt`] if the
/// length prefix is malformed.
pub fn peel(
    packet: &OnionPacket,
    node_key: &SecretKey,
    associated_data: &[u8],
    path_key: Option<&PublicKey>,
) -> Result<Peeled, OnionError> {
    if packet.version != ONION_VERSION {
        return Err(OnionError::InvalidVersion(packet.version));
    }

    let node_key = match path_key {
        Some(path_key) => blind_node_key(node_key, path_key)?,
        None => *node_key,
    };

    let shared_secret = SharedSecret::new(&packet.public_key, &node_key);
    let mu = derive_key(KeyType::Mu, &shared_secret.secret_bytes());
    let expected = hmac(&mu, &[&packet.hop_payloads, associated_data]);
    // Not a constant-time comparison: this crate drives other implementations
    // under test, it is not a forwarding node with a secret to leak.
    if expected != packet.hmac {
        return Err(OnionError::HmacMismatch);
    }

    // Deobfuscating a zero-extended buffer regenerates the padding the sender
    // accounted for in the filler, keeping the packet a constant size.
    let rho = derive_key(KeyType::Rho, &shared_secret.secret_bytes());
    let mut unwrapped = vec![0u8; STREAM_SIZE];
    unwrapped[..PAYMENT_HOP_PAYLOADS_SIZE].copy_from_slice(&packet.hop_payloads);
    apply_stream(&rho, &mut unwrapped);

    let mut cursor: &[u8] = &unwrapped;
    let length = BigSize::read(&mut cursor)?.value();
    if length < 2 {
        return Err(OnionError::PayloadTooShort(length));
    }

    // Measure what the reader consumed rather than recomputing the prefix
    // width from `length`, so the payload boundary cannot drift from the
    // `bigsize` decoder.
    let prefix_len = unwrapped.len() - cursor.len();
    let needed = (prefix_len as u64)
        .saturating_add(length)
        .saturating_add(HMAC_SIZE as u64);
    let Some(shift) = usize::try_from(needed)
        .ok()
        .filter(|shift| *shift <= PAYMENT_HOP_PAYLOADS_SIZE)
    else {
        return Err(OnionError::PayloadsTooLong {
            needed,
            capacity: PAYMENT_HOP_PAYLOADS_CAPACITY,
        });
    };
    let payload_end = shift - HMAC_SIZE;

    let payload = unwrapped[prefix_len..payload_end].to_vec();
    let mut next_hmac = [0u8; HMAC_SIZE];
    next_hmac.copy_from_slice(&unwrapped[payload_end..shift]);

    if next_hmac == [0u8; HMAC_SIZE] {
        return Ok(Peeled::Final {
            payload,
            shared_secret,
        });
    }

    let mut hop_payloads = [0u8; PAYMENT_HOP_PAYLOADS_SIZE];
    hop_payloads.copy_from_slice(&unwrapped[shift..shift + PAYMENT_HOP_PAYLOADS_SIZE]);

    let secp = Secp256k1::new();
    let tweak = blinding_factor(&packet.public_key, &shared_secret)?;
    let next_public_key = packet
        .public_key
        .mul_tweak(&secp, &tweak)
        .map_err(|_| OnionError::KeyBlindingFailed)?;

    Ok(Peeled::Forward {
        payload,
        next: OnionPacket {
            version: ONION_VERSION,
            public_key: next_public_key,
            hop_payloads,
            hmac: next_hmac,
        },
        shared_secret,
    })
}

/// Derives the shared secret for each node of a route, in route order.
///
/// # Errors
///
/// Returns [`OnionError::KeyBlindingFailed`] if blinding the ephemeral key
/// yields an invalid key.
pub fn derive_shared_secrets(
    session_key: &SecretKey,
    node_ids: &[PublicKey],
) -> Result<Vec<SharedSecret>, OnionError> {
    let secp = Secp256k1::new();
    let mut ephemeral_key = *session_key;
    let mut secrets = Vec::with_capacity(node_ids.len());

    for node_id in node_ids {
        let shared_secret = SharedSecret::new(node_id, &ephemeral_key);
        let ephemeral_public = PublicKey::from_secret_key(&secp, &ephemeral_key);
        let tweak = blinding_factor(&ephemeral_public, &shared_secret)?;
        ephemeral_key = ephemeral_key
            .mul_tweak(&tweak)
            .map_err(|_| OnionError::KeyBlindingFailed)?;
        secrets.push(shared_secret);
    }

    Ok(secrets)
}

/// The blinding factor `SHA256(ephemeral_public_key || shared_secret)`.
fn blinding_factor(
    ephemeral_public: &PublicKey,
    shared_secret: &SharedSecret,
) -> Result<Scalar, OnionError> {
    let mut engine = Sha256::engine();
    engine.input(&ephemeral_public.serialize());
    engine.input(&shared_secret.secret_bytes());
    let hash = Sha256::from_engine(engine).to_byte_array();

    Scalar::from_be_bytes(hash).map_err(|_| OnionError::KeyBlindingFailed)
}

/// Tweaks a node key with the blinded path's `path_key`, per BOLT 4 route
/// blinding.
fn blind_node_key(node_key: &SecretKey, path_key: &PublicKey) -> Result<SecretKey, OnionError> {
    let blinding_secret = SharedSecret::new(path_key, node_key);
    let tweak = hmac(b"blinded_node_id", &[&blinding_secret.secret_bytes()]);
    let tweak = Scalar::from_be_bytes(tweak).map_err(|_| OnionError::KeyBlindingFailed)?;
    node_key
        .mul_tweak(&tweak)
        .map_err(|_| OnionError::KeyBlindingFailed)
}

/// The BOLT 4 `shift_size`: bytes a payload of `payload_len` occupies in
/// `hop_payloads`: its `bigsize` length prefix, the payload itself, and the
/// next hop's HMAC.
fn shift_size(payload_len: usize) -> usize {
    BigSize::new(payload_len as u64)
        .len()
        .saturating_add(payload_len)
        .saturating_add(HMAC_SIZE)
}

/// Generates the deterministic padding that the hops before the last one add
/// as they peel.
///
/// Each hop XORs a zero-extended buffer with its `rho` stream, so the tail of
/// the packet that reaches hop `k` is fully determined by the shared secrets of
/// hops `0..k`. The sender must reproduce it or the HMACs will not match.
fn generate_filler(shared_secrets: &[SharedSecret], hops: &[Hop]) -> Vec<u8> {
    debug_assert!(!hops.is_empty(), "build rejects empty routes");

    let mut filler: Vec<u8> = Vec::new();

    for (secret, hop) in shared_secrets.iter().zip(hops).take(hops.len() - 1) {
        let rho = derive_key(KeyType::Rho, &secret.secret_bytes());
        let mut stream = vec![0u8; STREAM_SIZE];
        apply_stream(&rho, &mut stream);

        debug_assert!(
            filler.len() <= PAYMENT_HOP_PAYLOADS_SIZE,
            "build rejects routes whose payloads exceed the packet"
        );

        // What this hop already holds is obfuscated once more, ...
        let start = PAYMENT_HOP_PAYLOADS_SIZE - filler.len();
        for (byte, stream_byte) in filler
            .iter_mut()
            .zip(&stream[start..PAYMENT_HOP_PAYLOADS_SIZE])
        {
            *byte ^= stream_byte;
        }
        // ... and the zeros it appends become the next hop's new tail.
        let shift = shift_size(hop.payload.len());
        filler.extend_from_slice(
            &stream[PAYMENT_HOP_PAYLOADS_SIZE..PAYMENT_HOP_PAYLOADS_SIZE + shift],
        );
    }

    filler
}
