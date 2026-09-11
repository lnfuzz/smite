//! BOLT 4 test vectors and round-trip properties.

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde::Deserialize;

use super::keys::hmac;
use super::{
    HopPayload, KEY_SIZE, KeyType, ONION_VERSION, OnionBuilder, OnionError, OnionPacket,
    PAYMENT_HOP_PAYLOADS_SIZE, PaymentData, Peeled, apply_stream, derive_key,
    derive_shared_secrets, peel,
};
use crate::bolt::{BigSize, BoltError, PAYMENT_ONION_PACKET_SIZE, ShortChannelId, WireFormat};

/// The `onion-test.json` vector from the BOLT repository, verbatim.
const ONION_TEST: &str = include_str!("test_vectors/onion-test.json");

/// The `onion-error-test.json` vector from the BOLT repository, verbatim.
///
/// Currently only its key derivation is checked.
/// TODO: check the return packet once failure messages land.
const ONION_ERROR_TEST: &str = include_str!("test_vectors/onion-error-test.json");

/// `onion-test.json`: a route, the packet it builds, and each hop's private key.
#[derive(Deserialize)]
struct OnionTest {
    generate: OnionTestRoute,
    #[serde(with = "hex")]
    onion: Vec<u8>,
    /// Hop private keys, in route order.
    decode: Vec<SecretKey>,
}

#[derive(Deserialize)]
struct OnionTestRoute {
    session_key: SecretKey,
    #[serde(with = "hex")]
    associated_data: Vec<u8>,
    hops: Vec<OnionTestHop>,
}

#[derive(Deserialize)]
struct OnionTestHop {
    pubkey: PublicKey,
    /// The hop payload, prefixed with its `bigsize` length.
    #[serde(with = "hex")]
    payload: Vec<u8>,
}

/// `onion-error-test.json`; the error packet itself is not decoded yet.
#[derive(Deserialize)]
struct OnionErrorTest {
    generate: OnionErrorTestRoute,
}

#[derive(Deserialize)]
struct OnionErrorTestRoute {
    session_key: SecretKey,
    hops: Vec<OnionErrorTestHop>,
}

#[derive(Deserialize)]
struct OnionErrorTestHop {
    pubkey: PublicKey,
    hop_shared_secret: SharedSecret,
    ammag_key: HexKey,
    /// Only listed for the erring node.
    um_key: Option<HexKey>,
}

#[derive(Deserialize)]
struct HexKey(#[serde(with = "hex")] [u8; KEY_SIZE]);

fn onion_test() -> OnionTest {
    serde_json::from_str(ONION_TEST).expect("valid test vector file")
}

fn onion_error_test() -> OnionErrorTest {
    serde_json::from_str(ONION_ERROR_TEST).expect("valid test vector file")
}

/// The vector's payloads carry their `bigsize` length prefix; the builder adds
/// its own, so strip it.
fn strip_length_prefix(payload: &[u8]) -> Vec<u8> {
    let mut cursor = payload;
    let length = BigSize::read(&mut cursor).expect("length prefix is valid");
    assert_eq!(
        u64::try_from(cursor.len()).unwrap(),
        length.value(),
        "vector payload length prefix disagrees with its body"
    );
    cursor.to_vec()
}

/// Deterministic keys for the property tests: hop `i` uses secret key `[i; 32]`.
fn route(hops: usize) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let secp = Secp256k1::new();
    let secrets: Vec<SecretKey> = (1..=hops)
        .map(|i| SecretKey::from_slice(&[u8::try_from(i).unwrap(); 32]).unwrap())
        .collect();
    let publics = secrets
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();
    (secrets, publics)
}

fn session_key() -> SecretKey {
    SecretKey::from_slice(&[0x41; 32]).unwrap()
}

/// Peels `packet` with each hop key in turn, returning the payload each hop
/// saw. Asserts that exactly the last hop is the final one.
fn peel_route(
    packet: &OnionPacket,
    hop_keys: &[SecretKey],
    associated_data: &[u8],
) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut current = packet.clone();

    for (i, hop_key) in hop_keys.iter().enumerate() {
        let is_last = i == hop_keys.len() - 1;
        match peel(&current, hop_key, associated_data, None).expect("packet peels") {
            Peeled::Forward { payload, next, .. } => {
                assert!(!is_last, "hop {i} forwards but should be final");
                payloads.push(payload);
                current = next;
            }
            Peeled::Final { payload, .. } => {
                assert!(is_last, "hop {i} is final but should forward");
                payloads.push(payload);
            }
        }
    }

    payloads
}

#[test]
fn bolt4_vector_construct_matches_reference_packet() {
    let vector = onion_test();
    let generate = vector.generate;

    let mut builder =
        OnionBuilder::new(generate.session_key).associated_data(generate.associated_data);
    for hop in generate.hops {
        builder = builder.raw_hop(hop.pubkey, strip_length_prefix(&hop.payload));
    }

    let built = builder.build().expect("vector route fits");

    assert_eq!(built.packet.encode(), vector.onion);
}

#[test]
fn bolt4_vector_peels_at_every_hop() {
    let vector = onion_test();
    let packet = OnionPacket::decode(&vector.onion).expect("vector packet decodes");

    let expected: Vec<Vec<u8>> = vector
        .generate
        .hops
        .iter()
        .map(|hop| strip_length_prefix(&hop.payload))
        .collect();

    assert_eq!(
        peel_route(&packet, &vector.decode, &vector.generate.associated_data),
        expected
    );
}

#[test]
fn bolt4_vector_hop_payload_decodes() {
    let payload = strip_length_prefix(&onion_test().generate.hops[0].payload);

    let decoded = HopPayload::decode(&payload).expect("vector payload decodes");

    assert_eq!(
        decoded,
        HopPayload::forward(ShortChannelId::from_u64(1), 15_000, 1_500)
    );
    assert_eq!(decoded.encode(), payload);
}

#[test]
fn bolt4_vector_derives_shared_secrets_and_keys() {
    let generate = onion_error_test().generate;

    let node_ids: Vec<PublicKey> = generate.hops.iter().map(|hop| hop.pubkey).collect();
    let secrets =
        derive_shared_secrets(&generate.session_key, &node_ids).expect("vector keys blind");

    for (hop, secret) in generate.hops.iter().zip(&secrets) {
        assert_eq!(*secret, hop.hop_shared_secret);
        assert_eq!(
            derive_key(KeyType::Ammag, &secret.secret_bytes()),
            hop.ammag_key.0
        );
        // Only the erring node's `um` key is listed.
        if let Some(um_key) = &hop.um_key {
            assert_eq!(derive_key(KeyType::Um, &secret.secret_bytes()), um_key.0);
        }
    }
}

#[test]
fn roundtrip_over_varying_payload_sizes() {
    for hops in 1..=5usize {
        let (secrets, publics) = route(hops);
        let payloads: Vec<Vec<u8>> = (0..hops)
            .map(|i| vec![u8::try_from(i).unwrap(); 2 + i * 37])
            .collect();

        let mut builder = OnionBuilder::new(session_key()).associated_data([0x42; 32]);
        for (public, payload) in publics.iter().zip(&payloads) {
            builder = builder.raw_hop(*public, payload.clone());
        }
        let built = builder.build().expect("route fits");

        assert_eq!(built.shared_secrets.len(), hops);
        assert_eq!(peel_route(&built.packet, &secrets, &[0x42; 32]), payloads);
    }
}

#[test]
fn roundtrip_fills_the_packet_exactly() {
    // 20 hops * (1 length + 32 payload + 32 hmac) = 1300 bytes.
    let hops = 20;
    let (secrets, publics) = route(hops);
    let payloads: Vec<Vec<u8>> = (0..hops)
        .map(|i| vec![u8::try_from(i).unwrap(); 32])
        .collect();

    let mut builder = OnionBuilder::new(session_key());
    for (public, payload) in publics.iter().zip(&payloads) {
        builder = builder.raw_hop(*public, payload.clone());
    }
    let built = builder.build().expect("exactly full route fits");

    assert_eq!(peel_route(&built.packet, &secrets, &[]), payloads);
}

#[test]
fn build_rejects_payloads_that_overflow_the_packet() {
    let (_, publics) = route(1);

    // 3-byte length prefix + 1266-byte payload + 32-byte HMAC is one byte too many.
    let built = OnionBuilder::new(session_key())
        .raw_hop(publics[0], vec![0xab; 1266])
        .build();

    assert_eq!(
        built,
        Err(OnionError::PayloadsTooLong {
            needed: 1301,
            capacity: PAYMENT_HOP_PAYLOADS_SIZE as u64,
        })
    );
}

#[test]
fn build_rejects_empty_route() {
    assert_eq!(
        OnionBuilder::new(session_key()).build(),
        Err(OnionError::NoHops)
    );
}

#[test]
fn peel_rejects_unknown_version() {
    let (secrets, publics) = route(1);
    let built = OnionBuilder::new(session_key())
        .version(1)
        .raw_hop(publics[0], vec![0x02; 8])
        .build()
        .expect("route fits");

    assert_eq!(
        peel(&built.packet, &secrets[0], &[], None),
        Err(OnionError::InvalidVersion(1))
    );
}

#[test]
fn peel_rejects_tampered_payloads() {
    let (secrets, publics) = route(2);
    let built = OnionBuilder::new(session_key())
        .raw_hop(publics[0], vec![0x02; 8])
        .raw_hop(publics[1], vec![0x03; 8])
        .build()
        .expect("route fits");

    let mut packet = built.packet;
    packet.hop_payloads[0] ^= 0x01;

    assert_eq!(
        peel(&packet, &secrets[0], &[], None),
        Err(OnionError::HmacMismatch)
    );
}

#[test]
fn peel_rejects_wrong_associated_data() {
    let (secrets, publics) = route(1);
    let built = OnionBuilder::new(session_key())
        .associated_data([0x42; 32])
        .raw_hop(publics[0], vec![0x02; 8])
        .build()
        .expect("route fits");

    assert_eq!(
        peel(&built.packet, &secrets[0], &[0x43; 32], None),
        Err(OnionError::HmacMismatch)
    );
}

#[test]
fn peel_rejects_reserved_payload_lengths() {
    // Lengths 0 and 1 are reserved: 0 was the legacy format, 1 is unassigned.
    for reserved in 0..2usize {
        let (secrets, publics) = route(1);
        let built = OnionBuilder::new(session_key())
            .raw_hop(publics[0], vec![0xff; reserved])
            .build()
            .expect("route fits");

        assert_eq!(
            peel(&built.packet, &secrets[0], &[], None),
            Err(OnionError::PayloadTooShort(reserved as u64))
        );
    }
}

#[test]
fn packet_decode_requires_exact_size() {
    let (_, publics) = route(1);
    let built = OnionBuilder::new(session_key())
        .raw_hop(publics[0], vec![0x02; 8])
        .build()
        .expect("route fits");
    let encoded = built.packet.encode();

    assert_eq!(encoded.len(), PAYMENT_ONION_PACKET_SIZE);
    assert_eq!(
        OnionPacket::decode(&encoded[..encoded.len() - 1]),
        Err(OnionError::Bolt(BoltError::Truncated {
            expected: PAYMENT_ONION_PACKET_SIZE,
            actual: PAYMENT_ONION_PACKET_SIZE - 1,
        }))
    );
    let mut oversized = encoded.clone();
    oversized.push(0);
    assert_eq!(
        OnionPacket::decode(&oversized),
        Err(OnionError::Bolt(BoltError::Truncated {
            expected: PAYMENT_ONION_PACKET_SIZE,
            actual: PAYMENT_ONION_PACKET_SIZE + 1,
        }))
    );
    assert_eq!(OnionPacket::decode(&encoded).unwrap(), built.packet);
}

#[test]
fn packet_decode_rejects_an_invalid_ephemeral_key() {
    let (_, publics) = route(1);
    let built = OnionBuilder::new(session_key())
        .raw_hop(publics[0], vec![0x02; 8])
        .build()
        .expect("route fits");

    // The ephemeral key follows the version byte; 0x04 is not a valid
    // compressed-point prefix.
    let mut encoded = built.packet.encode();
    encoded[1] = 0x04;
    let mut key = built.packet.public_key.serialize();
    key[0] = 0x04;

    assert_eq!(
        OnionPacket::decode(&encoded),
        Err(OnionError::Bolt(BoltError::InvalidPublicKey(key)))
    );
}

#[test]
fn hop_payload_roundtrips_every_field() {
    let (_, publics) = route(1);
    let payload = HopPayload {
        amt_to_forward: Some(1_000_000),
        outgoing_cltv_value: Some(700_000),
        short_channel_id: Some(ShortChannelId::new(700_000, 3, 1)),
        payment_data: Some(PaymentData {
            payment_secret: [0x11; 32],
            total_msat: 2_000_000,
        }),
        encrypted_recipient_data: Some(vec![0x22; 16]),
        current_path_key: Some(publics[0]),
        payment_metadata: Some(vec![0x33; 8]),
        total_amount_msat: Some(3_000_000),
    };

    assert_eq!(HopPayload::decode(&payload.encode()).unwrap(), payload);
}

#[test]
fn hop_payload_encodes_zero_amounts_as_empty_values() {
    let payload = HopPayload {
        amt_to_forward: Some(0),
        outgoing_cltv_value: Some(0),
        ..HopPayload::default()
    };

    // Two records, each with a zero-length truncated integer value.
    assert_eq!(payload.encode(), vec![2, 0, 4, 0]);
    assert_eq!(HopPayload::decode(&payload.encode()).unwrap(), payload);
}

#[test]
fn hop_payload_rejects_non_minimal_truncated_integers() {
    // amt_to_forward with a leading zero byte.
    let payload = [2u8, 2, 0, 1];

    assert_eq!(
        HopPayload::decode(&payload),
        Err(OnionError::Bolt(BoltError::TruncatedIntNotMinimal))
    );
}

#[test]
fn hop_payload_rejects_unknown_even_types() {
    let payload = [20u8, 1, 0];

    assert_eq!(
        HopPayload::decode(&payload),
        Err(OnionError::Bolt(BoltError::TlvUnknownEvenType(20)))
    );
}

#[test]
fn hop_payload_receive_roundtrips() {
    let payload = HopPayload::receive(1_000, 800_000, [0x77; 32], 5_000);

    assert_eq!(
        payload.payment_data,
        Some(PaymentData {
            payment_secret: [0x77; 32],
            total_msat: 5_000,
        })
    );
    assert_eq!(HopPayload::decode(&payload.encode()).unwrap(), payload);
}

#[test]
fn builds_and_peels_a_typed_two_hop_route() {
    let (secrets, publics) = route(2);
    let forward = HopPayload::forward(ShortChannelId::new(800_000, 5, 1), 1_000_500, 700_100);
    let receive = HopPayload::receive(1_000_000, 700_000, [0x66; 32], 1_000_000);

    let built = OnionBuilder::new(session_key())
        .associated_data([0x11; 32])
        .hop(publics[0], &forward)
        .hop(publics[1], &receive)
        .build()
        .expect("route fits");

    let peeled = peel(&built.packet, &secrets[0], &[0x11; 32], None).expect("first hop peels");
    assert_eq!(HopPayload::decode(peeled.payload()).unwrap(), forward);
    assert_eq!(peeled.shared_secret(), &built.shared_secrets[0]);

    let Peeled::Forward { next, .. } = peeled else {
        panic!("first hop should forward")
    };
    let peeled = peel(&next, &secrets[1], &[0x11; 32], None).expect("second hop peels");
    assert_eq!(HopPayload::decode(peeled.payload()).unwrap(), receive);
    assert_eq!(peeled.shared_secret(), &built.shared_secrets[1]);
    assert!(matches!(peeled, Peeled::Final { .. }));
}

#[test]
fn peel_unwraps_a_blinded_hop() {
    let secp = Secp256k1::new();
    let node_key = SecretKey::from_slice(&[7; 32]).unwrap();
    let node_id = PublicKey::from_secret_key(&secp, &node_key);
    let path_secret = SecretKey::from_slice(&[9; 32]).unwrap();
    let path_key = PublicKey::from_secret_key(&secp, &path_secret);

    // The sender encrypts to the blinded node id; only a node holding both its
    // own key and the path key can undo the tweak.
    let blinding_secret = SharedSecret::new(&node_id, &path_secret);
    let tweak = hmac(b"blinded_node_id", &[&blinding_secret.secret_bytes()]);
    let blinded_node_id = node_id
        .mul_tweak(&secp, &Scalar::from_be_bytes(tweak).unwrap())
        .unwrap();

    let payload = HopPayload {
        encrypted_recipient_data: Some(vec![0x55; 24]),
        ..HopPayload::default()
    };
    let built = OnionBuilder::new(session_key())
        .hop(blinded_node_id, &payload)
        .build()
        .expect("route fits");

    let peeled =
        peel(&built.packet, &node_key, &[], Some(&path_key)).expect("blinded packet peels");
    assert_eq!(HopPayload::decode(peeled.payload()).unwrap(), payload);
    assert_eq!(peeled.shared_secret(), &built.shared_secrets[0]);

    // Without the path key, the onion is not addressed to this node.
    assert_eq!(
        peel(&built.packet, &node_key, &[], None),
        Err(OnionError::HmacMismatch)
    );
}

/// Builds a one-hop packet whose deobfuscated `hop_payloads` start with
/// `plaintext`, so `peel` can be driven past what the builder would produce.
fn craft_packet(node_key: &SecretKey, plaintext: &[u8]) -> OnionPacket {
    let secp = Secp256k1::new();
    let session = session_key();
    let node_id = PublicKey::from_secret_key(&secp, node_key);
    let shared_secret = SharedSecret::new(&node_id, &session).secret_bytes();

    let mut hop_payloads = [0u8; PAYMENT_HOP_PAYLOADS_SIZE];
    hop_payloads[..plaintext.len()].copy_from_slice(plaintext);
    apply_stream(&derive_key(KeyType::Rho, &shared_secret), &mut hop_payloads);

    let mu = derive_key(KeyType::Mu, &shared_secret);
    OnionPacket {
        version: ONION_VERSION,
        public_key: PublicKey::from_secret_key(&secp, &session),
        hmac: hmac(&mu, &[&hop_payloads, &[]]),
        hop_payloads,
    }
}

#[test]
fn peel_rejects_declared_lengths_that_overflow_the_packet() {
    let node_key = SecretKey::from_slice(&[3; 32]).unwrap();

    for (prefix, length) in [
        // The shortest length that overflows: 3 + 1266 + 32 = 1301 bytes.
        (vec![0xfd, 0x04, 0xf2], 1266u64),
        // Longer than `hop_payloads` itself.
        (vec![0xfd, 0x05, 0x15], 1301u64),
        // Lengths needing the 5- and 9-byte bigsize encodings, and the largest
        // length a bigsize can declare at all.
        (vec![0xfe, 0x00, 0x01, 0x00, 0x00], 0x1_0000u64),
        (vec![0xff, 0, 0, 0, 1, 0, 0, 0, 0], 0x1_0000_0000u64),
        (
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            u64::MAX,
        ),
    ] {
        let packet = craft_packet(&node_key, &prefix);

        assert_eq!(
            peel(&packet, &node_key, &[], None),
            Err(OnionError::PayloadsTooLong {
                // `u64::MAX` saturates: the true size is unrepresentable.
                needed: (prefix.len() as u64)
                    .saturating_add(length)
                    .saturating_add(32),
                capacity: PAYMENT_HOP_PAYLOADS_SIZE as u64,
            })
        );
    }
}

#[test]
fn peel_rejects_a_malformed_length_prefix() {
    let node_key = SecretKey::from_slice(&[3; 32]).unwrap();
    // 0xfd introduces a 2-byte value, but 1 fits in a single byte.
    let packet = craft_packet(&node_key, &[0xfd, 0x00, 0x01]);

    assert_eq!(
        peel(&packet, &node_key, &[], None),
        Err(OnionError::Bolt(BoltError::BigSizeNotMinimal))
    );
}
