//! BOLT 4 test vectors and round-trip properties.

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Deserializer};

use super::{HopPayload, KEY_SIZE, KeyType, OnionError, PaymentData, derive_key};
use crate::bolt::{BigSize, BoltError, ShortChannelId, WireFormat};

/// The `onion-test.json` vector from the BOLT repository, verbatim.
const ONION_TEST: &str = include_str!("test_vectors/onion-test.json");

/// The `onion-error-test.json` vector from the BOLT repository, verbatim.
///
/// Currently only its key derivation is checked.
/// TODO: check the return packet once failure messages land.
const ONION_ERROR_TEST: &str = include_str!("test_vectors/onion-error-test.json");

/// `onion-test.json`; only the hop payloads are decoded so far.
#[derive(Deserialize)]
struct OnionTest {
    generate: OnionTestRoute,
}

#[derive(Deserialize)]
struct OnionTestRoute {
    hops: Vec<OnionTestHop>,
}

#[derive(Deserialize)]
struct OnionTestHop {
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
    hops: Vec<OnionErrorTestHop>,
}

#[derive(Deserialize)]
struct OnionErrorTestHop {
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

/// The vector's payloads carry their `bigsize` length prefix; strip it to get
/// the bare TLV stream.
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

/// Deterministic keys: hop `i` uses secret key `[i; 32]`.
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

#[test]
fn bolt4_vector_derives_error_keys() {
    for hop in onion_error_test().generate.hops {
        let secret = hop.hop_shared_secret.secret_bytes();

        assert_eq!(derive_key(KeyType::Ammag, &secret), hop.ammag_key);
        // Only the erring node's `um` key is listed.
        if let Some(um_key) = hop.um_key {
            assert_eq!(derive_key(KeyType::Um, &secret), um_key);
        }
    }
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
