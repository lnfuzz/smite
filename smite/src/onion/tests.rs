//! BOLT 4 test vectors and round-trip properties.

use bitcoin::secp256k1::ecdh::SharedSecret;
use serde::{Deserialize, Deserializer};

use super::{KEY_SIZE, KeyType, derive_key};

/// The `onion-error-test.json` vector from the BOLT repository, verbatim.
///
/// Currently only its key derivation is checked.
/// TODO: check the return packet once failure messages land.
const ONION_ERROR_TEST: &str = include_str!("test_vectors/onion-error-test.json");

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

fn onion_error_test() -> OnionErrorTest {
    serde_json::from_str(ONION_ERROR_TEST).expect("valid test vector file")
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
