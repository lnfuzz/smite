//! BOLT 11 invoice test vectors.

use super::*;
use serde::Deserialize;

/// A single invoice test vector.
#[derive(Deserialize)]
struct InvoiceVector {
    /// Vector name, used as context in assertion failures.
    description: String,
    /// Whether the invoice is expected to decode.
    valid: bool,
    /// Bech32-encoded invoice.
    invoice: String,
    /// Expected payment hash of a valid invoice, hex encoded.
    payment_hash: Option<String>,
    /// Expected payment secret of a valid invoice, hex encoded.
    payment_secret: Option<String>,
    /// Expected error of an invalid invoice, in its `Display` form.
    error: Option<String>,
}

/// Checks every vector in `json` against `decode`.
fn run_invoice_vectors(json: &str, decode: fn(&str) -> Result<Invoice, InvoiceError>) {
    let vectors: Vec<InvoiceVector> = serde_json::from_str(json).expect("valid test vector file");
    for vector in vectors {
        let name = &vector.description;
        let result = decode(&vector.invoice);
        if vector.valid {
            let decoded = result.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                Some(hex::encode(decoded.payment_hash)),
                vector.payment_hash,
                "{name}"
            );
            assert_eq!(
                Some(hex::encode(decoded.payment_secret)),
                vector.payment_secret,
                "{name}"
            );
        } else {
            let error = result.expect_err(name);
            assert_eq!(Some(error.to_string()), vector.error, "{name}");
        }
    }
}

// BOLT 11 Examples, decoded with any HRP accepted since they are mainnet and
// testnet invoices, mostly with amounts, which the decoder does not support yet
//    https://github.com/lightning/bolts/blob/master/11-payment-encoding.md#examples
//
// Invalid invoices that break rules the decoder does not check (e.g. the
// amount, feature bits, the `n` field or the signature) are omitted.
// TODO: add them once invoices are fully decoded, e.g. for an invoice
// decoding oracle.
#[test]
fn bolt11_vectors() {
    run_invoice_vectors(include_str!("test_vectors/bolt11.json"), |invoice| {
        Invoice::from_data(&CheckedHrpstring::new::<Bolt11Bech32>(invoice)?)
    });
}

// Vectors not from BOLT 11, covering the regtest HRP check, the length limit
// and the data part errors BOLT 11 has no example for. Well-formed invoices are
// generated with LDK's `lightning-invoice`. Malformed ones are built from the
// regtest invoice's timestamp, payment hash and secret, with one part broken
// and a zero signature.
#[test]
fn custom_vectors() {
    run_invoice_vectors(include_str!("test_vectors/custom.json"), Invoice::decode);
}
