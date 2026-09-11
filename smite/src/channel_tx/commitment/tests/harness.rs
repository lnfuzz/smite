//! Test vector file format and the runner shared by the commitment tests.

use crate::bolt::ChannelTypeVariant;
use crate::channel_tx::commitment::*;

/// A file of commitment transaction test vectors.
///
/// Vector files may carry documentation-only keys (`reference` on the file,
/// `comment` on a vector); those are not deserialized.
#[derive(serde::Deserialize)]
struct TestVectorFile {
    /// What the file covers, used as context in assertion failures.
    description: String,
    /// Channel type shared by every vector in the file.
    channel_type: ChannelTypeVariant,
    /// Funding transaction outpoint.
    funding_outpoint: OutPoint,
    /// Total channel funding amount in satoshis.
    funding_amount_satoshis: u64,
    /// Commitment number every vector in the file is built at.
    commitment_number: u64,
    /// CSV delay each party imposes on the other's `to_local` output.
    to_self_delay: u16,
    /// Opener's static keys.
    opener: PartyKeys,
    /// Acceptor's static keys.
    acceptor: PartyKeys,
    /// The vectors themselves.
    tests: Vec<CommitmentVector>,
}

/// Static keys for one side of the channel, shared by every vector in a file.
#[derive(serde::Deserialize)]
struct PartyKeys {
    /// Funding private key, used to sign commitment transactions.
    funding_privkey: SecretKey,
    /// Funding public key used in the funding output.
    funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive the revocation key.
    revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the `to_local` output key.
    delayed_payment_basepoint: PublicKey,
    /// Per-commitment point used to derive all commitment-specific keys.
    per_commitment_point: PublicKey,
}

/// A single commitment transaction test vector.
#[derive(serde::Deserialize)]
struct CommitmentVector {
    /// Vector name, as given by the BOLT 3 appendix where applicable.
    name: String,
    /// Fee rate for the commitment transaction.
    feerate_per_kw: u32,
    /// Dust limit both parties use for this vector.
    dust_limit_satoshis: u64,
    /// Opener's balance in millisatoshis, before fees and anchor outputs.
    to_opener_msat: u64,
    /// Acceptor's balance in millisatoshis.
    to_acceptor_msat: u64,
    /// Opener's expected signature over its own commitment, DER encoded.
    local_signature: Signature,
    /// Acceptor's signature over the opener's commitment, DER encoded.
    remote_signature: Signature,
}

impl PartyKeys {
    /// Builds this party's channel config, taking the per-vector dust limit and
    /// the file-wide `to_self_delay`.
    fn to_party_config(&self, dust_limit_satoshis: u64, to_self_delay: u16) -> ChannelPartyConfig {
        ChannelPartyConfig {
            funding_pubkey: self.funding_pubkey,
            payment_basepoint: self.payment_basepoint,
            revocation_basepoint: self.revocation_basepoint,
            delayed_payment_basepoint: self.delayed_payment_basepoint,
            dust_limit_satoshis,
            to_self_delay,
        }
    }
}

impl TestVectorFile {
    /// Builds the channel config for a vector.
    fn build_channel_config(&self, vector: &CommitmentVector) -> ChannelConfig {
        ChannelConfig {
            funding_outpoint: self.funding_outpoint,
            funding_satoshis: self.funding_amount_satoshis,
            channel_type: self.channel_type.to_features(),
            opener: self
                .opener
                .to_party_config(vector.dust_limit_satoshis, self.to_self_delay),
            acceptor: self
                .acceptor
                .to_party_config(vector.dust_limit_satoshis, self.to_self_delay),
            minimum_depth: 8,
        }
    }

    /// Builds the commitment state for a vector.
    fn build_commitment_state(&self, vector: &CommitmentVector) -> CommitmentState {
        CommitmentState {
            commitment_number: self.commitment_number,
            feerate_per_kw: vector.feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: self.opener.per_commitment_point,
                balance_msat: vector.to_opener_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: self.acceptor.per_commitment_point,
                balance_msat: vector.to_acceptor_msat,
            },
        }
    }

    /// Builds the holder identity for the given side.
    fn build_holder_identity(&self, side: Side) -> HolderIdentity {
        let funding_privkey = match side {
            Side::Opener => self.opener.funding_privkey,
            Side::Acceptor => self.acceptor.funding_privkey,
        };

        HolderIdentity {
            side,
            funding_privkey,
        }
    }
}

/// Runs every commitment vector in a test vector file.
///
/// Note: local is the opener.
pub fn run_commitment_vectors(json: &str) {
    let file: TestVectorFile = serde_json::from_str(json).expect("valid test vector file");
    assert!(
        !file.tests.is_empty(),
        "{}: no test vectors",
        file.description
    );

    let opener_holder = file.build_holder_identity(Side::Opener);
    let acceptor_holder = file.build_holder_identity(Side::Acceptor);

    for vector in &file.tests {
        let context = format!("{}: {}", file.description, vector.name);
        let channel_config = file.build_channel_config(vector);
        let commitment_state = file.build_commitment_state(vector);

        // Opener signs own commitment.
        assert_eq!(
            channel_config.sign_holder_commitment(&commitment_state, &opener_holder),
            vector.local_signature,
            "{context}: local signature mismatch",
        );

        // Acceptor signs opener's commitment.
        assert!(
            channel_config.verify_counterparty_signature(
                &commitment_state,
                &opener_holder,
                &vector.remote_signature,
            ),
            "{context}: remote signature does not verify",
        );

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let acceptor_commit_sig =
            channel_config.sign_counterparty_commitment(&commitment_state, &opener_holder);
        assert!(
            channel_config.verify_counterparty_signature(
                &commitment_state,
                &acceptor_holder,
                &acceptor_commit_sig,
            ),
            "{context}: acceptor commitment signature does not verify",
        );
    }
}
