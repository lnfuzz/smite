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
    /// HTLC basepoint private key, used to sign HTLC transactions.
    htlc_basepoint_privkey: SecretKey,
    /// Funding public key used in the funding output.
    funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive the revocation key.
    revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the `to_local` output key.
    delayed_payment_basepoint: PublicKey,
    /// HTLC basepoint used to derive HTLC keys.
    htlc_basepoint: PublicKey,
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
    /// Default dust limit used by both parties unless overridden below.
    #[serde(default)]
    dust_limit_satoshis: Option<u64>,
    /// Dust limit used for the opener's commitment, overriding the default.
    #[serde(default)]
    opener_dust_limit_satoshis: Option<u64>,
    /// Dust limit used for the acceptor's commitment, overriding the default.
    #[serde(default)]
    acceptor_dust_limit_satoshis: Option<u64>,
    /// Opener's balance in millisatoshis, before fees and anchor outputs.
    to_opener_msat: u64,
    /// Acceptor's balance in millisatoshis.
    to_acceptor_msat: u64,
    /// HTLCs offered by the acceptor, deducted from its balance above.
    #[serde(default)]
    incoming_htlcs: Vec<HtlcVector>,
    /// HTLCs offered by the opener, deducted from its balance above.
    #[serde(default)]
    outgoing_htlcs: Vec<HtlcVector>,
    /// Opener's expected signature over its own commitment, DER encoded.
    local_signature: Signature,
    /// Opener's expected signatures over its own HTLC transactions, in
    /// commitment output order.
    #[serde(default)]
    local_htlc_signatures: Vec<Signature>,
    /// Acceptor's signature over the opener's commitment, DER encoded.
    remote_signature: Signature,
    /// Acceptor's signatures over the opener's HTLC transactions, in commitment
    /// output order.
    #[serde(default)]
    remote_htlc_signatures: Vec<Signature>,
    /// Number of untrimmed HTLC outputs on the acceptor's commitment, signed by
    /// the opener.
    acceptor_num_htlcs: usize,
}

/// A single in-flight HTLC used by a commitment vector.
///
/// The offering side comes from the key holding it: `incoming_htlcs` is offered
/// by the acceptor, `outgoing_htlcs` by the opener.
#[derive(serde::Deserialize)]
struct HtlcVector {
    /// HTLC ID.
    id: u64,
    /// HTLC amount in millisatoshis.
    amount_msat: u64,
    /// The expiry height of the HTLC.
    cltv_expiry: u32,
    /// Payment preimage, HTLC's payment hash is `SHA256` of this.
    #[serde(with = "hex")]
    payment_preimage: [u8; 32],
}

impl HtlcVector {
    /// Builds the HTLC as offered by `offerer`.
    fn to_htlc(&self, offerer: Side) -> Htlc {
        Htlc {
            id: self.id,
            offerer,
            amount_msat: self.amount_msat,
            cltv_expiry: self.cltv_expiry,
            payment_hash: Sha256::hash(&self.payment_preimage).to_byte_array(),
        }
    }
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
            htlc_basepoint: self.htlc_basepoint,
            dust_limit_satoshis,
            to_self_delay,
        }
    }
}

impl TestVectorFile {
    /// Builds the channel config for a vector.
    fn build_channel_config(&self, vector: &CommitmentVector) -> ChannelConfig {
        let opener_dust_limit_satoshis = vector
            .opener_dust_limit_satoshis
            .or(vector.dust_limit_satoshis)
            .expect("opener dust limit must be set");
        let acceptor_dust_limit_satoshis = vector
            .acceptor_dust_limit_satoshis
            .or(vector.dust_limit_satoshis)
            .expect("acceptor dust limit must be set");

        ChannelConfig {
            funding_outpoint: self.funding_outpoint,
            funding_satoshis: self.funding_amount_satoshis,
            channel_type: self.channel_type.to_features(),
            opener: self
                .opener
                .to_party_config(opener_dust_limit_satoshis, self.to_self_delay),
            acceptor: self
                .acceptor
                .to_party_config(acceptor_dust_limit_satoshis, self.to_self_delay),
            minimum_depth: 8,
        }
    }

    /// Builds the channel commitment states for both sides from a commitment
    /// vector, adding its HTLCs to both.
    fn build_channel_commitments(&self, vector: &CommitmentVector) -> ChannelCommitments {
        let new_state = |local_side, per_commitment_point| CommitmentState {
            local_side,
            commitment_number: self.commitment_number,
            feerate_per_kw: vector.feerate_per_kw,
            per_commitment_point,
            opener_balance_msat: vector.to_opener_msat,
            acceptor_balance_msat: vector.to_acceptor_msat,
            htlcs: Vec::new(),
        };

        let mut commitments = ChannelCommitments {
            opener: new_state(Side::Opener, self.opener.per_commitment_point),
            acceptor: new_state(Side::Acceptor, self.acceptor.per_commitment_point),
        };

        // Build both commitment states identically, as in the BOLT test
        // vectors. They could differ in practice, but identical states still
        // cover the same case.
        for side in [Side::Opener, Side::Acceptor] {
            // Add incoming HTLCs.
            for htlc in &vector.incoming_htlcs {
                commitments
                    .add_htlc(side, htlc.to_htlc(Side::Acceptor))
                    .expect("balance covers HTLCs");
            }

            // Add outgoing HTLCs.
            for htlc in &vector.outgoing_htlcs {
                commitments
                    .add_htlc(side, htlc.to_htlc(Side::Opener))
                    .expect("balance covers HTLCs");
            }
        }

        commitments
    }

    /// Builds the holder identity for the given side.
    fn build_holder_identity(&self, side: Side) -> HolderIdentity {
        let keys = match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        };

        HolderIdentity {
            side,
            funding_privkey: keys.funding_privkey,
            htlc_basepoint_privkey: keys.htlc_basepoint_privkey,
        }
    }

    /// Checks one vector, returning a message per failed assertion.
    fn check_vector(&self, vector: &CommitmentVector) -> Vec<String> {
        let channel_config = self.build_channel_config(vector);
        let commitments = self.build_channel_commitments(vector);
        let opener_holder = self.build_holder_identity(Side::Opener);
        let acceptor_holder = self.build_holder_identity(Side::Acceptor);
        let mut failures = Vec::new();

        // Opener signs own commitment and its HTLC transactions.
        let (local_signature, local_htlc_signatures) =
            channel_config.sign_holder_commitment(&commitments, &opener_holder);
        if local_signature != vector.local_signature {
            failures.push(format!(
                "{}: local signature mismatch\n  expected: {}\n  actual:   {}",
                vector.name, vector.local_signature, local_signature,
            ));
        }
        if local_htlc_signatures != vector.local_htlc_signatures {
            failures.push(format!(
                "{}: local HTLC signatures mismatch\n  expected: {:?}\n  actual:   {:?}",
                vector.name, vector.local_htlc_signatures, local_htlc_signatures,
            ));
        }

        // Acceptor signs opener's commitment and HTLC transactions, then the
        // opener verifies it.
        let (remote_signature, remote_htlc_signatures) =
            channel_config.sign_counterparty_commitment(&commitments, &acceptor_holder);
        if remote_signature != vector.remote_signature {
            failures.push(format!(
                "{}: remote signature mismatch\n  expected: {}\n  actual:   {}",
                vector.name, vector.remote_signature, remote_signature,
            ));
        }
        if remote_htlc_signatures != vector.remote_htlc_signatures {
            failures.push(format!(
                "{}: remote HTLC signatures mismatch\n  expected: {:?}\n  actual:   {:?}",
                vector.name, vector.remote_htlc_signatures, remote_htlc_signatures,
            ));
        }
        if !channel_config.verify_counterparty_signature(
            &commitments,
            &opener_holder,
            &vector.remote_signature,
            &vector.remote_htlc_signatures,
        ) {
            failures.push(format!("{}: remote signature does not verify", vector.name));
        }

        // Opener signs the acceptor's commitment and HTLC transactions, then
        // the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            channel_config.sign_counterparty_commitment(&commitments, &opener_holder);
        if acceptor_htlc_sigs.len() != vector.acceptor_num_htlcs {
            failures.push(format!(
                "{}: acceptor HTLC signature count mismatch\n  expected: {}\n  actual:   {}",
                vector.name,
                vector.acceptor_num_htlcs,
                acceptor_htlc_sigs.len(),
            ));
        }
        if !channel_config.verify_counterparty_signature(
            &commitments,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ) {
            failures.push(format!(
                "{}: acceptor signature does not verify",
                vector.name,
            ));
        }

        failures
    }
}

/// Runs every commitment vector in a test vector file.
///
/// Note: local is the opener.
///
/// # Panics
///
/// Panics if any vector fails, after checking them all, so one run reports
/// every mismatch instead of only the first.
pub fn run_commitment_vectors(json: &str) {
    let file: TestVectorFile = serde_json::from_str(json).expect("valid test vector file");
    assert!(
        !file.tests.is_empty(),
        "{}: no test vectors",
        file.description
    );

    let failures: Vec<String> = file
        .tests
        .iter()
        .flat_map(|vector| file.check_vector(vector))
        .collect();
    assert!(
        failures.is_empty(),
        "{}: {} failed checks across {} vectors\n{}",
        file.description,
        failures.len(),
        file.tests.len(),
        failures.join("\n"),
    );
}
