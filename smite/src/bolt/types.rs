//! Fundamental types for BOLT message encoding.

use super::{FeatureBit, Features};
use bitcoin::OutPoint;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum Lightning message size (2-byte length prefix limit).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of a channel ID in bytes.
pub const CHANNEL_ID_SIZE: usize = 32;

/// Size of a chain hash (SHA256).
pub const CHAIN_HASH_SIZE: usize = 32;

/// Size of a SHA256 Hash.
pub const SHA256_HASH_SIZE: usize = 32;

/// Size of a transaction ID in bytes.
pub const TXID_SIZE: usize = 32;

/// Size of a compact ECDSA signature in bytes.
pub const COMPACT_SIGNATURE_SIZE: usize = 64;

/// Size of a compressed secp256k1 public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// Size of an encoded `short_channel_id` in bytes.
pub const SHORT_CHANNEL_ID_SIZE: usize = 8;

/// Size of payment onion routing packets in bytes.
pub const PAYMENT_ONION_PACKET_SIZE: usize = 1366;

/// Size of a per-commitment secret in bytes.
pub const PER_COMMITMENT_SECRET_SIZE: usize = 32;

/// A 32-byte channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ChannelId(pub [u8; CHANNEL_ID_SIZE]);

impl ChannelId {
    /// Special all-zero channel ID indicating "all channels" (for errors)
    /// or "not channel-specific" (for warnings).
    pub const ALL: Self = Self([0u8; CHANNEL_ID_SIZE]);

    /// Creates a channel ID from a byte array.
    #[must_use]
    pub const fn new(bytes: [u8; CHANNEL_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the channel ID as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CHANNEL_ID_SIZE] {
        &self.0
    }

    /// Create _v1_ channel ID from a funding tx outpoint
    #[must_use]
    pub fn v1_from_funding_outpoint(outpoint: OutPoint) -> Self {
        let mut res = outpoint.txid.to_byte_array();
        res[30] ^= ((outpoint.vout >> 8) & 0xff) as u8;
        res[31] ^= (outpoint.vout & 0xff) as u8;
        Self(res)
    }
}

impl fmt::Display for ChannelId {
    /// Formats channel ID into hex string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_hex())
    }
}

/// A specific BOLT 2 `channel_type` feature-bit combination.
///
/// Each variant corresponds to a channel type accepted by at least one target
/// implementation:
///
/// - `option_static_remotekey` (bit 12)
/// - `option_anchors` (bits 22 and 12)
/// - `zero_fee_commitments` (bit 40)
/// - `option_simple_taproot` (bit 80)
/// - `option_simple_taproot_staging` (bit 180)
/// - `option_script_enforced_lease` (bits 2022, 22, 12)
///
/// Additionally, the following bits can be added to any channel type:
/// - `option_scid_alias` (bit 46)
/// - `option_zeroconf` (bit 50)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChannelTypeVariant {
    /// bit 12
    StaticRemoteKey,
    /// bits 12, 46
    StaticRemoteKeyScidAlias,
    /// bits 12, 50
    StaticRemoteKeyZeroConf,
    /// bits 12, 46, 50
    StaticRemoteKeyScidAliasZeroConf,
    /// bits 12, 22
    Anchors,
    /// bits 12, 22, 46
    AnchorsScidAlias,
    /// bits 12, 22, 50
    AnchorsZeroConf,
    /// bits 12, 22, 46, 50
    AnchorsScidAliasZeroConf,
    /// bit 40
    ZeroFeeCommitments,
    /// bits 40, 46
    ZeroFeeCommitmentsScidAlias,
    /// bits 40, 50
    ZeroFeeCommitmentsZeroConf,
    /// bits 40, 46, 50
    ZeroFeeCommitmentsScidAliasZeroConf,
    /// bit 80
    SimpleTaproot,
    /// bits 80, 46
    SimpleTaprootScidAlias,
    /// bits 80, 50
    SimpleTaprootZeroConf,
    /// bits 80, 46, 50
    SimpleTaprootScidAliasZeroConf,
    /// bit 180
    SimpleTaprootStaging,
    /// bits 180, 46
    SimpleTaprootStagingScidAlias,
    /// bits 180, 50
    SimpleTaprootStagingZeroConf,
    /// bits 180, 46, 50
    SimpleTaprootStagingScidAliasZeroConf,
    /// bits 12, 22, 2022
    ScriptEnforcedLease,
    /// bits 12, 22, 2022, 46
    ScriptEnforcedLeaseScidAlias,
    /// bits 12, 22, 2022, 50
    ScriptEnforcedLeaseZeroConf,
    /// bits 12, 22, 2022, 46, 50
    ScriptEnforcedLeaseScidAliasZeroConf,
}

impl ChannelTypeVariant {
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::StaticRemoteKey,
        Self::StaticRemoteKeyScidAlias,
        Self::StaticRemoteKeyZeroConf,
        Self::StaticRemoteKeyScidAliasZeroConf,
        Self::Anchors,
        Self::AnchorsScidAlias,
        Self::AnchorsZeroConf,
        Self::AnchorsScidAliasZeroConf,
        Self::ZeroFeeCommitments,
        Self::ZeroFeeCommitmentsScidAlias,
        Self::ZeroFeeCommitmentsZeroConf,
        Self::ZeroFeeCommitmentsScidAliasZeroConf,
        Self::SimpleTaproot,
        Self::SimpleTaprootScidAlias,
        Self::SimpleTaprootZeroConf,
        Self::SimpleTaprootScidAliasZeroConf,
        Self::SimpleTaprootStaging,
        Self::SimpleTaprootStagingScidAlias,
        Self::SimpleTaprootStagingZeroConf,
        Self::SimpleTaprootStagingScidAliasZeroConf,
        Self::ScriptEnforcedLease,
        Self::ScriptEnforcedLeaseScidAlias,
        Self::ScriptEnforcedLeaseZeroConf,
        Self::ScriptEnforcedLeaseScidAliasZeroConf,
    ];

    /// The feature bits (even/required) contained in this channel type.
    #[must_use]
    pub fn bits(self) -> &'static [FeatureBit] {
        use Features as F;
        match self {
            Self::StaticRemoteKey => &[F::OPTION_STATIC_REMOTEKEY],
            Self::StaticRemoteKeyScidAlias => &[F::OPTION_STATIC_REMOTEKEY, F::OPTION_SCID_ALIAS],
            Self::StaticRemoteKeyZeroConf => &[F::OPTION_STATIC_REMOTEKEY, F::OPTION_ZEROCONF],
            Self::StaticRemoteKeyScidAliasZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::Anchors => &[F::OPTION_STATIC_REMOTEKEY, F::OPTION_ANCHORS],
            Self::AnchorsScidAlias => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCID_ALIAS,
            ],
            Self::AnchorsZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_ZEROCONF,
            ],
            Self::AnchorsScidAliasZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::ZeroFeeCommitments => &[F::ZERO_FEE_COMMITMENTS],
            Self::ZeroFeeCommitmentsScidAlias => &[F::ZERO_FEE_COMMITMENTS, F::OPTION_SCID_ALIAS],
            Self::ZeroFeeCommitmentsZeroConf => &[F::ZERO_FEE_COMMITMENTS, F::OPTION_ZEROCONF],
            Self::ZeroFeeCommitmentsScidAliasZeroConf => &[
                F::ZERO_FEE_COMMITMENTS,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::SimpleTaproot => &[F::OPTION_SIMPLE_TAPROOT],
            Self::SimpleTaprootScidAlias => &[F::OPTION_SIMPLE_TAPROOT, F::OPTION_SCID_ALIAS],
            Self::SimpleTaprootZeroConf => &[F::OPTION_SIMPLE_TAPROOT, F::OPTION_ZEROCONF],
            Self::SimpleTaprootScidAliasZeroConf => &[
                F::OPTION_SIMPLE_TAPROOT,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::SimpleTaprootStaging => &[F::OPTION_SIMPLE_TAPROOT_STAGING],
            Self::SimpleTaprootStagingScidAlias => {
                &[F::OPTION_SIMPLE_TAPROOT_STAGING, F::OPTION_SCID_ALIAS]
            }
            Self::SimpleTaprootStagingZeroConf => {
                &[F::OPTION_SIMPLE_TAPROOT_STAGING, F::OPTION_ZEROCONF]
            }
            Self::SimpleTaprootStagingScidAliasZeroConf => &[
                F::OPTION_SIMPLE_TAPROOT_STAGING,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
            Self::ScriptEnforcedLease => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
            ],
            Self::ScriptEnforcedLeaseScidAlias => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
                F::OPTION_SCID_ALIAS,
            ],
            Self::ScriptEnforcedLeaseZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
                F::OPTION_ZEROCONF,
            ],
            Self::ScriptEnforcedLeaseScidAliasZeroConf => &[
                F::OPTION_STATIC_REMOTEKEY,
                F::OPTION_ANCHORS,
                F::OPTION_SCRIPT_ENFORCED_LEASE,
                F::OPTION_SCID_ALIAS,
                F::OPTION_ZEROCONF,
            ],
        }
    }

    /// Converts the channel type variant to a `Features` bitmap.
    #[must_use]
    pub fn to_features(self) -> Features {
        Features::from_bits(self.bits())
    }

    /// Encodes the channel type as a BOLT feature bitmap (big-endian bytes).
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        self.to_features().into_bytes()
    }
}

impl fmt::Display for ChannelTypeVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A BOLT 7 `short_channel_id`.
///
/// Per [BOLT 7]:
///   * the most significant 3 bytes encode the block height,
///   * the next 3 bytes encode the transaction index within the block,
///   * the least significant 2 bytes encode the output index of the funding
///     transaction.
///
/// Internally stored as the packed 8-byte big-endian representation:
/// `(block << 40) | (tx_index << 16) | output_index`.
///
/// [BOLT 7]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ShortChannelId(u64);

impl ShortChannelId {
    /// Maximum representable block height (3 bytes, big-endian).
    pub const MAX_BLOCK: u32 = 0x00ff_ffff;
    /// Maximum representable transaction index (3 bytes, big-endian).
    pub const MAX_TX_INDEX: u32 = 0x00ff_ffff;

    /// Constructs a `short_channel_id` from its components.
    ///
    /// # Panics
    ///
    /// Panics if `block` or `tx_index` exceed their 24-bit field.
    #[must_use]
    pub const fn new(block: u32, tx_index: u32, output_index: u16) -> Self {
        assert!(block <= Self::MAX_BLOCK, "block is out-of-range");
        assert!(tx_index <= Self::MAX_TX_INDEX, "tx_index is out-of-range");
        let packed = ((block as u64) << 40) | ((tx_index as u64) << 16) | (output_index as u64);
        Self(packed)
    }

    /// Constructs a `short_channel_id` from its raw packed form.
    #[must_use]
    pub const fn from_u64(packed: u64) -> Self {
        Self(packed)
    }

    /// Returns the packed `u64` representation.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the block height component.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // value is masked to 24 bits
    pub const fn block(self) -> u32 {
        ((self.0 >> 40) & 0x00ff_ffff) as u32
    }

    /// Returns the transaction index component.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // value is masked to 24 bits
    pub const fn tx_index(self) -> u32 {
        ((self.0 >> 16) & 0x00ff_ffff) as u32
    }

    /// Returns the output index component.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // low 16 bits
    pub const fn output_index(self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

impl fmt::Display for ShortChannelId {
    /// Formats as the BOLT 7 human-readable form `<block>x<tx>x<out>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}x{}",
            self.block(),
            self.tx_index(),
            self.output_index()
        )
    }
}

/// A BOLT 1 truncated 32-bit integer (`tu32`).
///
/// Its width is only recoverable from the enclosing TLV record, so `read`
/// consumes every remaining byte. Decode one only from a slice already
/// narrowed to the TLV value it ends, never from a cursor running over a
/// message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Tu32(pub u32);

/// A BOLT 1 truncated 64-bit integer (`tu64`).
///
/// Its width is only recoverable from the enclosing TLV record, so `read`
/// consumes every remaining byte. Decode one only from a slice already
/// narrowed to the TLV value it ends, never from a cursor running over a
/// message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Tu64(pub u64);

/// A variable-length unsigned integer similar to Bitcoin's `CompactSize`
/// encoding, but big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigSize(pub u64);

impl BigSize {
    /// Creates a `BigSize` from a `u64` value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner `u64` value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the encoded length of this `BigSize` value.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // BigSize always encodes to at least 1 byte
    pub const fn len(self) -> usize {
        if self.value() < 0xfd {
            1
        } else if self.value() < 0x1_0000 {
            3
        } else if self.value() < 0x1_0000_0000 {
            5
        } else {
            9
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, Txid};

    #[test]
    fn bigsize_new() {
        let bs = BigSize::new(42);
        assert_eq!(bs.0, 42);
        assert_eq!(bs.value(), 42);
    }

    #[test]
    fn bigsize_value() {
        for v in [0u64, 1, 252, 253, 65535, 65536, u64::MAX] {
            assert_eq!(BigSize::new(v).value(), v);
        }
    }

    #[test]
    fn channel_id_all_is_zeros() {
        assert_eq!(ChannelId::ALL.0, [0u8; CHANNEL_ID_SIZE]);
    }

    #[test]
    fn channel_id_new() {
        let bytes = [0x42u8; CHANNEL_ID_SIZE];
        let id = ChannelId::new(bytes);
        assert_eq!(id.0, bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn channel_id_default_is_all() {
        assert_eq!(ChannelId::default(), ChannelId::ALL);
    }

    #[test]
    fn channel_id_from_funding_outpoint_xors_last_two_bytes() {
        let funding_outpoint = OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 1,
        };
        let expected = "0202020202020202020202020202020202020202020202020202020202020203";
        let channel_id = ChannelId::v1_from_funding_outpoint(funding_outpoint);

        assert_eq!(channel_id.to_string(), expected);
    }

    #[test]
    fn short_channel_id_new_roundtrips_components() {
        let scid = ShortChannelId::new(539_268, 845, 1);
        assert_eq!(scid.block(), 539_268);
        assert_eq!(scid.tx_index(), 845);
        assert_eq!(scid.output_index(), 1);
    }

    #[test]
    fn short_channel_id_new_accepts_max_components() {
        let scid = ShortChannelId::new(
            ShortChannelId::MAX_BLOCK,
            ShortChannelId::MAX_TX_INDEX,
            u16::MAX,
        );
        assert_eq!(scid.block(), ShortChannelId::MAX_BLOCK);
        assert_eq!(scid.tx_index(), ShortChannelId::MAX_TX_INDEX);
        assert_eq!(scid.output_index(), u16::MAX);
    }

    #[test]
    #[should_panic(expected = "block is out-of-range")]
    fn short_channel_id_new_panics_on_block_overflow() {
        let _ = ShortChannelId::new(ShortChannelId::MAX_BLOCK + 1, 0, 0);
    }

    #[test]
    #[should_panic(expected = "tx_index is out-of-range")]
    fn short_channel_id_new_panics_on_tx_index_overflow() {
        let _ = ShortChannelId::new(0, ShortChannelId::MAX_TX_INDEX + 1, 0);
    }

    #[test]
    fn short_channel_id_display_uses_bolt7_format() {
        let scid = ShortChannelId::new(539_268, 845, 1);
        assert_eq!(format!("{scid}"), "539268x845x1");
    }

    #[test]
    fn short_channel_id_from_u64_inverse_of_as_u64() {
        for packed in [0u64, 1, 0x1234_5678_9abc_def0, u64::MAX] {
            let scid = ShortChannelId::from_u64(packed);
            assert_eq!(scid.as_u64(), packed);
        }
    }

    #[test]
    fn short_channel_id_ord_matches_packed_u64() {
        let a = ShortChannelId::new(100, 0, 0);
        let b = ShortChannelId::new(100, 0, 1);
        let c = ShortChannelId::new(100, 1, 0);
        let d = ShortChannelId::new(101, 0, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
    }
}
