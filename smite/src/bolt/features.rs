//! BOLT 9 feature bitfield primitives.

/// BOLT 9 feature bit index. Even bits are required (reject if unknown); odd
/// bits are optional (safe to ignore if unknown): "it's ok to be odd" rule.
pub type FeatureBit = usize;

/// BOLT 9 feature bitfield, encoded as big-endian bytes.
#[derive(Debug, Clone, Default)]
pub struct Features(Vec<u8>);

impl Features {
    /// `gossip_queries` (bits 6/7).
    pub const GOSSIP_QUERIES: FeatureBit = 6;
    /// `gossip_queries_ex` (bits 10/11).
    pub const GOSSIP_QUERIES_EX: FeatureBit = 10;
    /// `option_static_remotekey` (bits 12/13).
    pub const OPTION_STATIC_REMOTEKEY: FeatureBit = 12;
    /// `option_anchors` (bits 22/23).
    pub const OPTION_ANCHORS: FeatureBit = 22;
    /// `option_shutdown_anysegwit` (bits 26/27).
    pub const OPTION_SHUTDOWN_ANYSEGWIT: FeatureBit = 26;
    /// `option_dual_fund` (bits 28/29).
    pub const OPTION_DUAL_FUND: FeatureBit = 28;
    /// `zero_fee_commitments` (bits 40/41).
    pub const ZERO_FEE_COMMITMENTS: FeatureBit = 40;
    /// `option_provide_storage` (bits 42/43).
    pub const OPTION_PROVIDE_STORAGE: FeatureBit = 42;
    /// `option_scid_alias` (bits 46/47).
    pub const OPTION_SCID_ALIAS: FeatureBit = 46;
    /// `option_zeroconf` (bits 50/51).
    pub const OPTION_ZEROCONF: FeatureBit = 50;
    /// `option_simple_close` (bits 60/61).
    pub const OPTION_SIMPLE_CLOSE: FeatureBit = 60;
    /// `option_simple_taproot` (bits 80/81).
    pub const OPTION_SIMPLE_TAPROOT: FeatureBit = 80;
    /// `option_simple_taproot_staging` (bits 180/181).
    pub const OPTION_SIMPLE_TAPROOT_STAGING: FeatureBit = 180;
    /// `option_script_enforced_lease` (bits 2022/2023).
    /// Note: Currently, this feature is LND-specific and is not defined in BOLT 9.
    pub const OPTION_SCRIPT_ENFORCED_LEASE: FeatureBit = 2022;

    /// Creates an empty set of features.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates features with the given bits set.
    #[must_use]
    pub fn from_bits(bits: &[FeatureBit]) -> Self {
        let mut features = Self::new();
        for &bit in bits {
            features.set_bit(bit);
        }
        features
    }

    /// Consumes the features into their underlying bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Sets the bit, extending the features with leading zero bytes if needed.
    ///
    /// # Panics
    ///
    /// Panics if bit exceeds the BOLT 9 feature bitfield's u16-byte length
    /// limit.
    pub fn set_bit(&mut self, bit: FeatureBit) {
        let byte_offset = bit / 8;
        assert!(
            byte_offset < u16::MAX as usize,
            "feature bit {bit} exceeds the feature bitfield length limit"
        );

        let mut len = self.0.len();
        if len <= byte_offset {
            let new_len = byte_offset + 1;
            let mut new_features = vec![0u8; new_len];
            new_features[(new_len - len)..].copy_from_slice(&self.0);
            self.0 = new_features;
            len = new_len;
        }

        let mask = 1 << (bit % 8);
        self.0[len - 1 - byte_offset] |= mask;
    }

    /// Clears the bit, no-op if beyond the feature's length.
    pub fn clear_bit(&mut self, bit: FeatureBit) {
        let byte_offset = bit / 8;
        let len = self.0.len();
        if byte_offset < len {
            let mask = 1 << (bit % 8);
            self.0[len - 1 - byte_offset] &= !mask;
        }
    }

    /// Returns whether the bit is set.
    #[must_use]
    pub fn is_bit_set(&self, bit: FeatureBit) -> bool {
        let byte_offset = bit / 8;
        let len = self.0.len();
        if len <= byte_offset {
            return false;
        }

        let mask = 1 << (bit % 8);
        self.0[len - 1 - byte_offset] & mask != 0
    }

    /// Returns whether the feature is supported by checking its required or
    /// optional bit.
    #[must_use]
    pub fn supports_feature(&self, bit: FeatureBit) -> bool {
        self.is_bit_set(bit) || self.is_bit_set(bit ^ 1)
    }

    /// Clears the feature's required (even) and optional (odd) bits.
    pub fn clear_feature(&mut self, bit: FeatureBit) {
        self.clear_bit(bit);
        self.clear_bit(bit ^ 1);
    }

    /// Returns whether every bit set here is supported by `other`, where the
    /// feature's required (even) or optional (odd) bit both count as support.
    #[must_use]
    pub fn is_supported(&self, other: &Features) -> bool {
        for bit in 0..(self.0.len() * 8) {
            if self.is_bit_set(bit) && !other.supports_feature(bit) {
                return false;
            }
        }
        true
    }
}

impl PartialEq for Features {
    /// Returns true if this set and other have the same feature bits set.
    fn eq(&self, other: &Self) -> bool {
        for bit in 0..(self.0.len().max(other.0.len()) * 8) {
            if self.is_bit_set(bit) != other.is_bit_set(bit) {
                return false;
            }
        }
        true
    }
}

impl Eq for Features {}

impl From<Vec<u8>> for Features {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for Features {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_features_support_no_features() {
        let features = Features::new();
        assert!(!features.supports_feature(Features::OPTION_ANCHORS));
        assert!(!features.supports_feature(Features::OPTION_STATIC_REMOTEKEY));
        assert!(!features.supports_feature(Features::GOSSIP_QUERIES));
    }

    #[test]
    fn from_bits_sets_requested_bits() {
        assert_eq!(Features::from_bits(&[]), Features::new());
        assert_eq!(
            Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]).into_bytes(),
            vec![0x10, 0x00]
        );
        assert_eq!(
            Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY, Features::OPTION_ANCHORS]),
            Features::from(vec![0x40, 0x10, 0x00])
        );
    }

    #[test]
    fn supports_multiple_set_features() {
        let features = Features::from_bits(&[
            Features::OPTION_ANCHORS,
            Features::OPTION_STATIC_REMOTEKEY,
            Features::OPTION_DUAL_FUND,
        ]);

        assert!(features.supports_feature(Features::OPTION_ANCHORS));
        assert!(features.supports_feature(Features::OPTION_STATIC_REMOTEKEY));
        assert!(features.supports_feature(Features::OPTION_DUAL_FUND));
        assert!(!features.supports_feature(Features::OPTION_ZEROCONF));
    }

    #[test]
    fn set_bit_within_existing_length() {
        let mut fv = Features::from(vec![0x00, 0x00]);
        fv.set_bit(0);
        assert_eq!(fv, Features::from(vec![0x00, 0x01]));
        fv.set_bit(8);
        assert_eq!(fv, Features::from(vec![0x01, 0x01]));
    }

    #[test]
    fn set_bit_grows_and_preserves_existing_bits() {
        let mut fv = Features::from(vec![0x01]);
        fv.set_bit(12);
        assert_eq!(fv, Features::from(vec![0x10, 0x01]));
        assert!(fv.is_bit_set(0));
        assert!(fv.is_bit_set(12));
    }

    #[test]
    fn set_bit_accepts_the_highest_bit_within_the_length_limit() {
        // The bitfield is length-prefixed with a `u16`, so `u16::MAX` bytes
        // hold bits 0 through `u16::MAX * 8 - 1`.
        let highest = u16::MAX as usize * 8 - 1;
        let mut fv = Features::new();
        fv.set_bit(highest);
        assert!(fv.is_bit_set(highest));
        assert_eq!(fv.into_bytes().len(), u16::MAX as usize);
    }

    #[test]
    #[should_panic(expected = "exceeds the feature bitfield length limit")]
    fn set_bit_panics_beyond_the_length_limit() {
        Features::new().set_bit(u16::MAX as usize * 8);
    }

    #[test]
    fn clear_bit_within_bounds_and_noop_out_of_bounds() {
        let mut fv = Features::from(vec![0xff, 0xff]);
        fv.clear_bit(0);
        assert_eq!(fv, Features::from(vec![0xff, 0xfe]));
        // Out of range: no-op.
        fv.clear_bit(100);
        assert_eq!(fv, Features::from(vec![0xff, 0xfe]));
    }

    #[test]
    fn is_bit_set_uses_big_endian_bit_order() {
        let fv = Features::from(vec![0x00, 0x01]);
        assert!(fv.is_bit_set(0));
        assert!(!fv.is_bit_set(1));

        let fv = Features::from(vec![0x01, 0x00]);
        assert!(fv.is_bit_set(8));
        assert!(!fv.is_bit_set(0));
    }

    #[test]
    fn is_bit_set_out_of_bounds_returns_false() {
        assert!(!Features::new().is_bit_set(0));
        assert!(!Features::from(vec![0xff]).is_bit_set(8));
    }

    #[test]
    fn supports_feature_uses_big_endian_bit_order() {
        // Required (bit 22), optional (bit 23).
        assert!(Features::from(vec![0x40, 0x00, 0x00]).supports_feature(Features::OPTION_ANCHORS));
        assert!(Features::from(vec![0x80, 0x00, 0x00]).supports_feature(Features::OPTION_ANCHORS));
        // No support.
        assert!(!Features::from(vec![0x00, 0x00, 0x40]).supports_feature(Features::OPTION_ANCHORS));
        assert!(!Features::from(vec![0x00, 0x00, 0x80]).supports_feature(Features::OPTION_ANCHORS));
        assert!(!Features::from(vec![]).supports_feature(Features::OPTION_ANCHORS));
        assert!(!Features::from(vec![0xff, 0xff]).supports_feature(Features::OPTION_ANCHORS));
        assert!(!Features::from(vec![0x00, 0x10]).supports_feature(Features::OPTION_ANCHORS));
    }

    #[test]
    fn supports_feature_matches_either_bit_set() {
        // Only the required (even) bit set.
        let required_only = Features::from_bits(&[22]);
        assert!(required_only.supports_feature(Features::OPTION_ANCHORS));
        assert!(required_only.supports_feature(23));
        // Only the optional (odd) bit set.
        let optional_only = Features::from_bits(&[23]);
        assert!(optional_only.supports_feature(Features::OPTION_ANCHORS));
        assert!(optional_only.supports_feature(23));
        // Neither bit set.
        assert!(
            !Features::from_bits(&[Features::OPTION_ZEROCONF])
                .supports_feature(Features::OPTION_ANCHORS)
        );
    }

    #[test]
    fn clear_feature_clears_both_bits() {
        // Passing the even bit clears the pair.
        let mut fv = Features::from_bits(&[22, 23]);
        fv.clear_feature(Features::OPTION_ANCHORS);
        assert!(!fv.supports_feature(Features::OPTION_ANCHORS));
        // Passing the odd bit clears the pair.
        let mut fv = Features::from_bits(&[22, 23]);
        fv.clear_feature(23);
        assert!(!fv.supports_feature(Features::OPTION_ANCHORS));
    }

    #[test]
    fn clear_feature_removes_support() {
        let mut features =
            Features::from_bits(&[Features::OPTION_ANCHORS, Features::OPTION_STATIC_REMOTEKEY]);

        assert!(features.supports_feature(Features::OPTION_ANCHORS));
        assert!(features.supports_feature(Features::OPTION_STATIC_REMOTEKEY));

        features.clear_feature(Features::OPTION_ANCHORS);
        assert!(!features.supports_feature(Features::OPTION_ANCHORS));
        assert!(features.supports_feature(Features::OPTION_STATIC_REMOTEKEY));
    }

    #[test]
    fn is_supported_with_empty_and_nonempty_features() {
        let empty = Features::new();
        let single_bit = Features::from_bits(&[Features::OPTION_ANCHORS]);
        let multiple_bits =
            Features::from_bits(&[Features::OPTION_ANCHORS, Features::OPTION_STATIC_REMOTEKEY]);

        assert!(empty.is_supported(&empty));
        assert!(empty.is_supported(&single_bit));
        assert!(empty.is_supported(&multiple_bits));

        assert!(!single_bit.is_supported(&empty));
        assert!(single_bit.is_supported(&single_bit));
        assert!(single_bit.is_supported(&multiple_bits));

        assert!(!multiple_bits.is_supported(&empty));
        assert!(!multiple_bits.is_supported(&single_bit));
        assert!(multiple_bits.is_supported(&multiple_bits));
    }

    #[test]
    fn is_supported_with_fewer_bits() {
        let superset = Features::from(vec![0xff, 0xff]);
        let subset1 = Features::from(vec![0x0f, 0xff]);
        let subset2 = Features::from(vec![0xff, 0x0f]);

        assert!(subset1.is_supported(&superset));
        assert!(subset2.is_supported(&superset));

        assert!(!subset2.is_supported(&subset1));
        assert!(!subset1.is_supported(&subset2));

        assert!(!superset.is_supported(&subset1));
        assert!(!superset.is_supported(&subset2));
    }

    #[test]
    fn is_supported_with_partial_overlap() {
        let anchors_and_remotekey =
            Features::from_bits(&[Features::OPTION_ANCHORS, Features::OPTION_STATIC_REMOTEKEY]);
        let remotekey_and_dual_fund = Features::from_bits(&[
            Features::OPTION_STATIC_REMOTEKEY,
            Features::OPTION_DUAL_FUND,
        ]);

        assert!(!anchors_and_remotekey.is_supported(&remotekey_and_dual_fund));
        assert!(!remotekey_and_dual_fund.is_supported(&anchors_and_remotekey));
    }

    #[test]
    fn is_supported_with_different_lengths() {
        let short = Features::from(vec![0x01]);
        let long = Features::from(vec![0x10, 0x01]);

        assert!(short.is_supported(&long));
        assert!(!long.is_supported(&short));

        let short = Features::from(vec![0x01]);
        let long = Features::from(vec![0x01, 0x00]);

        assert!(!short.is_supported(&long));
        assert!(!long.is_supported(&short));

        let short = Features::from(vec![0x80]);
        let long = Features::from(vec![0x00, 0x80]);

        assert!(short.is_supported(&long));
        assert!(long.is_supported(&short));
    }

    #[test]
    fn is_supported_accepts_optional_bit_for_required_bit() {
        // A channel type carries `option_scid_alias` as required (bit 46),
        // while peers advertise it as optional (bit 47) in `init`.
        let channel_type = Features::from_bits(&[
            Features::OPTION_STATIC_REMOTEKEY,
            Features::OPTION_SCID_ALIAS,
        ]);
        let mut negotiated = Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]);
        negotiated.set_bit(Features::OPTION_SCID_ALIAS ^ 1);

        assert!(!negotiated.is_bit_set(Features::OPTION_SCID_ALIAS));
        assert!(channel_type.is_supported(&negotiated));

        // A required bit is also satisfied by the same required bit.
        let mut negotiated = Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]);
        negotiated.set_bit(Features::OPTION_SCID_ALIAS);
        assert!(channel_type.is_supported(&negotiated));

        // A feature advertised in neither parity is still not negotiated.
        let anchors = Features::from_bits(&[Features::OPTION_ANCHORS]);
        assert!(!anchors.is_supported(&negotiated));
    }

    #[test]
    fn is_supported_accepts_required_bit_for_optional_bit() {
        // The pairing is symmetric: an optional bit on the left is satisfied
        // by the required bit on the right.
        let optional = Features::from_bits(&[Features::OPTION_SCID_ALIAS ^ 1]);
        let required = Features::from_bits(&[Features::OPTION_SCID_ALIAS]);

        assert!(optional.is_supported(&required));
        assert!(required.is_supported(&optional));
    }

    #[test]
    fn equality_with_same_and_different_bits() {
        let lease = Features::from_bits(&[Features::OPTION_SCRIPT_ENFORCED_LEASE]);
        assert_eq!(lease, Features::from_bits(&[2022]));
        assert_eq!(
            Features::from(vec![0x02, 0x01]),
            Features::from(vec![0x02, 0x01])
        );

        // equality ignores leading zero bytes.
        assert_eq!(Features::from(vec![0x01]), Features::from(vec![0x00, 0x01]));
        assert_eq!(Features::new(), Features::from(vec![0x00, 0x00]));

        assert_ne!(Features::from(vec![0x01]), Features::from(vec![0x02]));
        assert_ne!(Features::from(vec![0x01]), Features::from(vec![0x01, 0x00]));
        assert_ne!(Features::from(vec![0x01]), Features::from(vec![0x01, 0x01]));
        assert_ne!(Features::from(vec![0x01, 0x00]), Features::from(vec![0x00]));
        assert_ne!(lease, Features::from_bits(&[2023]));
    }
}
