//! Mutator that tweaks embedded literal values in Load and Extract operations.

use bitcoin::secp256k1::SecretKey;
use rand::seq::IteratorRandom;
use rand::{Rng, RngExt};
use smite::bolt::{MAX_MESSAGE_SIZE, ShortChannelId};

use super::Mutator;
use crate::operation::{AcceptChannelField, ChannelTypeVariant, ShutdownScriptVariant};
use crate::{Operation, Program};

/// Mutates the embedded parameter of a randomly chosen `is_param_mutable`
/// instruction. For numeric loads, applies a random arithmetic tweak. For byte
/// loads, flips/adds/removes bytes. For extract operations, swaps to a random
/// field with the same output type.
pub struct OperationParamMutator;

impl Mutator for OperationParamMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        let Some(idx) = program
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(i, instr)| instr.operation.is_param_mutable().then_some(i))
            .choose(rng)
        else {
            return false;
        };

        mutate_operation(&mut program.instructions[idx].operation, rng)
    }
}

/// Returns `true` if the operation was changed.
fn mutate_operation(op: &mut Operation, rng: &mut impl Rng) -> bool {
    match op {
        Operation::LoadAmount(v) => {
            *v = tweak_u64(*v, rng);
            true
        }
        Operation::LoadShortChannelId(v) => {
            *v = tweak_short_channel_id(*v, rng);
            true
        }
        Operation::LoadFeeratePerKw(v)
        | Operation::LoadBlockHeight(v)
        | Operation::LoadTimestamp(v)
        | Operation::LoadForwardingFee(v) => {
            *v = tweak_u32(*v, rng);
            true
        }
        Operation::LoadU16(v) => {
            *v = tweak_u16(*v, rng);
            true
        }
        Operation::LoadU8(v) => {
            *v = tweak_u8(*v, rng);
            true
        }
        Operation::LoadBytes(bytes) | Operation::LoadFeatures(bytes) => {
            mutate_bytes(bytes, rng);
            true
        }
        Operation::LoadPrivateKey(bytes) => {
            mutate_private_key(bytes, rng);
            true
        }
        Operation::LoadChannelId(bytes) => {
            mutate_fixed_bytes(bytes, rng);
            true
        }
        Operation::LoadShutdownScript(variant) => {
            mutate_shutdown_script(variant, rng);
            true
        }
        Operation::LoadChannelType(variant) => {
            mutate_channel_type(variant, rng);
            true
        }
        Operation::MineBlocks(v) => {
            // Limit the number of mined blocks to keep execution times low.
            // Reference execution timings:
            // MineBlocks(10): 16ms
            // MineBlocks(100): 157ms
            // MineBlocks(200): 359ms
            // MineBlocks(255): 468ms
            *v = rng.random_range(1..=16);
            true
        }
        Operation::ExtractAcceptChannel(field) => mutate_extract_field(field, rng),
        Operation::BuildNodeAnnouncement { rgb_color, alias } => {
            // Randomly mutate rgb_color or alias bytes in place; never change
            // their lengths (array types prevent it).
            if rng.random() {
                mutate_fixed_bytes(rgb_color, rng);
            } else {
                mutate_fixed_bytes(alias, rng);
            }
            true
        }
        Operation::SendChannelReady { include_alias } => {
            // Toggle the SCID alias TLV. Flipping always changes the value;
            // a random bool could repeat it and waste the mutation.
            *include_alias = !*include_alias;
            true
        }

        // Non-mutable variants. Reaching here means `is_param_mutable` and this
        // match have drifted out of sync.
        Operation::DerivePoint
        | Operation::CreateFundingTransaction
        | Operation::LoadTargetPubkeyFromContext
        | Operation::LoadChainHashFromContext
        | Operation::BuildOpenChannel
        | Operation::BuildChannelAnnouncement
        | Operation::BuildChannelUpdate
        | Operation::BuildAnnouncementSignatures
        | Operation::SendMessage
        | Operation::SendOpenChannel
        | Operation::SendFundingCreated
        | Operation::SendShutdown
        | Operation::RecvAcceptChannel
        | Operation::RecvFundingSigned
        | Operation::RecvChannelReady
        | Operation::BroadcastTransaction
        | Operation::LookupShortChannelId => {
            unreachable!("is_param_mutable returned true for {op:?}")
        }
    }
}

// -- Numeric tweaks --

fn tweak_u64(v: u64, rng: &mut impl Rng) -> u64 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=256)),
        2 => v.wrapping_sub(rng.random_range(1..=256)),
        _ => interesting_u64(rng),
    }
}

fn tweak_u32(v: u32, rng: &mut impl Rng) -> u32 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=256)),
        2 => v.wrapping_sub(rng.random_range(1..=256)),
        _ => interesting_u32(rng),
    }
}

fn tweak_u16(v: u16, rng: &mut impl Rng) -> u16 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=16)),
        2 => v.wrapping_sub(rng.random_range(1..=16)),
        _ => interesting_u16(rng),
    }
}

fn tweak_u8(v: u8, rng: &mut impl Rng) -> u8 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=8)),
        2 => v.wrapping_sub(rng.random_range(1..=8)),
        _ => interesting_u8(rng),
    }
}

// -- Short channel id mutations --

/// Mutates a packed BOLT 7 `short_channel_id`.
///
/// Unlike a plain u64 tweak, this picks values that are interesting at the
/// component level (`block` / `tx_index` / `output_index`), since most SCID
/// parsing and validation logic is sensitive to those boundaries rather than
/// to the packed integer as a whole.
fn tweak_short_channel_id(v: u64, rng: &mut impl Rng) -> u64 {
    let scid = ShortChannelId::from_u64(v);
    let block = scid.block();
    let tx_index = scid.tx_index();
    let output_index = scid.output_index();

    match rng.random_range(0..8) {
        // Replace with an SCID at a known interesting boundary.
        0 => interesting_scid(rng).as_u64(),
        // Replace just the block component with an interesting value.
        1 => ShortChannelId::new(interesting_scid_u24(rng), tx_index, output_index).as_u64(),
        // Replace just the tx_index component with an interesting value.
        2 => ShortChannelId::new(block, interesting_scid_u24(rng), output_index).as_u64(),
        // Replace just the output_index component with an interesting value.
        3 => ShortChannelId::new(block, tx_index, interesting_u16(rng)).as_u64(),
        // Build a fully random but well-formed SCID.
        4 => ShortChannelId::new(
            rng.random_range(0..=ShortChannelId::MAX_BLOCK),
            rng.random_range(0..=ShortChannelId::MAX_TX_INDEX),
            rng.random(),
        )
        .as_u64(),
        // Small delta on the packed form: may straddle component boundaries.
        5 => v.wrapping_add(rng.random_range(1..=256)),
        6 => v.wrapping_sub(rng.random_range(1..=256)),
        // Fully random u64 (may exceed valid component ranges).
        _ => rng.random(),
    }
}

// -- Byte mutations --

/// Shuffle a random subrange of `bytes` using Fisher-Yates.
fn shuffle_subrange(bytes: &mut [u8], rng: &mut impl Rng) {
    if bytes.len() < 2 {
        return;
    }
    let max_len = bytes.len().min(16);
    let len = rng.random_range(2..=max_len);
    let start = rng.random_range(0..=bytes.len() - len);
    for i in (1..len).rev() {
        let j = rng.random_range(0..=i);
        bytes.swap(start + i, start + j);
    }
}

/// Picks the byte used by repeated-fill mutations, biased toward
/// `INTERESTING_U8`.
fn repeated_byte(rng: &mut impl Rng) -> u8 {
    if rng.random_range(0..4) == 0 {
        rng.random()
    } else {
        interesting_u8(rng)
    }
}

/// Overwrites a range of `bytes` with a single repeated byte, preserving the
/// slice's length.
fn fill_repeated(bytes: &mut [u8], rng: &mut impl Rng) {
    if bytes.is_empty() {
        return;
    }
    let (start, len) = if rng.random() {
        (0, bytes.len())
    } else {
        let len = rng.random_range(1..=bytes.len());
        (rng.random_range(0..=bytes.len() - len), len)
    };
    bytes[start..start + len].fill(repeated_byte(rng));
}

fn mutate_bytes(bytes: &mut Vec<u8>, rng: &mut impl Rng) {
    match rng.random_range(0..12) {
        // Flip a random bit.
        0 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            bytes[idx] ^= 1 << rng.random_range(0..8u8);
        }
        // Change a random byte.
        1 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            bytes[idx] = rng.random();
        }
        // Shuffle a random subrange.
        2 if bytes.len() >= 2 => {
            shuffle_subrange(bytes, rng);
        }
        // Insert a random byte.
        3 if bytes.len() < MAX_MESSAGE_SIZE => {
            let pos = rng.random_range(0..=bytes.len());
            bytes.insert(pos, rng.random());
        }
        // Insert repeated bytes. Requires room for at least 2 bytes.
        4 if bytes.len() + 2 <= MAX_MESSAGE_SIZE => {
            let pos = rng.random_range(0..=bytes.len());
            let max_count = (MAX_MESSAGE_SIZE - bytes.len()).min(128);
            let count = rng.random_range(2..=max_count);
            let byte = repeated_byte(rng);
            bytes.splice(pos..pos, std::iter::repeat_n(byte, count));
        }
        // Remove a random byte.
        5 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            bytes.remove(idx);
        }
        // Erase a byte range (up to half the length).
        6 if bytes.len() >= 2 => {
            let max_erase = bytes.len() / 2;
            let count = rng.random_range(1..=max_erase);
            let start = rng.random_range(0..=bytes.len() - count);
            bytes.drain(start..start + count);
        }
        // Add or subtract a small delta from a random byte.
        7 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            let delta = rng.random_range(1..=35);
            if rng.random() {
                bytes[idx] = bytes[idx].wrapping_add(delta);
            } else {
                bytes[idx] = bytes[idx].wrapping_sub(delta);
            }
        }
        // Copy a chunk from one position to another.
        8 if bytes.len() >= 2 => {
            let max_len = (bytes.len() - 1).min(32);
            let len = rng.random_range(1..=max_len);
            let src = rng.random_range(0..=bytes.len() - len);
            let dst = rng.random_range(0..=bytes.len() - len);
            bytes.copy_within(src..src + len, dst);
        }
        // Overwrite a byte range with a repeated byte.
        9 if !bytes.is_empty() => fill_repeated(bytes, rng),
        // Replace with a repeated byte at a random length.
        10 => {
            let len = rng.random_range(0..=256);
            bytes.clear();
            bytes.resize(len, repeated_byte(rng));
        }
        // Replace with random length and content.
        _ => {
            let len = rng.random_range(0..=256);
            bytes.resize(len, 0);
            rng.fill(&mut bytes[..]);
        }
    }
}

/// In-place byte tweaks that preserve the slice's length.
fn mutate_fixed_bytes(bytes: &mut [u8], rng: &mut impl Rng) {
    if bytes.is_empty() {
        return;
    }
    let n = bytes.len();
    match rng.random_range(0..7) {
        // Flip a random bit.
        0 => {
            let idx = rng.random_range(0..n);
            bytes[idx] ^= 1 << rng.random_range(0..8u8);
        }
        // Change a random byte.
        1 => {
            let idx = rng.random_range(0..n);
            bytes[idx] = rng.random();
        }
        // Shuffle a random subrange.
        2 => shuffle_subrange(bytes, rng),
        // Add or subtract a small delta from a random byte.
        3 => {
            let idx = rng.random_range(0..n);
            let delta = rng.random_range(1..=35);
            if rng.random() {
                bytes[idx] = bytes[idx].wrapping_add(delta);
            } else {
                bytes[idx] = bytes[idx].wrapping_sub(delta);
            }
        }
        // Copy a chunk from one position to another.
        4 if n >= 2 => {
            let max_len = (n - 1).min(32);
            let len = rng.random_range(1..=max_len);
            let src = rng.random_range(0..=n - len);
            let dst = rng.random_range(0..=n - len);
            bytes.copy_within(src..src + len, dst);
        }
        // Overwrite a byte range with a repeated byte.
        5 => fill_repeated(bytes, rng),
        // Randomize entirely.
        _ => rng.fill(bytes),
    }
}

/// Tweaks a private key in place, keeping it a valid secp256k1 scalar.
///
/// The executor derives points and signs with these keys, so an out-of-range
/// key aborts the run instead of exercising the target. Uniformly random bytes
/// are out of range with probability ~2^-128, but repeated-byte fills land on
/// the invalid values (all-zero, and all-`0xFF` runs that reach the curve
/// order) often enough to matter, so the rare invalid result is repaired.
fn mutate_private_key(bytes: &mut [u8; 32], rng: &mut impl Rng) {
    mutate_fixed_bytes(bytes, rng);
    if SecretKey::from_slice(bytes).is_err() {
        // Only zero and values >= the curve order are invalid. The order is
        // just under 2^256, so clearing the top byte pulls any out-of-range
        // value below it, and setting the low bit rules out zero.
        bytes[0] = 0;
        bytes[31] |= 1;
    }
}

// -- Enum mutations --

/// Swaps to a different `ChannelTypeVariant`.
fn mutate_channel_type(variant: &mut ChannelTypeVariant, rng: &mut impl Rng) {
    let current = *variant;
    *variant = ChannelTypeVariant::ALL
        .iter()
        .copied()
        .filter(|v| *v != current)
        .choose(rng)
        .expect("ChannelTypeVariant::ALL contains multiple variants");
}

/// Mutates a `ShutdownScriptVariant`. Half the time, mutates the variant's
/// embedded bytes in place; otherwise replaces with a random different variant.
/// Falls through to a variant swap if the current variant has no embedded
/// bytes.
fn mutate_shutdown_script(variant: &mut ShutdownScriptVariant, rng: &mut impl Rng) {
    if rng.random() && mutate_shutdown_script_bytes(variant, rng) {
        return;
    }
    let current = std::mem::discriminant(variant);
    for _ in 0..8 {
        let candidate = ShutdownScriptVariant::random(rng);
        if std::mem::discriminant(&candidate) != current {
            *variant = candidate;
            return;
        }
    }
}

/// Mutates the variant's embedded bytes via `mutate_fixed_bytes`. Returns
/// `false` if the variant carries no bytes to mutate.
fn mutate_shutdown_script_bytes(variant: &mut ShutdownScriptVariant, rng: &mut impl Rng) -> bool {
    let bytes: &mut [u8] = match variant {
        ShutdownScriptVariant::Empty => return false,
        ShutdownScriptVariant::P2pkh(h)
        | ShutdownScriptVariant::P2sh(h)
        | ShutdownScriptVariant::P2wpkh(h) => h,
        ShutdownScriptVariant::P2wsh(h) => h,
        ShutdownScriptVariant::AnySegwit { program, .. } => program,
        ShutdownScriptVariant::OpReturn(data) => data,
    };
    mutate_fixed_bytes(bytes, rng);
    true
}

/// Returns `true` if the field was swapped, `false` if no same-type alternative
/// field exists.
fn mutate_extract_field(field: &mut AcceptChannelField, rng: &mut impl Rng) -> bool {
    // Only swap to fields with the same output type to preserve program validity.
    let target_type = field.output_type();
    let Some(new_field) = AcceptChannelField::ALL
        .iter()
        .copied()
        .filter(|f| f.output_type() == target_type && f != field)
        .choose(rng)
    else {
        return false;
    };
    *field = new_field;
    true
}

// -- Interesting boundary values --
//
// Each width includes all boundaries from narrower widths plus width-specific
// boundaries and BOLT-relevant constants.

const INTERESTING_U8: &[u8] = &[0, 1, 0x7F, 0x80, 0xFF];

#[rustfmt::skip]
const INTERESTING_U16: &[u16] = &[
    // u8 boundaries
    0, 1, 0x7F, 0x80, 0xFF,
    // u16 boundaries
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    // BOLT constants
    6,    // minimum confirmation depth
    144,  // blocks per day
    483,  // max accepted HTLCs (BOLT 2)
    2016, // blocks per 2 weeks
];

#[rustfmt::skip]
const INTERESTING_U32: &[u32] = &[
    // u8 boundaries
    0, 1, 0x7F, 0x80, 0xFF,
    // u16 boundaries
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    // u32 boundaries
    0x1_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF,
    // BOLT constants
    6,    // minimum confirmation depth
    144,  // blocks per day
    253,  // min feerate in sat/kw
    2016, // blocks per 2 weeks
];

#[rustfmt::skip]
const INTERESTING_U64: &[u64] = &[
    // u8 boundaries
    0, 1, 0x7F, 0x80, 0xFF,
    // u16 boundaries
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    // u32 boundaries
    0x1_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF,
    // u64 boundaries
    0x1_0000_0000, 0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF,
    // BOLT constants (sats and msats)
    546,                        // dust limit (sats)
    546_000,                    // dust limit (msats)
    16_777_216,                 // non-wumbo channel limit, 2^24 (sats)
    16_777_216_000,             // non-wumbo channel limit (msats)
    100_000_000,                // 1 BTC (sats)
    100_000_000_000,            // 1 BTC (msats)
    2_100_000_000_000_000,      // 21M BTC (sats)
    2_100_000_000_000_000_000,  // 21M BTC (msats)
];

/// Interesting SCID boundary values. Covers the all-zero SCID, each component
/// independently maxed out, all components maxed simultaneously, and each
/// component set to its smallest non-zero value.
const INTERESTING_SCID: &[ShortChannelId] = &[
    ShortChannelId::new(0, 0, 0),
    ShortChannelId::new(ShortChannelId::MAX_BLOCK, 0, 0),
    ShortChannelId::new(0, ShortChannelId::MAX_TX_INDEX, 0),
    ShortChannelId::new(0, 0, u16::MAX),
    ShortChannelId::new(
        ShortChannelId::MAX_BLOCK,
        ShortChannelId::MAX_TX_INDEX,
        u16::MAX,
    ),
    ShortChannelId::new(1, 0, 0),
    ShortChannelId::new(0, 1, 0),
    ShortChannelId::new(0, 0, 1),
];

/// Interesting boundary values for 24-bit SCID components (`block` and `tx_index`).
const INTERESTING_SCID_U24: &[u32] = &[
    0,
    1,
    ShortChannelId::MAX_BLOCK / 2,
    ShortChannelId::MAX_BLOCK - 1,
    ShortChannelId::MAX_BLOCK,
];

fn interesting_u8(rng: &mut impl Rng) -> u8 {
    INTERESTING_U8[rng.random_range(0..INTERESTING_U8.len())]
}

fn interesting_u16(rng: &mut impl Rng) -> u16 {
    INTERESTING_U16[rng.random_range(0..INTERESTING_U16.len())]
}

fn interesting_u32(rng: &mut impl Rng) -> u32 {
    INTERESTING_U32[rng.random_range(0..INTERESTING_U32.len())]
}

fn interesting_u64(rng: &mut impl Rng) -> u64 {
    INTERESTING_U64[rng.random_range(0..INTERESTING_U64.len())]
}

fn interesting_scid(rng: &mut impl Rng) -> ShortChannelId {
    INTERESTING_SCID[rng.random_range(0..INTERESTING_SCID.len())]
}

fn interesting_scid_u24(rng: &mut impl Rng) -> u32 {
    INTERESTING_SCID_U24[rng.random_range(0..INTERESTING_SCID_U24.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn shuffle_subrange_preserves_elements() {
        let mut rng = SmallRng::seed_from_u64(0);
        let sorted = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut shuffled = sorted.clone();

        for _ in 0..100 {
            shuffle_subrange(&mut shuffled, &mut rng);
            shuffled.sort_unstable();
            assert_eq!(
                shuffled, sorted,
                "shuffle_subrange must preserve all original elements"
            );
        }
    }

    #[test]
    fn shuffle_subrange_mutates_input() {
        let mut rng = SmallRng::seed_from_u64(0);
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut mutated = false;

        for _ in 0..50 {
            let mut cloned = data.clone();
            shuffle_subrange(&mut cloned, &mut rng);
            if data != cloned {
                mutated = true;
            }
        }
        assert!(mutated, "shuffle_subrange doesn't mutate input");
    }

    #[test]
    fn repeated_byte_is_biased_toward_interesting() {
        let mut rng = SmallRng::seed_from_u64(0);
        let interesting = (0..1000)
            .filter(|_| INTERESTING_U8.contains(&repeated_byte(&mut rng)))
            .count();

        // 3/4 of the draws come straight from INTERESTING_U8, plus the rare
        // random byte that happens to land on one.
        assert!(
            interesting > 600,
            "repeated_byte is not biased toward INTERESTING_U8: {interesting}/1000"
        );
    }

    #[test]
    fn fill_repeated_preserves_length_and_writes_a_run() {
        let mut rng = SmallRng::seed_from_u64(0);
        let original: Vec<u8> = (0..32).collect();

        for _ in 0..100 {
            let mut bytes = original.clone();
            fill_repeated(&mut bytes, &mut rng);
            assert_eq!(bytes.len(), original.len(), "fill_repeated changed length");

            let run: Vec<u8> = bytes
                .iter()
                .zip(&original)
                .filter_map(|(new, old)| (new != old).then_some(*new))
                .collect();
            assert!(
                run.windows(2).all(|w| w[0] == w[1]),
                "fill_repeated wrote more than one value: {run:?}"
            );
        }
    }

    #[test]
    fn fill_repeated_produces_boundary_runs() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut all_zeros = false;
        let mut all_ones = false;

        for _ in 0..1000 {
            let mut bytes = [0x5a; 32];
            fill_repeated(&mut bytes, &mut rng);
            all_zeros |= bytes == [0x00; 32];
            all_ones |= bytes == [0xFF; 32];
        }
        assert!(all_zeros, "fill_repeated never produced an all-zero field");
        assert!(all_ones, "fill_repeated never produced an all-ones field");
    }

    #[test]
    fn mutate_private_key_stays_on_curve() {
        let mut rng = SmallRng::seed_from_u64(0);

        // Walk from each starting point that repeated fills are most likely to
        // push out of range, mutating cumulatively so the walk visits the
        // repaired keys too.
        for start in [[0x00; 32], [0xFF; 32], [0x5a; 32]] {
            let mut bytes = start;
            for _ in 0..10_000 {
                mutate_private_key(&mut bytes, &mut rng);
                assert!(
                    SecretKey::from_slice(&bytes).is_ok(),
                    "mutate_private_key produced an invalid key: {bytes:?}"
                );
            }
        }
    }

    #[test]
    fn fill_repeated_empty_is_noop() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut empty: Vec<u8> = vec![];
        fill_repeated(&mut empty, &mut rng);
        assert!(empty.is_empty());
    }

    #[test]
    fn mutate_fixed_bytes_produces_boundary_runs() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut all_zeros = false;
        let mut all_ones = false;

        for _ in 0..10_000 {
            let mut bytes = [0x5a; 32];
            mutate_fixed_bytes(&mut bytes, &mut rng);
            all_zeros |= bytes == [0x00; 32];
            all_ones |= bytes == [0xFF; 32];
        }
        assert!(
            all_zeros,
            "mutate_fixed_bytes never produced an all-zero field"
        );
        assert!(
            all_ones,
            "mutate_fixed_bytes never produced an all-ones field"
        );
    }

    #[test]
    fn mutate_bytes_produces_boundary_runs() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut all_zeros = false;
        let mut all_ones = false;

        for _ in 0..10_000 {
            let mut bytes = vec![0x5a; 32];
            mutate_bytes(&mut bytes, &mut rng);
            all_zeros |= !bytes.is_empty() && bytes.iter().all(|b| *b == 0x00);
            all_ones |= !bytes.is_empty() && bytes.iter().all(|b| *b == 0xFF);
        }
        assert!(all_zeros, "mutate_bytes never produced an all-zero field");
        assert!(all_ones, "mutate_bytes never produced an all-ones field");
    }

    #[test]
    fn shuffle_subrange_empty_and_single() {
        let mut rng = SmallRng::seed_from_u64(0);

        let mut empty: Vec<u8> = vec![];
        shuffle_subrange(&mut empty, &mut rng);
        assert!(empty.is_empty());

        let mut single = vec![0xFF];
        shuffle_subrange(&mut single, &mut rng);
        assert_eq!(single, vec![0xFF]);
    }
}
