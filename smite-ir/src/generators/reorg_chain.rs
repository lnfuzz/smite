//! Generator for chain reorganizations.

use rand::{Rng, RngExt};

use super::Generator;
use crate::Operation;
use crate::builder::ProgramBuilder;

/// Generates a shallow chain reorganization.
///
/// Emits instructions to:
/// 1. Mine blocks to confirm any broadcast transaction
/// 2. Reorg the chain
#[derive(Clone, Copy)]
pub struct ReorgChainGenerator;

impl Generator for ReorgChainGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Mine blocks to confirm any broadcast transaction.
        builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);

        // One or two block reorgs occur naturally on mainnet and are therefore
        // the shallow reorgs a Lightning node is expected to handle.
        builder.append(Operation::ReorgChain(rng.random_range(1..=2)), &[]);
    }
}
