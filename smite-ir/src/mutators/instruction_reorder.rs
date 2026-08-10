//! Mutator that swaps Act instructions.

use rand::{Rng, seq::IteratorRandom};

use super::Mutator;
use crate::Program;

/// Swaps two `Act` instructions that have no data dependencies between them.
/// An `Act` is any instruction that is not pure, i.e. one whose position in the
/// program affects behavior. This explores alternative execution orderings
/// while preserving SSA invariants.
pub struct InstructionReorderMutator;

impl Mutator for InstructionReorderMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        // Select an Act instruction at random (say Act_1).
        let Some(act1_idx) = program
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(i, instr)| (!instr.operation.is_pure()).then_some(i))
            .choose(rng)
        else {
            return false;
        };

        // Find the first instruction that consumes Act_1. We cannot move
        // Act_1 past this point without breaking def-before-use.
        let mut usage_boundary = act1_idx;
        for instr in &program.instructions[(act1_idx + 1)..] {
            if instr.inputs.contains(&act1_idx) {
                break;
            }
            usage_boundary += 1;
        }

        // Uniformly sample a valid Act_2 from the safe range.
        let Some(act2_idx) = ((act1_idx + 1)..=usage_boundary)
            .filter(|&i| {
                // Ensure the candidate is an Act and does not depend on anything
                // defined at or after Act_1, guaranteeing it can be safely moved up.
                !program.instructions[i].operation.is_pure()
                    && !program.instructions[i]
                        .inputs
                        .iter()
                        .any(|&input| input >= act1_idx)
            })
            .choose(rng)
        else {
            // Abort if no valid independent Act instructions exist in the range.
            return false;
        };

        // Swap Act_1 and Act_2.
        program.instructions.swap(act1_idx, act2_idx);

        // Healing: Update downstream references to Act_1 and Act_2.
        for instr in &mut program.instructions[(act2_idx + 1)..] {
            for input in &mut instr.inputs {
                if *input == act1_idx {
                    *input = act2_idx;
                } else if *input == act2_idx {
                    *input = act1_idx;
                }
            }
        }
        true
    }
}
