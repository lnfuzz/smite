//! Mutator that inserts spliced programs.

use rand::{Rng, RngExt};

use super::Mutator;
use crate::{Program, ProgramBuilder};

/// Inserts a spliced program at a random point in the given program.
pub struct SpliceInsertionMutator {
    splice: Program,
}

impl SpliceInsertionMutator {
    #[must_use]
    pub fn new(splice: Program) -> Self {
        Self { splice }
    }
}

impl Mutator for SpliceInsertionMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        let insert_idx = rng.random_range(0..=program.instructions.len());
        let mut builder = ProgramBuilder::new();
        let mut iter = std::mem::take(&mut program.instructions).into_iter();

        // Consume and append the pre-insertion instructions.
        for instr in iter.by_ref().take(insert_idx) {
            builder.append(instr.operation, &instr.inputs);
        }

        // Insert the spliced program.
        for instr in &self.splice.instructions {
            let shifted_inputs: Vec<usize> = instr
                .inputs
                .iter()
                .map(|&input| input + insert_idx)
                .collect();
            builder.append(instr.operation.clone(), &shifted_inputs);
        }

        // Consume, shift, and append the post-insertion instructions.
        for mut instr in iter {
            for input in &mut instr.inputs {
                if *input >= insert_idx {
                    *input += self.splice.instructions.len();
                }
            }
            builder.append(instr.operation, &instr.inputs);
        }
        *program = builder.build();

        true
    }
}
