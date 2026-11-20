//! Feedback-driven minimization of instruction suffixes.

use super::MinimizeSession;
use crate::Program;

/// Searches for a shorter instruction prefix using external execution feedback.
///
/// Prefixes preserve SSA references because instructions only reference earlier
/// instructions. After a rejection, the binary search tries longer prefixes.
/// Only candidates accepted by the caller are retained.
pub struct Truncator {
    /// The original program or the last candidate accepted by the caller.
    program: Program,
    /// The pending prefix to execute, or `None` when the search is complete.
    candidate: Option<Program>,
    /// Lower end of the remaining prefix search range.
    min_prefix_len: usize,
}

impl Truncator {
    /// Starts a session, taking ownership of a well-formed program.
    #[must_use]
    pub fn new(program: Program) -> Self {
        let mut session = Self {
            program,
            candidate: None,
            min_prefix_len: 0,
        };
        session.update_candidate();
        session
    }

    /// Chooses the next prefix between the search bounds.
    fn update_candidate(&mut self) {
        let accepted_len = self.program.instructions.len();
        self.candidate = (self.min_prefix_len < accepted_len).then(|| {
            let len = self.min_prefix_len.midpoint(accepted_len);
            Program {
                instructions: self.program.instructions[..len].to_vec(),
            }
        });
    }
}

impl MinimizeSession for Truncator {
    fn candidate(&self) -> Option<&Program> {
        self.candidate.as_ref()
    }

    fn feedback(&mut self, accepted: bool) {
        let Some(candidate) = self.candidate.take() else {
            return;
        };
        if accepted {
            self.program = candidate;
        } else {
            self.min_prefix_len = candidate.instructions.len() + 1;
        }
        self.update_candidate();
    }

    fn program(&self) -> &Program {
        &self.program
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;
    use crate::generators::OpenChannelGenerator;
    use crate::{Generator, Operation, ProgramBuilder};

    #[test]
    fn finds_each_coverage_boundary_and_preserves_the_last_accepted_program() {
        // Model a target whose coverage depends on its first required instructions.
        // Exercise empty, single-instruction, and both odd and even input lengths.
        for len in 0..=64 {
            let mut builder = ProgramBuilder::new();
            for _ in 0..len {
                builder.append(Operation::MineBlocks(1), &[]);
            }
            let original = builder.build();
            for required in 0..=len {
                let mut truncator = Truncator::new(original.clone());
                let mut accepted = original.clone();
                let mut attempts = 0;
                while let Some(candidate) = truncator.candidate() {
                    assert_eq!(truncator.candidate(), Some(candidate));
                    assert_eq!(
                        candidate.instructions,
                        original.instructions[..candidate.instructions.len()]
                    );
                    assert!(candidate.instructions.len() < accepted.instructions.len());
                    let preserves_coverage = candidate.instructions.len() >= required;
                    if preserves_coverage {
                        accepted = candidate.clone();
                    }
                    truncator.feedback(preserves_coverage);
                    assert_eq!(truncator.program(), &accepted);
                    attempts += 1;
                    assert!(attempts <= len.ilog2() + 1);
                }
                assert_eq!(truncator.program().instructions.len(), required);
                truncator.feedback(false);
                truncator.feedback(true);
                assert_eq!(truncator.program(), &accepted);
            }
        }
    }

    #[test]
    fn generated_candidates_preserve_instruction_references() {
        let mut builder = ProgramBuilder::new();
        OpenChannelGenerator.generate(&mut builder, &mut SmallRng::seed_from_u64(0));
        let original = builder.build();

        for accepted in [false, true] {
            let mut truncator = Truncator::new(original.clone());
            while let Some(candidate) = truncator.candidate() {
                let mut rebuilt = ProgramBuilder::new();
                for instruction in &candidate.instructions {
                    rebuilt.append(instruction.operation.clone(), &instruction.inputs);
                }
                assert_eq!(&rebuilt.build(), candidate);
                truncator.feedback(accepted);
            }
        }
    }
}
