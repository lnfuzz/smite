//! Common-subexpression elimination minimizer.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use super::Minimizer;
use crate::{Instruction, Program};

/// Merges instructions that compute the same pure expression.
///
/// Two pure instructions are equivalent when they share the same operation
/// and the same canonicalized inputs. Walking the program in order makes
/// the merge transitive: by the time we reach instruction `i`, SSA
/// guarantees every input it references is already canonicalized, so two
/// compute ops whose inputs collapsed to the same canonical loads are
/// themselves recognized as equivalent.
pub struct CommonSubexpressionEliminator;

impl Minimizer for CommonSubexpressionEliminator {
    fn minimize(&self, program: &mut Program) -> bool {
        let n = program.instructions.len();
        let mut canonical: HashMap<Instruction, usize> = HashMap::new();
        let mut new_idx = vec![0usize; n];
        let mut instructions = Vec::with_capacity(n);

        for (i, mut instr) in std::mem::take(&mut program.instructions)
            .into_iter()
            .enumerate()
        {
            for input in &mut instr.inputs {
                *input = new_idx[*input];
            }
            if !instr.operation.is_pure() {
                new_idx[i] = instructions.len();
                instructions.push(instr);
                continue;
            }
            match canonical.entry(instr.clone()) {
                Entry::Occupied(e) => new_idx[i] = *e.get(),
                Entry::Vacant(e) => {
                    e.insert(instructions.len());
                    new_idx[i] = instructions.len();
                    instructions.push(instr);
                }
            }
        }

        let changed = instructions.len() < n;
        program.instructions = instructions;
        changed
    }
}
