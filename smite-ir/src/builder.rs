//! Program builder for generators.
//!
//! `ProgramBuilder` maintains an instruction list and a type-indexed variable
//! registry. Generators call builder methods to emit instructions -- they never
//! manipulate instruction indices directly.

use std::collections::HashMap;

use rand::{Rng, RngExt};

use super::{Instruction, Operation, Program, VariableType};

/// A candidate variable that can satisfy a type request.
#[derive(Debug, Clone)]
enum Candidate {
    /// Variable at this instruction index is directly usable.
    Direct(usize),
    /// A field can be extracted from a compound variable.
    Extract {
        /// Instruction index of the compound variable.
        compound_idx: usize,
        /// The operation required to extract the field.
        operation: Operation,
    },
}

/// Builds an IR program by appending instructions and tracking available
/// variables by type.
pub struct ProgramBuilder {
    instructions: Vec<Instruction>,
    /// Candidate variables indexed by output type.
    candidates: HashMap<VariableType, Vec<Candidate>>,
}

impl ProgramBuilder {
    /// Creates an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            candidates: HashMap::new(),
        }
    }

    /// Appends an instruction and registers its output variable (if any) as a
    /// candidate. Returns the instruction index.
    ///
    /// # Panics
    ///
    /// Panics if the inputs have the wrong count, reference out-of-bounds or
    /// void instructions, or have mismatched types.
    pub fn append(&mut self, operation: Operation, inputs: &[usize]) -> usize {
        let expected = operation.input_types();
        assert_eq!(
            inputs.len(),
            expected.len(),
            "{operation:?}: expected {} inputs, got {}",
            expected.len(),
            inputs.len(),
        );
        let len = self.instructions.len();
        for (i, (&input_idx, &expected_type)) in inputs.iter().zip(expected.iter()).enumerate() {
            let actual_type = self
                .instructions
                .get(input_idx)
                .and_then(|instr| instr.operation.output_type())
                .unwrap_or_else(|| {
                    panic!("{operation:?} input {i}: index {input_idx} out of bounds ({len})")
                });
            assert_eq!(
                actual_type, expected_type,
                "{operation:?} input {i}: expected {expected_type:?}, got {actual_type:?}",
            );
            if actual_type.is_affine() {
                let cands = self.candidates.get_mut(&actual_type).unwrap_or_else(|| {
                    panic!("{operation:?} input {i}: no candidates for {actual_type:?}")
                });

                // Find the position, or panic if it doesn't exist.
                let pos = cands
                    .iter()
                    .position(|c| match c {
                        Candidate::Direct(idx) => *idx == input_idx,
                        Candidate::Extract { .. } => {
                            panic!("extractable affine variable in candidate list")
                        }
                    })
                    .unwrap_or_else(|| {
                        panic!("{operation:?} input {i}: affine {actual_type:?} already consumed")
                    });

                // Consume it.
                cands.remove(pos);
            }
        }

        let idx = self.instructions.len();

        if let Some(out_type) = operation.output_type() {
            // Register extractable fields for compound types.
            for (extract_op, field_type) in operation.extractable_fields() {
                assert!(
                    !field_type.is_affine(),
                    "affine variables cannot be extracted"
                );
                assert!(!out_type.is_affine(), "compound variables cannot be affine");
                self.candidates
                    .entry(field_type)
                    .or_default()
                    .push(Candidate::Extract {
                        compound_idx: idx,
                        operation: extract_op,
                    });
            }

            self.candidates
                .entry(out_type)
                .or_default()
                .push(Candidate::Direct(idx));
        }

        self.instructions.push(Instruction {
            operation,
            inputs: inputs.to_vec(),
        });

        idx
    }

    /// Selects or creates a variable of the given type using probabilistic
    /// variable selection (75% most recent, 15% any existing, 10% fresh).
    /// For affine variables the most recent candidate is always selected.
    ///
    /// # Panics
    ///
    /// Panics in the following scenarios:
    /// * An affine type is requested but its candidate pool is empty (all
    ///   instances have been consumed).
    /// * Attempts to generate a fresh variable for a type that cannot be
    ///   instantiated out-of-thin-air (e.g., `Message`, `AcceptChannel`,
    ///   or affine types).
    /// * Resolving the chosen candidate triggers a panic in the underlying
    ///   `append` operation.
    pub fn pick_variable(&mut self, var_type: VariableType, rng: &mut impl Rng) -> usize {
        let Some(candidates) = self.candidates.get(&var_type) else {
            return self.generate_fresh(var_type, rng);
        };

        if var_type.is_affine() {
            let chosen_candidate = candidates
                .last()
                .unwrap_or_else(|| panic!("no candidates for {var_type:?}"))
                .clone();
            return self.resolve_candidate(chosen_candidate);
        }

        let roll = rng.random_range(0..20);
        match roll {
            // 10%: generate a fresh value even though candidates exist.
            0..=1 => self.generate_fresh(var_type, rng),
            // 15%: pick any existing candidate.
            2..=4 => {
                let i = rng.random_range(0..candidates.len());
                let candidate = candidates[i].clone();
                self.resolve_candidate(candidate)
            }
            // 75%: pick the most recent candidate.
            _ => {
                let candidate = candidates.last().expect("non-empty").clone();
                self.resolve_candidate(candidate)
            }
        }
    }

    /// Emits instructions that produce a fresh value of the given type.
    ///
    /// # Panics
    ///
    /// Panics if `var_type` is `Message` (requires composed inputs) or
    /// `AcceptChannel` (requires protocol interaction).
    pub fn generate_fresh(&mut self, var_type: VariableType, rng: &mut impl Rng) -> usize {
        match var_type {
            VariableType::Amount => self.append(Operation::LoadAmount(rng.random()), &[]),
            VariableType::FeeratePerKw => {
                self.append(Operation::LoadFeeratePerKw(rng.random()), &[])
            }
            VariableType::BlockHeight => self.append(Operation::LoadBlockHeight(rng.random()), &[]),
            VariableType::Timestamp => self.append(Operation::LoadTimestamp(rng.random()), &[]),
            VariableType::ForwardingFee => {
                self.append(Operation::LoadForwardingFee(rng.random()), &[])
            }
            VariableType::U16 => self.append(Operation::LoadU16(rng.random()), &[]),
            VariableType::U8 => self.append(Operation::LoadU8(rng.random()), &[]),
            VariableType::Bytes => {
                let len = rng.random_range(0..=256);
                let mut bytes = vec![0u8; len];
                rng.fill(&mut bytes[..]);
                self.append(Operation::LoadBytes(bytes), &[])
            }
            VariableType::Features => {
                let len = rng.random_range(0..=16);
                let mut bytes = vec![0u8; len];
                rng.fill(&mut bytes[..]);
                self.append(Operation::LoadFeatures(bytes), &[])
            }
            VariableType::PrivateKey => self.append(Operation::LoadPrivateKey(rng.random()), &[]),
            VariableType::ChannelId => self.append(Operation::LoadChannelId(rng.random()), &[]),
            VariableType::ShortChannelId => {
                self.append(Operation::LoadShortChannelId(rng.random()), &[])
            }
            VariableType::ChainHash => self.append(Operation::LoadChainHashFromContext, &[]),
            VariableType::Point => {
                let sk_idx = self.generate_fresh(VariableType::PrivateKey, rng);
                self.append(Operation::DerivePoint, &[sk_idx])
            }
            VariableType::Message => {
                panic!("cannot generate fresh Message: requires composed inputs")
            }
            VariableType::OpenChannelMessage => {
                panic!("cannot generate fresh OpenChannelMessage: requires composed inputs")
            }
            VariableType::AcceptChannel => {
                panic!("cannot generate fresh AcceptChannel: requires protocol interaction")
            }
            VariableType::FundingTransaction => {
                panic!("cannot generate fresh FundingTransaction: requires composed inputs")
            }
            VariableType::SentOpenChannel => {
                panic!("cannot generate fresh SentOpenChannel: affine type")
            }
            VariableType::SentFundingCreated => {
                panic!("cannot generate fresh SentFundingCreated: affine type")
            }
        }
    }

    /// Builds the final program from the accumulated instructions.
    #[must_use]
    pub fn build(self) -> Program {
        Program {
            instructions: self.instructions,
        }
    }

    /// Resolves a candidate to a variable index, inserting an Extract
    /// instruction if needed.
    fn resolve_candidate(&mut self, candidate: Candidate) -> usize {
        match candidate {
            Candidate::Direct(idx) => idx,
            Candidate::Extract {
                compound_idx,
                operation,
            } => self.append(operation, &[compound_idx]),
        }
    }

    /// Returns the current number of instructions.
    #[must_use]
    pub fn instructions_len(&self) -> usize {
        self.instructions.len()
    }
}

impl Default for ProgramBuilder {
    fn default() -> Self {
        Self::new()
    }
}
