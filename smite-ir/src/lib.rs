//! Smite IR: intermediate representation for structured Lightning protocol
//! fuzzing.
//!
//! This crate defines the IR types, generators, and mutators used to produce
//! and transform structured fuzzing programs.  It is engine-agnostic -- no
//! dependency on AFL++ or `LibAFL`.
//!
//! # Modules
//! - [`instruction`] - Single IR instruction (operation + input references).
//! - [`malform`] - Byte-level edits applied to encoded messages before sending.
//! - [`minimizers`] - Shrink a program while preserving interesting behaviour.
//! - [`operation`] - Operations that load, compute, build or act.
//! - [`program`] - Ordered list of instructions.
//! - [`variable`] - Typed runtime values and lightweight type tags.

pub mod builder;
pub mod generators;
pub mod instruction;
pub mod malform;
pub mod minimizers;
pub mod mutators;
pub mod operation;
pub mod program;
pub mod variable;

pub use builder::ProgramBuilder;
pub use generators::Generator;
pub use instruction::Instruction;
pub use malform::Malformation;
pub use minimizers::Minimizer;
pub use mutators::Mutator;
pub use operation::Operation;
pub use program::Program;
pub use variable::{Variable, VariableType};

#[cfg(test)]
mod tests;
