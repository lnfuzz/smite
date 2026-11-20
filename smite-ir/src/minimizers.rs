//! IR program minimizers.
//!
//! A [`Minimizer`] reduces a [`Program`] to a smaller, behaviourally
//! equivalent version in a single pass. Both transforms are safe in IR
//! semantics, so they don't need an oracle to drive the search.
//!
//! A [`MinimizeSession`] proposes candidates whose results must be checked
//! externally. [`Truncator`] uses this feedback to find a shorter program prefix.
//! Run truncation first so the remaining passes can remove newly dead code.
//!
//! Run them in pipeline order for best results:
//! 1. [`DeadCodeEliminator`] — drop dead instructions and reindex
//! 2. [`CommonSubexpressionEliminator`] — merge equivalent pure expressions

mod cse;
mod dead_code;
mod truncator;

pub use cse::CommonSubexpressionEliminator;
pub use dead_code::DeadCodeEliminator;
pub use truncator::Truncator;

use super::Program;

/// A minimizer that reduces an IR program in one call.
pub trait Minimizer {
    /// Reduces `program` in place to a smaller, behaviourally equivalent
    /// version. Returns `true` if the program was modified.
    fn minimize(&self, program: &mut Program) -> bool;
}

/// An iterative minimizer driven by external execution feedback.
///
/// Inspect [`Self::candidate`], execute it, then call [`Self::feedback`] with
/// whether the candidate preserves the behavior being minimized. Repeat until
/// there is no candidate. [`Self::program`] always holds the last accepted
/// program, including when the most recent candidate was rejected.
pub trait MinimizeSession {
    /// Returns the pending candidate, or `None` when minimization is complete.
    /// Repeated calls return the same candidate until feedback is supplied.
    fn candidate(&self) -> Option<&Program>;

    /// Reports whether the pending candidate was accepted and advances the
    /// session. Calling this after completion has no effect.
    fn feedback(&mut self, accepted: bool);

    /// Returns the original program or the most recently accepted candidate.
    fn program(&self) -> &Program;
}
