//! Decodes a serialized IR program and prints it to standard output.
//!
//! IR programs are postcard-encoded [`Program`]s; that is how the fuzzing loop
//! serializes them (see `smite-ir-mutator`). This command decodes one and
//! prints it using the IR's `Display` format, the same textual form the mutator
//! emits in its trim logs.

use std::fs;
use std::path::PathBuf;

use clap::Args;
use smite_ir::Program;

use crate::error::CliError;

/// Command handler for `smitebot print-ir`.
pub struct PrintIrCommand;

/// CLI arguments for `smitebot print-ir`.
#[derive(Debug, Args)]
pub struct PrintIrArgs {
    /// Path to a postcard-encoded IR program.
    path: PathBuf,
}

impl PrintIrCommand {
    /// Decodes the input at `args.path` and prints it as readable IR.
    pub fn execute(args: &PrintIrArgs) -> Result<(), CliError> {
        let bytes = fs::read(&args.path)
            .map_err(|e| CliError::Msg(format!("failed to read {}: {e}", args.path.display())))?;

        let text = render(&bytes).map_err(|e| {
            CliError::Msg(format!(
                "failed to decode IR program from {}: {e}",
                args.path.display()
            ))
        })?;

        // `Program`'s Display terminates every instruction with a newline, so an
        // empty program renders to an empty string.
        if text.is_empty() {
            println!("(empty program)");
        }
        print!("{text}");
        Ok(())
    }
}

/// Decodes postcard-encoded bytes into an IR program and renders it as text.
fn render(bytes: &[u8]) -> Result<String, postcard::Error> {
    let program: Program = postcard::from_bytes(bytes)?;
    Ok(program.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smite_ir::{Instruction, Operation};

    /// Postcard is how smite IR programs are serialized in the fuzzing loop.
    fn encode(program: &Program) -> Vec<u8> {
        postcard::to_allocvec(program).expect("postcard serialization")
    }

    #[test]
    fn render_decodes_and_formats_program() {
        let program = Program {
            instructions: vec![Instruction {
                operation: Operation::LoadAmount(1000),
                inputs: vec![],
            }],
        };
        let text = render(&encode(&program)).unwrap();
        assert_eq!(text, program.to_string());
        assert!(text.starts_with("v0 = "), "unexpected rendering: {text:?}");
    }

    #[test]
    fn render_empty_program_is_empty_string() {
        let program = Program {
            instructions: vec![],
        };
        assert_eq!(render(&encode(&program)).unwrap(), "");
    }

    #[test]
    fn render_rejects_invalid_serialization() {
        assert!(render(&[0xFF; 8]).is_err());
    }
}
