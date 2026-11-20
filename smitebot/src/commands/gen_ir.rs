//! Encodes a generated IR program to a file.
//!
//! The inverse of [`print_ir`](super::print_ir): it runs one of `smite-ir`'s
//! generators against a seeded RNG and writes the postcard encoding the
//! scenario binaries read from `SMITE_INPUT`. Seeding the RNG makes a given
//! `--seed` always produce the same program, so a generated input can be
//! rebuilt rather than kept around.

use std::fs;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use smite_ir::builder::ProgramBuilder;
use smite_ir::generators::{
    AnyGenerator, ChannelAnnouncementGenerator, ChannelReadyGenerator, ChannelUpdateGenerator,
    FundingCreatedGenerator, FundingFlowGenerator, NodeAnnouncementGenerator, OpenChannelGenerator,
};
use smite_ir::{Generator, Program};

/// Command handler for `smitebot gen-ir`.
pub struct GenIrCommand;

/// The generator to run. Mirrors [`AnyGenerator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum GeneratorName {
    /// A `channel_announcement` for a random channel.
    ChannelAnnouncement,
    /// A `channel_update` for a random channel.
    ChannelUpdate,
    /// A `node_announcement`.
    NodeAnnouncement,
    /// An `open_channel` with bounded parameters.
    OpenChannel,
    /// A `funding_created` for a random channel.
    FundingCreated,
    /// A `channel_ready` for a random channel.
    ChannelReady,
    /// The complete v1 outbound funding flow.
    FundingFlow,
}

impl From<GeneratorName> for AnyGenerator {
    fn from(name: GeneratorName) -> Self {
        match name {
            GeneratorName::ChannelAnnouncement => {
                Self::ChannelAnnouncement(ChannelAnnouncementGenerator)
            }
            GeneratorName::ChannelUpdate => Self::ChannelUpdate(ChannelUpdateGenerator),
            GeneratorName::NodeAnnouncement => Self::NodeAnnouncement(NodeAnnouncementGenerator),
            GeneratorName::OpenChannel => Self::OpenChannel(OpenChannelGenerator),
            GeneratorName::FundingCreated => Self::FundingCreated(FundingCreatedGenerator),
            GeneratorName::ChannelReady => Self::ChannelReady(ChannelReadyGenerator),
            GeneratorName::FundingFlow => Self::FundingFlow(FundingFlowGenerator),
        }
    }
}

/// CLI arguments for `smitebot gen-ir`.
#[derive(Debug, Args)]
pub struct GenIrArgs {
    /// Generator to run.
    #[arg(long, value_enum)]
    generator: GeneratorName,
    /// RNG seed; the same seed always produces the same program.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Path to write the postcard-encoded program to.
    #[arg(short = 'o', long)]
    output: PathBuf,
}

impl GenIrCommand {
    /// Generates a program and writes its postcard encoding to `args.output`.
    pub fn execute(args: &GenIrArgs) -> bool {
        let program = generate(args.generator, args.seed);
        let bytes = match postcard::to_allocvec(&program) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("failed to encode IR program: {e}");
                return false;
            }
        };

        if let Err(e) = fs::write(&args.output, &bytes) {
            log::error!("failed to write {}: {e}", args.output.display());
            return false;
        }

        log::info!(
            "wrote {} instructions ({} bytes) to {}",
            program.instructions.len(),
            bytes.len(),
            args.output.display(),
        );
        true
    }
}

/// Runs `generator` against an RNG seeded with `seed`.
fn generate(generator: GeneratorName, seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    AnyGenerator::from(generator).generate(&mut builder, &mut rng);
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use smite_ir::Operation;

    /// Ensure `GeneratorName` and `AnyGenerator` stay in sync.
    #[test]
    fn generator_name_is_complete() {
        assert_eq!(
            GeneratorName::value_variants().len(),
            AnyGenerator::ALL.len()
        );
    }

    #[test]
    fn same_seed_generates_same_program() {
        let first = generate(GeneratorName::FundingFlow, 7);
        let second = generate(GeneratorName::FundingFlow, 7);
        assert_eq!(first.to_string(), second.to_string());
    }

    #[test]
    fn funding_flow_ends_with_the_channel_ready_exchange() {
        let program = generate(GeneratorName::FundingFlow, 7);
        let ops = &program.instructions;
        assert!(matches!(
            ops[ops.len() - 2].operation,
            Operation::SendChannelReady { .. }
        ));
        assert!(matches!(
            ops[ops.len() - 1].operation,
            Operation::RecvChannelReady
        ));
    }

    /// `print-ir` must be able to read back what this command writes.
    #[test]
    fn generated_program_round_trips_through_postcard() {
        let program = generate(GeneratorName::FundingFlow, 7);
        let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
        let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
        assert_eq!(decoded.to_string(), program.to_string());
    }
}
