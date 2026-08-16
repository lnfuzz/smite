//! `smitebot` command-line interface.

mod commands;
mod config;
mod latency_stats;
mod libnyx;
mod state;
mod tmux;
mod utils;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use commands::{
    BenchExecArgs, BenchExecCommand, BuildArgs, BuildCommand, ConfigArgs, ConfigCommand,
    CorpusArgs, CorpusCommand, DoctorArgs, DoctorCommand, PrintIrArgs, PrintIrCommand,
    ReproduceArgs, ReproduceCommand, StartArgs, StartCommand, StatusArgs, StatusCommand, StopArgs,
    StopCommand,
};

#[derive(Debug, Parser)]
#[command(name = "smitebot", version, about = "Smite campaign manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Benchmark Nyx execution speed by running one input many times.
    BenchExec(BenchExecArgs),
    /// Build Smite workload Docker images.
    Build(BuildArgs),
    /// Validate a campaign configuration file.
    Config(ConfigArgs),
    /// Manage fuzzing corpus: merge runner queues or minimize with `afl-cmin`.
    Corpus(CorpusArgs),
    /// Validate host prerequisites for running Smite campaigns.
    Doctor(DoctorArgs),
    /// Decode a fuzzer input and print it as readable IR.
    PrintIr(PrintIrArgs),
    /// Replay a single input against a campaign's target in Docker.
    Reproduce(ReproduceArgs),
    /// Launch a fuzzing campaign.
    Start(StartArgs),
    /// Report the status of a campaign.
    Status(StatusArgs),
    /// Stop a running campaign and reap its processes.
    Stop(StopArgs),
}

fn main() -> ExitCode {
    simple_logger::init_with_env().expect("Failed to initialize logger");

    let cli = Cli::parse();
    let success = match cli.command {
        Commands::BenchExec(args) => BenchExecCommand::execute(&args),
        Commands::Build(args) => BuildCommand::execute(&args),
        Commands::Config(args) => ConfigCommand::execute(&args),
        Commands::Corpus(args) => CorpusCommand::execute(&args),
        Commands::Doctor(args) => DoctorCommand::execute(&args),
        Commands::PrintIr(args) => PrintIrCommand::execute(&args),
        Commands::Reproduce(args) => ReproduceCommand::execute(&args),
        Commands::Start(args) => StartCommand::execute(&args),
        Commands::Status(args) => StatusCommand::execute(&args),
        Commands::Stop(args) => StopCommand::execute(&args),
    };

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
