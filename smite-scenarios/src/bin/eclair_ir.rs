//! Eclair IR fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{EclairWarmupSetup, IrScenario};
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<IrScenario<EclairTarget, EclairWarmupSetup>>()
}
