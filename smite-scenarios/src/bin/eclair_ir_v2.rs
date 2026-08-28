//! Eclair channel establishment v2 IR fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{IrScenario, PostInitDualFundSetup};
use smite_scenarios::targets::EclairTarget;

fn main() -> std::process::ExitCode {
    smite_run::<IrScenario<EclairTarget, PostInitDualFundSetup>>()
}
