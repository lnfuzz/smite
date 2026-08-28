//! CLN channel establishment v2 IR fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::{IrScenario, PostInitDualFundSetup};
use smite_scenarios::targets::ClnTarget;

fn main() -> std::process::ExitCode {
    smite_run::<IrScenario<ClnTarget, PostInitDualFundSetup>>()
}
