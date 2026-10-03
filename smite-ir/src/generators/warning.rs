//! Generator for the BOLT 1 `warning` message.

use rand::{Rng, RngExt};
use smite::bolt::ChannelId;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `warning` send.
///
/// Targets only log warnings, so this mainly covers their parsing and logging
/// of untrusted `data` for both known and unknown channels.
#[derive(Clone, Copy)]
pub struct SendWarningGenerator;

impl Generator for SendWarningGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // The all-zero id marks a warning as not channel-specific (BOLT 1), a
        // path the mutator rarely reaches by flipping bits in a real channel_id.
        let channel_id = if rng.random_ratio(1, 4) {
            builder.append(Operation::LoadChannelId(ChannelId::ALL.0), &[])
        } else {
            builder.pick_variable(VariableType::ChannelId, rng)
        };
        let data = builder.pick_variable(VariableType::Bytes, rng);

        builder.append(Operation::SendWarning, &[channel_id, data]);
    }
}
