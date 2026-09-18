//! Generator for the BOLT 1 `error` message.

use rand::{Rng, RngExt};
use smite::bolt::ChannelId;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `error` send.
///
/// The target fails the referenced channel, so inserting this after a funding
/// flow exercises its force-close path.
#[derive(Clone, Copy)]
pub struct SendErrorGenerator;

impl Generator for SendErrorGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // The all-zero id fails every channel at once (BOLT 1), a path the
        // mutator rarely reaches by flipping bits in a real channel_id.
        let channel_id = if rng.random_ratio(1, 4) {
            builder.append(Operation::LoadChannelId(ChannelId::ALL.0), &[])
        } else {
            builder.pick_variable(VariableType::ChannelId, rng)
        };
        let data = builder.pick_variable(VariableType::Bytes, rng);

        builder.append(Operation::SendError, &[channel_id, data]);
    }
}
