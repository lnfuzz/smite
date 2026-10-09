//! IR program generators.
//!
//! Generators produce type-correct instruction sequences that represent
//! interesting protocol interactions. Each generator knows the *shape* of a
//! protocol flow but delegates value selection and variable reuse to
//! `ProgramBuilder`.

mod channel_announcement;
mod channel_ready;
mod channel_update;
mod funding_created;
mod funding_flow;
mod node_announcement;
mod open_channel;

pub use channel_announcement::ChannelAnnouncementGenerator;
pub use channel_ready::ChannelReadyGenerator;
pub use channel_update::ChannelUpdateGenerator;
pub use funding_created::FundingCreatedGenerator;
pub use funding_flow::FundingFlowGenerator;
pub use node_announcement::NodeAnnouncementGenerator;
pub use open_channel::OpenChannelGenerator;

use rand::Rng;
use rand::seq::IndexedRandom;

use super::builder::ProgramBuilder;

/// A generator that emits instructions into a `ProgramBuilder`.
pub trait Generator {
    /// Emits instructions for this generator's protocol interaction.
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng);
}

/// A list of all the available generators. Any generators included
/// here may be used by the custom mutator library.
#[derive(Clone, Copy)]
pub enum AnyGenerator {
    ChannelAnnouncement(ChannelAnnouncementGenerator),
    ChannelUpdate(ChannelUpdateGenerator),
    NodeAnnouncement(NodeAnnouncementGenerator),
    OpenChannel(OpenChannelGenerator),
    FundingCreated(FundingCreatedGenerator),
    ChannelReady(ChannelReadyGenerator),
    FundingFlow(FundingFlowGenerator),
}

impl AnyGenerator {
    /// All variants. Keep in sync with the enum definition.
    pub const ALL: &[Self] = &[
        Self::ChannelAnnouncement(ChannelAnnouncementGenerator),
        Self::ChannelUpdate(ChannelUpdateGenerator),
        Self::NodeAnnouncement(NodeAnnouncementGenerator),
        Self::OpenChannel(OpenChannelGenerator),
        Self::FundingCreated(FundingCreatedGenerator),
        Self::ChannelReady(ChannelReadyGenerator),
        Self::FundingFlow(FundingFlowGenerator),
    ];

    /// Relative pick weight for [`Self::choose`]; 0 disables.
    #[must_use]
    pub fn weight(&self) -> u32 {
        match self {
            Self::ChannelAnnouncement(_)
            | Self::ChannelUpdate(_)
            | Self::NodeAnnouncement(_)
            | Self::OpenChannel(_)
            | Self::FundingCreated(_)
            | Self::ChannelReady(_)
            | Self::FundingFlow(_) => 10,
        }
    }

    /// Picks a generator from `ALL` with probability proportional to its
    /// [`Self::weight`].
    ///
    /// # Panics
    ///
    /// Panics if every generator has a weight of zero.
    pub fn choose(rng: &mut impl Rng) -> Self {
        *Self::ALL
            .choose_weighted(rng, Self::weight)
            .expect("at least one generator must have non-zero weight")
    }
}

impl Generator for AnyGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        match self {
            Self::ChannelAnnouncement(generator) => generator.generate(builder, rng),
            Self::ChannelUpdate(generator) => generator.generate(builder, rng),
            Self::NodeAnnouncement(generator) => generator.generate(builder, rng),
            Self::OpenChannel(generator) => generator.generate(builder, rng),
            Self::FundingCreated(generator) => generator.generate(builder, rng),
            Self::ChannelReady(generator) => generator.generate(builder, rng),
            Self::FundingFlow(generator) => generator.generate(builder, rng),
        }
    }
}
