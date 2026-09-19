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

/// Weight of a generator that does not override [`Generator::weight`].
pub const DEFAULT_WEIGHT: u32 = 10;

/// A generator that emits instructions into a `ProgramBuilder`.
pub trait Generator {
    /// Emits instructions for this generator's protocol interaction.
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng);

    /// Relative pick weight for [`AnyGenerator::choose`]; 0 disables.
    /// Lower it for generators that should be picked less often.
    fn weight(&self) -> u32 {
        DEFAULT_WEIGHT
    }
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

    /// Picks a generator from `ALL` with probability proportional to its
    /// [`Generator::weight`].
    ///
    /// # Panics
    ///
    /// Panics if every generator reports a weight of zero.
    pub fn choose(rng: &mut impl Rng) -> Self {
        *Self::ALL
            .choose_weighted(rng, Generator::weight)
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

    fn weight(&self) -> u32 {
        match self {
            Self::ChannelAnnouncement(generator) => generator.weight(),
            Self::ChannelUpdate(generator) => generator.weight(),
            Self::NodeAnnouncement(generator) => generator.weight(),
            Self::OpenChannel(generator) => generator.weight(),
            Self::FundingCreated(generator) => generator.weight(),
            Self::ChannelReady(generator) => generator.weight(),
            Self::FundingFlow(generator) => generator.weight(),
        }
    }
}
