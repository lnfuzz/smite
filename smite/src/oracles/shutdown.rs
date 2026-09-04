//! BOLT 2 `shutdown` oracle, for cooperative-close initiation.

use std::collections::HashMap;

use super::Oracle;
use crate::bolt::{ChannelId, Features, Shutdown, is_standard_shutdown_script};
use crate::channel_tx::ChannelState;
use crate::violation::Violation;

/// Context for [`ShutdownOracle`].
pub struct ShutdownContext<'a> {
    /// The `shutdown` received from the peer.
    pub shutdown: &'a Shutdown,
    /// Channel states tracked by the executor, keyed by `channel_id`.
    pub channel_states: &'a HashMap<ChannelId, ChannelState>,
    /// Features negotiated with the target, used to validate the sender's
    /// `scriptpubkey` when the peer did not commit to an `upfront_shutdown_script`.
    /// Taken from the target's advertised `init` features: the harness echoes
    /// `option_shutdown_anysegwit` and `option_simple_close` back in its own
    /// `init`, so a bit the target advertised is a bit that was negotiated.
    pub negotiated_features: &'a Features,
}

/// Checks that a received `shutdown` references a channel we know and carries a
/// `scriptpubkey` that matches the peer's committed `upfront_shutdown_script`,
/// or, absent a commitment, one BOLT 2 permits a sender to use for the
/// negotiated features.
pub struct ShutdownOracle;

impl Oracle<ShutdownContext<'_>> for ShutdownOracle {
    fn evaluate(&self, context: &ShutdownContext<'_>) -> Result<(), Violation> {
        let Shutdown {
            channel_id,
            scriptpubkey,
        } = context.shutdown;

        // Check that the `shutdown` references a channel we established.
        let Some(state) = context.channel_states.get(channel_id) else {
            return Err(Violation::UnknownChannel(*channel_id));
        };

        match &state.peer_upfront_shutdown_script {
            // The peer committed to an `upfront_shutdown_script`, so its
            // `shutdown` must carry exactly that `scriptpubkey`.
            Some(upfront) if !upfront.is_empty() => {
                if scriptpubkey != upfront {
                    return Err(Violation::UpfrontShutdownScriptMismatch(
                        *channel_id,
                        scriptpubkey.clone(),
                    ));
                }
            }
            // No or empty commitment, so any standard sender form is allowed.
            _ => {
                if !is_standard_shutdown_script(scriptpubkey, context.negotiated_features) {
                    return Err(Violation::NonStandardShutdownScript(
                        *channel_id,
                        scriptpubkey.clone(),
                    ));
                }
            }
        }

        // TODO(htlc): BOLT 2 forbids sending `shutdown` while HTLCs are still pending
        // on our commitment.

        Ok(())
    }
}
