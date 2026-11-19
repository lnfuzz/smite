//! Tracks a BOLT 2 interactive transaction construction.
//!
//! The protocol is turn-based: the peer replies to each message we send. The
//! exchange is concluded when a `tx_complete` from one peer is directly
//! followed by a `tx_complete` from the other. [`TxExchange`] applies the
//! messages to a [`SharedTransaction`] in the order the peer processes them,
//! so the transaction matches the one the peer builds.
//!
//! A program may send several messages before reading any reply. The peer
//! still replies to each one before processing the next, so each message we
//! send is applied only once the peer has replied to our previous one.
//! Messages that come after the concluding `tx_complete` are never applied.

use std::collections::VecDeque;

use super::interactive_tx::{Contributor, SharedInput, SharedOutput, SharedTransaction};

/// One interactive transaction message, sent or received.
///
/// An added input or output must have its sender as `contributor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `tx_add_input`.
    AddInput { serial_id: u64, input: SharedInput },
    /// `tx_add_output`.
    AddOutput {
        serial_id: u64,
        output: SharedOutput,
    },
    /// `tx_remove_input`, with the `serial_id` of the input to remove.
    RemoveInput(u64),
    /// `tx_remove_output`, with the `serial_id` of the output to remove.
    RemoveOutput(u64),
    /// `tx_complete`.
    Complete,
}

impl Step {
    /// Whether `side` can send this step.
    fn is_from(&self, side: Contributor) -> bool {
        match self {
            Self::AddInput { input, .. } => input.contributor == side,
            Self::AddOutput { output, .. } => output.contributor == side,
            Self::RemoveInput(_) | Self::RemoveOutput(_) | Self::Complete => true,
        }
    }
}

/// How far the exchange has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Inputs and outputs can still be added and removed.
    Open {
        /// Whether the last applied message is ours, so the peer still has to
        /// reply to it.
        awaiting_reply: bool,
        /// Who sent the last applied message, if it was a `tx_complete`. If
        /// the other peer's `tx_complete` comes next, the exchange is
        /// concluded.
        last_tx_complete: Option<Contributor>,
    },
    /// Each peer sent a `tx_complete`, one directly after the other.
    Concluded,
    /// The peer sent `tx_abort`.
    Aborted,
}

/// The transaction being negotiated, and how far its exchange has progressed.
#[derive(Debug, Clone)]
pub struct TxExchange {
    shared_tx: SharedTransaction,
    phase: Phase,
    /// Messages we sent that are not applied yet, because the peer has not
    /// replied to the message before them. Oldest first.
    queued: VecDeque<Step>,
}

impl TxExchange {
    /// Starts an exchange for a transaction with the given `nLockTime`.
    #[must_use]
    pub fn new(locktime: u32) -> Self {
        Self {
            shared_tx: SharedTransaction::new(locktime),
            phase: Phase::Open {
                awaiting_reply: false,
                last_tx_complete: None,
            },
            queued: VecDeque::new(),
        }
    }

    /// The transaction as the peer has built it so far.
    ///
    /// Messages we sent that are still waiting for an earlier reply are not in
    /// it yet, so read every expected reply before building from it.
    #[must_use]
    pub fn shared_tx(&self) -> &SharedTransaction {
        &self.shared_tx
    }

    /// Whether two consecutive `tx_complete`s concluded the exchange, and the
    /// peer has not aborted since.
    #[must_use]
    pub fn concluded(&self) -> bool {
        match self.phase {
            Phase::Concluded => true,
            Phase::Open { .. } | Phase::Aborted => false,
        }
    }

    /// Whether the peer aborted the negotiation.
    #[must_use]
    pub fn aborted(&self) -> bool {
        match self.phase {
            Phase::Aborted => true,
            Phase::Open { .. } | Phase::Concluded => false,
        }
    }

    /// Whether the peer still has to reply to one of our messages.
    ///
    /// Reading when no reply is due would consume the peer's next message,
    /// usually its `commitment_signed`.
    #[must_use]
    pub fn expects_reply(&self) -> bool {
        match self.phase {
            Phase::Open { awaiting_reply, .. } => awaiting_reply,
            Phase::Concluded | Phase::Aborted => false,
        }
    }

    /// Records a message we sent.
    ///
    /// Ignored once the exchange has concluded or the peer aborted, since the
    /// peer no longer applies or replies to these messages.
    ///
    /// # Panics
    ///
    /// If an added input or output does not have [`Contributor::Local`] as its
    /// `contributor`.
    pub fn send(&mut self, step: Step) {
        assert!(step.is_from(Contributor::Local), "{step:?}");
        match self.phase {
            Phase::Open {
                awaiting_reply: false,
                ..
            } => self.take(step, Contributor::Local),
            Phase::Open {
                awaiting_reply: true,
                ..
            } => self.queued.push_back(step),
            Phase::Concluded | Phase::Aborted => {}
        }
    }

    /// Records a message the peer sent, as its reply to the last message we
    /// applied, then applies our next queued message. Ignored once the
    /// exchange has concluded or the peer aborted.
    ///
    /// # Panics
    ///
    /// If an added input or output does not have [`Contributor::Remote`] as
    /// its `contributor`.
    pub fn receive(&mut self, step: Step) {
        assert!(step.is_from(Contributor::Remote), "{step:?}");
        self.take(step, Contributor::Remote);
        if let Some(next) = self.queued.pop_front() {
            self.take(next, Contributor::Local);
        }
    }

    /// Records the peer's `tx_abort`, which ends the negotiation.
    ///
    /// Also applies after the exchange concluded, since the peer checks the
    /// finished transaction when it receives our `tx_complete`.
    pub fn receive_abort(&mut self) {
        self.phase = Phase::Aborted;
        self.queued.clear();
    }

    /// Handles the next message of the exchange, sent by `from`. Does nothing
    /// once the exchange has concluded or the peer aborted.
    fn take(&mut self, step: Step, from: Contributor) {
        let Phase::Open {
            last_tx_complete, ..
        } = self.phase
        else {
            return;
        };
        // After our message the peer has to reply.
        let awaiting_reply = from == Contributor::Local;
        match step {
            Step::Complete if last_tx_complete.is_some_and(|other| other != from) => {
                self.conclude();
            }
            Step::Complete => {
                self.phase = Phase::Open {
                    awaiting_reply,
                    last_tx_complete: Some(from),
                };
            }
            contribution => {
                self.phase = Phase::Open {
                    awaiting_reply,
                    last_tx_complete: None,
                };
                self.apply(contribution, from);
            }
        }
    }

    /// Concludes the exchange. Our queued messages come after the concluding
    /// `tx_complete`, so they are never applied and get no reply.
    fn conclude(&mut self) {
        if !self.queued.is_empty() {
            log::debug!(
                "exchange concluded, dropped {} send(s) after it",
                self.queued.len()
            );
        }
        self.phase = Phase::Concluded;
        self.queued.clear();
    }

    /// Applies an added or removed input or output, sent by `from`.
    ///
    /// A duplicate `serial_id`, or the removal of an entry the other peer
    /// added, is ignored: BOLT 2 requires whoever receives it to fail the
    /// negotiation instead.
    ///
    /// TODO: Report either one from the peer as a violation in an
    /// `InteractiveTxOracle`.
    fn apply(&mut self, step: Step, from: Contributor) {
        match step {
            Step::AddInput { serial_id, input } => {
                if let Err(err) = self.shared_tx.add_input(serial_id, input) {
                    log::debug!("{from:?} added an input: {err}, kept the first");
                }
            }
            Step::AddOutput { serial_id, output } => {
                if let Err(err) = self.shared_tx.add_output(serial_id, output) {
                    log::debug!("{from:?} added an output: {err}, kept the first");
                }
            }
            Step::RemoveInput(serial_id) => {
                if self.shared_tx.remove_input(serial_id, from).is_none() {
                    log::debug!(
                        "{from:?} removed input with serial_id {serial_id} it did not add, kept"
                    );
                }
            }
            Step::RemoveOutput(serial_id) => {
                if self.shared_tx.remove_output(serial_id, from).is_none() {
                    log::debug!(
                        "{from:?} removed output with serial_id {serial_id} it did not add, kept"
                    );
                }
            }
            Step::Complete => unreachable!("tx_complete contributes nothing"),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, ScriptBuf, Txid};

    use super::*;
    use crate::channel_tx::interactive_tx::MAX_SEQUENCE;
    use Contributor::{Local, Remote};

    fn add_input(serial_id: u64, contributor: Contributor) -> Step {
        Step::AddInput {
            serial_id,
            input: SharedInput {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: u32::try_from(serial_id).expect("small serial id"),
                },
                sequence: MAX_SEQUENCE,
                contributor,
                prevout: None,
            },
        }
    }

    fn add_output(serial_id: u64, contributor: Contributor) -> Step {
        Step::AddOutput {
            serial_id,
            output: SharedOutput {
                value: 1000,
                script_pubkey: ScriptBuf::new(),
                contributor,
            },
        }
    }

    fn input_ids(exchange: &TxExchange) -> Vec<(u64, Contributor)> {
        exchange
            .shared_tx()
            .inputs()
            .map(|(id, input)| (id, input.contributor))
            .collect()
    }

    fn output_ids(exchange: &TxExchange) -> Vec<(u64, Contributor)> {
        exchange
            .shared_tx()
            .outputs()
            .map(|(id, output)| (id, output.contributor))
            .collect()
    }

    #[test]
    fn in_step_exchange_owes_one_reply_per_send() {
        let mut exchange = TxExchange::new(0);
        assert!(!exchange.expects_reply());

        exchange.send(add_input(2, Local));
        assert!(exchange.expects_reply());
        exchange.receive(add_input(1, Remote));
        assert!(!exchange.expects_reply());

        assert_eq!(input_ids(&exchange), vec![(1, Remote), (2, Local)]);
        assert!(!exchange.concluded());
    }

    #[test]
    fn our_tx_complete_after_the_peers_concludes_on_the_spot() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(Step::Complete);
        assert!(!exchange.concluded());

        exchange.send(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());
    }

    #[test]
    fn the_peers_tx_complete_after_ours_concludes() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(add_input(1, Remote));
        exchange.send(Step::Complete);
        assert!(exchange.expects_reply());

        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.aborted());
        assert!(!exchange.expects_reply());
    }

    #[test]
    fn a_contribution_between_tx_completes_keeps_the_exchange_open() {
        // Normally the tx_completes on either side of a contribution come from
        // the same peer. The peer's unsolicited input here puts one between
        // the peer's tx_complete and ours.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(Step::Complete);
        exchange.receive(add_input(1, Remote));
        exchange.send(Step::Complete);
        assert!(!exchange.concluded());
        assert!(exchange.expects_reply());
    }

    #[test]
    fn tx_completes_from_the_same_side_do_not_conclude() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(Step::Complete);
        // Unsolicited: it replies to nothing, so it directly follows the
        // peer's first tx_complete.
        exchange.receive(Step::Complete);
        assert!(!exchange.concluded());

        exchange.send(Step::Complete);
        assert!(exchange.concluded());
    }

    #[test]
    fn pipelined_sends_apply_in_the_peers_order() {
        // The peer adds and then removes its input 5 before it processes our
        // input 5, which has the wrong parity, so the two never collide.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.send(add_output(10, Local));
        exchange.send(add_input(5, Local));

        exchange.receive(add_input(5, Remote));
        assert_eq!(input_ids(&exchange), vec![(2, Local), (5, Remote)]);
        exchange.receive(Step::RemoveInput(5));
        assert_eq!(input_ids(&exchange), vec![(2, Local), (5, Local)]);
    }

    #[test]
    fn late_conclusion_on_the_peers_tx_complete_drops_later_sends() {
        // After the first reply we send two more inputs, a tx_complete and a
        // change output without reading. The peer's tx_complete in reply to
        // the third input is directly followed by ours, so the exchange
        // concludes and the change output is never applied.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(Step::Complete);
        exchange.send(add_input(4, Local));
        exchange.send(add_input(6, Local));
        exchange.send(Step::Complete);
        exchange.send(add_output(2000, Local));

        exchange.receive(add_input(1, Remote));
        assert!(!exchange.concluded());
        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());

        assert_eq!(
            input_ids(&exchange),
            vec![(1, Remote), (2, Local), (4, Local), (6, Local)],
        );
        assert_eq!(output_ids(&exchange), Vec::new());
    }

    #[test]
    fn late_conclusion_on_our_tx_complete_drops_later_sends() {
        // The peer replies to our input with an output, and to our
        // tx_complete with its own, which concludes the exchange. The output
        // and removal we sent afterwards are never applied.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.send(Step::Complete);
        exchange.send(add_output(2000, Local));
        exchange.send(Step::RemoveInput(2));

        exchange.receive(add_output(1, Remote));
        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());

        assert_eq!(input_ids(&exchange), vec![(2, Local)]);
        assert_eq!(output_ids(&exchange), vec![(1, Remote)]);
    }

    #[test]
    fn steps_after_the_conclusion_are_not_recorded() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(Step::Complete);
        exchange.send(Step::Complete);

        exchange.send(add_output(2000, Local));
        assert!(!exchange.expects_reply());
        exchange.receive(add_input(1, Remote));
        assert_eq!(output_ids(&exchange), Vec::new());
        assert_eq!(input_ids(&exchange), vec![(2, Local)]);
    }

    #[test]
    fn a_tx_complete_replying_to_an_input_does_not_conclude() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.send(add_input(4, Local));
        exchange.send(Step::Complete);

        exchange.receive(Step::Complete);
        // It replies to our first input, not to our tx_complete.
        assert!(!exchange.concluded());
        assert!(exchange.expects_reply());
        exchange.receive(add_input(1, Remote));
        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
    }

    #[test]
    fn abort_ends_the_negotiation_without_concluding() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.send(add_input(4, Local));
        exchange.receive_abort();

        assert!(exchange.aborted());
        assert!(!exchange.concluded());
        assert!(!exchange.expects_reply());

        exchange.send(add_input(6, Local));
        assert!(!exchange.expects_reply());
        assert_eq!(input_ids(&exchange), vec![(2, Local)]);
    }

    #[test]
    fn abort_is_recorded_after_the_conclusion() {
        let mut exchange = TxExchange::new(0);
        exchange.send(Step::Complete);
        exchange.receive(Step::Complete);
        exchange.receive_abort();

        assert!(exchange.aborted());
        assert!(!exchange.concluded());
    }

    #[test]
    fn removals_apply_on_behalf_of_the_sender() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(add_output(1, Remote));

        // Each peer tries to remove an entry the other added; both stay.
        exchange.send(Step::RemoveOutput(1));
        exchange.receive(Step::RemoveInput(2));
        assert_eq!(input_ids(&exchange), vec![(2, Local)]);
        assert_eq!(output_ids(&exchange), vec![(1, Remote)]);

        exchange.send(Step::RemoveInput(2));
        exchange.receive(Step::RemoveOutput(1));
        assert_eq!(input_ids(&exchange), Vec::new());
        assert_eq!(output_ids(&exchange), Vec::new());
    }

    #[test]
    #[should_panic(expected = "AddInput")]
    fn a_sent_step_must_carry_us_as_contributor() {
        TxExchange::new(0).send(add_input(2, Remote));
    }

    #[test]
    #[should_panic(expected = "AddOutput")]
    fn a_received_step_must_carry_the_peer_as_contributor() {
        TxExchange::new(0).receive(add_output(1, Local));
    }
}
