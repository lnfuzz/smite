//! The turn-based interactive transaction exchange of BOLT 2.
//!
//! Two peers build one transaction by taking turns: the peer answers every
//! message we send, and two consecutive `tx_complete`s, one from each side in
//! either order, conclude the exchange. [`TxExchange`] replays the messages in
//! the order the peer handles them and builds the [`SharedTransaction`] from
//! that order alone.
//!
//! A program may send several messages before reading any reply. The peer
//! still takes them one per turn, so a send joins the transaction only once
//! the reply to the send before it has arrived, and nothing sent after the
//! concluding `tx_complete` ever does.

use std::collections::VecDeque;

use super::interactive_tx::{Contributor, SharedInput, SharedOutput, SharedTransaction};

/// One message of the exchange, in either direction.
///
/// An added input or output carries the side that sent it as its
/// `contributor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    AddInput {
        serial_id: u64,
        input: SharedInput,
    },
    AddOutput {
        serial_id: u64,
        output: SharedOutput,
    },
    RemoveInput(u64),
    RemoveOutput(u64),
    /// `tx_complete`.
    Complete,
}

impl Step {
    /// Whether `side` may send this step: an addition must name it as the
    /// contributor.
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
    /// Taking contributions. Holds who sent the latest message taken, if it
    /// was a `tx_complete`: one from the other side right after it concludes.
    Open {
        last_tx_complete: Option<Contributor>,
    },
    /// Two consecutive `tx_complete`s ended the exchange.
    Concluded,
    /// The peer sent `tx_abort`. May follow a conclusion: the peer checks the
    /// assembled transaction only then.
    Aborted { after_conclusion: bool },
}

/// The shared transaction, built from the exchange in the order the peer
/// handles it.
#[derive(Debug, Clone)]
pub struct TxExchange {
    shared_tx: SharedTransaction,
    /// Our sends the peer has yet to answer, oldest first. The oldest is
    /// already in `shared_tx`, since the peer handles it before answering;
    /// each later one joins when the reply before it arrives. Empty once the
    /// exchange is over.
    unanswered: VecDeque<Step>,
    phase: Phase,
}

impl TxExchange {
    /// Starts an exchange for a transaction with the given `nLockTime`.
    #[must_use]
    pub fn new(locktime: u32) -> Self {
        Self {
            shared_tx: SharedTransaction::new(locktime),
            unanswered: VecDeque::new(),
            phase: Phase::Open {
                last_tx_complete: None,
            },
        }
    }

    /// The transaction as the peer has built it so far.
    ///
    /// Sends still waiting on the reply before them are not in it yet, so read
    /// every owed reply before building from it.
    #[must_use]
    pub fn shared_tx(&self) -> &SharedTransaction {
        &self.shared_tx
    }

    /// Whether two consecutive `tx_complete`s have concluded the exchange.
    #[must_use]
    pub fn concluded(&self) -> bool {
        matches!(
            self.phase,
            Phase::Concluded
                | Phase::Aborted {
                    after_conclusion: true
                }
        )
    }

    /// Whether the peer aborted the negotiation.
    #[must_use]
    pub fn aborted(&self) -> bool {
        matches!(self.phase, Phase::Aborted { .. })
    }

    /// How many messages the peer still owes a reply to.
    #[must_use]
    pub fn outstanding_replies(&self) -> usize {
        self.unanswered.len()
    }

    /// Whether the peer owes us a message.
    ///
    /// Reading when nothing is owed would consume whatever the peer moved on
    /// to, usually its `commitment_signed`, and leave every later operation a
    /// message behind.
    #[must_use]
    pub fn expects_reply(&self) -> bool {
        !self.unanswered.is_empty()
    }

    /// Records a step we sent.
    ///
    /// Once the exchange has concluded or the peer aborted, the peer takes no
    /// further steps and owes no replies, so a later step is not recorded. The
    /// message still goes out for the peer to judge.
    pub fn send(&mut self, step: Step) {
        debug_assert!(step.is_from(Contributor::Local), "{step:?}");
        if !matches!(self.phase, Phase::Open { .. }) {
            return;
        }
        self.unanswered.push_back(step);
        if self.unanswered.len() == 1 {
            self.take_oldest_send();
        }
    }

    /// Records a step the peer sent, as its reply to our oldest unanswered
    /// send. Ignored once the exchange is over, as in [`Self::send`].
    pub fn receive(&mut self, step: Step) {
        debug_assert!(step.is_from(Contributor::Remote), "{step:?}");
        self.unanswered.pop_front();
        self.take(step, Contributor::Remote);
        self.take_oldest_send();
    }

    /// Records the peer's `tx_abort`. The peer forgets the negotiation, so it
    /// owes no further replies.
    pub fn receive_abort(&mut self) {
        self.phase = Phase::Aborted {
            after_conclusion: self.concluded(),
        };
        self.unanswered.clear();
    }

    /// Lets the peer take our oldest unanswered send, now that it has answered
    /// everything before it.
    fn take_oldest_send(&mut self) {
        if let Some(step) = self.unanswered.front().cloned() {
            self.take(step, Contributor::Local);
        }
    }

    /// Adds the next message in the order the peer handles them. Nothing is
    /// taken once the exchange is over.
    fn take(&mut self, step: Step, from: Contributor) {
        let Phase::Open { last_tx_complete } = self.phase else {
            return;
        };
        match step {
            Step::Complete if last_tx_complete.is_some_and(|other| other != from) => {
                self.conclude(from);
            }
            Step::Complete => {
                self.phase = Phase::Open {
                    last_tx_complete: Some(from),
                };
            }
            contribution => {
                self.phase = Phase::Open {
                    last_tx_complete: None,
                };
                self.apply(contribution, from);
            }
        }
    }

    /// Ends the exchange on a `tx_complete` from `from`. Our sends after it
    /// are never taken and get no reply.
    fn conclude(&mut self, from: Contributor) {
        // Our concluding tx_complete is itself the oldest unanswered send.
        let dropped = self.unanswered.len() - usize::from(from == Contributor::Local);
        if dropped > 0 {
            log::debug!("exchange concluded, dropped {dropped} send(s) after it");
        }
        self.phase = Phase::Concluded;
        self.unanswered.clear();
    }

    /// Applies a contribution from `from`.
    ///
    /// A duplicate `serial_id`, or a removal of the other side's entry, is not
    /// applied: BOLT 2 has the receiver fail the negotiation over it instead.
    ///
    /// TODO: Report the peer doing either as a violation from an
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
        assert!(!exchange.expects_reply());
    }

    #[test]
    fn a_contribution_between_tx_completes_keeps_the_exchange_open() {
        // In turn order the two tx_completes around a contribution come from
        // the same side; only an unsolicited one puts it between the peer's
        // and ours.
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
        // Unsolicited, so it follows the peer's own.
        exchange.receive(Step::Complete);
        assert!(!exchange.concluded());

        exchange.send(Step::Complete);
        assert!(exchange.concluded());
    }

    #[test]
    fn pipelined_sends_apply_in_the_peers_order() {
        // The peer adds and removes its own odd serial_id 5 while our
        // wrong-parity 5 is still waiting its turn, so the two never collide.
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
        // Three inputs go out with two replies unread, then a tx_complete and
        // a change output. The peer's tx_complete answering the third input
        // and our tx_complete are consecutive, so the exchange concludes
        // without the change output.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(Step::Complete);
        exchange.send(add_input(4, Local));
        exchange.send(add_input(6, Local));
        exchange.send(Step::Complete);
        exchange.send(add_output(2000, Local));
        assert_eq!(exchange.outstanding_replies(), 4);

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
        // Our tx_complete answers the peer's contribution, its tx_complete
        // answers ours; the output and removal we sent after never reach it.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.send(Step::Complete);
        exchange.send(add_output(2000, Local));
        exchange.send(Step::RemoveInput(2));
        assert_eq!(exchange.outstanding_replies(), 4);

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
    fn a_reply_settles_a_backlog_left_by_a_dropped_receive() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.send(add_input(4, Local));
        exchange.send(Step::Complete);
        assert_eq!(exchange.outstanding_replies(), 3);

        exchange.receive(Step::Complete);
        // The tx_complete answered our first input, not our tx_complete.
        assert!(!exchange.concluded());
        assert_eq!(exchange.outstanding_replies(), 2);
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
    fn abort_after_the_conclusion_keeps_it() {
        let mut exchange = TxExchange::new(0);
        exchange.send(Step::Complete);
        exchange.receive(Step::Complete);
        exchange.receive_abort();

        assert!(exchange.aborted());
        assert!(exchange.concluded());
    }

    #[test]
    fn removals_apply_on_behalf_of_the_sender() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2, Local));
        exchange.receive(add_output(1, Remote));

        // Each side names the other's entry, which stays.
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
    #[cfg(debug_assertions)]
    #[should_panic(expected = "AddInput")]
    fn a_sent_step_must_carry_us_as_contributor() {
        TxExchange::new(0).send(add_input(2, Remote));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "AddOutput")]
    fn a_received_step_must_carry_the_peer_as_contributor() {
        TxExchange::new(0).receive(add_output(1, Local));
    }
}
