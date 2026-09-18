//! The turn-based interactive transaction exchange of BOLT 2.
//!
//! Two peers build one transaction by taking turns: every message we send
//! earns a reply, until the pair of consecutive `tx_complete`s, one from each
//! side in either order, concludes the exchange. [`TxExchange`] owns the
//! [`SharedTransaction`] being built and drives it from the messages that go
//! out and come in, so callers only translate wire messages.
//!
//! A program may send several messages before reading any reply, so whether a
//! `tx_complete` of ours concluded the exchange is often only known once the
//! reply to the message before it arrives. Sends are queued until answered,
//! and the conclusion is settled from the replies as they come in.

use std::collections::VecDeque;

use super::interactive_tx::{Contributor, SharedInput, SharedOutput, SharedTransaction};

/// One turn of the exchange, in either direction.
///
/// The `contributor` an added input or output carries is overwritten by
/// whichever side takes the turn.
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

/// The shared transaction together with how far the exchange building it has
/// progressed.
#[derive(Debug, Clone)]
pub struct TxExchange {
    shared_tx: SharedTransaction,
    /// Whether two consecutive `tx_complete`s have concluded the exchange.
    /// Nothing sent afterwards is part of the transaction.
    concluded: bool,
    /// Whether the peer aborted the negotiation. May follow a conclusion: the
    /// peer checks the assembled transaction only then.
    aborted: bool,
    /// Whether the peer's `tx_complete` is the latest message in either
    /// direction, so that a `tx_complete` of ours would conclude the exchange
    /// on the spot. Only ever set while nothing is unanswered.
    peer_sent_tx_complete: bool,
    /// Messages we have sent that the peer still owes a reply to, oldest
    /// first. `Some` is our `tx_complete`, with the shared transaction as it
    /// stood when it went out: should the exchange turn out to have concluded
    /// on it, nothing we sent afterwards reached the peer's transaction, so
    /// ours goes back to this. `None` is a contribution.
    ///
    /// Queuing rather than tracking only the latest send keeps a program
    /// whose sends and receives have been knocked out of step by a mutator
    /// from reading a message behind for the rest of its run.
    unanswered: VecDeque<Option<SharedTransaction>>,
}

impl TxExchange {
    /// Starts an exchange for a transaction with the given `nLockTime`.
    #[must_use]
    pub fn new(locktime: u32) -> Self {
        Self {
            shared_tx: SharedTransaction::new(locktime),
            concluded: false,
            aborted: false,
            peer_sent_tx_complete: false,
            unanswered: VecDeque::new(),
        }
    }

    /// The transaction as both peers should see it so far.
    #[must_use]
    pub fn shared_tx(&self) -> &SharedTransaction {
        &self.shared_tx
    }

    /// Whether two consecutive `tx_complete`s have concluded the exchange.
    #[must_use]
    pub fn concluded(&self) -> bool {
        self.concluded
    }

    /// Whether the peer aborted the negotiation.
    #[must_use]
    pub fn aborted(&self) -> bool {
        self.aborted
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
    /// message behind. An aborted negotiation owes nothing.
    #[must_use]
    pub fn expects_reply(&self) -> bool {
        !self.aborted && !self.unanswered.is_empty()
    }

    /// Records a step we sent, applying it to the shared transaction and
    /// noting the reply it earns.
    ///
    /// Once the exchange has concluded the peer takes no further
    /// contributions and owes no further replies, so a later step is neither
    /// recorded nor waited on. The message still goes out for the peer to
    /// judge.
    pub fn send(&mut self, step: Step) {
        if self.concluded {
            return;
        }
        if step == Step::Complete {
            debug_assert!(!self.peer_sent_tx_complete || self.unanswered.is_empty());
            if self.peer_sent_tx_complete {
                self.concluded = true;
            } else {
                self.unanswered.push_back(Some(self.shared_tx.clone()));
            }
        } else {
            self.apply(step, Contributor::Local);
            self.unanswered.push_back(None);
        }
        self.peer_sent_tx_complete = false;
    }

    /// Records a step the peer sent as the reply to our oldest unanswered
    /// message, then applies it.
    ///
    /// A `tx_complete` consecutive with one of ours, in either order,
    /// concludes the exchange. Everything we sent after that `tx_complete`
    /// never reached the peer's transaction, so ours is rolled back to how it
    /// stood when the `tx_complete` went out; the peer's contributions since
    /// preceded the conclusion and stay.
    pub fn receive(&mut self, step: Step) {
        let answered = self.unanswered.pop_front();
        if step != Step::Complete {
            self.peer_sent_tx_complete = false;
            self.apply(step, Contributor::Remote);
            return;
        }

        // Consecutive with ours if it answers our tx_complete, or if our
        // tx_complete is the next thing we sent after what it answers.
        let concluding = answered.flatten().or_else(|| {
            self.unanswered
                .pop_front_if(|sent| sent.is_some())
                .flatten()
        });
        let Some(snapshot) = concluding else {
            self.peer_sent_tx_complete = self.unanswered.is_empty();
            return;
        };

        self.concluded = true;
        self.peer_sent_tx_complete = false;
        if !self.unanswered.is_empty() {
            log::debug!(
                "exchange concluded on an earlier tx_complete, \
                 dropped {} contribution(s) sent after it",
                self.unanswered.len(),
            );
            self.unanswered.clear();
            self.shared_tx.restore_local(&snapshot);
        }
    }

    /// Records the peer's `tx_abort`. It answers our oldest unanswered
    /// message like any other reply, and ends the negotiation.
    pub fn abort(&mut self) {
        self.unanswered.pop_front();
        self.peer_sent_tx_complete = false;
        self.aborted = true;
    }

    /// Applies a contribution on behalf of `contributor`.
    ///
    /// `SharedTransaction` caps inputs and outputs at BOLT 2's 252 and drops
    /// anything past that. The message still goes out, so from there on our
    /// view and the peer's diverge: the negotiation cannot conclude either
    /// way, since the peer fails on the same cap, but the divergence also
    /// misaligns the input positions `tx_signatures` witnesses are ordered
    /// by, which is worth naming when reading a log.
    fn apply(&mut self, step: Step, contributor: Contributor) {
        match step {
            Step::AddInput {
                serial_id,
                mut input,
            } => {
                input.contributor = contributor;
                if !self.shared_tx.add_input(serial_id, input) {
                    log::debug!(
                        "shared transaction is full, dropped input with serial_id {serial_id}"
                    );
                }
            }
            Step::AddOutput {
                serial_id,
                mut output,
            } => {
                output.contributor = contributor;
                if !self.shared_tx.add_output(serial_id, output) {
                    log::debug!(
                        "shared transaction is full, dropped output with serial_id {serial_id}"
                    );
                }
            }
            Step::RemoveInput(serial_id) => {
                if self
                    .shared_tx
                    .remove_input(serial_id, contributor)
                    .is_none()
                {
                    log::debug!(
                        "{contributor:?} removed input with serial_id {serial_id} it did not add, kept"
                    );
                }
            }
            Step::RemoveOutput(serial_id) => {
                if self
                    .shared_tx
                    .remove_output(serial_id, contributor)
                    .is_none()
                {
                    log::debug!(
                        "{contributor:?} removed output with serial_id {serial_id} it did not add, kept"
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
    use crate::channel_tx::interactive_tx::{MAX_INPUTS, MAX_SEQUENCE};

    /// An input whose contributor the exchange is expected to overwrite.
    fn input(vout: u32) -> SharedInput {
        SharedInput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout,
            },
            sequence: MAX_SEQUENCE,
            contributor: Contributor::Remote,
            prevout: None,
        }
    }

    fn output() -> SharedOutput {
        SharedOutput {
            value: 1000,
            script_pubkey: ScriptBuf::new(),
            contributor: Contributor::Remote,
        }
    }

    fn add_input(serial_id: u64) -> Step {
        Step::AddInput {
            serial_id,
            input: input(u32::try_from(serial_id).expect("small serial id")),
        }
    }

    fn add_output(serial_id: u64) -> Step {
        Step::AddOutput {
            serial_id,
            output: output(),
        }
    }

    fn input_ids(exchange: &TxExchange) -> Vec<(u64, Contributor)> {
        exchange
            .shared_tx()
            .inputs()
            .map(|(id, input)| (id, input.contributor))
            .collect()
    }

    fn output_ids(exchange: &TxExchange) -> Vec<u64> {
        exchange.shared_tx().outputs().map(|(id, _)| id).collect()
    }

    #[test]
    fn in_step_exchange_owes_one_reply_per_send() {
        let mut exchange = TxExchange::new(0);
        assert!(!exchange.expects_reply());

        exchange.send(add_input(2));
        assert!(exchange.expects_reply());
        exchange.receive(add_input(1));
        assert!(!exchange.expects_reply());

        assert_eq!(
            input_ids(&exchange),
            vec![(1, Contributor::Remote), (2, Contributor::Local)],
        );
        assert!(!exchange.concluded());
    }

    #[test]
    fn our_tx_complete_after_the_peers_concludes_on_the_spot() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.receive(Step::Complete);
        assert!(!exchange.concluded());

        exchange.send(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());
    }

    #[test]
    fn the_peers_tx_complete_after_ours_concludes() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.receive(add_input(1));
        exchange.send(Step::Complete);
        assert!(exchange.expects_reply());

        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());
    }

    #[test]
    fn a_contribution_between_tx_completes_keeps_the_exchange_open() {
        let mut exchange = TxExchange::new(0);
        exchange.send(Step::Complete);
        exchange.receive(add_input(1));
        exchange.send(Step::Complete);
        assert!(!exchange.concluded());
        assert!(exchange.expects_reply());
    }

    #[test]
    fn late_conclusion_on_the_peers_tx_complete_rolls_back_later_sends() {
        // Three inputs go out with two replies unread, then a tx_complete and
        // a change output. The peer's tx_complete answering the third input
        // and our tx_complete are consecutive, so the exchange concludes
        // without the change output.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.receive(Step::Complete);
        exchange.send(add_input(4));
        exchange.send(add_input(6));
        exchange.send(Step::Complete);
        exchange.send(add_output(2000));
        assert_eq!(exchange.outstanding_replies(), 4);

        exchange.receive(add_input(1));
        assert!(!exchange.concluded());
        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());

        assert_eq!(
            input_ids(&exchange),
            vec![
                (1, Contributor::Remote),
                (2, Contributor::Local),
                (4, Contributor::Local),
                (6, Contributor::Local),
            ],
        );
        assert!(output_ids(&exchange).is_empty());
    }

    #[test]
    fn late_conclusion_on_our_tx_complete_rolls_back_later_sends() {
        // Our tx_complete answers the peer's contribution, its tx_complete
        // answers ours; the output we sent in between never reached it.
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.send(Step::Complete);
        exchange.send(add_output(2000));
        exchange.send(Step::RemoveInput(2));
        assert_eq!(exchange.outstanding_replies(), 4);

        exchange.receive(add_output(1));
        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
        assert!(!exchange.expects_reply());

        assert_eq!(input_ids(&exchange), vec![(2, Contributor::Local)]);
        assert_eq!(output_ids(&exchange), vec![1]);
    }

    #[test]
    fn sends_after_the_conclusion_are_not_recorded() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.receive(Step::Complete);
        exchange.send(Step::Complete);

        exchange.send(add_output(2000));
        assert!(!exchange.expects_reply());
        assert!(output_ids(&exchange).is_empty());
    }

    #[test]
    fn a_reply_settles_a_backlog_left_by_a_dropped_receive() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.send(add_input(4));
        exchange.send(Step::Complete);
        assert_eq!(exchange.outstanding_replies(), 3);

        exchange.receive(Step::Complete);
        // The tx_complete answered our first input, not our tx_complete.
        assert!(!exchange.concluded());
        assert_eq!(exchange.outstanding_replies(), 2);
        exchange.receive(add_input(1));
        exchange.receive(Step::Complete);
        assert!(exchange.concluded());
    }

    #[test]
    fn abort_stops_expecting_replies_without_concluding() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.send(add_input(4));
        exchange.abort();

        assert!(exchange.aborted());
        assert!(!exchange.concluded());
        assert!(!exchange.expects_reply());
        assert_eq!(exchange.outstanding_replies(), 1);
    }

    #[test]
    fn abort_after_the_conclusion_keeps_it() {
        let mut exchange = TxExchange::new(0);
        exchange.send(Step::Complete);
        exchange.receive(Step::Complete);
        exchange.abort();

        assert!(exchange.aborted());
        assert!(exchange.concluded());
    }

    #[test]
    fn removals_only_touch_the_senders_own_entries() {
        let mut exchange = TxExchange::new(0);
        exchange.send(add_input(2));
        exchange.receive(add_input(1));

        exchange.send(Step::RemoveInput(1));
        exchange.receive(Step::RemoveInput(2));
        assert_eq!(
            input_ids(&exchange),
            vec![(1, Contributor::Remote), (2, Contributor::Local)],
        );

        exchange.send(Step::RemoveInput(2));
        exchange.receive(Step::RemoveInput(1));
        assert!(input_ids(&exchange).is_empty());
    }

    #[test]
    fn contributions_past_the_cap_are_dropped_in_both_directions() {
        let mut exchange = TxExchange::new(0);
        for serial_id in 0..u64::try_from(MAX_INPUTS).expect("fits") {
            exchange.send(add_input(serial_id));
        }
        exchange.send(add_input(1000));
        exchange.receive(add_input(1001));

        assert_eq!(exchange.shared_tx().inputs().count(), MAX_INPUTS);
        assert!(input_ids(&exchange).iter().all(|(id, _)| *id < 1000));
    }
}
