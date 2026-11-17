//! The lifecycle states of a plan, an operation, and a step.
//!
//! `docs/ACTION_CONTRACTS.md` section 6 owns the states and
//! `docs/ARCHITECTURE.md` section 7 has the summary diagram. The state names
//! are the names in the specification. `Prepared` describes a plan,
//! `Admitted` describes an operation and a step that has no intent record,
//! and `IntentCommitted`, `DispatchConsumed`, and `Verifying` describe a
//! step. A request that fails admission has no state: it is a rejection.
//!
//! Dispatch and durability are separate facts. [`StepProgress`] keeps the
//! three values together and accepts only the combinations and the
//! transitions that the specification permits.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::encoding::wire_enum;

wire_enum! {
    /// The state of a plan.
    PlanState {
        /// The immutable plan exists. No mutation authority is consumed.
        Prepared => "Prepared",
    }
}

wire_enum! {
    /// The state of an admitted operation.
    OperationState {
        /// The operation, its reservations, and its executor are established.
        Admitted => "Admitted",
        /// Each requested final target condition is verified.
        Completed => "Completed",
        /// Some effects are verified; other work was skipped, was refused,
        /// or failed.
        Partial => "Partial",
        /// Work was submitted, no effect is verified, and an intentional
        /// stop left the target condition unmet.
        Incomplete => "Incomplete",
        /// No external mutation was submitted and no error needs a failed
        /// result.
        NoAction => "NoAction",
        /// No effect is verified and a known failure prevents completion.
        Failed => "Failed",
        /// The evidence cannot establish the effect. Reconciliation is
        /// necessary before a conflicting retry.
        UnknownOutcome => "UnknownOutcome",
    }
}

wire_enum! {
    /// The state of one step of an admitted operation.
    StepState {
        /// The operation is admitted and the step has no intent record.
        Admitted => "Admitted",
        /// The intent and its budget context are durably recorded.
        IntentCommitted => "IntentCommitted",
        /// The step is single-use. No other request can submit it.
        DispatchConsumed => "DispatchConsumed",
        /// The external call was submitted and its outcome is observed.
        Verifying => "Verifying",
        /// Each requested final target condition of the step is verified.
        Completed => "Completed",
        /// Some effects of the step are verified.
        Partial => "Partial",
        /// The step was submitted and an intentional stop left the target
        /// condition unmet.
        Incomplete => "Incomplete",
        /// No external call was issued for the step.
        NoAction => "NoAction",
        /// A known failure prevents completion of the step.
        Failed => "Failed",
        /// The evidence cannot establish the effect of the step.
        UnknownOutcome => "UnknownOutcome",
    }
}

wire_enum! {
    /// Whether the external call of a step or a target was submitted.
    DispatchState {
        /// No external call was submitted.
        NotSubmitted => "not_submitted",
        /// The external call was submitted.
        Submitted => "submitted",
        /// The evidence cannot establish whether the call was submitted.
        SubmissionUncertain => "submission_uncertain",
    }
}

wire_enum! {
    /// How a record was kept.
    Durability {
        /// The record is in the durable journal.
        Durable => "durable",
        /// The record is in bounded volatile state only. Only the
        /// critical-memory exception makes this value.
        Volatile => "volatile",
        /// An earlier boundary was durable and a later write failed.
        PersistenceFailed => "persistence_failed",
    }
}

impl OperationState {
    /// Each state that this build knows.
    pub const ALL: [Self; 7] = [
        Self::Admitted,
        Self::Completed,
        Self::Partial,
        Self::Incomplete,
        Self::NoAction,
        Self::Failed,
        Self::UnknownOutcome,
    ];

    /// Whether the state is a settled result. `UnknownOutcome` is not
    /// settled: it needs reconciliation. A value that this build does not
    /// recognize is not settled.
    pub fn is_settled(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Incomplete | Self::NoAction | Self::Failed
        )
    }

    /// Whether the operation can go from this state to `next`.
    ///
    /// `Admitted` goes to each result. `UnknownOutcome` goes to a settled
    /// result when reconciliation establishes it. A settled result and a
    /// value that this build does not recognize go nowhere.
    pub fn can_transition_to(&self, next: &Self) -> bool {
        match self {
            Self::Admitted => next.is_settled() || matches!(next, Self::UnknownOutcome),
            Self::UnknownOutcome => next.is_settled(),
            _ => false,
        }
    }

    /// The state after the transition to `next`.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::NotPermitted`] when the specification does
    /// not permit the transition.
    pub fn transition(&self, next: Self) -> Result<Self, TransitionError> {
        if self.can_transition_to(&next) {
            Ok(next)
        } else {
            Err(TransitionError::NotPermitted {
                from: self.as_str().to_owned(),
                to: next.as_str().to_owned(),
            })
        }
    }
}

impl StepState {
    /// Each state that this build knows.
    pub const ALL: [Self; 10] = [
        Self::Admitted,
        Self::IntentCommitted,
        Self::DispatchConsumed,
        Self::Verifying,
        Self::Completed,
        Self::Partial,
        Self::Incomplete,
        Self::NoAction,
        Self::Failed,
        Self::UnknownOutcome,
    ];

    /// Whether the state is a settled result. `UnknownOutcome` is not
    /// settled.
    pub fn is_settled(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Incomplete | Self::NoAction | Self::Failed
        )
    }

    /// Whether the step can go from this state to `next` on the normal
    /// durable path.
    ///
    /// | From | To |
    /// | --- | --- |
    /// | `Admitted` | `IntentCommitted`, `NoAction`, `Failed` |
    /// | `IntentCommitted` | `DispatchConsumed`, `NoAction`, `Failed` |
    /// | `DispatchConsumed` | `Verifying`, `NoAction`, `UnknownOutcome` |
    /// | `Verifying` | `Completed`, `Partial`, `Incomplete`, `Failed`, `UnknownOutcome` |
    /// | `UnknownOutcome` | each settled state, through reconciliation |
    ///
    /// The critical-memory exception has one more transition, `Admitted` to
    /// `DispatchConsumed` with volatile durability. Only
    /// [`StepProgress::advance`] permits it.
    pub fn can_transition_to(&self, next: &Self) -> bool {
        match self {
            Self::Admitted => matches!(next, Self::IntentCommitted | Self::NoAction | Self::Failed),
            Self::IntentCommitted => {
                matches!(next, Self::DispatchConsumed | Self::NoAction | Self::Failed)
            }
            Self::DispatchConsumed => {
                matches!(
                    next,
                    Self::Verifying | Self::NoAction | Self::UnknownOutcome
                )
            }
            Self::Verifying => matches!(
                next,
                Self::Completed
                    | Self::Partial
                    | Self::Incomplete
                    | Self::Failed
                    | Self::UnknownOutcome
            ),
            Self::UnknownOutcome => next.is_settled(),
            _ => false,
        }
    }

    /// Whether `dispatch` can be the dispatch state of a step in this state.
    fn accepts_dispatch(&self, dispatch: &DispatchState) -> bool {
        use DispatchState::{NotSubmitted, SubmissionUncertain, Submitted};
        match self {
            Self::Admitted | Self::IntentCommitted | Self::DispatchConsumed | Self::NoAction => {
                matches!(dispatch, NotSubmitted)
            }
            Self::Verifying => matches!(dispatch, Submitted),
            // Reconciliation can settle a step whose submission stays
            // uncertain, for example a target that is absent after a crash.
            Self::Completed | Self::Partial | Self::Incomplete | Self::UnknownOutcome => {
                matches!(dispatch, Submitted | SubmissionUncertain)
            }
            Self::Failed => matches!(dispatch, NotSubmitted | Submitted),
            Self::Unrecognized(_) => false,
        }
    }

    /// Whether `durability` can be the durability of a step in this state.
    /// `IntentCommitted` is durable. `Admitted` and `DispatchConsumed` are
    /// durable, or volatile for the critical-memory exception.
    fn accepts_durability(&self, durability: &Durability) -> bool {
        match self {
            Self::IntentCommitted => matches!(durability, Durability::Durable),
            Self::Admitted | Self::DispatchConsumed => {
                matches!(durability, Durability::Durable | Durability::Volatile)
            }
            Self::Unrecognized(_) => false,
            _ => durability.is_recognized(),
        }
    }
}

impl DispatchState {
    /// Whether an external call was, or possibly was, submitted.
    pub fn is_possibly_submitted(&self) -> bool {
        matches!(self, Self::Submitted | Self::SubmissionUncertain)
    }

    /// A recorded submission stays recorded. An uncertain submission can
    /// become submitted or, when reconciliation proves it, not submitted.
    fn can_become(&self, next: &Self) -> bool {
        match self {
            Self::NotSubmitted | Self::SubmissionUncertain => next.is_recognized(),
            Self::Submitted => matches!(next, Self::Submitted),
            Self::Unrecognized(_) => false,
        }
    }
}

impl Durability {
    /// Whether the record is durable. Only this value permits a filesystem
    /// dispatch.
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Durable)
    }

    /// A volatile or failed record never becomes durable in place, and a
    /// durable record never becomes volatile.
    fn can_become(&self, next: &Self) -> bool {
        match self {
            Self::Durable => matches!(next, Self::Durable | Self::PersistenceFailed),
            Self::Volatile => matches!(next, Self::Volatile),
            Self::PersistenceFailed => matches!(next, Self::PersistenceFailed),
            Self::Unrecognized(_) => false,
        }
    }
}

/// The reason a state change was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransitionError {
    /// The specification does not permit the transition.
    #[error("the transition from `{from}` to `{to}` is not permitted")]
    NotPermitted {
        /// The current state.
        from: String,
        /// The requested state.
        to: String,
    },
    /// The dispatch state does not agree with the state, or a recorded
    /// submission would be removed.
    #[error("the dispatch state `{dispatch}` is not permitted for the state `{state}`")]
    Dispatch {
        /// The state.
        state: String,
        /// The dispatch state.
        dispatch: String,
    },
    /// The durability does not agree with the state, or a volatile or failed
    /// record would be reported as durable.
    #[error("the durability `{durability}` is not permitted for the state `{state}`")]
    Durability {
        /// The state.
        state: String,
        /// The durability.
        durability: String,
    },
}

/// The state, the dispatch state, and the durability of one step.
///
/// The fields are private. [`StepProgress::admitted`] makes the first value
/// and [`StepProgress::advance`] makes each later value, so a value of this
/// type always has a permitted combination. A decoded value with a field
/// that this build does not recognize is kept as it is and cannot advance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "StepProgressWire")]
pub struct StepProgress {
    state: StepState,
    dispatch: DispatchState,
    durability: Durability,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepProgressWire {
    state: StepState,
    dispatch: DispatchState,
    durability: Durability,
}

impl TryFrom<StepProgressWire> for StepProgress {
    type Error = TransitionError;

    fn try_from(wire: StepProgressWire) -> Result<Self, Self::Error> {
        let progress = Self {
            state: wire.state,
            dispatch: wire.dispatch,
            durability: wire.durability,
        };
        if progress.is_recognized() {
            check_combination(&progress.state, &progress.dispatch, &progress.durability)?;
        }
        Ok(progress)
    }
}

fn check_combination(
    state: &StepState,
    dispatch: &DispatchState,
    durability: &Durability,
) -> Result<(), TransitionError> {
    if !state.accepts_dispatch(dispatch) {
        return Err(TransitionError::Dispatch {
            state: state.as_str().to_owned(),
            dispatch: dispatch.as_str().to_owned(),
        });
    }
    if !state.accepts_durability(durability) {
        return Err(TransitionError::Durability {
            state: state.as_str().to_owned(),
            durability: durability.as_str().to_owned(),
        });
    }
    Ok(())
}

impl StepProgress {
    /// The progress of a step of an operation that was admitted with
    /// `durability`: `Admitted`, not submitted.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::Durability`] when `durability` is
    /// `persistence_failed` or a value that this build does not recognize:
    /// an admission is durable, or volatile for the critical-memory
    /// exception.
    pub fn admitted(durability: Durability) -> Result<Self, TransitionError> {
        if !matches!(durability, Durability::Durable | Durability::Volatile) {
            return Err(TransitionError::Durability {
                state: StepState::Admitted.as_str().to_owned(),
                durability: durability.as_str().to_owned(),
            });
        }
        Ok(Self {
            state: StepState::Admitted,
            dispatch: DispatchState::NotSubmitted,
            durability,
        })
    }

    /// The state of the step.
    pub fn state(&self) -> &StepState {
        &self.state
    }

    /// Whether the external call was submitted.
    pub fn dispatch(&self) -> &DispatchState {
        &self.dispatch
    }

    /// How the record of the step is kept.
    pub fn durability(&self) -> &Durability {
        &self.durability
    }

    /// Whether this build recognizes the three values.
    pub fn is_recognized(&self) -> bool {
        self.state.is_recognized()
            && self.dispatch.is_recognized()
            && self.durability.is_recognized()
    }

    /// The progress after the step goes to `state` with `dispatch` and
    /// `durability`.
    ///
    /// # Errors
    ///
    /// Returns a [`TransitionError`] when:
    ///
    /// - The specification does not permit the transition. `Admitted` to
    ///   `DispatchConsumed` is permitted only when the step was admitted
    ///   with volatile durability.
    /// - `dispatch` or `durability` is not permitted for `state`.
    /// - A recorded submission would be removed, or a submission would be
    ///   recorded for a step whose dispatch was not consumed.
    /// - A volatile or failed record would become durable, or a durable
    ///   record would become volatile.
    /// - A value is one that this build does not recognize.
    pub fn advance(
        &self,
        state: StepState,
        dispatch: DispatchState,
        durability: Durability,
    ) -> Result<Self, TransitionError> {
        let volatile_consumption: bool = matches!(self.state, StepState::Admitted)
            && matches!(state, StepState::DispatchConsumed)
            && matches!(self.durability, Durability::Volatile);
        let volatile_intent: bool = matches!(self.durability, Durability::Volatile)
            && matches!(state, StepState::IntentCommitted);
        if volatile_intent || !(self.state.can_transition_to(&state) || volatile_consumption) {
            return Err(TransitionError::NotPermitted {
                from: self.state.as_str().to_owned(),
                to: state.as_str().to_owned(),
            });
        }
        // A call exists only after the dispatch of the step was consumed.
        let first_submission: bool = matches!(self.dispatch, DispatchState::NotSubmitted)
            && dispatch.is_possibly_submitted();
        let consumed: bool = matches!(self.state, StepState::DispatchConsumed);
        if !self.dispatch.can_become(&dispatch) || (first_submission && !consumed) {
            return Err(TransitionError::Dispatch {
                state: state.as_str().to_owned(),
                dispatch: dispatch.as_str().to_owned(),
            });
        }
        if !self.durability.can_become(&durability) {
            return Err(TransitionError::Durability {
                state: state.as_str().to_owned(),
                durability: durability.as_str().to_owned(),
            });
        }
        check_combination(&state, &dispatch, &durability)?;
        Ok(Self {
            state,
            dispatch,
            durability,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DispatchState, Durability, OperationState, PlanState, StepProgress, StepState,
        TransitionError,
    };

    use DispatchState::{NotSubmitted, SubmissionUncertain, Submitted};

    fn permitted_step_transitions() -> Vec<(StepState, StepState)> {
        use StepState::{
            Admitted, Completed, DispatchConsumed, Failed, Incomplete, IntentCommitted, NoAction,
            Partial, UnknownOutcome, Verifying,
        };
        vec![
            (Admitted, IntentCommitted),
            (Admitted, NoAction),
            (Admitted, Failed),
            (IntentCommitted, DispatchConsumed),
            (IntentCommitted, NoAction),
            (IntentCommitted, Failed),
            (DispatchConsumed, Verifying),
            (DispatchConsumed, NoAction),
            (DispatchConsumed, UnknownOutcome),
            (Verifying, Completed),
            (Verifying, Partial),
            (Verifying, Incomplete),
            (Verifying, Failed),
            (Verifying, UnknownOutcome),
            (UnknownOutcome, Completed),
            (UnknownOutcome, Partial),
            (UnknownOutcome, Incomplete),
            (UnknownOutcome, NoAction),
            (UnknownOutcome, Failed),
        ]
    }

    #[test]
    fn each_step_transition_is_permitted_or_rejected_as_specified() {
        let permitted = permitted_step_transitions();
        let mut count = 0;
        for from in &StepState::ALL {
            for to in &StepState::ALL {
                let expected = permitted.contains(&(from.clone(), to.clone()));
                assert_eq!(from.can_transition_to(to), expected, "{from} -> {to}");
                count += usize::from(expected);
            }
        }
        assert_eq!(count, permitted.len());
        assert_eq!(count, 19);
    }

    #[test]
    fn each_operation_transition_is_permitted_or_rejected_as_specified() {
        use OperationState::{
            Admitted, Completed, Failed, Incomplete, NoAction, Partial, UnknownOutcome,
        };
        let settled = [Completed, Partial, Incomplete, NoAction, Failed];
        for from in &OperationState::ALL {
            for to in &OperationState::ALL {
                let expected = match from {
                    Admitted => settled.contains(to) || *to == UnknownOutcome,
                    UnknownOutcome => settled.contains(to),
                    _ => false,
                };
                assert_eq!(from.can_transition_to(to), expected, "{from} -> {to}");
                assert_eq!(from.transition(to.clone()).is_ok(), expected);
            }
        }
        assert_eq!(
            Completed.transition(Admitted),
            Err(TransitionError::NotPermitted {
                from: "Completed".to_owned(),
                to: "Admitted".to_owned(),
            })
        );
        assert!(!UnknownOutcome.is_settled());
        assert!(!Admitted.is_settled());
    }

    #[test]
    fn an_unknown_state_goes_nowhere_and_nothing_goes_to_it() {
        let step: StepState = serde_json::from_str("\"Suspended\"").unwrap();
        let operation: OperationState = serde_json::from_str("\"Suspended\"").unwrap();
        assert!(!step.is_recognized() && !step.is_settled());
        assert!(!operation.is_recognized() && !operation.is_settled());
        assert_ne!(operation, OperationState::Completed);
        for known in &StepState::ALL {
            assert!(!step.can_transition_to(known));
            assert!(!known.can_transition_to(&step));
        }
        for known in &OperationState::ALL {
            assert!(!operation.can_transition_to(known));
            assert!(!known.can_transition_to(&operation));
        }
        // The spelling is exact.
        assert!(!OperationState::from_wire("completed").is_recognized());
        assert!(!PlanState::from_wire("prepared").is_recognized());
        assert_eq!(
            serde_json::to_string(&PlanState::Prepared).unwrap(),
            "\"Prepared\""
        );
    }

    #[test]
    fn each_state_value_round_trips() {
        for state in &StepState::ALL {
            let json = serde_json::to_string(state).unwrap();
            assert_eq!(json, format!("\"{state}\""));
            assert_eq!(&serde_json::from_str::<StepState>(&json).unwrap(), state);
        }
        for state in &OperationState::ALL {
            let json = serde_json::to_string(state).unwrap();
            assert_eq!(
                &serde_json::from_str::<OperationState>(&json).unwrap(),
                state
            );
        }
        for (value, text) in [
            (NotSubmitted, "\"not_submitted\""),
            (Submitted, "\"submitted\""),
            (SubmissionUncertain, "\"submission_uncertain\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), text);
            assert_eq!(serde_json::from_str::<DispatchState>(text).unwrap(), value);
        }
        for (value, text) in [
            (Durability::Durable, "\"durable\""),
            (Durability::Volatile, "\"volatile\""),
            (Durability::PersistenceFailed, "\"persistence_failed\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), text);
            assert_eq!(serde_json::from_str::<Durability>(text).unwrap(), value);
        }
        let dispatch: DispatchState = serde_json::from_str("\"queued\"").unwrap();
        assert!(!dispatch.is_recognized() && !dispatch.is_possibly_submitted());
        let durability: Durability = serde_json::from_str("\"replicated\"").unwrap();
        assert!(!durability.is_recognized() && !durability.is_durable());
    }

    #[test]
    fn the_normal_path_advances_with_durable_records() {
        let durable = Durability::Durable;
        let step = StepProgress::admitted(durable.clone()).unwrap();
        let step = step
            .advance(StepState::IntentCommitted, NotSubmitted, durable.clone())
            .unwrap();
        let step = step
            .advance(StepState::DispatchConsumed, NotSubmitted, durable.clone())
            .unwrap();
        let step = step
            .advance(StepState::Verifying, Submitted, durable.clone())
            .unwrap();
        let done = step
            .advance(StepState::Completed, Submitted, durable.clone())
            .unwrap();
        assert_eq!(done.state(), &StepState::Completed);
        assert_eq!(done.dispatch(), &Submitted);
        assert!(done.durability().is_durable());
        // A result commit can fail after the durable boundaries.
        let degraded = step
            .advance(
                StepState::Completed,
                Submitted,
                Durability::PersistenceFailed,
            )
            .unwrap();
        assert_eq!(degraded.durability(), &Durability::PersistenceFailed);
        // A settled step does not change.
        assert!(
            done.advance(StepState::Verifying, Submitted, durable)
                .is_err()
        );
    }

    #[test]
    fn a_dispatch_state_must_agree_with_the_state() {
        let durable = Durability::Durable;
        let admitted = StepProgress::admitted(durable.clone()).unwrap();
        let committed = admitted
            .advance(StepState::IntentCommitted, NotSubmitted, durable.clone())
            .unwrap();
        // No call exists before the dispatch is consumed.
        assert!(matches!(
            admitted.advance(StepState::IntentCommitted, Submitted, durable.clone()),
            Err(TransitionError::Dispatch { .. })
        ));
        let consumed = committed
            .advance(StepState::DispatchConsumed, NotSubmitted, durable.clone())
            .unwrap();
        // `Verifying` means that the call was submitted.
        for dispatch in [NotSubmitted, SubmissionUncertain] {
            assert!(
                consumed
                    .advance(StepState::Verifying, dispatch, durable.clone())
                    .is_err()
            );
        }
        // `NoAction` means that no call was issued.
        assert!(
            consumed
                .advance(StepState::NoAction, Submitted, durable.clone())
                .is_err()
        );
        consumed
            .advance(StepState::NoAction, NotSubmitted, durable.clone())
            .unwrap();
        // A crash after consumption leaves the submission uncertain.
        let unknown = consumed
            .advance(
                StepState::UnknownOutcome,
                SubmissionUncertain,
                durable.clone(),
            )
            .unwrap();
        assert!(
            consumed
                .advance(StepState::UnknownOutcome, NotSubmitted, durable.clone())
                .is_err()
        );
        // Reconciliation can prove that no call was submitted.
        unknown
            .advance(StepState::NoAction, NotSubmitted, durable.clone())
            .unwrap();
        unknown
            .advance(StepState::Completed, Submitted, durable.clone())
            .unwrap();
        // Reconciliation can settle a step whose submission stays
        // uncertain.
        for state in [
            StepState::Completed,
            StepState::Partial,
            StepState::Incomplete,
        ] {
            unknown
                .advance(state, SubmissionUncertain, durable.clone())
                .unwrap();
        }
        // A call exists only after the dispatch was consumed: a step that
        // fails before it has no submission.
        for early in [&admitted, &committed] {
            for dispatch in [Submitted, SubmissionUncertain] {
                assert!(matches!(
                    early.advance(StepState::Failed, dispatch, durable.clone()),
                    Err(TransitionError::Dispatch { .. })
                ));
            }
            early
                .advance(StepState::Failed, NotSubmitted, durable.clone())
                .unwrap();
        }
        // A recorded submission is not removed.
        let verifying = consumed
            .advance(StepState::Verifying, Submitted, durable.clone())
            .unwrap();
        let lost = verifying
            .advance(StepState::UnknownOutcome, Submitted, durable.clone())
            .unwrap();
        assert!(matches!(
            lost.advance(StepState::NoAction, NotSubmitted, durable.clone()),
            Err(TransitionError::Dispatch { .. })
        ));
        assert!(
            verifying
                .advance(StepState::Failed, NotSubmitted, durable)
                .is_err()
        );
    }

    #[test]
    fn a_volatile_record_is_never_reported_as_durable_intent() {
        let volatile = Durability::Volatile;
        let admitted = StepProgress::admitted(volatile.clone()).unwrap();
        // The exception records intent and consumption together.
        let consumed = admitted
            .advance(StepState::DispatchConsumed, NotSubmitted, volatile.clone())
            .unwrap();
        assert_eq!(consumed.durability(), &Durability::Volatile);
        // `IntentCommitted` is a durable state.
        for durability in [volatile.clone(), Durability::Durable] {
            assert!(
                admitted
                    .advance(StepState::IntentCommitted, NotSubmitted, durability)
                    .is_err()
            );
        }
        // A volatile record does not become durable in place.
        assert!(matches!(
            consumed.advance(StepState::Verifying, Submitted, Durability::Durable),
            Err(TransitionError::Durability { .. })
        ));
        let verifying = consumed
            .advance(StepState::Verifying, Submitted, volatile.clone())
            .unwrap();
        verifying
            .advance(StepState::Completed, Submitted, volatile.clone())
            .unwrap();
        // The durable path cannot skip the intent record.
        let durable = StepProgress::admitted(Durability::Durable).unwrap();
        assert!(matches!(
            durable.advance(
                StepState::DispatchConsumed,
                NotSubmitted,
                Durability::Durable
            ),
            Err(TransitionError::NotPermitted { .. })
        ));
        // A durable record does not become volatile.
        assert!(
            durable
                .advance(StepState::NoAction, NotSubmitted, volatile)
                .is_err()
        );
        // A failed write cannot consume a dispatch.
        let committed = durable
            .advance(
                StepState::IntentCommitted,
                NotSubmitted,
                Durability::Durable,
            )
            .unwrap();
        assert!(
            committed
                .advance(
                    StepState::DispatchConsumed,
                    NotSubmitted,
                    Durability::PersistenceFailed
                )
                .is_err()
        );
        committed
            .advance(
                StepState::Failed,
                NotSubmitted,
                Durability::PersistenceFailed,
            )
            .unwrap();
        // An admission is durable or volatile.
        assert!(StepProgress::admitted(Durability::PersistenceFailed).is_err());
        let failed_admission = json!({
            "state": "Admitted", "dispatch": "not_submitted", "durability": "persistence_failed"
        });
        assert!(serde_json::from_value::<StepProgress>(failed_admission).is_err());
        assert!(StepProgress::admitted(Durability::from_wire("other")).is_err());
    }

    #[test]
    fn a_progress_record_round_trips_and_rejects_a_bad_combination() {
        let step = StepProgress::admitted(Durability::Durable).unwrap();
        let value = serde_json::to_value(&step).unwrap();
        assert_eq!(
            value,
            json!({ "state": "Admitted", "dispatch": "not_submitted", "durability": "durable" })
        );
        assert_eq!(serde_json::from_value::<StepProgress>(value).unwrap(), step);

        for bad in [
            json!({ "state": "Completed", "dispatch": "not_submitted", "durability": "durable" }),
            json!({ "state": "NoAction", "dispatch": "submitted", "durability": "durable" }),
            json!({ "state": "IntentCommitted", "dispatch": "not_submitted", "durability": "volatile" }),
            json!({ "state": "Admitted", "dispatch": "not_submitted" }),
            json!({ "state": "Admitted", "dispatch": "not_submitted", "durability": "durable", "x": 1 }),
        ] {
            assert!(
                serde_json::from_value::<StepProgress>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_progress_record_with_an_unknown_value_cannot_advance() {
        let value =
            json!({ "state": "Suspended", "dispatch": "not_submitted", "durability": "durable" });
        let step: StepProgress = serde_json::from_value(value.clone()).unwrap();
        assert!(!step.is_recognized());
        assert!(!step.state().is_settled());
        assert_eq!(serde_json::to_value(&step).unwrap(), value);
        for state in &StepState::ALL {
            for dispatch in [NotSubmitted, Submitted, SubmissionUncertain] {
                assert!(
                    step.advance(state.clone(), dispatch, Durability::Durable)
                        .is_err()
                );
            }
        }
        let unknown_dispatch: StepProgress = serde_json::from_value(
            json!({ "state": "Verifying", "dispatch": "queued", "durability": "durable" }),
        )
        .unwrap();
        assert!(
            unknown_dispatch
                .advance(StepState::Completed, Submitted, Durability::Durable)
                .is_err()
        );
        let known = StepProgress::admitted(Durability::Durable).unwrap();
        assert!(
            known
                .advance(
                    StepState::from_wire("Suspended"),
                    NotSubmitted,
                    Durability::Durable
                )
                .is_err()
        );
    }
}
