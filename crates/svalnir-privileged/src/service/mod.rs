//! The service of the helper: one request in, one response out.
//!
//! [`HelperService`] connects the parts of the crate. For one message of a
//! transport it does these steps in sequence and stops at the first one
//! that fails:
//!
//! 1. The peer: the platform verified its code identity, and the platform
//!    gave its effective user. The bytes of a peer that is not verified
//!    are not decoded.
//! 2. Decoding: [`decode_request`], with
//!    its limits.
//! 3. The caller: a [`CallerIdentity`] from the facts of the transport.
//!    The helper has one caller role. A peer has it only when its verified
//!    code identity is the identity of the agent in the settings of the
//!    helper.
//! 4. The clock of the helper.
//! 5. The decision and the consumption of the step:
//!    [`HelperState::admit`].
//! 6. Durability: the record of the consumed step goes to the
//!    [`RecordStore`] before the executor gets the step. If the write
//!    fails, the step is recorded as `NoAction` and no call is submitted
//!    (`docs/ACTION_CONTRACTS.md` section 12).
//! 7. Execution, with the gate of [`HelperState::still_covers`] and a new
//!    clock reading before each entry.
//! 8. The result: the state of the step from the entry results, with the
//!    aggregation rules of `svalnir-core`, then the record of the result.
//!
//! The service holds one lock for the full request, so the helper does one
//! step at a time. A status query waits for a step in work and then gets
//! its result.

mod clock;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

pub use clock::{CLOCK_DOMAIN, ClockSource, ClockUnavailable, SystemClock};
use svalnir_core::action::{
    ActionError, ActionStage, ClientRole, DispatchState, Durability, ErrorFamily, StepState,
    TargetResult, aggregate_step,
};
use svalnir_core::id::{RequestId, TargetId};
use svalnir_core::time::WallTime;
use thiserror::Error;

use crate::executor::{EvictionExecutor, Execution};
use crate::request::{
    CallerIdentity, CodeIdentity, DecodeError, HelperRequest, StepCorrelation, decode_request,
};
use crate::response::{
    Condition, EncodeError, EntryReport, HelperResponse, RefusalReport, ReportOrigin, ResponseBody,
    StepReport, action_error,
};
use crate::transport::{CodeVerification, PeerFacts, Reply, RequestHandler};
use crate::validation::{
    Admission, BoundedOperation, ConsumedRequest, Dispatch, HelperClock, HelperState, RecordError,
    Refusal, RefusalReason, StepKey, StepStatus,
};

/// The reason a write of the record store failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the record store did not make the record durable")]
pub struct StoreError;

/// The durable record of the helper: its own authoritative action record
/// (`docs/ACTION_CONTRACTS.md` section 12).
///
/// A call returns `Ok` only after its record is durable. The storage is
/// owned by the helper user; no file of the calling user is a part of it.
pub trait RecordStore: Send {
    /// Makes the record of a consumed step durable. The service calls this
    /// before the executor gets the step.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the record is not durable.
    fn write_consumed(&mut self, request: &ConsumedRequest) -> Result<(), StoreError>;

    /// Makes the result of a consumed step durable: its state and its
    /// entry results.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the record is not durable.
    fn write_result(
        &mut self,
        key: &StepKey,
        state: &StepState,
        entries: Option<&[EntryReport]>,
    ) -> Result<(), StoreError>;

    /// Removes the record of a step that the state of the helper removed.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the removal is not durable. The
    /// service continues: a record that stays is restored as a settled
    /// step and removed again.
    fn remove(&mut self, key: &StepKey) -> Result<(), StoreError>;
}

/// A record store that makes no record durable. Each write fails, so a
/// service with this store submits no call.
///
/// This build has no durable store of the helper; the binary uses this
/// one.
// TODO(npochaev): add the durable record store of the helper in root-owned
// storage, and restore the state from it at the start of the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnavailableStore;

impl RecordStore for UnavailableStore {
    fn write_consumed(&mut self, _request: &ConsumedRequest) -> Result<(), StoreError> {
        Err(StoreError)
    }

    fn write_result(
        &mut self,
        _key: &StepKey,
        _state: &StepState,
        _entries: Option<&[EntryReport]>,
    ) -> Result<(), StoreError> {
        Err(StoreError)
    }

    fn remove(&mut self, _key: &StepKey) -> Result<(), StoreError> {
        Err(StoreError)
    }
}

/// What the service keeps for a consumed step beside its state: the entry
/// results and the durability of the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    /// The result of each entry. `None` when the step has no entry
    /// results.
    pub entries: Option<Vec<EntryReport>>,
    /// How the record of the state of the step was kept.
    pub durability: Durability,
    /// The error of the step as a whole.
    pub error: Option<ActionError>,
}

struct Inner<S, E> {
    state: HelperState,
    results: BTreeMap<StepKey, StepResult>,
    store: S,
    executor: E,
}

/// The service of the helper.
pub struct HelperService<S, E, C> {
    inner: Mutex<Inner<S, E>>,
    clock: C,
}

impl<S, E, C> std::fmt::Debug for HelperService<S, E, C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HelperService")
            .finish_non_exhaustive()
    }
}

/// A response and whether its message counts against the peer.
struct Outcome {
    response: HelperResponse,
    penalized: bool,
}

impl Outcome {
    fn rejected(code: &'static str, family: ErrorFamily) -> Self {
        Self {
            response: HelperResponse::rejected(code, family),
            penalized: true,
        }
    }

    fn condition(condition: Condition) -> Self {
        Self::rejected(condition.code(), condition.family())
    }

    fn decode_error(error: DecodeError) -> Self {
        Self::rejected(error.code(), ErrorFamily::Request)
    }
}

impl<S: RecordStore, E: EvictionExecutor, C: ClockSource> HelperService<S, E, C> {
    /// Makes the service.
    ///
    /// `state` is the state of the helper, new or restored from the
    /// durable record. `results` has the entry results of the restored
    /// steps; a step of `state` with no value in it has no entry results.
    pub fn new(
        state: HelperState,
        results: BTreeMap<StepKey, StepResult>,
        store: S,
        executor: E,
        clock: C,
    ) -> Self {
        let results: BTreeMap<StepKey, StepResult> = results
            .into_iter()
            .filter(|(key, _)| state.consumed().find(key).is_some())
            .collect();
        Self {
            inner: Mutex::new(Inner {
                state,
                results,
                store,
                executor,
            }),
            clock,
        }
    }

    /// Runs `read` with the state of the helper. `None` means that the
    /// state is not usable.
    pub fn with_state<T>(&self, read: impl FnOnce(&HelperState) -> T) -> Option<T> {
        self.inner
            .lock()
            .ok()
            .map(|inner: MutexGuard<'_, Inner<S, E>>| read(&inner.state))
    }

    fn respond(&self, peer: &PeerFacts, message: &[u8]) -> Outcome {
        let CodeVerification::Verified(code) = peer.code() else {
            return Outcome::condition(Condition::PeerUnverified);
        };
        let Some(uid) = peer.effective_uid() else {
            return Outcome::condition(Condition::PeerUserUnavailable);
        };
        // A panic while the lock was held leaves a state that the service
        // cannot trust: a step is possibly in work in it.
        let Ok(mut inner) = self.inner.lock() else {
            return Outcome::condition(Condition::StateUnavailable);
        };
        let request: HelperRequest = match decode_request(message, inner.state.config().protocols) {
            Ok(request) => request,
            Err(error) => return Outcome::decode_error(error),
        };
        let body: ResponseBody = match role_of(code, &inner.state.config().agent) {
            Some(role) => {
                let caller: CallerIdentity =
                    CallerIdentity::from_transport(code.clone(), uid, peer.login_session(), role);
                self.decide(&mut inner, &caller, &request)
            }
            None => refused(&Refusal {
                reason: RefusalReason::CallerNotPermitted,
                correlation: request.correlation.clone(),
            }),
        };
        Outcome {
            response: HelperResponse::new(Some(request.request_id), body),
            penalized: false,
        }
    }

    fn decide(
        &self,
        inner: &mut Inner<S, E>,
        caller: &CallerIdentity,
        request: &HelperRequest,
    ) -> ResponseBody {
        let Ok(clock) = self.clock.now() else {
            return ResponseBody::Refused(RefusalReport {
                correlation: request.correlation.clone(),
                error: Condition::ClockUnavailable.to_action_error(
                    ActionStage::Admission,
                    DispatchState::NotSubmitted,
                    Some(&request.correlation),
                ),
            });
        };
        let admission: Admission = inner.state.admit(caller, request, &clock);
        inner.forget_removed_steps();
        match admission {
            Admission::Refused(refusal) => refused(&refusal),
            Admission::Known(status) => {
                let result: Option<&StepResult> = inner.results.get(&status.key);
                ResponseBody::Step(report(&status, ReportOrigin::Record, result))
            }
            Admission::Dispatch(dispatch) => {
                let status: StepStatus = self.execute(inner, &dispatch, &request.correlation);
                let result: Option<&StepResult> = inner.results.get(&status.key);
                ResponseBody::Step(report(&status, ReportOrigin::ThisRequest, result))
            }
        }
    }

    /// Does one consumed step and records its result. Returns the recorded
    /// state.
    fn execute(
        &self,
        inner: &mut Inner<S, E>,
        dispatch: &Dispatch,
        correlation: &StepCorrelation,
    ) -> StepStatus {
        let key: StepKey = dispatch.key().clone();
        let Inner {
            state,
            results,
            store,
            executor,
        } = inner;

        // The record of the consumption is durable before a call.
        let consumed: Result<(), StoreError> = state
            .consumed()
            .find(&key)
            .ok_or(StoreError)
            .and_then(|request: &ConsumedRequest| store.write_consumed(request));
        if consumed.is_err() {
            return settle(
                state,
                results,
                &key,
                correlation,
                StepState::NoAction,
                StepResult {
                    entries: None,
                    durability: Durability::Volatile,
                    error: Some(Condition::RecordNotDurable.to_action_error(
                        ActionStage::Dispatch,
                        DispatchState::NotSubmitted,
                        Some(correlation),
                    )),
                },
            );
        }

        let BoundedOperation::EvictEntries(eviction) = dispatch.operation();
        let clock: &C = &self.clock;
        let covering: &HelperState = state;
        let mut gate = || -> Result<WallTime, RefusalReason> {
            let now: HelperClock = clock.now().map_err(|_| RefusalReason::ClockNotComparable)?;
            covering.still_covers(dispatch, &now)?;
            Ok(now.wall)
        };
        let execution: Execution = executor.evict(eviction, &mut gate);

        let submitted: bool = execution
            .entries
            .iter()
            .any(EntryReport::is_possibly_submitted);
        if submitted {
            // A refused transition leaves `DispatchConsumed`, from which
            // the result below can only be `UnknownOutcome`.
            let _in_work: Result<StepStatus, RecordError> =
                state.record_progress(&key, StepState::Verifying);
        }
        let aggregated: StepState = aggregate_entries(&execution.entries, submitted);
        let stop_error: Option<ActionError> = execution.stopped.map(|reason: RefusalReason| {
            action_error(
                reason.code(),
                reason.family(),
                ActionStage::Dispatch,
                DispatchState::NotSubmitted,
                Some(correlation),
            )
        });
        let status: StepStatus = settle(
            state,
            results,
            &key,
            correlation,
            aggregated,
            StepResult {
                entries: Some(execution.entries),
                durability: Durability::Durable,
                error: stop_error,
            },
        );

        // The result is durable after the effect. A failed write leaves a
        // durable record of a consumed step with no result: a restart of
        // the helper restores it as `UnknownOutcome`.
        if let Some(result) = results.get_mut(&key)
            && store
                .write_result(&key, &status.state, result.entries.as_deref())
                .is_err()
        {
            result.durability = Durability::PersistenceFailed;
            if result.error.is_none() {
                result.error = Some(Condition::ResultNotDurable.to_action_error(
                    ActionStage::Verification,
                    if submitted {
                        DispatchState::Submitted
                    } else {
                        DispatchState::NotSubmitted
                    },
                    Some(correlation),
                ));
            }
        }
        status
    }
}

impl<S: RecordStore, E> Inner<S, E> {
    /// Removes the results and the durable records of the steps that the
    /// state removed.
    fn forget_removed_steps(&mut self) {
        let removed: Vec<StepKey> = self
            .results
            .keys()
            .filter(|key: &&StepKey| self.state.consumed().find(key).is_none())
            .cloned()
            .collect();
        for key in removed {
            self.results.remove(&key);
            // A record that stays is restored as a settled step, and the
            // state removes it again.
            let _removed: Result<(), StoreError> = self.store.remove(&key);
        }
    }
}

/// The role of a verified peer. The helper has one caller role: the agent.
/// A peer has it only when its verified code identity is the identity of
/// the agent in the settings of the helper. The role never comes from the
/// message.
fn role_of(code: &CodeIdentity, agent: &CodeIdentity) -> Option<ClientRole> {
    (code == agent).then_some(ClientRole::Agent)
}

fn refused(refusal: &Refusal) -> ResponseBody {
    let error: ActionError = refusal.to_action_error().unwrap_or_else(|_| {
        action_error(
            "helper_refused",
            refusal.reason.family(),
            ActionStage::Admission,
            DispatchState::NotSubmitted,
            Some(&refusal.correlation),
        )
    });
    ResponseBody::Refused(RefusalReport {
        correlation: refusal.correlation.clone(),
        error,
    })
}

fn report(status: &StepStatus, origin: ReportOrigin, result: Option<&StepResult>) -> StepReport {
    StepReport {
        correlation: status.correlation.clone(),
        origin,
        state: status.state.clone(),
        // A step with no result of this lifetime came from the durable
        // record.
        durability: result.map_or(Durability::Durable, |result: &StepResult| {
            result.durability.clone()
        }),
        entries: result.and_then(|result: &StepResult| result.entries.clone()),
        error: result.and_then(|result: &StepResult| result.error.clone()),
    }
}

/// Records `next` as the state of the step, and keeps `result` for it.
/// When the record refuses the transition, the step gets `UnknownOutcome`:
/// its dispatch was consumed, and its result is not one that the state
/// machine accepts.
fn settle(
    state: &mut HelperState,
    results: &mut BTreeMap<StepKey, StepResult>,
    key: &StepKey,
    correlation: &StepCorrelation,
    next: StepState,
    result: StepResult,
) -> StepStatus {
    let status: StepStatus = state
        .record_progress(key, next)
        .or_else(|_| state.record_progress(key, StepState::UnknownOutcome))
        .unwrap_or_else(|_| StepStatus {
            key: key.clone(),
            correlation: correlation.clone(),
            state: state
                .consumed()
                .find(key)
                .map_or(StepState::UnknownOutcome, |recorded: &ConsumedRequest| {
                    recorded.state.clone()
                }),
        });
    results.insert(key.clone(), result);
    status
}

/// The state of a step from its entry results, with the rules of
/// `svalnir_core::action::aggregate_step`. Entry results that do not agree
/// with the contract give `UnknownOutcome` after a possible call and
/// `NoAction` with no call.
fn aggregate_entries(entries: &[EntryReport], submitted: bool) -> StepState {
    let fallback: StepState = if submitted {
        StepState::UnknownOutcome
    } else {
        StepState::NoAction
    };
    let targets: Option<Vec<TargetResult>> = entries
        .iter()
        .map(|entry: &EntryReport| {
            let target_id: TargetId = TargetId::new(format!("entry-{}", entry.index)).ok()?;
            entry.to_target_result(target_id, Durability::Durable).ok()
        })
        .collect();
    let Some(targets) = targets else {
        return fallback;
    };
    let aggregated: StepState = aggregate_step(&targets).unwrap_or_else(|_| fallback.clone());
    // A step with no call has `NoAction`: the state machine has no other
    // settled state for it.
    if !submitted && aggregated != StepState::NoAction {
        return fallback;
    }
    aggregated
}

impl<S: RecordStore, E: EvictionExecutor, C: ClockSource> RequestHandler
    for HelperService<S, E, C>
{
    fn handle(&self, peer: &PeerFacts, message: &[u8]) -> Reply {
        let outcome: Outcome = self.respond(peer, message);
        let request_id: Option<RequestId> = outcome.response.request_id.clone();
        encode(&outcome.response, request_id, outcome.penalized)
    }

    fn malformed_frame(&self) -> Reply {
        let outcome: Outcome = Outcome::condition(Condition::FrameMalformed);
        encode(&outcome.response, None, outcome.penalized)
    }
}

/// Encodes a response. A response over the size limit is replaced by a
/// report with no entry results, or by a rejection.
fn encode(response: &HelperResponse, request_id: Option<RequestId>, penalized: bool) -> Reply {
    let payload: Vec<u8> = response
        .encode()
        .or_else(|error: EncodeError| match (&response.body, error) {
            (ResponseBody::Step(step), EncodeError::TooLarge) => HelperResponse::new(
                request_id,
                ResponseBody::Step(StepReport {
                    entries: None,
                    error: Some(Condition::ResponseTooLarge.to_action_error(
                        ActionStage::Verification,
                        DispatchState::SubmissionUncertain,
                        Some(&step.correlation),
                    )),
                    ..step.clone()
                }),
            )
            .encode(),
            _ => Err(error),
        })
        .or_else(|_| {
            HelperResponse::rejected(
                Condition::ResponseTooLarge.code(),
                Condition::ResponseTooLarge.family(),
            )
            .encode()
        })
        .unwrap_or_default();
    Reply { payload, penalized }
}
