//! The status board: what a client reads about an operation while the
//! coordinator works.
//!
//! The board is the only state that the driver and its clients share. Its
//! lock is the scheduling lock of the coordinator. Each critical section
//! copies a few values and makes no journal call, no executor call, and no
//! measurement, so a status query or a stop request waits for no
//! application, native callback, or storage operation
//! (`docs/ACTION_CONTRACTS.md` section 6).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use svalnir_core::action::{Operation, ResourceEffect, StopReason};
use svalnir_core::id::OperationId;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::MonotonicNanos;

/// The largest number of settled operations that the board keeps. The
/// journal has each durable operation.
pub const MAX_RETAINED_OPERATIONS: usize = 256;

/// How far a stop request of an operation went. A later level includes
/// each earlier one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StopAcknowledgement {
    /// The request is on the board. The coordinator reads it at its next
    /// boundary.
    Received,
    /// The running coordinator dispatches no further step of the
    /// operation. No durable fence exists: a restart does not know the
    /// request.
    CurrentInstance,
    /// The journal has the stop fence of the operation. It survives a
    /// restart.
    DurableFence,
    /// The operation is settled and no step executes. A settled stopped
    /// operation can have effects of earlier steps.
    Settled,
}

/// What the coordinator does with an operation now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Admitted. A different operation is active.
    Waiting,
    /// Active, between two steps.
    Running,
    /// A call was issued, and the exit of a member is observed until this
    /// time at the latest.
    Observing {
        /// The end of the observation window.
        until: MonotonicNanos,
    },
    /// Settled, or `UnknownOutcome` that needs reconciliation.
    Finished,
}

/// The work that the calls of a filesystem operation did. This is not
/// reclaimed capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkTotals {
    /// The entries that the executor removed.
    pub removed_entries: EntryCount,
    /// The sum of the logical sizes of the removed entries.
    pub removed_logical_bytes: Bytes,
    /// The sum of the allocated sizes of the removed entries.
    pub removed_allocated_bytes: Bytes,
    /// The entries that the executor moved to Trash.
    pub trashed_entries: EntryCount,
    /// Whether each sum is exact. `false` also when a sum did not fit.
    pub exact: bool,
}

/// The stop request of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopView {
    /// Why the operation stops.
    pub reason: StopReason,
    /// How far the request went.
    pub acknowledgement: StopAcknowledgement,
}

/// One operation, as a client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationView {
    /// The operation record with each step and each target result.
    pub operation: Operation,
    /// What the coordinator does with the operation now.
    pub phase: Phase,
    /// The stop request, when the operation has one.
    pub stop: Option<StopView>,
    /// The measurements before and after the work. An estimate and an
    /// accepted request are not in this list.
    pub resource_effects: Vec<ResourceEffect>,
    /// The work of the filesystem calls.
    pub work: WorkTotals,
    /// True when a record of the operation is not in the durable journal:
    /// a write failed, or the operation uses the volatile record of the
    /// critical-memory exception.
    pub degraded_recording: bool,
}

/// The result of a wait for an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The operation is finished.
    Finished(Box<OperationView>),
    /// The time of the client ended. The operation continues: a client
    /// timeout cancels nothing.
    TimedOut(Box<OperationView>),
    /// The board has no operation with the identity.
    Unknown,
}

#[derive(Debug, Default)]
struct BoardState {
    operations: BTreeMap<OperationId, OperationView>,
    finished: VecDeque<OperationId>,
    stop_requests: Vec<OperationId>,
    /// The finished operations whose result is in memory and not in the
    /// journal. Each one is also in `finished`, so the set is bounded.
    unrecorded: BTreeSet<OperationId>,
}

#[derive(Debug, Default)]
pub(super) struct Board {
    state: Mutex<BoardState>,
    changed: Condvar,
}

impl Board {
    fn lock(&self) -> MutexGuard<'_, BoardState> {
        // A panic of a client thread while it holds the lock leaves a
        // consistent state: each critical section is one assignment.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes the current view of an operation.
    pub(super) fn publish(&self, view: OperationView) {
        let mut state = self.lock();
        let id: OperationId = view.operation.operation_id().clone();
        let finished: bool = view.phase == Phase::Finished;
        let was_finished: bool = state
            .operations
            .get(&id)
            .is_some_and(|earlier| earlier.phase == Phase::Finished);
        // A stop request that a client made after the driver read the
        // view is kept.
        let stop: Option<StopView> = match (state.operations.get(&id), &view.stop) {
            (Some(earlier), None) => earlier.stop.clone(),
            _ => view.stop.clone(),
        };
        state
            .operations
            .insert(id.clone(), OperationView { stop, ..view });
        if finished && !was_finished {
            state.finished.push_back(id);
            while state.finished.len() > MAX_RETAINED_OPERATIONS {
                if let Some(oldest) = state.finished.pop_front() {
                    state.operations.remove(&oldest);
                    state.unrecorded.remove(&oldest);
                }
            }
        }
        drop(state);
        self.changed.notify_all();
    }

    /// Records whether the journal has the result of a finished
    /// operation. A result that the journal does not have is not
    /// acknowledged as settled.
    pub(super) fn set_recorded(&self, operation_id: &OperationId, recorded: bool) {
        let mut state = self.lock();
        if recorded {
            state.unrecorded.remove(operation_id);
        } else if state.operations.contains_key(operation_id) {
            state.unrecorded.insert(operation_id.clone());
        }
    }

    pub(super) fn view(&self, operation_id: &OperationId) -> Option<OperationView> {
        self.lock().operations.get(operation_id).cloned()
    }

    /// Whether a client requested a stop of the operation.
    pub(super) fn stop_requested(&self, operation_id: &OperationId) -> bool {
        self.lock()
            .operations
            .get(operation_id)
            .is_some_and(|view| view.stop.is_some())
    }

    /// The stop requests that the driver did not process.
    pub(super) fn take_stop_requests(&self) -> Vec<OperationId> {
        std::mem::take(&mut self.lock().stop_requests)
    }

    /// Records a stop request. Returns the acknowledgement, or `None`
    /// when the board has no operation with the identity.
    pub(super) fn request_stop(
        &self,
        operation_id: &OperationId,
        reason: StopReason,
        level: StopAcknowledgement,
    ) -> Option<StopAcknowledgement> {
        let mut state = self.lock();
        let recorded: bool = !state.unrecorded.contains(operation_id);
        let view: &mut OperationView = state.operations.get_mut(operation_id)?;
        if view.phase == Phase::Finished {
            // An operation that is finished and not settled, or whose
            // result the journal does not have, dispatches nothing. It
            // is not reported as settled.
            return Some(if recorded && view.operation.state().is_settled() {
                StopAcknowledgement::Settled
            } else {
                view.stop
                    .as_ref()
                    .map_or(level, |stop| stop.acknowledgement.max(level))
            });
        }
        let acknowledgement: StopAcknowledgement = if let Some(stop) = &mut view.stop {
            stop.acknowledgement = stop.acknowledgement.max(level);
            stop.acknowledgement
        } else {
            view.stop = Some(StopView {
                reason,
                acknowledgement: level,
            });
            level
        };
        if !state.stop_requests.contains(operation_id) {
            state.stop_requests.push(operation_id.clone());
        }
        drop(state);
        self.changed.notify_all();
        Some(acknowledgement)
    }

    pub(super) fn wait(&self, operation_id: &OperationId, timeout: Duration) -> WaitOutcome {
        let start = Instant::now();
        let mut state = self.lock();
        loop {
            let Some(view) = state.operations.get(operation_id) else {
                return WaitOutcome::Unknown;
            };
            if view.phase == Phase::Finished {
                return WaitOutcome::Finished(Box::new(view.clone()));
            }
            let Some(left) = timeout.checked_sub(start.elapsed()) else {
                return WaitOutcome::TimedOut(Box::new(view.clone()));
            };
            if left.is_zero() {
                return WaitOutcome::TimedOut(Box::new(view.clone()));
            }
            state = self
                .changed
                .wait_timeout(state, left)
                .map_or_else(|poisoned| poisoned.into_inner().0, |(guard, _)| guard);
        }
    }
}

/// The interface of the coordinator for a different thread: status
/// queries, stop requests, and a wait with a timeout of the client.
///
/// A call answers from the status board. It does not wait for the driver,
/// for the journal, or for an executor call.
#[derive(Debug, Clone)]
pub struct CoordinatorHandle {
    pub(super) board: Arc<Board>,
}

impl CoordinatorHandle {
    /// The current view of an operation that this coordinator admitted or
    /// reconciled. `None` for an operation that the board does not have;
    /// the journal has each durable operation.
    pub fn operation(&self, operation_id: &OperationId) -> Option<OperationView> {
        self.board.view(operation_id)
    }

    /// Requests that the coordinator dispatches no further step of the
    /// operation. The result is [`StopAcknowledgement::Received`] until
    /// the driver processes the request; read the later level with
    /// [`CoordinatorHandle::operation`]. A call that was issued is not
    /// recalled.
    pub fn cancel(&self, operation_id: &OperationId) -> Option<StopAcknowledgement> {
        self.board.request_stop(
            operation_id,
            StopReason::Canceled,
            StopAcknowledgement::Received,
        )
    }

    /// Waits until the operation is finished, to a maximum of `timeout`.
    /// The end of the timeout cancels nothing.
    pub fn wait(&self, operation_id: &OperationId, timeout: Duration) -> WaitOutcome {
        self.board.wait(operation_id, timeout)
    }
}
