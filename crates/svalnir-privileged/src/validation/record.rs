//! The bounded record of consumed requests.
//!
//! `docs/ACTION_CONTRACTS.md` section 11 and `docs/INTERFACES.md` section 12
//! own the rules: the helper keeps its own consumption state, a repeated
//! step returns its recorded state and makes no second native call, and a
//! record stays for the full validity of its request.
//!
//! The record is the decision state only. This module does not write it to
//! storage. The layer that owns the journal of the helper makes the record
//! durable before it gives a step to the executor.

use std::collections::BTreeMap;

use svalnir_core::action::{StepState, WorkCharge};
use svalnir_core::digest::ContentDigest;
use svalnir_core::id::{BootId, ClockDomainId, OperationId, PrivilegeGrantId, RequestId, StepId};
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use super::state::HelperClock;
use crate::request::StepCorrelation;

/// The largest capacity of the record, in requests.
pub const MAX_RECORD_CAPACITY: usize = 4096;

/// The deduplication identity of a delegated step: the authenticated user,
/// the operation of the agent, and the step.
///
/// The user comes from the [`CallerIdentity`](crate::request::CallerIdentity)
/// of the transport. Thus one user cannot read or repeat the step of
/// another user, and cannot make a record that hides it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepKey {
    /// The authenticated user.
    pub principal: Uid,
    /// The operation of the agent.
    pub operation_id: OperationId,
    /// The delegated step.
    pub step_id: StepId,
}

/// One consumed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRequest {
    /// The deduplication identity.
    pub key: StepKey,
    /// The transport identity of the request that the helper accepted.
    pub request_id: RequestId,
    /// The plan, the operation, and the step of the request.
    pub correlation: StepCorrelation,
    /// The digest of the content of the request: its correlation, its
    /// validity, and its operation. The transport identity is not a part.
    pub content: ContentDigest,
    /// The privilege grant that covered the request.
    pub grant_id: PrivilegeGrantId,
    /// The work that the helper accepted. It counts against the rate
    /// ceiling of the grant.
    pub charge: WorkCharge,
    /// The clock domain of the two monotonic times.
    pub clock_domain: ClockDomainId,
    /// The boot of the two monotonic times.
    pub boot_id: BootId,
    /// The monotonic time at which the helper accepted the request.
    pub accepted_at: MonotonicNanos,
    /// The wall-clock time at which the helper accepted the request. The
    /// helper uses it only to keep the record after the monotonic timeline
    /// changed, for example after a restart of the host.
    pub accepted_wall: WallTime,
    /// The monotonic time at which the request expires.
    pub expires_at: MonotonicNanos,
    /// The state of the step. It is `DispatchConsumed` when the helper
    /// accepts the request.
    pub state: StepState,
}

impl ConsumedRequest {
    /// The recorded state, as a reply gives it.
    pub fn status(&self) -> StepStatus {
        StepStatus {
            key: self.key.clone(),
            correlation: self.correlation.clone(),
            state: self.state.clone(),
        }
    }

    fn is_on_timeline(&self, clock: &HelperClock) -> bool {
        self.clock_domain == clock.clock_domain && self.boot_id == clock.boot_id
    }

    /// Whether the request counts against a rate window that ends at the
    /// time of `clock`. A request whose time cannot be compared with the
    /// clock counts.
    fn counts_in_window(&self, clock: &HelperClock, window: Nanoseconds) -> bool {
        if !self.is_on_timeline(clock) {
            return true;
        }
        self.accepted_at
            .checked_add(window)
            .is_none_or(|end: MonotonicNanos| clock.monotonic < end)
    }

    /// Whether the record can be removed with no risk of a replay.
    ///
    /// A step that is not settled stays: the helper must give its state to
    /// a query, and reconciliation must settle it. A settled step of this
    /// timeline stays until its request is expired and its retention is
    /// complete. After that time the helper refuses the same request for
    /// its expiry. A settled step of a different clock domain or boot
    /// stays until the retention is complete on the wall clock: a restart
    /// of the host does not make room in a rate window, and does not make
    /// the identity of a consumed step free at once.
    fn is_removable(&self, clock: &HelperClock, retention: Nanoseconds) -> bool {
        if !self.state.is_settled() {
            return false;
        }
        if !self.is_on_timeline(clock) {
            return self.is_retained_on_wall_clock(clock, retention);
        }
        clock.monotonic >= self.expires_at
            && self
                .accepted_at
                .checked_add(retention)
                .is_some_and(|end: MonotonicNanos| clock.monotonic >= end)
    }
}

impl ConsumedRequest {
    /// Whether the retention is complete on the wall clock. The retention
    /// is rounded up to whole seconds, with one more second for the
    /// fractions of the two times. A wall clock that went back gives
    /// `false`.
    fn is_retained_on_wall_clock(&self, clock: &HelperClock, retention: Nanoseconds) -> bool {
        const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
        let Some(needed) = (retention.get() / NANOSECONDS_PER_SECOND).checked_add(2) else {
            return false;
        };
        clock
            .wall
            .unix_seconds()
            .checked_sub(self.accepted_wall.unix_seconds())
            .and_then(|elapsed: i64| u64::try_from(elapsed).ok())
            .is_some_and(|elapsed: u64| elapsed >= needed)
    }
}

/// The recorded state of a delegated step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepStatus {
    /// The deduplication identity of the step.
    pub key: StepKey,
    /// The plan, the operation, and the step.
    pub correlation: StepCorrelation,
    /// The state of the step. `DispatchConsumed` and `Verifying` mean that
    /// the step is in work. `UnknownOutcome` needs reconciliation.
    pub state: StepState,
}

/// The accepted requests of one grant in one rate window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateUsage {
    /// The number of accepted requests.
    pub requests: u32,
    /// The sum of the accepted work.
    pub work: WorkCharge,
}

/// The reason a change of the record was refused. No refused change has an
/// effect on the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecordError {
    /// The capacity is zero or larger than [`MAX_RECORD_CAPACITY`].
    #[error("the capacity of the record is not in its permitted range")]
    Capacity,
    /// The record is full.
    #[error("the record of consumed requests is full")]
    Full,
    /// The record has the step.
    #[error("the record has the step")]
    Duplicate,
    /// The record does not have the step.
    #[error("the record does not have the step")]
    NotRecorded,
    /// The state is not a state of a consumed step, or the step cannot go
    /// from its state to the new state.
    #[error("the state is not permitted for the step")]
    State,
}

/// The bounded record of consumed requests.
///
/// The record has a fixed capacity. When it is full, the helper refuses
/// each new mutation request. It does not remove a record to make room,
/// because a removed record of a request that is not expired permits a
/// replay. [`ConsumedRequests::remove_expired`] removes only the records
/// that [`ConsumedRequest`] shows to be safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRequests {
    capacity: usize,
    retention: Nanoseconds,
    entries: BTreeMap<StepKey, ConsumedRequest>,
}

impl ConsumedRequests {
    /// Makes an empty record.
    ///
    /// `retention` is the shortest time for which a settled request stays
    /// after the helper accepted it.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Capacity`] when `capacity` is zero or larger
    /// than [`MAX_RECORD_CAPACITY`].
    pub fn new(capacity: usize, retention: Nanoseconds) -> Result<Self, RecordError> {
        if capacity == 0 || capacity > MAX_RECORD_CAPACITY {
            return Err(RecordError::Capacity);
        }
        Ok(Self {
            capacity,
            retention,
            entries: BTreeMap::new(),
        })
    }

    /// Makes the record from the requests of an earlier lifetime of the
    /// helper.
    ///
    /// # Errors
    ///
    /// Returns a [`RecordError`] when the capacity is not permitted, when
    /// there are more requests than the capacity, when two requests have
    /// one step, or when a state is not a state of a consumed step. The
    /// function does not drop a request to make the others fit.
    pub fn restore(
        capacity: usize,
        retention: Nanoseconds,
        requests: impl IntoIterator<Item = ConsumedRequest>,
    ) -> Result<Self, RecordError> {
        let mut record: Self = Self::new(capacity, retention)?;
        for request in requests {
            record.insert(request)?;
        }
        Ok(record)
    }

    /// The capacity, in requests.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The retention of a settled request.
    pub fn retention(&self) -> Nanoseconds {
        self.retention
    }

    /// The number of recorded requests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the record has no request.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the record has no room for a new request.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// The recorded requests, in the sequence of their keys.
    pub fn requests(&self) -> impl Iterator<Item = &ConsumedRequest> {
        self.entries.values()
    }

    /// The record of a step.
    pub fn find(&self, key: &StepKey) -> Option<&ConsumedRequest> {
        self.entries.get(key)
    }

    /// The number of recorded requests of `principal`.
    pub fn count_for(&self, principal: Uid) -> usize {
        self.entries
            .keys()
            .filter(|key: &&StepKey| key.principal == principal)
            .count()
    }

    /// Whether a recorded request of `principal` has the transport
    /// identity `request_id`. The requests of a different user are not
    /// examined: one user cannot learn or block the identities of another.
    pub fn has_request_id(&self, principal: Uid, request_id: &RequestId) -> bool {
        self.entries.values().any(|request: &ConsumedRequest| {
            request.key.principal == principal && &request.request_id == request_id
        })
    }

    /// The accepted requests of `grant_id` in the rate window that ends at
    /// the time of `clock`. `None` means that a sum does not fit its type.
    pub fn usage(
        &self,
        grant_id: &PrivilegeGrantId,
        clock: &HelperClock,
        window: Nanoseconds,
    ) -> Option<RateUsage> {
        let mut usage: RateUsage = RateUsage {
            requests: 0,
            work: WorkCharge::ZERO,
        };
        for request in self.entries.values() {
            if &request.grant_id == grant_id && request.counts_in_window(clock, window) {
                usage.requests = usage.requests.checked_add(1)?;
                usage.work = usage.work.checked_add(request.charge)?;
            }
        }
        Some(usage)
    }

    /// Adds a consumed request.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::State`] when the state is before
    /// `DispatchConsumed` or is not recognized, [`RecordError::Duplicate`]
    /// when the record has the step, and [`RecordError::Full`] when the
    /// record has no room.
    pub fn insert(&mut self, request: ConsumedRequest) -> Result<(), RecordError> {
        if !is_consumed_state(&request.state) {
            return Err(RecordError::State);
        }
        if self.entries.contains_key(&request.key) {
            return Err(RecordError::Duplicate);
        }
        if self.is_full() {
            return Err(RecordError::Full);
        }
        self.entries.insert(request.key.clone(), request);
        Ok(())
    }

    /// Records the next state of a step.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::NotRecorded`] when the record does not have
    /// the step, and [`RecordError::State`] when the step cannot go from
    /// its state to `next`.
    pub fn advance(&mut self, key: &StepKey, next: StepState) -> Result<StepStatus, RecordError> {
        let request: &mut ConsumedRequest =
            self.entries.get_mut(key).ok_or(RecordError::NotRecorded)?;
        if !is_consumed_state(&next) || !request.state.can_transition_to(&next) {
            return Err(RecordError::State);
        }
        request.state = next;
        Ok(request.status())
    }

    /// Removes each record that can be removed with no risk of a replay.
    /// Returns the number of removed records.
    pub fn remove_expired(&mut self, clock: &HelperClock) -> usize {
        let before: usize = self.entries.len();
        let retention: Nanoseconds = self.retention;
        self.entries
            .retain(|_, request: &mut ConsumedRequest| !request.is_removable(clock, retention));
        before.saturating_sub(self.entries.len())
    }
}

/// Whether `state` is a state of a step whose dispatch was consumed.
fn is_consumed_state(state: &StepState) -> bool {
    match state {
        StepState::DispatchConsumed
        | StepState::Verifying
        | StepState::Completed
        | StepState::Partial
        | StepState::Incomplete
        | StepState::NoAction
        | StepState::Failed
        | StepState::UnknownOutcome => true,
        StepState::Admitted | StepState::IntentCommitted | StepState::Unrecognized(_) => false,
    }
}
