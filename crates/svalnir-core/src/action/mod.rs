//! The action contract: classes, plans, operations, steps, outcomes,
//! errors, budgets, leases, and the journal interface.
//!
//! `docs/ACTION_CONTRACTS.md` owns the contract. This module has types and
//! pure functions only. It deletes no file and signals no process.
//!
//! | Module | Contents | Section of `docs/ACTION_CONTRACTS.md` |
//! | --- | --- | --- |
//! | [`class`] | Action classes and trigger classes | 1, 3 |
//! | [`plan`] | The immutable plan, its bindings, and its approval | 2, 3 |
//! | [`envelope`] | The immutable request envelope of one step | 3 |
//! | [`budget`] | Budgets and resource leases | 5 |
//! | [`state`] | Plan, operation, and step states and their transitions | 6 |
//! | [`operation`] | The operation record and its steps | 2, 6, 9 |
//! | [`outcome`] | Target results, aggregation, and resource effects | 9 |
//! | [`error`] | The error and retry taxonomy | 10 |
//! | [`journal`] | The journal interface and the recording rule | 11, 12 |
//! | [`checked`] | Records that passed a consistency check | |

pub mod budget;
pub mod checked;
pub mod class;
pub mod envelope;
pub mod error;
pub mod journal;
pub mod operation;
pub mod outcome;
pub mod plan;
pub mod state;

#[cfg(test)]
mod tests;

pub use budget::{
    BudgetError, BudgetScope, LeaseResource, ResourceLease, ScopedAllowance, SlotAllowance,
    WorkAllowance, WorkBudget, WorkBudgetError, WorkCharge,
};
pub use checked::{Check, Checked};
pub use class::{ActionClass, TriggerClass};
pub use envelope::{
    Correlation, EnvelopeContent, EnvelopeError, EvidenceBinding, RecordingMode, RequestEnvelope,
    Reservation, StepLimits,
};
pub use error::{
    ActionError, ActionStage, ErrorCode, ErrorCodeError, ErrorFamily, PermittedNextStep,
};
pub use journal::{
    Admission, DispatchConsumption, DispatchReceipt, Journal, JournalError, RecordingRefusal,
    StopFence, VolatileJournal, VolatileJournalError, check_dispatch_recording,
    critical_exception_applies,
};
pub use operation::{Operation, OperationError, Step};
pub use outcome::{
    Attribution, CapacityEffect, CapacityEffectError, EffectEvidence, NativeResult, OutcomeError,
    ResourceEffect, StopReason, TargetEffect, TargetResult, TargetResultRecord, aggregate,
    aggregate_step,
};
pub use plan::{
    ApplicationBinding, ClientRole, Escalation, ExecutorRole, FileBinding, FileObjectType,
    MAX_APPLICATION_MEMBERS, MAX_PLAN_TARGETS, PLAN_SCHEMA_VERSION, Plan, PlanApproval,
    PlanContent, PlanError, PlanLimits, PlanTarget, PlannedStep, Principal, TargetBinding, Trigger,
    Validity,
};
pub use state::{
    DispatchState, Durability, OperationState, PlanState, StepProgress, StepState, TransitionError,
};
