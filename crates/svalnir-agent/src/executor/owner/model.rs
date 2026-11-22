//! The types of the owner executor.

use std::time::Duration;

use svalnir_core::action::{
    ActionClass, DispatchConsumption, DispatchReceipt, DispatchState, ExecutorRole,
    OwnerOperationBinding, RequestEnvelope, ScopeAllocationEffect, TargetBinding, TargetResult,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::id::AdapterId;
use thiserror::Error;

use super::measure::ScopeLimits;
use super::native::ResponsibilitySymbols;

/// The error codes of the owner executor (`docs/INTERFACES.md` section 4).
pub mod code {
    /// The scope root is absent, is a symbolic link, is not a directory,
    /// or has a different device, inode, or owner than the plan.
    pub const SCOPE_ROOT_CHANGED: &str = "scope_root_changed";
    /// The executable is absent, is a symbolic link, is not a regular
    /// file, or has a different device, inode, owner, mode, size, or digest
    /// than the plan.
    pub const OWNER_EXECUTABLE_CHANGED: &str = "owner_executable_changed";
    /// The owner or the mode of the executable or of a directory above it
    /// permits a change by a different user.
    pub const OWNER_EXECUTABLE_NOT_TRUSTED: &str = "owner_executable_not_trusted";
    /// The measurement of the scope before the command is not complete.
    pub const SCOPE_NOT_MEASURED: &str = "scope_not_measured";
    /// The system refused to start the command.
    pub const OWNER_OPERATION_NOT_STARTED: &str = "owner_operation_not_started";
    /// The command passed its deadline, and its group was stopped.
    pub const OWNER_OPERATION_DEADLINE: &str = "owner_operation_deadline";
    /// The command exited with a status other than 0 or ended by a signal.
    pub const OWNER_OPERATION_FAILED: &str = "owner_operation_failed";
    /// A process of the group ran after the exit of the command.
    pub const OWNER_OPERATION_CHILDREN_REMAINED: &str = "owner_operation_children_remained";
    /// The bound `within_scope` of an automatic step is not verified.
    pub const OWNER_OPERATION_BOUND_NOT_VERIFIED: &str = "owner_operation_bound_not_verified";
    /// The scope is larger than the charge of the plan. The code of the
    /// filesystem executor.
    pub const TARGET_GREW: &str = "target_grew";
    /// A root record of the process does not agree with the scope. The code
    /// of the filesystem executor.
    pub const APPROVED_ROOT_MISMATCH: &str = "approved_root_mismatch";
    /// The mount table reports the scope root as not local.
    pub const ROOT_NOT_LOCAL: &str = "root_not_local";
    /// The mount table cannot give the locality of the scope root.
    pub const ROOT_LOCALITY_UNKNOWN: &str = "root_locality_unknown";
    /// The effective user of the process is not the principal of the step.
    pub const PRINCIPAL_MISMATCH: &str = "principal_mismatch";
    /// The responsibility functions of the system are absent, or a call of
    /// one failed (owner decision D1 of 2026-11-22).
    pub const OWNER_DISCLAIM_UNAVAILABLE: &str = "owner_disclaim_unavailable";
    /// The journal did not record the process of the command.
    pub const OWNER_PROCESS_NOT_RECORDED: &str = "owner_process_not_recorded";
    /// A live descendant of the command found no room in the set of the
    /// descendants, so the worker cannot know each process of the command.
    pub const OWNER_DESCENDANTS_TRUNCATED: &str = "owner_descendants_truncated";
    /// The journal did not record a change of the descendants of the
    /// command.
    pub const OWNER_DESCENDANTS_NOT_RECORDED: &str = "owner_descendants_not_recorded";

    /// Each code of this module.
    pub const ALL: [&str; 18] = [
        OWNER_DISCLAIM_UNAVAILABLE,
        OWNER_PROCESS_NOT_RECORDED,
        OWNER_DESCENDANTS_TRUNCATED,
        OWNER_DESCENDANTS_NOT_RECORDED,
        SCOPE_ROOT_CHANGED,
        OWNER_EXECUTABLE_CHANGED,
        OWNER_EXECUTABLE_NOT_TRUSTED,
        SCOPE_NOT_MEASURED,
        OWNER_OPERATION_NOT_STARTED,
        OWNER_OPERATION_DEADLINE,
        OWNER_OPERATION_FAILED,
        OWNER_OPERATION_CHILDREN_REMAINED,
        OWNER_OPERATION_BOUND_NOT_VERIFIED,
        TARGET_GREW,
        APPROVED_ROOT_MISMATCH,
        ROOT_NOT_LOCAL,
        ROOT_LOCALITY_UNKNOWN,
        PRINCIPAL_MISMATCH,
    ];
}

/// The settings of the owner executor.
#[derive(Debug, Clone)]
pub struct OwnerExecutorConfig {
    /// The adapter identity of the observations of the executor.
    pub adapter: AdapterId,
    /// The home directory of the user, which the diagnostic tail replaces
    /// with `~`.
    pub home_directory: LosslessPath,
    /// The largest executable that the executor reads for its digest.
    pub max_executable_bytes: u64,
    /// The bounds of a measurement of the scope.
    pub scope: ScopeLimits,
    /// The longest interval between two readings of the stop conditions
    /// while the command runs. At most 100 ms.
    pub stop_poll: Duration,
    /// The time between `SIGTERM` and `SIGKILL` to the group at a stop.
    /// At most 2 seconds.
    pub stop_grace: Duration,
    /// The names of the responsibility functions (owner decision D1 of
    /// 2026-11-22). A test names a function that is absent to show that no
    /// command starts without the disclaim.
    pub responsibility: ResponsibilitySymbols,
    /// The longest wait of the worker for the record of the process of the
    /// command in the journal.
    pub record_wait: Duration,
    /// The largest number of live descendants that the worker keeps for one
    /// command. At most [`MAX_OWNER_DESCENDANTS`]; a test sets a smaller
    /// value to show the truncation.
    ///
    /// [`MAX_OWNER_DESCENDANTS`]: crate::journal::MAX_OWNER_DESCENDANTS
    pub max_descendants: usize,
}

impl OwnerExecutorConfig {
    /// The settings of the specification, with the adapter and the home
    /// directory of the process.
    pub fn new(adapter: AdapterId, home_directory: LosslessPath) -> Self {
        Self {
            adapter,
            home_directory,
            max_executable_bytes: 512 * 1024 * 1024,
            scope: ScopeLimits::default(),
            stop_poll: Duration::from_millis(100),
            stop_grace: Duration::from_secs(2),
            responsibility: ResponsibilitySymbols::default(),
            max_descendants: crate::journal::MAX_OWNER_DESCENDANTS,
            record_wait: Duration::from_secs(30),
        }
    }
}

/// The reason an envelope is not a step of the owner executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OwnerAdmissionRefusal {
    /// The action class is not `RunOwnerOperation`.
    #[error("the step is not an owner operation")]
    ActionClass,
    /// The target is not an owner-operation binding.
    #[error("the target is not an owner-operation binding")]
    Target,
    /// The executor of the step is not the executor of the owning user.
    #[error("the step is not a step of the user executor")]
    Executor,
    /// The receipt is not for a consumption by this caller.
    #[error("the dispatch of the step was not consumed by this caller")]
    NotConsumed,
    /// The intent and the dispatch consumption are not durable.
    #[error("the record of the step is not durable")]
    NotDurable,
}

/// One step that the owner executor can do: an envelope of the class
/// `RunOwnerOperation` with the receipt of its durable dispatch
/// consumption. The value has no copy: one consumed dispatch gives one
/// command.
#[derive(Debug)]
pub struct AdmittedOwnerStep<'a> {
    envelope: &'a RequestEnvelope,
    owner: &'a OwnerOperationBinding,
}

impl<'a> AdmittedOwnerStep<'a> {
    /// Pairs an envelope with the receipt of its dispatch consumption.
    ///
    /// # Errors
    ///
    /// Returns an [`OwnerAdmissionRefusal`] when the envelope is not an
    /// owner operation of the user executor, or when the receipt does not
    /// permit the start of a command.
    pub fn new(
        envelope: &'a RequestEnvelope,
        receipt: &'a DispatchReceipt,
    ) -> Result<Self, OwnerAdmissionRefusal> {
        if envelope.action_class != ActionClass::RunOwnerOperation {
            return Err(OwnerAdmissionRefusal::ActionClass);
        }
        let TargetBinding::OwnerOperation(owner) = &envelope.target.binding else {
            return Err(OwnerAdmissionRefusal::Target);
        };
        if !matches!(envelope.executor, ExecutorRole::User) {
            return Err(OwnerAdmissionRefusal::Executor);
        }
        if !matches!(receipt.consumption, DispatchConsumption::Consumed) {
            return Err(OwnerAdmissionRefusal::NotConsumed);
        }
        let permitted: bool = receipt.permits_submission(
            &envelope.action_class,
            &envelope.trigger.class,
            &envelope.recording,
        );
        if !permitted || !receipt.durability.is_durable() {
            return Err(OwnerAdmissionRefusal::NotDurable);
        }
        Ok(Self { envelope, owner })
    }

    /// The request envelope.
    pub fn envelope(&self) -> &'a RequestEnvelope {
        self.envelope
    }

    /// The owner-operation binding of the target.
    pub fn owner(&self) -> &'a OwnerOperationBinding {
        self.owner
    }

    /// The envelope and the binding. The value is used up: one consumed
    /// dispatch gives one command.
    pub fn into_parts(self) -> (&'a RequestEnvelope, &'a OwnerOperationBinding) {
        (self.envelope, self.owner)
    }
}

/// The result of one owner step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOutcome {
    /// The target result, in the form of the action contract.
    pub result: TargetResult,
    /// The measurements of the scope before and after the command. `None`
    /// when no command started.
    pub scope: Option<ScopeAllocationEffect>,
    /// The exit status of the command, when it exited.
    pub exit_status: Option<i32>,
    /// The redacted end of the output of the command, for the log of the
    /// process. It is not in the journal.
    pub diagnostic_tail: Option<String>,
}

/// A defect of the executor: it made no target result that passes the
/// consistency check of the action contract. The caller records the
/// target as `UnknownOutcome` when `dispatch` is not `not_submitted`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the owner executor made no consistent target result")]
pub struct OwnerFault {
    /// Whether the command was, or possibly was, started.
    pub dispatch: DispatchState,
    /// The measurements of the scope, when the executor made them.
    pub scope: Option<ScopeAllocationEffect>,
}

/// The result of one step: an outcome, or the fault that prevented its
/// record.
pub type OwnerStepOutcome = Result<OwnerOutcome, Box<OwnerFault>>;
