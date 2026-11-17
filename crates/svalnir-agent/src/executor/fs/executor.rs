//! The filesystem executor: one admitted step to one target result.

use std::ffi::CString;
use std::os::fd::AsFd as _;
use std::time::SystemTime;

use svalnir_core::action::{
    ActionClass, ActionStage, Attribution, Checked, DispatchState, EffectEvidence, NativeResult,
    StopReason, TargetEffect, TargetResultRecord,
};
use svalnir_core::file::LosslessPath;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::WallTime;

use super::errors::{CallVerdict, Cause, code, mutation_verdict};
use super::model::{
    AdmittedStep, ApprovedRoots, BatchOutcome, ConfigError, ExecutionFault, ExecutorLimits,
    FsExecutorConfig, FsTargetOutcome, MAX_BATCH_STEPS, ProcessedWork, StepOutcome, Stop,
    StopSignal, path_components,
};
use super::native::{self, Kind};
use super::remove::{
    Attempt, EntryOutcome, Observed, TreeRemoval, count_removed, observe_entry, remove_file,
    remove_tree,
};
use super::resolve::{Checkpoint, HomeGuard, Injection, Located, Refusal, Resolution, locate};
use super::trash::{SystemTrash, TrashBackend, TrashFailure, TrashReply, TrashRequest};

/// The parts of one target result before the consistency check.
#[derive(Debug)]
struct Draft {
    dispatch: DispatchState,
    effect: TargetEffect,
    native: NativeResult,
    /// Whether the executor observed the entry for this result.
    observed: bool,
    attribution: Attribution,
    stop_reason: StopReason,
    failure: Option<(Cause, ActionStage)>,
    work: ProcessedWork,
    trash_item: Option<LosslessPath>,
}

impl Draft {
    /// A target for which no call was issued.
    fn not_submitted(effect: TargetEffect, stop_reason: StopReason) -> Self {
        Self {
            dispatch: DispatchState::NotSubmitted,
            effect,
            native: NativeResult::NotCalled,
            observed: false,
            attribution: Attribution::NotApplicable,
            stop_reason,
            failure: None,
            work: ProcessedWork::none(),
            trash_item: None,
        }
    }

    /// A target that was not started because of a stop.
    fn stopped(stop: Stop) -> Self {
        Self::not_submitted(TargetEffect::Skipped, stop.stop_reason())
    }

    /// A target that a check did not permit, or for which a read-only call
    /// failed.
    fn refused(refusal: Refusal) -> Self {
        let mut draft = Self::not_submitted(TargetEffect::Skipped, refusal.stop_reason);
        draft.failure = Some((refusal.cause, ActionStage::Dispatch));
        draft
    }

    /// A target that was absent at its revalidation.
    fn absent_before_call() -> Self {
        let mut draft = Self::not_submitted(TargetEffect::AlreadyAbsent, StopReason::Completed);
        draft.observed = true;
        draft
    }

    /// A target for which a call was issued.
    fn submitted(effect: TargetEffect, native: NativeResult, work: ProcessedWork) -> Self {
        Self {
            dispatch: DispatchState::Submitted,
            effect,
            native,
            observed: true,
            attribution: Attribution::NotApplicable,
            stop_reason: StopReason::Completed,
            failure: None,
            work,
            trash_item: None,
        }
    }

    /// The backend returned `ENOENT`: the entry was absent when the call
    /// ran. The cause of the absence is not established.
    fn absent_at_call(work: ProcessedWork) -> Self {
        let native = NativeResult::Errno {
            errno: libc::ENOENT,
        };
        let mut draft = Self::submitted(TargetEffect::AlreadyAbsent, native, work);
        draft.attribution = Attribution::Possible;
        draft
    }

    /// The call definitely had no effect on the target.
    fn no_effect(errno: Option<i32>, cause: Cause, work: ProcessedWork) -> Self {
        let mut draft = Self::submitted(TargetEffect::Refused, native_of(errno), work);
        draft.stop_reason = StopReason::Failed;
        draft.failure = Some((cause, ActionStage::Execution));
        draft
    }

    /// The effect of the call is not established.
    fn unknown(native: NativeResult, cause: Cause, work: ProcessedWork) -> Self {
        let mut draft = Self::submitted(TargetEffect::UnknownOutcome, native, work);
        draft.attribution = Attribution::Possible;
        draft.stop_reason = StopReason::Failed;
        draft.failure = Some((cause, ActionStage::Verification));
        draft
    }

    /// The result of one `unlinkat` call for the target itself.
    fn of_entry(outcome: EntryOutcome, work: ProcessedWork) -> Self {
        match outcome {
            EntryOutcome::Removed { attribution, errno } => {
                let native: NativeResult = errno.map_or(NativeResult::Succeeded, |errno| {
                    NativeResult::Errno { errno }
                });
                let mut draft = Self::submitted(TargetEffect::Removed, native, work);
                draft.attribution = attribution;
                draft
            }
            EntryOutcome::Absent => Self::absent_at_call(work),
            EntryOutcome::NoEffect { errno, cause } => Self::no_effect(errno, cause, work),
            EntryOutcome::Unknown { errno, cause } => {
                // A call that returned success has no error number.
                let native: NativeResult = errno.map_or(NativeResult::Succeeded, |errno| {
                    NativeResult::Errno { errno }
                });
                Self::unknown(native, cause, work)
            }
        }
    }
}

/// The native result of a call that failed.
fn native_of(errno: Option<i32>) -> NativeResult {
    errno.map_or(NativeResult::Refused, |errno| NativeResult::Errno { errno })
}

/// Makes the checked target result of a draft.
fn seal(step: &AdmittedStep<'_>, draft: Draft) -> StepOutcome {
    let envelope = step.envelope();
    let fault = |dispatch: &DispatchState, reason| ExecutionFault {
        target_id: step.target_id().clone(),
        dispatch: dispatch.clone(),
        reason,
    };
    let failure = match &draft.failure {
        Some((cause, stage)) => Some(
            cause
                .to_action_error(stage.clone(), draft.dispatch.clone(), envelope)
                .map_err(|error| fault(&draft.dispatch, error.into()))?,
        ),
        None => None,
    };
    let observed_at: Option<WallTime> = if draft.observed {
        WallTime::try_from(SystemTime::now()).ok()
    } else {
        None
    };
    // The record has the Trash item only for a `Trashed` effect. The
    // outcome keeps the item for each reply that names one.
    let record_item: Option<LosslessPath> = if matches!(draft.effect, TargetEffect::Trashed) {
        draft.trash_item.clone()
    } else {
        None
    };
    let record = TargetResultRecord {
        target_id: step.target_id().clone(),
        member: None,
        dispatch: draft.dispatch.clone(),
        effect: draft.effect,
        evidence: EffectEvidence {
            native: draft.native,
            source: draft.observed.then(|| envelope.adapter.clone()),
            observed_at,
            trash_item: record_item,
        },
        attribution: draft.attribution,
        durability: step.durability().clone(),
        stop_reason: draft.stop_reason,
        failure,
    };
    let result = Checked::new(record).map_err(|error| fault(&draft.dispatch, error.into()))?;
    Ok(FsTargetOutcome {
        result,
        work: draft.work,
        trash_item: draft.trash_item,
    })
}

/// The filesystem executor of the user agent.
///
/// The executor does one admitted filesystem step at a time: it
/// revalidates the target, issues the call of the action class, observes
/// the entry, and returns the target result. It decides no policy, reads
/// no clock for a deadline, and writes no journal. It measures no capacity:
/// the caller does that after each batch.
#[derive(Debug)]
pub struct FsExecutor {
    home: HomeGuard,
    limits: ExecutorLimits,
    trash: Box<dyn TrashBackend>,
    injection: Injection,
}

impl FsExecutor {
    /// Makes an executor with the Trash backend `trash`.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when the home directory of `config` is
    /// not an absolute normalized path below `/`, or cannot be opened from
    /// `/` with no symbolic link in its path.
    pub fn new(
        config: &FsExecutorConfig,
        trash: Box<dyn TrashBackend>,
    ) -> Result<Self, ConfigError> {
        let components: Vec<CString> = path_components(config.home_directory.as_bytes(), true)
            .ok_or(ConfigError::HomeDirectory)?;
        let home: HomeGuard =
            HomeGuard::anchor(components).map_err(|_| ConfigError::HomeUnavailable)?;
        Ok(Self {
            home,
            limits: config.limits,
            trash,
            injection: Injection::default(),
        })
    }

    /// Makes an executor with the Trash of the operating system.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when the home directory of `config` is
    /// not an absolute normalized path below `/`, or cannot be opened from
    /// `/` with no symbolic link in its path.
    pub fn with_system_trash(config: &FsExecutorConfig) -> Result<Self, ConfigError> {
        Self::new(config, Box::new(SystemTrash))
    }

    /// Replaces the hooks, for a test.
    #[cfg(test)]
    pub(super) fn with_injection(mut self, injection: Injection) -> Self {
        self.injection = injection;
        self
    }

    /// Does the steps of one batch in their sequence.
    ///
    /// The executor reads `stop` at the start of the batch and before each
    /// target. After a stop it starts no target: each step that was not
    /// started has a `Skipped` result with the stop reason and no
    /// submission. A step that was done keeps its result; a call that was
    /// issued is not reported as undone.
    ///
    /// The result has one entry for each step. A step after the first
    /// [`MAX_BATCH_STEPS`] steps is skipped with a `limits` error.
    pub fn execute_batch(
        &self,
        roots: &ApprovedRoots,
        steps: Vec<AdmittedStep<'_>>,
        stop: &dyn StopSignal,
    ) -> BatchOutcome {
        let mut outcomes: Vec<StepOutcome> = Vec::with_capacity(steps.len());
        let mut stopped: Option<Stop> = None;
        for (index, step) in steps.into_iter().enumerate() {
            if stopped.is_none() {
                stopped = stop.check();
            }
            let outcome: StepOutcome = if let Some(stop) = stopped {
                seal(&step, Draft::stopped(stop))
            } else if index >= MAX_BATCH_STEPS {
                let refusal = Refusal::skipped(Cause::limits(code::BATCH_LIMIT));
                seal(&step, Draft::refused(refusal))
            } else {
                self.execute_step(roots, step)
            };
            outcomes.push(outcome);
        }
        BatchOutcome { outcomes, stopped }
    }

    /// Does one step.
    ///
    /// The executor revalidates the target immediately before the call. A
    /// target that does not pass has a `Skipped` result with the reason and
    /// no submission; an absent target has `AlreadyAbsent`.
    ///
    /// # Errors
    ///
    /// Returns an [`ExecutionFault`] when the executor could not make a
    /// consistent target result. That is a defect of the executor; the
    /// fault says whether a call was submitted.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the step is consumed: one dispatch consumption gives one call"
    )]
    pub fn execute_step(&self, roots: &ApprovedRoots, step: AdmittedStep<'_>) -> StepOutcome {
        seal(&step, self.draft_of(roots, &step))
    }

    fn draft_of(&self, roots: &ApprovedRoots, step: &AdmittedStep<'_>) -> Draft {
        let envelope = step.envelope();
        // The user executor changes only the objects of its own user, with
        // the rights of that user.
        if native::effective_uid() != envelope.principal.uid.get() {
            return Draft::refused(Refusal::skipped(Cause::authority(code::PRINCIPAL_MISMATCH)));
        }
        let is_trash: bool = match step.action_class() {
            ActionClass::MoveToTrash => true,
            ActionClass::DeleteSelectedFiles | ActionClass::EvictRegenerableData => false,
            _ => {
                return Draft::refused(Refusal::skipped(Cause::request(
                    code::ACTION_CLASS_UNSUPPORTED,
                )));
            }
        };
        let located: Located = match locate(step.file(), roots, &self.home, &self.injection) {
            Resolution::Located(located) => located,
            Resolution::Absent => return Draft::absent_before_call(),
            Resolution::Refused(refusal) => return Draft::refused(refusal),
        };
        self.injection.reach(Checkpoint::Revalidated, &located.path);
        if is_trash {
            return self.move_to_trash(&located);
        }
        match located.metadata.kind {
            Kind::File | Kind::Symlink => {
                let outcome: EntryOutcome = remove_file(&located, &self.injection);
                let mut work = ProcessedWork::none();
                if matches!(outcome, EntryOutcome::Removed { .. }) {
                    count_removed(&mut work, &located.metadata);
                } else if matches!(
                    outcome,
                    EntryOutcome::NoEffect { .. } | EntryOutcome::Unknown { .. }
                ) {
                    work.remaining_entries = EntryCount::new(1);
                } else if matches!(outcome, EntryOutcome::Absent) {
                    work.vanished_entries = EntryCount::new(1);
                }
                Draft::of_entry(outcome, work)
            }
            Kind::Directory => match remove_tree(&located, &self.limits, &self.injection) {
                Ok(removal) => Self::draft_of_tree(removal),
                Err(refusal) => Draft::refused(refusal),
            },
            Kind::Other => Draft::refused(Refusal::skipped(Cause::eligibility(
                code::UNSUPPORTED_FILE_TYPE,
            ))),
        }
    }

    /// The result of a directory target.
    fn draft_of_tree(removal: TreeRemoval) -> Draft {
        let TreeRemoval {
            root,
            work,
            first_cause,
            indeterminate,
        } = removal;
        let outcome: EntryOutcome = match root {
            // The comparison of the target directory comes before each
            // call, so no call was issued.
            Attempt::Vanished => return Draft::absent_before_call(),
            Attempt::NotAttempted(refusal) => return Draft::refused(refusal),
            Attempt::Called(outcome) => outcome,
        };
        match outcome {
            // The directory is gone, or its condition is not established.
            EntryOutcome::Removed { .. } | EntryOutcome::Absent | EntryOutcome::Unknown { .. } => {
                Draft::of_entry(outcome, work)
            }
            EntryOutcome::NoEffect { errno, cause } => match indeterminate {
                // The directory stays and the effect of a call on one of
                // its entries is not established.
                Some(unknown) => Draft::unknown(native_of(errno), unknown, work),
                // The directory stays and a part of its entries was
                // removed. The target results of the action contract have
                // no effect for a target that was removed in part.
                // `Refused` has the attribution `not_applicable`, which
                // states that nothing changed; that is false here. The
                // result is thus `UnknownOutcome`, which never understates
                // the effect, and `ProcessedWork` has the exact counts.
                // The first entry that was not removed gives the cause.
                None if work.removed_entries > EntryCount::ZERO => {
                    Draft::unknown(native_of(errno), first_cause.unwrap_or(cause), work)
                }
                // The directory stays and no entry was removed. The first
                // entry that was not removed gives the cause; the error
                // number is that of the call on the directory.
                None => Draft::no_effect(errno, first_cause.unwrap_or(cause), work),
            },
        }
    }

    /// Moves a revalidated target to Trash. A failure is reported; it is
    /// never replaced with a permanent removal.
    fn move_to_trash(&self, located: &Located) -> Draft {
        let Ok(path) = LosslessPath::from_bytes(located.path.clone()) else {
            return Draft::refused(Refusal::skipped(Cause::request(
                code::RELATIVE_ENTRY_INVALID,
            )));
        };
        let request = TrashRequest {
            path: &path,
            is_directory: located.metadata.kind == Kind::Directory,
        };
        let reply: TrashReply = self.trash.move_to_trash(&request);
        let observed: Observed = observe_entry(
            located.parent.as_fd(),
            &located.name,
            Some(located.object),
            &self.injection,
            &located.path,
        );
        let mut remaining = ProcessedWork::none();
        remaining.remaining_entries = EntryCount::new(1);
        let unverified = || Cause::outcome(code::OUTCOME_UNVERIFIED);
        match reply {
            TrashReply::Moved { item, item_object } => {
                let mut draft: Draft = if observed == Observed::Present {
                    // The backend reports a move and the object of the
                    // plan is where it was.
                    Draft::unknown(NativeResult::Succeeded, unverified(), remaining)
                } else if item_object.is_none() && observed == Observed::Unobserved {
                    // The reply of the backend is the only evidence: it
                    // gave no item identity, and the source name cannot be
                    // read.
                    Draft::unknown(NativeResult::Succeeded, unverified(), remaining)
                } else if item_object.is_some_and(|object| object != located.object) {
                    // The backend moved another object: a component of the
                    // path changed between the revalidation and the call.
                    let cause = Cause::outcome(code::TRASH_ITEM_IDENTITY_MISMATCH);
                    Draft::unknown(NativeResult::Succeeded, cause, remaining)
                } else {
                    let mut work = ProcessedWork::none();
                    work.trashed_entries = EntryCount::new(1);
                    work.trashed_logical_bytes = match located.metadata.kind {
                        Kind::File | Kind::Symlink => {
                            u64::try_from(located.metadata.size).ok().map(Bytes::new)
                        }
                        Kind::Directory | Kind::Other => None,
                    };
                    let mut draft =
                        Draft::submitted(TargetEffect::Trashed, NativeResult::Succeeded, work);
                    // The identity of the item in Trash establishes that
                    // the object of the plan was moved. Without it, the
                    // absence of the source name is the only evidence.
                    draft.attribution = if item_object.is_some() {
                        Attribution::Established
                    } else {
                        Attribution::Possible
                    };
                    draft
                };
                draft.trash_item = item;
                draft
            }
            TrashReply::Failed(failure) => {
                Self::draft_of_trash_failure(failure, observed, remaining)
            }
            TrashReply::Unknown => Draft::unknown(
                NativeResult::Unavailable,
                Cause::outcome(code::TRASH_RESULT_UNKNOWN),
                remaining,
            ),
        }
    }

    /// The result of a Trash backend that reports a failure. The reply is
    /// compared with the name in the open parent directory: the backend
    /// resolves the path again, so its reply alone does not show the
    /// condition of the object of the plan.
    fn draft_of_trash_failure(
        failure: TrashFailure,
        observed: Observed,
        remaining: ProcessedWork,
    ) -> Draft {
        let (errno, verdict): (Option<i32>, CallVerdict) = match failure {
            TrashFailure::Errno(errno) => (Some(errno), mutation_verdict(Some(errno))),
            TrashFailure::PermissionDenied => (
                None,
                CallVerdict::NoEffect(Cause::native(code::PERMISSION_DENIED)),
            ),
            TrashFailure::ReadOnlyVolume => (
                None,
                CallVerdict::NoEffect(Cause::native(code::READ_ONLY_FILESYSTEM)),
            ),
            TrashFailure::Unsupported => (
                None,
                CallVerdict::NoEffect(Cause::native(code::TRASH_UNSUPPORTED)),
            ),
            TrashFailure::NotFound => (None, CallVerdict::Absent),
            TrashFailure::Other => (
                None,
                CallVerdict::Indeterminate(Cause::outcome(code::TRASH_FAILED)),
            ),
        };
        match (verdict, observed) {
            // The backend found no entry, and the name is absent in the
            // open parent directory also.
            (CallVerdict::Absent, Observed::Gone) => {
                let mut work = ProcessedWork::none();
                work.vanished_entries = EntryCount::new(1);
                Draft::absent_at_call(work)
            }
            // The backend found no entry at the path, and the object of
            // the plan is where it was: a component of the path changed.
            // Nothing was moved.
            (CallVerdict::Absent, Observed::Present) => {
                Draft::no_effect(errno, Cause::evidence(code::ENTRY_ABSENT), remaining)
            }
            // The backend reports a failure and the object of the plan is
            // where it was: the call had no effect.
            (CallVerdict::NoEffect(cause), Observed::Present) => {
                Draft::no_effect(errno, cause, remaining)
            }
            (CallVerdict::Indeterminate(cause), Observed::Present) => {
                Draft::no_effect(errno, Cause::native(cause.code), remaining)
            }
            // The backend reports a failure and the object is not where it
            // was.
            (CallVerdict::Absent | CallVerdict::NoEffect(_), _) => Draft::unknown(
                native_of(errno),
                Cause::outcome(code::OUTCOME_UNVERIFIED),
                remaining,
            ),
            (CallVerdict::Indeterminate(cause), _) => {
                Draft::unknown(native_of(errno), cause, remaining)
            }
        }
    }
}
