//! The owner executor: the checks before the start, the supervised
//! command, and the target result.

use std::path::{Path, PathBuf};
use std::time::Duration;

use svalnir_core::action::{
    ActionError, ActionStage, Attribution, Checked, DispatchState, Durability, EffectEvidence,
    ErrorCode, ErrorFamily, NativeResult, OwnerOperationBinding, OwnerOperationBound,
    RequestEnvelope, ScopeAllocationEffect, ScopeMeasurement, StopReason, TargetEffect,
    TargetResult, TargetResultRecord,
};
use svalnir_core::process::Uid;
use svalnir_core::time::WallTime;

use super::measure::measure_scope;
use super::model::{
    AdmittedOwnerStep, OwnerExecutorConfig, OwnerFault, OwnerOutcome, OwnerStepOutcome, code,
};
use super::supervise::{self, CommandSpec, Ending, Supervision};
use super::verify::{ExecutableRefusal, check_executable, is_planned_root};
use crate::executor::fs::{ApprovedRoots, StopSignal};
use crate::platform::volume::{Locality, MountTable};
use crate::scan::{CancellationToken, WallScanClock};

/// The longest interval between two readings of the stop conditions.
const MAX_STOP_POLL: Duration = Duration::from_millis(100);

/// The longest time between `SIGTERM` and `SIGKILL`.
const MAX_STOP_GRACE: Duration = Duration::from_secs(2);

/// A refusal before the start: the code and its family.
type Refusal = (&'static str, ErrorFamily);

/// The owner executor of the user.
#[derive(Debug, Clone)]
pub struct OwnerExecutor {
    config: OwnerExecutorConfig,
}

/// The effective user of this process.
fn effective_uid() -> Uid {
    // SAFETY: `geteuid` has no argument, cannot fail, and changes no state.
    Uid::new(unsafe { libc::geteuid() })
}

fn wall_now() -> Option<WallTime> {
    WallTime::try_from(std::time::SystemTime::now()).ok()
}

impl OwnerExecutor {
    /// Makes the executor. The stop interval is at most 100 ms and the stop
    /// grace at most 2 seconds; a longer value is cut to that bound.
    pub fn new(mut config: OwnerExecutorConfig) -> Self {
        config.stop_poll = config.stop_poll.min(MAX_STOP_POLL);
        config.stop_grace = config.stop_grace.min(MAX_STOP_GRACE);
        Self { config }
    }

    /// The settings.
    pub fn config(&self) -> &OwnerExecutorConfig {
        &self.config
    }

    /// Does one admitted step under the root records `roots` of this
    /// process (`docs/ACTION_CONTRACTS.md` section 7, the subsection of
    /// `RunOwnerOperation`).
    ///
    /// The coordinator reads its stop conditions, the producer activity,
    /// and the use check before this call. `signal` is read while the
    /// command runs.
    ///
    /// # Errors
    ///
    /// Returns an [`OwnerFault`] when the executor made no consistent
    /// target result.
    pub fn execute(
        &self,
        roots: &ApprovedRoots,
        step: AdmittedOwnerStep<'_>,
        signal: &dyn StopSignal,
    ) -> OwnerStepOutcome {
        let (envelope, owner): (&RequestEnvelope, &OwnerOperationBinding) = step.into_parts();
        let result = Draft {
            envelope,
            adapter: &self.config.adapter,
        };
        let skipped = |text: &str, family: ErrorFamily| -> OwnerStepOutcome {
            let result: TargetResult = result
                .skipped(text, family)
                .map_err(|NoRecord| no_record(DispatchState::NotSubmitted, None))?;
            Ok(OwnerOutcome {
                result,
                scope: None,
                exit_status: None,
                diagnostic_tail: None,
            })
        };
        let before: ScopeMeasurement = match self.check_before_start(roots, envelope, owner) {
            Ok(before) => before,
            Err((text, family)) => return skipped(text, family),
        };
        let spec: CommandSpec = CommandSpec {
            executable: owner.executable.path.to_path_buf(),
            arguments: owner.arguments.clone(),
            environment: owner
                .environment
                .iter()
                .map(|entry| (entry.name.clone(), entry.value.clone()))
                .collect(),
            working_directory: owner.working_directory.to_path_buf(),
        };
        let limits = Supervision {
            deadline: Duration::from_nanos(owner.command_deadline.get()),
            stop_poll: self.config.stop_poll,
            stop_grace: self.config.stop_grace,
        };
        let Ok(supervised) = supervise::run(&spec, &limits, signal) else {
            return skipped(code::OWNER_OPERATION_NOT_STARTED, ErrorFamily::Native);
        };
        // The scope is measured again after each end of the command.
        let after: Option<ScopeMeasurement> = self.measure(&owner.root_path.to_path_buf());
        let scope = ScopeAllocationEffect::new(envelope.target.target_id.clone(), before, after);
        let home: String = String::from_utf8_lossy(self.config.home_directory.as_bytes()).into();
        let exit_status: Option<i32> = match supervised.ending {
            Ending::Exited { status, .. } => Some(supervise::status_code(status)),
            _ => None,
        };
        // The bound of an automatic step is verified by the measurements:
        // the scope did not grow during the command.
        let bound_verified: bool = !envelope.trigger.class.is_automatic()
            || !matches!(owner.bound, OwnerOperationBound::WithinScope)
            || after.is_some_and(|after| {
                after.complete && before.complete && after.allocated_bytes <= before.allocated_bytes
            });
        match result.of_ending(supervised.ending, exit_status, bound_verified) {
            Ok(result) => Ok(OwnerOutcome {
                result,
                scope: Some(scope),
                exit_status,
                diagnostic_tail: Some(supervise::redacted(&supervised.tail, &home)),
            }),
            Err(NoRecord) => Err(no_record(DispatchState::Submitted, Some(scope))),
        }
    }

    /// The checks before the start, in the sequence of the specification.
    /// Returns the measurement of the scope before the command.
    fn check_before_start(
        &self,
        roots: &ApprovedRoots,
        envelope: &RequestEnvelope,
        owner: &OwnerOperationBinding,
    ) -> Result<ScopeMeasurement, Refusal> {
        let principal: Uid = envelope.principal.uid;
        if effective_uid() != principal {
            return Err((code::PRINCIPAL_MISMATCH, ErrorFamily::Authority));
        }
        if roots
            .root(&owner.root_id)
            .is_some_and(|root| root.path != owner.root_path || root.object != owner.root_object)
        {
            return Err((code::APPROVED_ROOT_MISMATCH, ErrorFamily::Evidence));
        }
        let root: PathBuf = owner.root_path.to_path_buf();
        let locality: Locality = MountTable::read().map_or(Locality::Unknown, |table| match table
            .path_locality(&root)
        {
            Locality::Local => table.device_locality(owner.root_object.device),
            other => other,
        });
        match locality {
            Locality::Local => {}
            Locality::NotLocal => return Err((code::ROOT_NOT_LOCAL, ErrorFamily::Eligibility)),
            Locality::Unknown => {
                return Err((code::ROOT_LOCALITY_UNKNOWN, ErrorFamily::Evidence));
            }
        }
        if !is_planned_root(&root, &owner.root_object, owner.owner) {
            return Err((code::SCOPE_ROOT_CHANGED, ErrorFamily::Evidence));
        }
        match check_executable(
            &owner.executable,
            principal,
            self.config.max_executable_bytes,
        ) {
            Ok(()) => {}
            Err(ExecutableRefusal::Changed) => {
                return Err((code::OWNER_EXECUTABLE_CHANGED, ErrorFamily::Evidence));
            }
            Err(ExecutableRefusal::NotTrusted) => {
                return Err((code::OWNER_EXECUTABLE_NOT_TRUSTED, ErrorFamily::Eligibility));
            }
        }
        let before: ScopeMeasurement = self
            .measure(&root)
            .filter(|measurement| measurement.complete)
            .ok_or((code::SCOPE_NOT_MEASURED, ErrorFamily::Evidence))?;
        // The plan does not authorize data or entries that appeared after
        // it was made.
        if !before.fits_in(&owner.charge) {
            return Err((code::TARGET_GREW, ErrorFamily::Evidence));
        }
        // The root can be replaced during the measurement.
        if !is_planned_root(&root, &owner.root_object, owner.owner) {
            return Err((code::SCOPE_ROOT_CHANGED, ErrorFamily::Evidence));
        }
        Ok(before)
    }

    fn measure(&self, root: &Path) -> Option<ScopeMeasurement> {
        measure_scope(
            root,
            self.config.scope,
            &CancellationToken::new(),
            &WallScanClock,
        )
    }
}

/// A record that the contract types rejected: a defect of the executor.
#[derive(Debug, Clone, Copy)]
struct NoRecord;

/// The fault of a step whose record was rejected.
fn no_record(dispatch: DispatchState, scope: Option<ScopeAllocationEffect>) -> Box<OwnerFault> {
    Box::new(OwnerFault { dispatch, scope })
}

/// The builder of the target result of one step.
struct Draft<'a> {
    envelope: &'a RequestEnvelope,
    adapter: &'a svalnir_core::id::AdapterId,
}

impl Draft<'_> {
    /// The result of a command that started, from the way it ended.
    fn of_ending(
        &self,
        ending: Ending,
        exit_status: Option<i32>,
        bound_verified: bool,
    ) -> Result<TargetResult, NoRecord> {
        match ending {
            Ending::Exited {
                children_remained: true,
                ..
            } => self.unknown(
                exit_status,
                StopReason::Failed,
                Some(code::OWNER_OPERATION_CHILDREN_REMAINED),
            ),
            Ending::Exited { status, .. } if status.success() => {
                if bound_verified {
                    self.completed()
                } else {
                    self.unknown(
                        exit_status,
                        StopReason::Failed,
                        Some(code::OWNER_OPERATION_BOUND_NOT_VERIFIED),
                    )
                }
            }
            Ending::Exited { .. } | Ending::Lost => self.unknown(
                exit_status,
                StopReason::Failed,
                Some(code::OWNER_OPERATION_FAILED),
            ),
            Ending::Deadline => self.unknown(
                None,
                StopReason::Failed,
                Some(code::OWNER_OPERATION_DEADLINE),
            ),
            Ending::Stopped(halt) => self.unknown(None, halt.stop_reason(), None),
        }
    }

    fn error(
        &self,
        text: &str,
        family: ErrorFamily,
        stage: ActionStage,
        dispatch: DispatchState,
    ) -> Result<ActionError, NoRecord> {
        let correlation = &self.envelope.correlation;
        Ok(ActionError {
            code: ErrorCode::new(text).map_err(|_| NoRecord)?,
            family,
            stage,
            dispatch,
            plan_id: Some(correlation.plan_id.clone()),
            operation_id: Some(correlation.operation_id.clone()),
            step_id: Some(correlation.step_id.clone()),
        })
    }

    fn check(record: TargetResultRecord) -> Result<TargetResult, NoRecord> {
        Checked::new(record).map_err(|_| NoRecord)
    }

    /// A target that got no command.
    fn skipped(&self, text: &str, family: ErrorFamily) -> Result<TargetResult, NoRecord> {
        let failure: ActionError = self.error(
            text,
            family,
            ActionStage::Dispatch,
            DispatchState::NotSubmitted,
        )?;
        Self::check(TargetResultRecord {
            target_id: self.envelope.target.target_id.clone(),
            member: None,
            dispatch: DispatchState::NotSubmitted,
            effect: TargetEffect::Skipped,
            evidence: EffectEvidence::none(),
            attribution: Attribution::NotApplicable,
            durability: Durability::Durable,
            stop_reason: StopReason::TargetSkipped,
            failure: Some(failure),
        })
    }

    /// A command that exited with status 0 and left no process.
    fn completed(&self) -> Result<TargetResult, NoRecord> {
        Self::check(TargetResultRecord {
            target_id: self.envelope.target.target_id.clone(),
            member: None,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::OperationCompleted,
            evidence: EffectEvidence {
                native: NativeResult::ExitStatus { status: 0 },
                source: Some(self.adapter.clone()),
                observed_at: wall_now(),
                trash_item: None,
            },
            attribution: Attribution::Possible,
            durability: Durability::Durable,
            stop_reason: StopReason::Completed,
            failure: None,
        })
    }

    /// A command whose effect is not known.
    fn unknown(
        &self,
        exit_status: Option<i32>,
        stop_reason: StopReason,
        text: Option<&str>,
    ) -> Result<TargetResult, NoRecord> {
        let failure: Option<ActionError> = match text {
            Some(text) => Some(self.error(
                text,
                ErrorFamily::Outcome,
                ActionStage::Execution,
                DispatchState::Submitted,
            )?),
            None => None,
        };
        let native: NativeResult = exit_status.map_or(NativeResult::Unavailable, |status| {
            NativeResult::ExitStatus { status }
        });
        Self::check(TargetResultRecord {
            target_id: self.envelope.target.target_id.clone(),
            member: None,
            dispatch: DispatchState::Submitted,
            effect: TargetEffect::UnknownOutcome,
            evidence: EffectEvidence {
                native,
                source: Some(self.adapter.clone()),
                observed_at: wall_now(),
                trash_item: None,
            },
            attribution: Attribution::Possible,
            durability: Durability::Durable,
            stop_reason,
            failure,
        })
    }
}
