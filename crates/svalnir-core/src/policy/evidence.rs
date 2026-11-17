//! Observation quality.
//!
//! `docs/POLICY_SPEC.md` section 6 and `docs/RESOURCE_MODEL.md` section 5
//! own the rules. An observation supports a decision only when it is of the
//! intended metric and scope, has a value with a known unit, covers its
//! complete scope, is in the clock domain and boot of the evaluation, and is
//! not older than `decision_sample_max_age`. Each other observation is a
//! problem. A problem is never a zero and never a normal state.

use std::fmt::Display;
use std::time::Duration;

use serde::Serialize;

use super::reason::{DecisionReason, Explanation, ReasonDetail};
use super::window::{ContinuityGeneration, QualifyingSample, WindowBinding};
use crate::id::{BootId, ClockDomainId, SampleId};
use crate::observation::{
    Coverage, MetricId, Observation, ObservationValue, Reading, Sample, Scope, ScopeKind,
    UnavailableReason, Unit, metric,
};
use crate::quantity::Nanoseconds;
use crate::time::{MonotonicNanos, WallTime};

/// The time of an evaluation. The caller reads the clock; this module does
/// not.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct EvaluationClock {
    /// The monotonic time of the evaluation.
    pub now: MonotonicNanos,
    /// The clock domain of `now`.
    pub clock_domain: ClockDomainId,
    /// The boot of `now`.
    pub boot_id: BootId,
    /// The clock continuity that the caller reports. The caller increases
    /// the value after sleep, wake, or another discontinuity.
    pub continuity: ContinuityGeneration,
    /// The monotonic time of the latest sleep, wake, or other discontinuity
    /// of this boot, when there was one. A sample that started before this
    /// time is not usable.
    pub last_discontinuity: Option<MonotonicNanos>,
}

/// The reason an observation cannot support a decision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceProblem {
    /// The snapshot has no observation.
    Missing,
    /// The observation has no value.
    Unavailable {
        /// The reason that the collector gave.
        reason: UnavailableReason,
    },
    /// The availability or the value is one that this build does not
    /// recognize.
    Unrecognized,
    /// The unit is not a unit of the value type.
    UnitMismatch,
    /// The observation is of a different metric.
    MetricMismatch,
    /// The observation is of a different scope.
    ScopeMismatch,
    /// The observation does not cover its complete scope.
    CoverageIncomplete,
    /// The observation is from a different clock domain or boot.
    ClockMismatch,
    /// The observation is later than the evaluation time.
    SampleFromFuture,
    /// The observation is from before the latest clock discontinuity.
    SampleBeforeDiscontinuity,
    /// The observation is older than `decision_sample_max_age`.
    SampleTooOld {
        /// The age of the observation, from the start of its acquisition.
        age: Nanoseconds,
        /// The largest accepted age.
        max_age: Nanoseconds,
    },
    /// No fresh corroborating system observation is available.
    CorroborationMissing,
    /// No volume in the snapshot has the selector.
    SelectorUnresolved,
    /// More than one volume in the snapshot has the selector.
    SelectorAmbiguous,
    /// The membership of a process is not verified.
    MembershipUnverified,
    /// More than one running instance matches the budget.
    AmbiguousInstances,
    /// The process inventory is not complete.
    InventoryIncomplete,
}

impl EvidenceProblem {
    /// The decision reason of the problem.
    pub const fn explanation(&self) -> Explanation {
        let (reason, detail): (DecisionReason, ReasonDetail) = match self {
            Self::Missing => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::ObservationMissing,
            ),
            Self::Unavailable { .. } => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::ObservationUnavailable,
            ),
            Self::Unrecognized => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::ObservationUnrecognized,
            ),
            Self::UnitMismatch => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::UnitMismatch,
            ),
            Self::MetricMismatch => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::MetricMismatch,
            ),
            Self::ScopeMismatch => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::ScopeMismatch,
            ),
            Self::CoverageIncomplete => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::CoverageIncomplete,
            ),
            Self::ClockMismatch => (DecisionReason::MetricStale, ReasonDetail::ClockMismatch),
            Self::SampleFromFuture => (DecisionReason::MetricStale, ReasonDetail::SampleFromFuture),
            Self::SampleTooOld { .. } => (DecisionReason::MetricStale, ReasonDetail::SampleTooOld),
            Self::SampleBeforeDiscontinuity => (
                DecisionReason::MetricStale,
                ReasonDetail::SampleBeforeDiscontinuity,
            ),
            Self::CorroborationMissing => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::CorroborationMissing,
            ),
            Self::SelectorUnresolved => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::SelectorUnresolved,
            ),
            Self::SelectorAmbiguous => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::SelectorAmbiguous,
            ),
            Self::MembershipUnverified => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::MembershipUnverified,
            ),
            Self::AmbiguousInstances => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::AmbiguousInstances,
            ),
            Self::InventoryIncomplete => (
                DecisionReason::MetricUnavailable,
                ReasonDetail::InventoryIncomplete,
            ),
        };
        Explanation::new(reason, detail)
    }
}

/// The evidence that one trigger or one candidate used, for a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceReport {
    /// The metric that the evaluation needed.
    pub metric_id: MetricId,
    /// The scope of the observation, when the snapshot has one.
    pub scope: Option<Scope>,
    /// The value as text, when the observation is usable.
    pub value: Option<String>,
    /// The unit of the observation.
    pub unit: Option<Unit>,
    /// The identity of the acquisition.
    pub sample_id: Option<SampleId>,
    /// The wall-clock time of the acquisition, for display only.
    pub captured_at: Option<WallTime>,
    /// The monotonic start of the acquisition.
    pub sampled_at: Option<MonotonicNanos>,
    /// The age at the evaluation time, when the clocks are comparable.
    pub age: Option<Nanoseconds>,
    /// True when the observation supports a decision.
    pub usable: bool,
    /// The problem of an observation that is not usable.
    pub problem: Option<EvidenceProblem>,
}

impl EvidenceReport {
    /// The report of an observation that the snapshot does not have.
    pub(super) fn missing(metric_id: MetricId, problem: EvidenceProblem) -> Self {
        Self {
            metric_id,
            scope: None,
            value: None,
            unit: None,
            sample_id: None,
            captured_at: None,
            sampled_at: None,
            age: None,
            usable: false,
            problem: Some(problem),
        }
    }
}

/// A usable observation.
#[derive(Debug)]
pub(super) struct Usable<'a, T> {
    pub(super) value: &'a T,
    pub(super) sample: &'a Sample,
}

impl<T> Usable<'_, T> {
    /// The observation as one qualifying sample of a window.
    pub(super) fn qualifying(
        &self,
        clock: &EvaluationClock,
        subject: Vec<String>,
    ) -> QualifyingSample {
        QualifyingSample {
            binding: binding(self.sample, clock, subject),
            at: self.sample.started_monotonic_ns,
            sample_id: self.sample.sample_id.clone(),
        }
    }
}

/// The scope that an observation must have.
#[derive(Debug, Clone, Copy)]
pub(super) enum ScopeCheck<'a> {
    /// The scope must be equal.
    Exact(&'a Scope),
    /// The kind of the scope must be equal.
    Kind(&'a ScopeKind),
}

/// The window binding of a sample.
pub(super) fn binding(
    sample: &Sample,
    clock: &EvaluationClock,
    subject: Vec<String>,
) -> WindowBinding {
    WindowBinding {
        clock_domain: sample.clock_domain.clone(),
        boot_id: sample.boot_id.clone(),
        collector_epoch: sample.collector_epoch.clone(),
        continuity: clock.continuity,
        subject,
    }
}

/// A configuration duration as nanoseconds. The validation makes sure that
/// the value fits; a value that does not fit becomes the largest value,
/// which makes a wait longer and never shorter.
pub(super) fn nanoseconds(duration: Duration) -> Nanoseconds {
    Nanoseconds::try_from(duration).unwrap_or(Nanoseconds::MAX)
}

/// The age of a sample at the evaluation time.
///
/// The age is from the start of the acquisition, which is the conservative
/// end (`docs/RESOURCE_MODEL.md` section 5).
pub(super) fn sample_age(
    sample: &Sample,
    clock: &EvaluationClock,
    max_age: Nanoseconds,
) -> Result<Nanoseconds, EvidenceProblem> {
    if sample.clock_domain != clock.clock_domain || sample.boot_id != clock.boot_id {
        return Err(EvidenceProblem::ClockMismatch);
    }
    if sample.finished_monotonic_ns > clock.now {
        return Err(EvidenceProblem::SampleFromFuture);
    }
    // A sample from before sleep, wake, or another discontinuity is not
    // evidence of the current state, also when its age is small on a clock
    // that does not advance during sleep.
    if clock
        .last_discontinuity
        .is_some_and(|at| sample.started_monotonic_ns < at)
    {
        return Err(EvidenceProblem::SampleBeforeDiscontinuity);
    }
    let Some(age) = clock
        .now
        .checked_duration_since(sample.started_monotonic_ns)
    else {
        return Err(EvidenceProblem::SampleFromFuture);
    };
    if age > max_age {
        return Err(EvidenceProblem::SampleTooOld { age, max_age });
    }
    Ok(age)
}

/// Decides whether an observation supports a decision.
pub(super) fn assess<'a, T: ObservationValue>(
    observation: &'a Observation<T>,
    metric: &MetricId,
    scope: ScopeCheck<'_>,
    clock: &EvaluationClock,
    max_age: Nanoseconds,
) -> Result<Usable<'a, T>, EvidenceProblem> {
    if observation.metric_id != *metric {
        return Err(EvidenceProblem::MetricMismatch);
    }
    let scope_matches: bool = match scope {
        ScopeCheck::Exact(expected) => observation.scope == *expected,
        ScopeCheck::Kind(expected) => observation.scope.kind == *expected,
    };
    if !scope_matches {
        return Err(EvidenceProblem::ScopeMismatch);
    }
    match &observation.reading {
        Reading::Available(_) => {}
        Reading::Unavailable(reason) => {
            return Err(EvidenceProblem::Unavailable {
                reason: reason.clone(),
            });
        }
        Reading::Unrecognized(_) => return Err(EvidenceProblem::Unrecognized),
    }
    let Some(value) = observation.value() else {
        return Err(EvidenceProblem::UnitMismatch);
    };
    if observation.coverage != Coverage::Complete {
        return Err(EvidenceProblem::CoverageIncomplete);
    }
    sample_age(&observation.sample, clock, max_age)?;
    Ok(Usable {
        value,
        sample: &observation.sample,
    })
}

/// The report of an observation and its assessment.
pub(super) fn report<T: ObservationValue + Display>(
    observation: &Observation<T>,
    clock: &EvaluationClock,
    problem: Option<EvidenceProblem>,
) -> EvidenceReport {
    let sample: &Sample = &observation.sample;
    let comparable: bool =
        sample.clock_domain == clock.clock_domain && sample.boot_id == clock.boot_id;
    let age: Option<Nanoseconds> = if comparable {
        clock
            .now
            .checked_duration_since(sample.started_monotonic_ns)
    } else {
        None
    };
    EvidenceReport {
        metric_id: observation.metric_id.clone(),
        scope: Some(observation.scope.clone()),
        value: if problem.is_none() {
            observation.value().map(ToString::to_string)
        } else {
            None
        },
        unit: Some(observation.unit.clone()),
        sample_id: Some(sample.sample_id.clone()),
        captured_at: Some(sample.captured_at),
        sampled_at: Some(sample.started_monotonic_ns),
        age,
        usable: problem.is_none(),
        problem,
    }
}

/// A system observation that corroborates the native pressure state.
///
/// The global memory trigger needs one or more of these that are available
/// and fresh. The value is not read: a large value is not a trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorroboratingEvidence {
    /// The metric of the observation.
    pub metric_id: MetricId,
    /// The scope of the observation.
    pub scope: Scope,
    /// True when the observation has a value in a unit of its value type.
    pub available: bool,
    /// How much of its scope the observation covers.
    pub coverage: Coverage,
    /// The acquisition of the observation.
    pub sample: Sample,
}

/// The host memory metrics that can corroborate the pressure state: the
/// page counts of the virtual memory statistics, the compressor, the swap
/// space and the swap and paging activity. `memory.pressure` is not in the
/// list: it does not corroborate itself. `memory.physical_bytes` is not in
/// the list: the installed memory does not change with the pressure. A metric
/// of another resource, such as CPU or disk, is not in the list.
///
/// This is the only list. Add a new host memory metric here.
pub const CORROBORATING_MEMORY_METRICS: &[MetricId] = &[
    metric::MEMORY_VM_FREE_PAGES,
    metric::MEMORY_VM_ACTIVE_PAGES,
    metric::MEMORY_VM_INACTIVE_PAGES,
    metric::MEMORY_VM_WIRED_PAGES,
    metric::MEMORY_VM_SPECULATIVE_PAGES,
    metric::MEMORY_VM_INTERNAL_PAGES,
    metric::MEMORY_VM_EXTERNAL_PAGES,
    metric::MEMORY_VM_PAGEINS_TOTAL,
    metric::MEMORY_VM_PAGEOUTS_TOTAL,
    metric::MEMORY_COMPRESSOR_PHYSICAL_PAGES,
    metric::MEMORY_COMPRESSOR_UNCOMPRESSED_PAGES,
    metric::MEMORY_COMPRESSOR_COMPRESSIONS_TOTAL,
    metric::MEMORY_COMPRESSOR_DECOMPRESSIONS_TOTAL,
    metric::MEMORY_SWAP_SWAPINS_TOTAL,
    metric::MEMORY_SWAP_SWAPOUTS_TOTAL,
    metric::MEMORY_SWAP_ALLOCATED_BYTES,
    metric::MEMORY_SWAP_USED_BYTES,
    metric::MEMORY_SWAP_AVAILABLE_BYTES,
];

impl CorroboratingEvidence {
    /// Takes the corroboration facts of an observation.
    pub fn from_observation<T: ObservationValue>(observation: &Observation<T>) -> Self {
        Self {
            metric_id: observation.metric_id.clone(),
            scope: observation.scope.clone(),
            available: observation.is_available(),
            coverage: observation.coverage.clone(),
            sample: observation.sample.clone(),
        }
    }

    /// True when the observation is an available, complete, fresh host
    /// observation of a metric in [`CORROBORATING_MEMORY_METRICS`]. The
    /// pressure state does not corroborate itself, and a metric of another
    /// resource does not corroborate memory pressure.
    pub(super) fn corroborates(&self, clock: &EvaluationClock, max_age: Nanoseconds) -> bool {
        self.available
            && self.coverage == Coverage::Complete
            && CORROBORATING_MEMORY_METRICS.contains(&self.metric_id)
            && self.scope.kind == ScopeKind::Host
            && sample_age(&self.sample, clock, max_age).is_ok()
    }
}
