//! Qualification windows.
//!
//! `docs/POLICY_SPEC.md` section 6 owns the contract. A window is explicit
//! state: the caller keeps it and passes it back. [`advance`] is a pure
//! function of the window, one piece of evidence, and the two durations.
//!
//! A window counts only the time between distinct observation instants that
//! satisfy the predicate. A gap, a sample that is not usable, a clock
//! discontinuity, or a changed identity resets the window. None of them
//! counts as time above or below a threshold.

use serde::{Deserialize, Serialize};

use super::evidence::EvidenceProblem;
use crate::id::{BootId, ClockDomainId, CollectorEpochId, SampleId};
use crate::quantity::Nanoseconds;
use crate::time::MonotonicNanos;

/// A counter of clock continuity that the caller keeps.
///
/// The caller increases the value after sleep, wake, or any other clock or
/// counter discontinuity. A window does not continue across two different
/// values.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ContinuityGeneration(u64);

impl ContinuityGeneration {
    /// Makes the value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The integer value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The identities that must stay the same during one window.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WindowBinding {
    /// The clock domain of the timestamps.
    pub clock_domain: ClockDomainId,
    /// The boot of the host.
    pub boot_id: BootId,
    /// The collector lifetime. A collector restart makes a new epoch.
    pub collector_epoch: CollectorEpochId,
    /// The clock continuity that the caller reports.
    pub continuity: ContinuityGeneration,
    /// The identity of the measured subject, for example a volume and its
    /// mount generation, or an application instance, its membership
    /// snapshot, and its process generations.
    pub subject: Vec<String>,
}

/// The state of one qualification window.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum QualificationWindow {
    /// No qualifying evidence is held.
    #[default]
    Idle,
    /// Qualifying evidence is held.
    Open(OpenWindow),
}

/// The evidence of an open window.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenWindow {
    /// The identities of the window.
    pub binding: WindowBinding,
    /// The instant of the first qualifying observation.
    pub first_at: MonotonicNanos,
    /// The instant of the latest qualifying observation.
    pub last_at: MonotonicNanos,
    /// The identity of the latest qualifying observation.
    pub last_sample: SampleId,
    /// The number of distinct observation instants.
    pub instants: u32,
}

impl OpenWindow {
    /// The time from the first to the latest qualifying observation.
    fn span(&self) -> Nanoseconds {
        self.last_at
            .checked_duration_since(self.first_at)
            .unwrap_or(Nanoseconds::ZERO)
    }
}

/// One qualifying observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifyingSample {
    /// The identities that the observation belongs to.
    pub binding: WindowBinding,
    /// The start of the acquisition.
    pub at: MonotonicNanos,
    /// The identity of the acquisition.
    pub sample_id: SampleId,
}

/// What the current observation says about the predicate of a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowEvidence {
    /// The observation is usable and the predicate is true.
    Holds(QualifyingSample),
    /// The observation is usable and the predicate is false.
    Contradicts,
    /// The observation is not usable.
    Unusable(EvidenceProblem),
}

/// The cause of a window reset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResetCause {
    /// A usable observation contradicts the predicate.
    Contradicted,
    /// The observation is not usable.
    EvidenceUnusable {
        /// The problem of the observation.
        problem: EvidenceProblem,
    },
    /// The time between two observations is larger than
    /// `max_qualifying_sample_gap`.
    Gap,
    /// The identity of the subject changed.
    IdentityChanged,
    /// The clock domain, the boot, or the clock continuity changed.
    ClockDiscontinuity,
    /// The collector started again.
    CollectorRestarted,
    /// The observation is earlier than the latest observation of the window.
    TimeWentBackwards,
}

/// What [`advance`] did to a window.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "transition", rename_all = "snake_case")]
#[non_exhaustive]
pub enum WindowTransition {
    /// The window was idle and stays idle.
    Idle,
    /// The window started at this observation.
    Started,
    /// The window got a new observation instant and is not qualified.
    Continued,
    /// The observation is the one that the window already has. A repeated
    /// read of one sample does not advance the window.
    Unchanged,
    /// The window spans the required duration.
    Qualified,
    /// The window was reset and is idle.
    Reset(ResetCause),
    /// The window was reset and started again at this observation.
    Restarted(ResetCause),
}

/// The result of [`advance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowStep {
    /// The state that the caller keeps for the next evaluation.
    pub window: QualificationWindow,
    /// A description of the step for a report.
    pub report: WindowReport,
}

/// A description of a window after a step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct WindowReport {
    /// What the step did.
    #[serde(flatten)]
    pub transition: WindowTransition,
    /// True when the window has two or more distinct instants that span the
    /// required duration.
    pub qualified: bool,
    /// The time from the first to the latest qualifying observation.
    pub observed_for: Nanoseconds,
    /// The required duration.
    pub required: Nanoseconds,
    /// The number of distinct observation instants.
    pub instants: u32,
}

fn step(
    window: QualificationWindow,
    transition: WindowTransition,
    required: Nanoseconds,
) -> WindowStep {
    let (observed_for, instants): (Nanoseconds, u32) = match &window {
        QualificationWindow::Idle => (Nanoseconds::ZERO, 0),
        QualificationWindow::Open(open) => (open.span(), open.instants),
    };
    let qualified: bool = instants >= 2 && observed_for >= required;
    let transition: WindowTransition = match transition {
        WindowTransition::Continued if qualified => WindowTransition::Qualified,
        other => other,
    };
    WindowStep {
        window,
        report: WindowReport {
            transition,
            qualified,
            observed_for,
            required,
            instants,
        },
    }
}

fn open_at(sample: QualifyingSample) -> QualificationWindow {
    QualificationWindow::Open(OpenWindow {
        binding: sample.binding,
        first_at: sample.at,
        last_at: sample.at,
        last_sample: sample.sample_id,
        instants: 1,
    })
}

/// The cause when the binding of an observation differs from that of the
/// window.
fn binding_change(window: &WindowBinding, sample: &WindowBinding) -> Option<ResetCause> {
    if window.clock_domain != sample.clock_domain
        || window.boot_id != sample.boot_id
        || window.continuity != sample.continuity
    {
        Some(ResetCause::ClockDiscontinuity)
    } else if window.collector_epoch != sample.collector_epoch {
        Some(ResetCause::CollectorRestarted)
    } else if window.subject != sample.subject {
        Some(ResetCause::IdentityChanged)
    } else {
        None
    }
}

/// Applies one piece of evidence to a window.
///
/// `required` is the duration that the window must span. `max_gap` is the
/// largest time between two successive observations of one window. The
/// window qualifies when it has two or more distinct observation instants
/// and they span `required` or more.
///
/// The function is pure: equal arguments give an equal result.
pub fn advance(
    prior: &QualificationWindow,
    evidence: WindowEvidence,
    required: Nanoseconds,
    max_gap: Nanoseconds,
) -> WindowStep {
    let sample: QualifyingSample = match evidence {
        WindowEvidence::Holds(sample) => sample,
        WindowEvidence::Contradicts => {
            return reset(prior, ResetCause::Contradicted, required);
        }
        WindowEvidence::Unusable(problem) => {
            return reset(prior, ResetCause::EvidenceUnusable { problem }, required);
        }
    };
    let QualificationWindow::Open(open) = prior else {
        return step(open_at(sample), WindowTransition::Started, required);
    };
    if let Some(cause) = binding_change(&open.binding, &sample.binding) {
        return step(
            open_at(sample),
            WindowTransition::Restarted(cause),
            required,
        );
    }
    if sample.sample_id == open.last_sample || sample.at == open.last_at {
        return step(prior.clone(), WindowTransition::Unchanged, required);
    }
    let Some(gap) = sample.at.checked_duration_since(open.last_at) else {
        let cause: ResetCause = ResetCause::TimeWentBackwards;
        return step(
            open_at(sample),
            WindowTransition::Restarted(cause),
            required,
        );
    };
    if gap > max_gap {
        let cause: ResetCause = ResetCause::Gap;
        return step(
            open_at(sample),
            WindowTransition::Restarted(cause),
            required,
        );
    }
    let continued: QualificationWindow = QualificationWindow::Open(OpenWindow {
        binding: open.binding.clone(),
        first_at: open.first_at,
        last_at: sample.at,
        last_sample: sample.sample_id,
        instants: open.instants.saturating_add(1),
    });
    step(continued, WindowTransition::Continued, required)
}

fn reset(prior: &QualificationWindow, cause: ResetCause, required: Nanoseconds) -> WindowStep {
    let transition: WindowTransition = match prior {
        QualificationWindow::Idle => WindowTransition::Idle,
        QualificationWindow::Open(_) => WindowTransition::Reset(cause),
    };
    step(QualificationWindow::Idle, transition, required)
}
