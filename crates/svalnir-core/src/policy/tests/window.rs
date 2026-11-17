//! Qualification windows: start, continue, qualify, and reset.

use super::SECOND;
use crate::id::{BootId, ClockDomainId, CollectorEpochId, SampleId};
use crate::policy::{
    ContinuityGeneration, EvidenceProblem, QualificationWindow, QualifyingSample, ResetCause,
    WindowBinding, WindowEvidence, WindowStep, WindowTransition, advance,
};
use crate::quantity::Nanoseconds;
use crate::time::MonotonicNanos;

const REQUIRED: Nanoseconds = Nanoseconds::new(30 * SECOND);
const MAX_GAP: Nanoseconds = Nanoseconds::new(10 * SECOND);

fn binding() -> WindowBinding {
    WindowBinding {
        clock_domain: ClockDomainId::new("clock_main").unwrap(),
        boot_id: BootId::new("boot_1").unwrap(),
        collector_epoch: CollectorEpochId::new("epoch_1").unwrap(),
        continuity: ContinuityGeneration::new(0),
        subject: vec!["vol_data".to_owned(), "mount_1".to_owned()],
    }
}

fn holds_with(binding: WindowBinding, nanoseconds: u64) -> WindowEvidence {
    WindowEvidence::Holds(QualifyingSample {
        binding,
        at: MonotonicNanos::new(nanoseconds),
        sample_id: SampleId::new(format!("s_{nanoseconds}")).unwrap(),
    })
}

fn holds(nanoseconds: u64) -> WindowEvidence {
    holds_with(binding(), nanoseconds)
}

fn next(window: &QualificationWindow, evidence: WindowEvidence) -> WindowStep {
    advance(window, evidence, REQUIRED, MAX_GAP)
}

/// Applies qualifying samples at the given times and returns the last step.
fn run(times: &[u64]) -> WindowStep {
    let mut window: QualificationWindow = QualificationWindow::Idle;
    let mut last: Option<WindowStep> = None;
    for time in times {
        let step: WindowStep = next(&window, holds(*time));
        window = step.window.clone();
        last = Some(step);
    }
    last.unwrap()
}

#[test]
fn a_window_starts_continues_and_qualifies_at_the_exact_duration() {
    // (sample times in nanoseconds, transition, qualified, observed)
    let cases: [(&[u64], WindowTransition, bool, u64); 5] = [
        (&[0], WindowTransition::Started, false, 0),
        (
            &[0, 10 * SECOND],
            WindowTransition::Continued,
            false,
            10 * SECOND,
        ),
        (
            &[0, 10 * SECOND, 20 * SECOND, 30 * SECOND - 1],
            WindowTransition::Continued,
            false,
            30 * SECOND - 1,
        ),
        (
            &[0, 10 * SECOND, 20 * SECOND, 30 * SECOND],
            WindowTransition::Qualified,
            true,
            30 * SECOND,
        ),
        (
            &[0, 10 * SECOND, 20 * SECOND, 30 * SECOND, 40 * SECOND],
            WindowTransition::Qualified,
            true,
            40 * SECOND,
        ),
    ];
    for (times, transition, qualified, observed) in cases {
        let step: WindowStep = run(times);
        assert_eq!(step.report.transition, transition, "{times:?}");
        assert_eq!(step.report.qualified, qualified, "{times:?}");
        assert_eq!(step.report.observed_for, Nanoseconds::new(observed));
        assert_eq!(step.report.required, REQUIRED);
        assert_eq!(usize::try_from(step.report.instants).unwrap(), times.len());
    }
}

#[test]
fn a_repeated_read_of_one_sample_does_not_advance_the_window() {
    let started: WindowStep = run(&[0]);
    for _ in 0..10 {
        let step: WindowStep = next(&started.window, holds(0));
        assert_eq!(step.report.transition, WindowTransition::Unchanged);
        assert_eq!(step.window, started.window);
        assert!(!step.report.qualified);
        assert_eq!(step.report.instants, 1);
    }
    // A different sample identity at the same instant is the same instant.
    let same_instant: WindowEvidence = WindowEvidence::Holds(QualifyingSample {
        binding: binding(),
        at: MonotonicNanos::new(0),
        sample_id: SampleId::new("s_other").unwrap(),
    });
    let step: WindowStep = next(&started.window, same_instant);
    assert_eq!(step.report.transition, WindowTransition::Unchanged);
    assert_eq!(step.report.instants, 1);
}

#[test]
fn a_gap_restarts_the_window_and_does_not_count_as_time() {
    // A gap that is equal to the limit continues the window.
    let at_limit: WindowStep = run(&[0, 10 * SECOND]);
    assert_eq!(at_limit.report.transition, WindowTransition::Continued);

    let after_gap: WindowStep = next(&at_limit.window, holds(20 * SECOND + 1));
    assert_eq!(
        after_gap.report.transition,
        WindowTransition::Restarted(ResetCause::Gap)
    );
    assert_eq!(after_gap.report.observed_for, Nanoseconds::ZERO);
    assert_eq!(after_gap.report.instants, 1);

    // The time before the gap is lost: the window qualifies 30 seconds
    // after the restart, not 30 seconds after the first sample.
    let mut window: QualificationWindow = after_gap.window;
    for seconds in [30, 40] {
        let step: WindowStep = next(&window, holds(seconds * SECOND + 1));
        assert!(!step.report.qualified, "at {seconds} s");
        window = step.window;
    }
    assert!(!next(&window, holds(50 * SECOND)).report.qualified);
    assert!(next(&window, holds(50 * SECOND + 1)).report.qualified);
}

#[test]
fn a_contradiction_or_an_unusable_sample_resets_the_window() {
    let open: WindowStep = run(&[0, 10 * SECOND, 20 * SECOND]);
    let problem: EvidenceProblem = EvidenceProblem::SampleTooOld {
        age: Nanoseconds::new(15 * SECOND),
        max_age: Nanoseconds::new(10 * SECOND),
    };
    let cases: [(WindowEvidence, ResetCause); 3] = [
        (WindowEvidence::Contradicts, ResetCause::Contradicted),
        (
            WindowEvidence::Unusable(EvidenceProblem::Missing),
            ResetCause::EvidenceUnusable {
                problem: EvidenceProblem::Missing,
            },
        ),
        (
            WindowEvidence::Unusable(problem.clone()),
            ResetCause::EvidenceUnusable { problem },
        ),
    ];
    for (evidence, cause) in cases {
        let step: WindowStep = next(&open.window, evidence.clone());
        assert_eq!(step.report.transition, WindowTransition::Reset(cause));
        assert_eq!(step.window, QualificationWindow::Idle);
        assert!(!step.report.qualified);

        // An idle window stays idle.
        let idle: WindowStep = next(&QualificationWindow::Idle, evidence);
        assert_eq!(idle.report.transition, WindowTransition::Idle);
        assert_eq!(idle.window, QualificationWindow::Idle);
    }

    // The window needs the full duration again after the reset.
    let restarted: WindowStep = next(&QualificationWindow::Idle, holds(25 * SECOND));
    assert_eq!(restarted.report.transition, WindowTransition::Started);
    assert!(!next(&restarted.window, holds(30 * SECOND)).report.qualified);
}

#[test]
fn a_changed_identity_or_clock_restarts_the_window() {
    let open: WindowStep = run(&[0, 10 * SECOND, 20 * SECOND]);
    let mut other_domain: WindowBinding = binding();
    other_domain.clock_domain = ClockDomainId::new("clock_other").unwrap();
    let mut other_boot: WindowBinding = binding();
    other_boot.boot_id = BootId::new("boot_2").unwrap();
    let mut after_wake: WindowBinding = binding();
    after_wake.continuity = ContinuityGeneration::new(1);
    let mut other_epoch: WindowBinding = binding();
    other_epoch.collector_epoch = CollectorEpochId::new("epoch_2").unwrap();
    let mut remounted: WindowBinding = binding();
    remounted.subject = vec!["vol_data".to_owned(), "mount_2".to_owned()];

    let cases: [(WindowBinding, ResetCause); 5] = [
        (other_domain, ResetCause::ClockDiscontinuity),
        (other_boot, ResetCause::ClockDiscontinuity),
        (after_wake, ResetCause::ClockDiscontinuity),
        (other_epoch, ResetCause::CollectorRestarted),
        (remounted, ResetCause::IdentityChanged),
    ];
    for (changed, cause) in cases {
        // The sample would qualify the window if the binding were the same.
        let step: WindowStep = next(&open.window, holds_with(changed, 30 * SECOND));
        assert_eq!(step.report.transition, WindowTransition::Restarted(cause));
        assert!(!step.report.qualified);
        assert_eq!(step.report.instants, 1);
    }
    assert!(next(&open.window, holds(30 * SECOND)).report.qualified);
}

#[test]
fn a_sample_that_is_earlier_than_the_window_restarts_it() {
    let open: WindowStep = run(&[0, 10 * SECOND, 20 * SECOND]);
    let step: WindowStep = next(&open.window, holds(15 * SECOND));
    assert_eq!(
        step.report.transition,
        WindowTransition::Restarted(ResetCause::TimeWentBackwards)
    );
    assert_eq!(step.report.instants, 1);
}

#[test]
fn one_instant_never_qualifies_even_for_a_short_duration() {
    let step: WindowStep = advance(
        &QualificationWindow::Idle,
        holds(0),
        Nanoseconds::new(1),
        MAX_GAP,
    );
    assert!(!step.report.qualified);
    let second: WindowStep = advance(&step.window, holds(1), Nanoseconds::new(1), MAX_GAP);
    assert!(second.report.qualified);
}
