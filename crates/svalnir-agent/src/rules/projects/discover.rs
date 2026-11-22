//! The discovery of `project.dependency-directory` for a manual eviction
//! (`docs/CLEANUP_RULES.md` section 12, "Manual eviction").
//!
//! The discovery runs the walk and each check of the inspection on the
//! roots of one request, with no measurement. For each unit that passes
//! the checks, it measures the unit with the measurement of the other
//! rules ([`crate::rules::unit`]), which also refuses a unit with a Git
//! repository at some depth, a hard-linked file, or an entry on another
//! device, and it establishes the age and the project activity
//! (predicate 5). Each root of the request is an approved root: it is
//! bound to its object, its volume, and its mount generation, as
//! [`crate::rules::bind_root`] binds a root of a declaration.
//!
//! The discovery is for the manual mode only. The discovery for an
//! eviction never examines the rule for an automatic operation.

use std::path::PathBuf;

use svalnir_core::config::UserLayout;
use svalnir_core::policy::ActivityFact;
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{Fact, RuleMode};
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::ProjectRule;
use super::activity::{BuildProcesses, ProcessEvidence};
use super::inspect::{
    ProjectHost, ProjectLimits, ProjectUnitOutcome, ProjectUnitReport, SearchRootOutcome,
    SearchRootReport, SearchRoots,
};
use super::recency::{ProjectRecency, RecencyHost, RecencyState};
use crate::platform::process::PathInventory;
use crate::platform::volume::{MountTable, MountTableSource};
use crate::rules::eviction::{
    BoundRoot, DiscoveryEnvironment, DiscoveryHost, RootResult, bind_root, refusal_name,
};
use crate::rules::git::{GitTool, GitToolProblem};
use crate::rules::in_use::UnitScope;
use crate::rules::model::{
    DiscoveredCandidate, DiscoveryCompletion, DiscoveryControl, DiscoveryError, DiscoveryLimits,
    DiscoveryScope, SkipReason,
};
use crate::rules::unit::{
    Assessment, Collector, ObjectKind, ObjectSnapshot, RootView, UnitUnderMeasurement,
    elapsed_between, establish_charge, lstat, target_evidence,
};
use crate::scan::CancellationToken;

/// The request of the discovery of `project.dependency-directory` for a
/// manual eviction.
#[derive(Clone, Copy)]
#[expect(
    missing_debug_implementations,
    reason = "the sources of the project activity are trait objects with no `Debug` bound"
)]
pub struct ProjectRequest<'a> {
    /// The roots of the request: the search roots and the project roots.
    pub roots: &'a SearchRoots,
    /// The Git executable, or why none was accepted.
    pub git: Result<&'a GitTool, GitToolProblem>,
    /// The sources and the quiet period of the project activity.
    pub recency: RecencyHost<'a>,
    /// The layouts of `[[cleanup.projects.layouts]]`.
    pub layouts: &'a [UserLayout],
    /// True when a project with the state `active` can give a candidate.
    /// A `busy` project never gives one.
    pub include_active: bool,
    /// The bounds of the walk.
    pub limits: ProjectLimits,
}

/// What the discovery found at one root of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::rules) struct ProjectRootResult {
    /// The path of the root, when it is known.
    pub(in crate::rules) path: Option<PathBuf>,
    /// The binding of the root, when the root was bound.
    pub(in crate::rules) bound: Option<BoundRoot>,
    /// The result for the report of the discovery.
    pub(in crate::rules) result: RootResult,
    /// The candidates of the root.
    pub(in crate::rules) candidates: Vec<DiscoveredCandidate>,
}

/// The process evidence of the inspection from the environment of a
/// discovery, so that a test gives the evidence of a fixture.
#[expect(
    missing_debug_implementations,
    reason = "the environment is a trait object with no `Debug` bound"
)]
pub struct EnvironmentEvidence<'a>(pub &'a dyn DiscoveryEnvironment);

impl ProcessEvidence for EnvironmentEvidence<'_> {
    fn build_processes(&self, principal: Uid) -> BuildProcesses {
        self.0.build_processes(principal)
    }

    fn monotonic_now(&self) -> Option<MonotonicNanos> {
        self.0.now().monotonic_ns
    }

    fn path_uses(&self, principal: Uid, scopes: &[UnitScope]) -> PathInventory {
        self.0.path_uses(principal, scopes)
    }
}

/// The skip reason of a stable reason of the inspection, and the predicate
/// that the reason does not satisfy.
fn skip_of(reason: &str) -> (SkipReason, Predicate, Fact) {
    use Predicate::{Activity, Exclusion, Identity, Layout, Protocols, Regenerable};
    match reason {
        "unit_protected" | "unit_excluded" => {
            (SkipReason::ExclusionOverlap, Exclusion, Fact::NotSatisfied)
        }
        "unit_protection_unknown" => (SkipReason::ExclusionOverlap, Exclusion, Fact::Unknown),
        "protected_child" => (SkipReason::ProtectedData, Exclusion, Fact::NotSatisfied),
        "protected_child_unknown" => (SkipReason::ProtectedData, Exclusion, Fact::Unknown),
        "project_marker_missing" | "unsupported_layout" => {
            (SkipReason::UnsupportedLayout, Layout, Fact::NotSatisfied)
        }
        "overlaps_unit" => (SkipReason::SharedOwnership, Identity, Fact::NotSatisfied),
        "unit_owner" => (SkipReason::WrongOwner, Identity, Fact::NotSatisfied),
        "unit_absent" => (SkipReason::Vanished, Identity, Fact::NotSatisfied),
        "unit_path_not_plain" | "unit_symbolic_link" => {
            (SkipReason::SymbolicLink, Protocols, Fact::NotSatisfied)
        }
        "unit_not_directory" => (SkipReason::UnsupportedObject, Protocols, Fact::NotSatisfied),
        "unit_device" => (SkipReason::MountCrossing, Protocols, Fact::NotSatisfied),
        "not_ignored" | "tracked_files" => {
            (SkipReason::NotRegenerable, Regenerable, Fact::NotSatisfied)
        }
        "no_repository" | "version_control_unknown" => (
            SkipReason::RegenerabilityUnknown,
            Regenerable,
            Fact::Unknown,
        ),
        "project_busy" | "producer_active" => {
            (SkipReason::ActiveProducer, Activity, Fact::NotSatisfied)
        }
        "activity_unknown" => (SkipReason::ActivityUnknown, Activity, Fact::Unknown),
        "unit_in_use" => (SkipReason::UnitInUse, Protocols, Fact::NotSatisfied),
        "unit_use_unknown" => (SkipReason::UnitUseUnknown, Protocols, Fact::Unknown),
        "project_not_readable" | "unit_not_readable" => {
            (SkipReason::AccessDenied, Identity, Fact::Unknown)
        }
        _ => (SkipReason::MeasurementIncomplete, Identity, Fact::Unknown),
    }
}

/// A predicate of `docs/CLEANUP_RULES.md` section 6 that a refusal of the
/// inspection does not satisfy.
#[derive(Debug, Clone, Copy)]
enum Predicate {
    Layout,
    Identity,
    Regenerable,
    Activity,
    Protocols,
    Exclusion,
}

/// The completion of a discovery for the end of the walk of a root.
const fn completion_of(outcome: &SearchRootOutcome) -> DiscoveryCompletion {
    use super::inspect::SearchCompletion;
    match outcome {
        // The depth bound is a bound of the search of the rule, and the
        // report of the root names it; the units that the walk found are
        // complete.
        SearchRootOutcome::Examined(
            SearchCompletion::Complete | SearchCompletion::DepthLimitReached,
        )
        | SearchRootOutcome::Absent
        | SearchRootOutcome::Refused(_)
        | SearchRootOutcome::Covered(_) => DiscoveryCompletion::Finished,
        SearchRootOutcome::Examined(
            SearchCompletion::DirectoryLimitReached | SearchCompletion::UnitLimitReached,
        ) => DiscoveryCompletion::UnitLimitReached,
        SearchRootOutcome::Examined(SearchCompletion::DeadlineReached) => {
            DiscoveryCompletion::TimeLimitReached
        }
        SearchRootOutcome::Examined(SearchCompletion::Cancelled) => DiscoveryCompletion::Cancelled,
    }
}

/// The inputs of the discovery of the roots of one request.
pub(in crate::rules) struct ProjectDiscoveryInput<'a> {
    pub(in crate::rules) host: &'a DiscoveryHost,
    pub(in crate::rules) request: &'a ProjectRequest<'a>,
    pub(in crate::rules) protected: &'a [PathBuf],
    pub(in crate::rules) limits: DiscoveryLimits,
    pub(in crate::rules) cancel: &'a CancellationToken,
    pub(in crate::rules) environment: &'a dyn DiscoveryEnvironment,
    pub(in crate::rules) mounts: MountTableSource,
}

impl ProjectRule {
    /// The discovery of each root of `input.request` for a manual eviction:
    /// the reports of the roots, and the result of each root.
    pub(in crate::rules) fn discover_roots(
        &self,
        input: &ProjectDiscoveryInput<'_>,
    ) -> (Vec<SearchRootReport>, Vec<ProjectRootResult>) {
        let request: &ProjectRequest<'_> = input.request;
        let evidence: EnvironmentEvidence<'_> = EnvironmentEvidence(input.environment);
        let host: ProjectHost<'_> = ProjectHost {
            principal: input.host.principal,
            locations: &input.host.locations,
            user_exclusions: &input.host.user_exclusions,
            git: request.git,
            processes: &evidence,
            recency: request.recency,
            layouts: request.layouts,
        };
        let inspection = self.examine(
            host,
            request.roots,
            request.limits,
            input.cancel,
            input.environment,
            input.mounts,
            false,
        );
        let mounts: Option<MountTable> = (input.mounts)().ok();
        // A root that the request left out has no result: another root of
        // the request examines its units.
        let results: Vec<ProjectRootResult> = inspection
            .roots
            .iter()
            .filter(|report| !matches!(report.outcome, SearchRootOutcome::Covered(_)))
            .map(|report| {
                let units: Vec<&ProjectUnitReport> = inspection
                    .units
                    .iter()
                    .filter(|unit| Some(&unit.search_root) == report.path.as_ref())
                    .collect();
                self.discover_root(input, report, &units, mounts.as_ref())
            })
            .collect();
        (inspection.roots, results)
    }

    /// The result of one root of the request.
    fn discover_root(
        &self,
        input: &ProjectDiscoveryInput<'_>,
        report: &SearchRootReport,
        units: &[&ProjectUnitReport],
        mounts: Option<&MountTable>,
    ) -> ProjectRootResult {
        let mut result: ProjectRootResult = ProjectRootResult {
            path: report.path.clone(),
            bound: None,
            result: RootResult::Refused("root_not_examined"),
            candidates: Vec::new(),
        };
        let path: PathBuf = match (&report.outcome, &report.path) {
            (SearchRootOutcome::Examined(_), Some(path)) => path.clone(),
            (SearchRootOutcome::Absent, _) => {
                result.result = RootResult::NotBound(super::super::RootProblem::Absent);
                return result;
            }
            (SearchRootOutcome::Refused(reason), _) => {
                result.result = RootResult::Refused(reason);
                return result;
            }
            (SearchRootOutcome::Examined(_), None) | (SearchRootOutcome::Covered(_), _) => {
                return result;
            }
        };
        let bound: BoundRoot = match bind_root(&path) {
            Ok(bound) => bound,
            Err(problem) => {
                result.result = RootResult::NotBound(problem);
                return result;
            }
        };
        let Some(mounts) = mounts else {
            result.result = RootResult::Refused("root_locality_unknown");
            return result;
        };
        match self.measure_units(input, &bound, mounts, &report.outcome, units) {
            Ok((root_result, candidates)) => {
                result.result = root_result;
                result.candidates = candidates;
                result.bound = Some(bound);
            }
            Err(error) => result.result = RootResult::Refused(refusal_name(&error)),
        }
        result
    }

    /// The assessment of each unit of one bound root.
    fn measure_units(
        &self,
        input: &ProjectDiscoveryInput<'_>,
        bound: &BoundRoot,
        mounts: &MountTable,
        outcome: &SearchRootOutcome,
        units: &[&ProjectUnitReport],
    ) -> Result<(RootResult, Vec<DiscoveredCandidate>), DiscoveryError> {
        let scope: DiscoveryScope<'_> = DiscoveryScope {
            root: &bound.binding,
            principal: input.host.principal,
            protected_paths: input.protected,
            user_exclusions: &input.host.user_exclusions,
        };
        let control: DiscoveryControl<'_> = DiscoveryControl {
            limits: input.limits,
            cancel: input.cancel,
            clock: input.environment,
        };
        let root: RootView = RootView::open(&scope, mounts)?;
        let mut collector: Collector<'_> = Collector::new(&control)?;
        let mut completion: DiscoveryCompletion = completion_of(outcome);
        for unit in units {
            if let Err(stopped) = collector.bounds.take_unit() {
                completion = stopped;
                break;
            }
            if !collector.has_candidate_room() {
                completion = DiscoveryCompletion::CandidateLimitReached;
                break;
            }
            let (assessment, stopped) = self.assess(input, &root, unit, &mut collector)?;
            if let Some(stopped) = stopped {
                completion = stopped;
                break;
            }
            collector.add(self.rule(), &root, assessment)?;
        }
        let discovery = collector.finish(self.rule(), &root, completion)?;
        let candidates: Vec<DiscoveredCandidate> = discovery.candidates;
        Ok((
            RootResult::Examined {
                completion: discovery.completion,
                skipped: discovery.skipped,
                skipped_omitted: discovery.skipped_omitted,
            },
            candidates,
        ))
    }

    /// The assessment of one unit, and the bound that stopped its
    /// measurement, if one did.
    fn assess(
        &self,
        input: &ProjectDiscoveryInput<'_>,
        root: &RootView,
        unit: &ProjectUnitReport,
        collector: &mut Collector<'_>,
    ) -> Result<(Assessment, Option<DiscoveryCompletion>), DiscoveryError> {
        let relative: PathBuf = unit
            .path
            .strip_prefix(&root.path)
            .map_err(|_| DiscoveryError::Internal("the unit is not below its root"))?
            .to_path_buf();
        let mut assessment: Assessment = Assessment::new(relative);
        assessment.layout = Some(unit.layout);
        match &unit.outcome {
            ProjectUnitOutcome::Checked => {}
            ProjectUnitOutcome::Refused { reason } => {
                refuse(&mut assessment, reason);
                return Ok((assessment, None));
            }
            // The discovery of the inspection does not measure: these
            // outcomes do not occur. A unit with one is not a candidate.
            ProjectUnitOutcome::Measured(_) | ProjectUnitOutcome::RepositoryRefused(_) => {
                refuse(&mut assessment, "measurement_incomplete");
                return Ok((assessment, None));
            }
        }
        // Predicate 1: the checks of the inspection found the layout, its
        // markers, and no protected child.
        assessment.eligibility.rule_supports_layout = Fact::Satisfied;
        // Predicate 4: Git ignores the unit, and the index has no path in it.
        assessment.eligibility.regenerable = Fact::Satisfied;
        let before: ObjectSnapshot = match lstat(&unit.path) {
            Ok(snapshot) if snapshot.kind == ObjectKind::Directory => snapshot,
            Ok(_) => {
                refuse(&mut assessment, "unit_not_directory");
                return Ok((assessment, None));
            }
            Err(_) => {
                refuse(&mut assessment, "unit_absent");
                return Ok((assessment, None));
            }
        };
        assessment.evidence = target_evidence(&assessment.relative, &before);
        // Predicate 2: the unit has the user as owner and is on the device of
        // the root.
        if before.owner != input.host.principal || before.object.device != root.device() {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::WrongOwner);
            return Ok((assessment, None));
        }
        assessment.eligibility.identity_matches = Fact::Satisfied;
        // Predicate 7: the hard exclusions and the user exclusions.
        if root.is_excluded(&assessment.relative) {
            assessment.eligibility.no_exclusion_overlap = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::ExclusionOverlap);
            return Ok((assessment, None));
        }
        assessment.eligibility.no_exclusion_overlap = Fact::Satisfied;
        // Predicate 8: the complete unit and its charge. The measurement
        // refuses a Git repository at each depth, with no exception for
        // the checkouts of Swift Package Manager: the filesystem executor
        // of an eviction refuses each repository.
        let stopped: Option<DiscoveryCompletion> = establish_charge(
            &mut assessment,
            None,
            &UnitUnderMeasurement {
                path: &unit.path,
                before: &before,
                principal: input.host.principal,
            },
            self.rule(),
            &mut collector.bounds,
            &mut |_, _| None,
        )?;
        if stopped.is_some() {
            return Ok((assessment, stopped));
        }
        if !assessment.reasons.is_empty() {
            return Ok((assessment, None));
        }
        self.assess_age(
            &mut assessment,
            &before,
            unit.recency.as_ref(),
            input.request.include_active,
            collector.observed_at(),
        );
        if lstat(&unit.path).ok().as_ref() != Some(&before) {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::IdentityChanged);
        }
        Ok((assessment, None))
    }

    /// Establishes the age, the project activity, and the protocols of a
    /// measured unit (predicates 5 and 6).
    ///
    /// The age is the time since the newest modification or status change
    /// of the unit and of each object below it, and it must be at least the
    /// minimum age and the quiescence of the declaration. The project must
    /// be `quiet`; with `include_active`, an `active` project is also
    /// accepted. The inspection refused each `busy` project and each unit
    /// with a build process or a use.
    fn assess_age(
        &self,
        assessment: &mut Assessment,
        before: &ObjectSnapshot,
        recency: Option<&ProjectRecency>,
        include_active: bool,
        now: Option<WallTime>,
    ) {
        let rule = self.rule();
        let required: Nanoseconds = rule.retention.minimum_age.max(rule.activity.quiescence);
        // The modification and the status change of the unit itself, and
        // the newest change of an object below it. A time that is not known
        // leaves the age unknown.
        let changed: Option<WallTime> = u32::try_from(before.stamp.changed_nanoseconds)
            .ok()
            .and_then(|nanoseconds| {
                WallTime::from_unix(before.stamp.changed_seconds, nanoseconds).ok()
            });
        let newest: Option<WallTime> = before.modified().zip(changed).map(|(modified, changed)| {
            let own: WallTime = modified.max(changed);
            assessment
                .newest_content_change
                .map_or(own, |content| content.max(own))
        });
        let mut inactive_for: Option<Nanoseconds> = None;
        let age: Fact = match (newest, now) {
            (Some(newest), Some(now)) if newest > now => {
                assessment.reasons.insert(SkipReason::FutureTimestamp);
                Fact::Unknown
            }
            (Some(newest), Some(now)) => {
                inactive_for = elapsed_between(newest, now);
                if inactive_for.is_some_and(|elapsed| elapsed >= required) {
                    Fact::Satisfied
                } else {
                    assessment.reasons.insert(SkipReason::RetentionNotElapsed);
                    Fact::NotSatisfied
                }
            }
            _ => {
                assessment.reasons.insert(SkipReason::AgeUnknown);
                Fact::Unknown
            }
        };
        let project: Fact = match recency.map(|recency| (recency.state, recency.fact())) {
            Some((RecencyState::Quiet, _)) => Fact::Satisfied,
            Some((RecencyState::Active, _)) if include_active => Fact::Satisfied,
            Some((RecencyState::Active, Fact::NotSatisfied)) => {
                assessment.reasons.insert(SkipReason::RetentionNotElapsed);
                Fact::NotSatisfied
            }
            Some((RecencyState::Busy, _)) => {
                assessment.reasons.insert(SkipReason::ActiveProducer);
                Fact::NotSatisfied
            }
            Some((RecencyState::Active, _)) | None => {
                assessment.reasons.insert(SkipReason::ActivityUnknown);
                Fact::Unknown
            }
        };
        assessment.eligibility.age_and_inactivity = match (age, project) {
            (Fact::Satisfied, Fact::Satisfied) => Fact::Satisfied,
            (Fact::NotSatisfied, _) | (_, Fact::NotSatisfied) => Fact::NotSatisfied,
            _ => Fact::Unknown,
        };
        assessment.activity = match (&assessment.eligibility.age_and_inactivity, inactive_for) {
            (Fact::Satisfied, Some(inactive_for)) => ActivityFact::Inactive { inactive_for },
            _ => ActivityFact::Unknown,
        };
        // The producer evidence and the use check of the inspection gave a
        // result for the unit; the discovery for an eviction makes the use
        // check again with one inventory for each discovery.
        assessment.eligibility.protocols_valid = Fact::Satisfied;
    }
}

/// Records the refusal `reason` of the inspection in `assessment`.
fn refuse(assessment: &mut Assessment, reason: &str) {
    let (skip, predicate, fact) = skip_of(reason);
    let eligibility = &mut assessment.eligibility;
    let slot: &mut Fact = match predicate {
        Predicate::Layout => &mut eligibility.rule_supports_layout,
        Predicate::Identity => &mut eligibility.identity_matches,
        Predicate::Regenerable => &mut eligibility.regenerable,
        Predicate::Activity => &mut eligibility.age_and_inactivity,
        Predicate::Protocols => &mut eligibility.protocols_valid,
        Predicate::Exclusion => &mut eligibility.no_exclusion_overlap,
    };
    *slot = fact;
    assessment.reasons.insert(skip);
}

/// Whether the rule `project.dependency-directory` is examined for
/// `purpose`: for a manual eviction only, never for an automatic one.
#[must_use]
pub fn examined_for(purpose: &RuleMode) -> bool {
    *purpose == RuleMode::ManualEviction
}
