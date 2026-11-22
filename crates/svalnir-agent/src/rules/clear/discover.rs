//! The discovery of one bound root of a clear rule, and the check of a
//! unit before its step (`docs/CLEANUP_RULES.md` section 12, "Clear
//! rules").
//!
//! The discovery reads the mount table, the names of the root, and the
//! metadata of each unit, and it measures each directory unit with the
//! measurement of the other rules ([`crate::rules::unit`]), which refuses a
//! unit with a Git repository at some depth, a hard-linked file, or an
//! entry on another device. It changes nothing.

use std::io;
use std::path::{Path, PathBuf};

use svalnir_core::action::WorkCharge;
use svalnir_core::policy::ActivityFact;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::Fact;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::{ClearRule, ClearSpec, UnitForm};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::rules::model::{
    Discovery, DiscoveryCompletion, DiscoveryControl, DiscoveryError, DiscoveryScope,
    MeasurementSource, ReclaimEstimate, SizeMeasure, SkipReason, UnitMeasurement,
};
use crate::rules::projects::UnitRecheck;
use crate::rules::unit::{
    Assessment, Collector, ObjectKind, ObjectSnapshot, RootView, UnitUnderMeasurement,
    elapsed_between, establish_charge, list_root, lstat, reason_of, target_evidence,
};
use crate::rules::xcode::ProducerProcesses;
use crate::scan::{EntryKind, PrivateBytes, PrivateSizeUnavailable};

/// The process evidence of a clear rule: whether a process of its
/// producer runs, and the monotonic time of the inventory.
#[derive(Debug, Clone, Copy)]
pub(in crate::rules) struct ProducerEvidence {
    pub(in crate::rules) processes: ProducerProcesses,
    pub(in crate::rules) observed_at: Option<MonotonicNanos>,
}

impl ProducerEvidence {
    /// The evidence at `now`. [`ProducerProcesses::NotRunning`] is evidence
    /// of inactivity only for `expiry` after its observation.
    fn processes_at(self, now: Option<MonotonicNanos>, expiry: Nanoseconds) -> ProducerProcesses {
        if self.processes != ProducerProcesses::NotRunning {
            return self.processes;
        }
        let age: Option<Nanoseconds> = now
            .zip(self.observed_at)
            .and_then(|(now, observed)| now.checked_duration_since(observed));
        match age {
            Some(age) if age <= expiry => ProducerProcesses::NotRunning,
            _ => ProducerProcesses::Unknown,
        }
    }
}

/// The inputs of the discovery of one bound root.
pub(in crate::rules) struct ClearDiscoveryInput<'a> {
    pub(in crate::rules) scope: &'a DiscoveryScope<'a>,
    pub(in crate::rules) control: &'a DiscoveryControl<'a>,
    pub(in crate::rules) evidence: ProducerEvidence,
    pub(in crate::rules) mounts: MountTableSource,
}

impl ClearRule {
    /// Finds the units of the root of `input.scope`: each child of the root
    /// that the rule does not keep.
    ///
    /// # Errors
    ///
    /// Returns a [`DiscoveryError`] when a limit is too large, when the
    /// root fails a check (also when it is not on a local filesystem), or
    /// when the root changed during the discovery.
    pub(in crate::rules) fn discover(
        &self,
        input: &ClearDiscoveryInput<'_>,
    ) -> Result<Discovery, DiscoveryError> {
        let mut collector: Collector<'_> = Collector::new(input.control)?;
        let mounts: MountTable =
            (input.mounts)().map_err(|_| DiscoveryError::RootLocalityUnknown)?;
        let root: RootView = RootView::open(input.scope, &mounts)?;
        let mut completion: DiscoveryCompletion = DiscoveryCompletion::Finished;
        let names: Vec<PathBuf> = if self.spec.units == UnitForm::MavenArtifact {
            let limit: usize = usize::try_from(input.control.limits.max_units)
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let device: u64 = u64::try_from(root.device().get()).unwrap_or(u64::MAX);
            let (units, complete) = super::artifact_directories(&root.path, device, limit);
            if !complete {
                completion = DiscoveryCompletion::UnitLimitReached;
            }
            units
        } else {
            list_root(&root, &collector.bounds, None).map_err(DiscoveryError::RootUnavailable)?
        };
        for name in names {
            if !collector.has_candidate_room() {
                completion = DiscoveryCompletion::CandidateLimitReached;
                break;
            }
            if let Err(stopped) = collector.bounds.take_unit() {
                completion = stopped;
                break;
            }
            let (assessment, stopped) = self.assess(input, &root, name, &mut collector)?;
            if let Some(stopped) = stopped {
                completion = stopped;
                break;
            }
            collector.add(self.rule(), &root, assessment)?;
        }
        collector.finish(self.rule(), &root, completion)
    }

    /// The assessment of the child `name` of the root, and the bound that
    /// stopped its measurement, if one did.
    fn assess(
        &self,
        input: &ClearDiscoveryInput<'_>,
        root: &RootView,
        name: PathBuf,
        collector: &mut Collector<'_>,
    ) -> Result<(Assessment, Option<DiscoveryCompletion>), DiscoveryError> {
        let spec: &ClearSpec = self.spec;
        let path: PathBuf = root.path.join(&name);
        let mut assessment: Assessment = Assessment::new(name);
        assessment.layout = Some(spec.layout);
        let before: ObjectSnapshot = match lstat(&path) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let reason: SkipReason = reason_of(&error);
                if reason == SkipReason::Vanished {
                    assessment.eligibility.identity_matches = Fact::NotSatisfied;
                }
                assessment.reasons.insert(reason);
                return Ok((assessment, None));
            }
        };
        assessment.evidence = target_evidence(&assessment.relative, &before);
        // A kept child is data that the rule never removes.
        if is_kept(spec, &assessment.relative) {
            assessment.eligibility.no_exclusion_overlap = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::ProtectedData);
            return Ok((assessment, None));
        }
        // Predicate 1: the child has a form that the rule removes.
        if let Some(reason) = form_refusal(spec, &assessment.relative, &before) {
            if reason == SkipReason::UnsupportedLayout {
                assessment.eligibility.rule_supports_layout = Fact::NotSatisfied;
            } else {
                assessment.eligibility.protocols_valid = Fact::NotSatisfied;
            }
            assessment.reasons.insert(reason);
            return Ok((assessment, None));
        }
        assessment.eligibility.rule_supports_layout = Fact::Satisfied;
        // Predicate 2: the owner and the device of the root.
        if before.owner != input.scope.principal {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::WrongOwner);
            return Ok((assessment, None));
        }
        if before.object.device != root.device() {
            assessment.eligibility.protocols_valid = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::MountCrossing);
            return Ok((assessment, None));
        }
        assessment.eligibility.identity_matches = Fact::Satisfied;
        // Predicate 4: the producer downloads or makes the data again. The
        // measurement makes it `not_satisfied` for a Git repository.
        assessment.eligibility.regenerable = Fact::Satisfied;
        // Predicate 7: the hard exclusions and the user exclusions.
        if root.is_excluded(&assessment.relative) {
            assessment.eligibility.no_exclusion_overlap = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::ExclusionOverlap);
            return Ok((assessment, None));
        }
        assessment.eligibility.no_exclusion_overlap = Fact::Satisfied;
        // Predicate 8: the complete unit and its charge.
        if before.kind == ObjectKind::Directory {
            let refuse: &'static [&'static str] = spec.refuse_names;
            let records: bool = spec.units == UnitForm::MavenArtifact;
            let unit_path: PathBuf = path.clone();
            let stopped: Option<DiscoveryCompletion> = establish_charge(
                &mut assessment,
                None,
                &UnitUnderMeasurement {
                    path: &path,
                    before: &before,
                    principal: input.scope.principal,
                },
                self.rule(),
                &mut collector.bounds,
                &mut |relative: &Path, kind: EntryKind| {
                    let refused: bool = kind != EntryKind::Directory
                        && (has_refused_name(refuse, relative)
                            || (records && is_local_record(&unit_path.join(relative), relative)));
                    refused.then_some(SkipReason::ProtectedData)
                },
            )?;
            if stopped.is_some() {
                return Ok((assessment, stopped));
            }
        } else {
            self.measure_file(&mut assessment, &before, collector.bounds.wall_now());
        }
        if !assessment.reasons.is_empty() {
            return Ok((assessment, None));
        }
        let now: Option<MonotonicNanos> = collector.bounds.monotonic_now();
        self.assess_age(&mut assessment, &before, input.evidence, now, collector);
        if lstat(&path).ok().as_ref() != Some(&before) {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::IdentityChanged);
        }
        Ok((assessment, None))
    }

    /// The measurement of a regular file unit from its snapshot: one item,
    /// with the larger of its logical size and its allocated size as the
    /// charge. A file with more than one link is refused.
    fn measure_file(
        &self,
        assessment: &mut Assessment,
        before: &ObjectSnapshot,
        measured_at: Option<WallTime>,
    ) {
        if before.link_count > 1 {
            assessment.eligibility.unit_and_charge_known = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::HardLinked);
            return;
        }
        let Some(allocated) = before.allocated else {
            assessment.eligibility.unit_and_charge_known = Fact::Unknown;
            assessment.reasons.insert(SkipReason::MeasurementIncomplete);
            return;
        };
        let charge: WorkCharge =
            WorkCharge::new(Bytes::new(before.size.max(allocated)), EntryCount::new(1));
        let ceiling: WorkCharge = self.rule().budget.per_candidate;
        if charge.work_bytes > ceiling.work_bytes {
            assessment.eligibility.unit_and_charge_known = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::OverCandidateCeiling);
            return;
        }
        let unavailable = || PrivateBytes::Unavailable {
            cause: PrivateSizeUnavailable::NotReported,
        };
        assessment.measurement = Some(UnitMeasurement {
            source: MeasurementSource::Scanned,
            logical_bytes: Bytes::new(before.size),
            allocated_bytes: Bytes::new(allocated),
            private_allocated_bytes: unavailable(),
            complete_family_shared_bytes: unavailable(),
            files: EntryCount::new(1),
            directories: EntryCount::new(0),
            symlinks: EntryCount::new(0),
            charge,
            estimate: ReclaimEstimate {
                bytes: Bytes::new(allocated),
                measure: SizeMeasure::AllocatedBytes,
                exclusive_storage_known: false,
                files_allocated_below_logical: EntryCount::new(u64::from(allocated < before.size)),
            },
            measured_at,
        });
        assessment.eligibility.unit_and_charge_known = Fact::Satisfied;
    }

    /// Establishes the quiet time and the producer activity of a measured
    /// unit (predicates 5 and 6).
    ///
    /// The age is the time since the newest modification or status change
    /// of the unit and of each object below it, and it must be at least the
    /// minimum age and the quiescence of the declaration. No process of the
    /// producer may run, from evidence that is not older than its expiry.
    fn assess_age(
        &self,
        assessment: &mut Assessment,
        before: &ObjectSnapshot,
        evidence: ProducerEvidence,
        now: Option<MonotonicNanos>,
        collector: &Collector<'_>,
    ) {
        let rule = self.rule();
        let required: Nanoseconds = rule.retention.minimum_age.max(rule.activity.quiescence);
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
        let age: Fact = match (newest, collector.observed_at()) {
            (Some(newest), Some(wall)) if newest > wall => {
                assessment.reasons.insert(SkipReason::FutureTimestamp);
                Fact::Unknown
            }
            (Some(newest), Some(wall)) => {
                inactive_for = elapsed_between(newest, wall);
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
        let producer: Fact = match evidence.processes_at(now, rule.activity.evidence_expiry) {
            ProducerProcesses::NotRunning => Fact::Satisfied,
            ProducerProcesses::Running => {
                assessment.reasons.insert(SkipReason::ActiveProducer);
                Fact::NotSatisfied
            }
            ProducerProcesses::Unknown => {
                assessment.reasons.insert(SkipReason::ActivityUnknown);
                Fact::Unknown
            }
        };
        assessment.eligibility.age_and_inactivity = match (age, producer) {
            (Fact::Satisfied, Fact::Satisfied) => Fact::Satisfied,
            (Fact::NotSatisfied, _) | (_, Fact::NotSatisfied) => Fact::NotSatisfied,
            _ => Fact::Unknown,
        };
        assessment.activity = match (&assessment.eligibility.age_and_inactivity, inactive_for) {
            (Fact::Satisfied, Some(inactive_for)) => ActivityFact::Inactive { inactive_for },
            _ => ActivityFact::Unknown,
        };
        // The discovery for an eviction makes the use check with one
        // inventory for each discovery.
        assessment.eligibility.protocols_valid = Fact::Satisfied;
    }
}

/// Whether the child `relative` of a root is a child that `spec` keeps.
fn is_kept(spec: &ClearSpec, relative: &Path) -> bool {
    spec.keep
        .iter()
        .any(|name| relative.as_os_str() == std::ffi::OsStr::new(name))
}

/// Whether the last component of `relative` is a name of `names`.
fn has_refused_name(names: &[&str], relative: &Path) -> bool {
    relative.file_name().is_some_and(|name| {
        names
            .iter()
            .any(|refused| name == std::ffi::OsStr::new(refused))
    })
}

/// Whether the file `relative` at `path` is a `_remote.repositories`
/// record of a local install.
fn is_local_record(path: &Path, relative: &Path) -> bool {
    relative
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(super::REMOTE_RECORD))
        && super::has_local_install_record(path)
}

/// The reason that the child `relative` with the snapshot `snapshot` is not
/// a unit of `spec`, or `None`.
fn form_refusal(
    spec: &ClearSpec,
    relative: &Path,
    snapshot: &ObjectSnapshot,
) -> Option<SkipReason> {
    match (snapshot.kind, spec.units) {
        (ObjectKind::SymbolicLink, _) => Some(SkipReason::SymbolicLink),
        (ObjectKind::Other, _) => Some(SkipReason::UnsupportedObject),
        (ObjectKind::Directory | ObjectKind::RegularFile, UnitForm::Any)
        | (ObjectKind::Directory, UnitForm::MavenArtifact) => None,
        (ObjectKind::RegularFile, UnitForm::GemFile)
            if relative
                .extension()
                .is_some_and(|extension| extension == "gem") =>
        {
            None
        }
        (ObjectKind::Directory | ObjectKind::RegularFile, UnitForm::GemFile) => {
            Some(SkipReason::UnsupportedLayout)
        }
        (ObjectKind::RegularFile, UnitForm::MavenArtifact) => Some(SkipReason::UnsupportedLayout),
    }
}

/// The largest number of entries that the check before a step reads below
/// one unit for a refused name.
const MAX_RECHECK_ENTRIES: u64 = 2_000_000;

/// The checks of the unit at `path` of the clear rule `spec`, made again
/// immediately before its step, after the use check
/// (`docs/ACTION_CONTRACTS.md` section 7):
///
/// - The unit is a child of the root `root` that the rule does not keep,
///   with the form of the rule, and the user `principal` owns it. A unit
///   that is gone gives [`UnitRecheck::Absent`].
/// - For `maven.repository`, the unit is still an artifact directory, and
///   no entry below it is `maven-metadata-local.xml` or a
///   `_remote.repositories` record of a local install. The walk follows no symbolic link and reads at
///   most 2 000 000 entries; a walk that stops or cannot read a directory
///   gives [`UnitRecheck::Unknown`].
///
/// The executor examines the identity of the object and each Git
/// repository again in its removal pass.
#[must_use]
pub fn recheck_unit(spec: &ClearSpec, principal: Uid, root: &Path, path: &Path) -> UnitRecheck {
    let Ok(relative) = path.strip_prefix(root) else {
        return UnitRecheck::Refused("unit_layout_changed");
    };
    let depth: usize = relative.components().count();
    let shape: bool = if spec.units == UnitForm::MavenArtifact {
        (1..=super::MAX_ARTIFACT_DEPTH).contains(&depth)
            && ancestors_are_directories(root, relative)
    } else {
        depth == 1
    };
    if !shape || is_kept(spec, relative) {
        return UnitRecheck::Refused("unit_layout_changed");
    }
    let snapshot: ObjectSnapshot = match lstat(path) {
        Ok(snapshot) => snapshot,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return UnitRecheck::Absent,
        Err(_) => return UnitRecheck::Unknown("unit_not_readable"),
    };
    if let Some(reason) = form_refusal(spec, relative, &snapshot) {
        return UnitRecheck::Refused(match reason {
            SkipReason::SymbolicLink => "unit_symbolic_link",
            _ => "unit_layout_changed",
        });
    }
    if snapshot.owner != principal {
        return UnitRecheck::Refused("unit_owner");
    }
    let records: bool = spec.units == UnitForm::MavenArtifact;
    if records && !super::is_artifact_directory(path) {
        return UnitRecheck::Refused("unit_layout_changed");
    }
    if (spec.refuse_names.is_empty() && !records) || snapshot.kind != ObjectKind::Directory {
        return UnitRecheck::Passed;
    }
    let refuses = |file: &Path, name: &Path| -> bool {
        has_refused_name(spec.refuse_names, name) || (records && is_local_record(file, name))
    };
    match find_refused(path, snapshot.object.device.get(), &refuses) {
        Ok(false) => UnitRecheck::Passed,
        Ok(true) => UnitRecheck::Refused("protected_child"),
        Err(()) => UnitRecheck::Unknown("protected_child_unknown"),
    }
}

/// Whether each component of `relative` above its last one is a directory
/// below `root`, not a symbolic link.
fn ancestors_are_directories(root: &Path, relative: &Path) -> bool {
    let mut path: PathBuf = root.to_path_buf();
    let mut components: Vec<_> = relative.components().collect();
    components.pop();
    components.into_iter().all(|component| {
        path.push(component);
        std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir())
    })
}

/// Whether a file below `unit` is one that `refuses` refuses, from its path
/// and its name. The walk follows no symbolic link, does not enter another
/// device, and reads at most [`MAX_RECHECK_ENTRIES`] entries. `Err` when it
/// cannot read a directory or stops at its bound.
fn find_refused(
    unit: &Path,
    device: i32,
    refuses: &dyn Fn(&Path, &Path) -> bool,
) -> Result<bool, ()> {
    use std::os::unix::fs::MetadataExt as _;

    let mut pending: Vec<PathBuf> = vec![unit.to_path_buf()];
    let mut entries: u64 = 0;
    while let Some(directory) = pending.pop() {
        let listing = std::fs::read_dir(&directory).map_err(|_| ())?;
        for entry in listing {
            let entry = entry.map_err(|_| ())?;
            entries = entries.saturating_add(1);
            if entries > MAX_RECHECK_ENTRIES {
                return Err(());
            }
            let path: PathBuf = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ())?;
            if metadata.is_dir() {
                if i32::try_from(metadata.dev()).ok() != Some(device) {
                    return Err(());
                }
                pending.push(path);
            } else if refuses(&path, Path::new(&entry.file_name())) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
