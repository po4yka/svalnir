//! The inputs and the results of candidate discovery.
//!
//! `docs/CLEANUP_RULES.md` sections 4, 6, 7, and 13 own the contract. Each
//! size in this file is a logical size, an allocated size, or an admission
//! charge. The only reclaim value is [`ReclaimEstimate`], which is an
//! estimate and not a measured result.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use svalnir_core::action::{FileBinding, FileObjectType, WorkCharge};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};
use svalnir_core::id::{MountId, RootId, VolumeId};
use svalnir_core::policy::MAX_CLEANUP_CANDIDATES;
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::rule::{
    CandidateEligibility, Fact, LifecycleState, Rule, RuleCandidate, RuleCandidateError,
    RuleCandidateRecord, RuleMode, RuleRef,
};
use svalnir_core::time::WallTime;
use thiserror::Error;

use crate::scan::{CancellationToken, MAX_DEPTH_LIMIT, PrivateBytes, ScanClock};

/// The largest permitted [`DiscoveryLimits::max_units`].
pub const MAX_UNITS_LIMIT: u32 = 100_000;

/// The largest permitted [`DiscoveryLimits::max_skipped`].
pub const MAX_SKIPPED_LIMIT: usize = 10_000;

/// An approved root that the caller resolved and bound.
///
/// The caller resolves the path from the approved root of the rule
/// declaration and from its own configuration. A rule reads no environment
/// variable and expands no `~`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootBinding {
    /// The identity of the root record that the agent holds.
    pub root_id: RootId,
    /// The absolute path of the root, with no `.` and no `..` component.
    pub path: PathBuf,
    /// The volume of the root.
    pub volume_id: VolumeId,
    /// The mount generation of the volume.
    pub mount_id: MountId,
    /// The device number of the volume. A root on another device is
    /// rejected.
    pub device: DeviceNumber,
}

/// The scope of one discovery: the root, the user, and the exclusions.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryScope<'a> {
    /// The approved root.
    pub root: &'a RootBinding,
    /// The user that the discovery acts for. An object of another owner is
    /// not a candidate.
    pub principal: Uid,
    /// The hard exclusions: the control-plane and recovery roots of
    /// Svalnir and each other protected root that the caller knows. Each
    /// path is absolute. An empty list states that the caller has none.
    pub protected_paths: &'a [PathBuf],
    /// The exclusions of the user configuration. Each path is absolute.
    pub user_exclusions: &'a [PathBuf],
}

/// The bounds of one discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLimits {
    /// The largest number of names of the root that the discovery
    /// examines.
    pub max_units: u32,
    /// The largest number of names that the measurements examine, for all
    /// units together.
    pub max_entries: EntryCount,
    /// The deepest directory level below a unit that a measurement opens.
    pub max_depth: u32,
    /// The longest time of the discovery, on a process-local monotonic
    /// clock.
    pub max_duration: Duration,
    /// The largest number of candidates in the result.
    pub max_candidates: usize,
    /// The largest number of recorded skips. The discovery counts each
    /// skip above this number in [`Discovery::skipped_omitted`].
    pub max_skipped: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_units: 2_000,
            max_entries: EntryCount::new(2_000_000),
            max_depth: 64,
            max_duration: Duration::from_secs(60),
            max_candidates: 1_024,
            max_skipped: 1_024,
        }
    }
}

impl DiscoveryLimits {
    /// Checks each limit against its permitted maximum.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::LimitTooLarge`] with the name of the first
    /// field that is above its maximum.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        let too_large = |field: &'static str| Err(DiscoveryError::LimitTooLarge { field });
        if self.max_units > MAX_UNITS_LIMIT {
            return too_large("max_units");
        }
        if self.max_depth > MAX_DEPTH_LIMIT {
            return too_large("max_depth");
        }
        if self.max_candidates > MAX_CLEANUP_CANDIDATES {
            return too_large("max_candidates");
        }
        if self.max_skipped > MAX_SKIPPED_LIMIT {
            return too_large("max_skipped");
        }
        Ok(())
    }
}

/// How much work a discovery does.
#[derive(Debug, Clone, Copy)]
pub enum DiscoveryMode<'a> {
    /// List the root and measure each unit. Do not use this mode during a
    /// resource emergency.
    Full,
    /// Use known candidates only. The discovery lists no directory and
    /// measures no tree: for each candidate of an earlier discovery it
    /// reads the metadata of the unit and its lifecycle or producer record
    /// again. The measurement of the earlier discovery stays in the
    /// candidate only when the unit shows no change; otherwise the charge
    /// is unknown.
    KnownCandidatesOnly(&'a [DiscoveredCandidate]),
}

/// The bounds, the cancellation, and the clock of one discovery.
#[derive(Clone, Copy)]
pub struct DiscoveryControl<'a> {
    /// The bounds.
    pub limits: DiscoveryLimits,
    /// The flag that stops the discovery from another thread.
    pub cancel: &'a CancellationToken,
    /// The source of the wall-clock time for the age of a candidate. A
    /// clock that gives no wall-clock time makes each age unknown.
    pub clock: &'a dyn ScanClock,
}

impl std::fmt::Debug for DiscoveryControl<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiscoveryControl")
            .field("limits", &self.limits)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

/// The reason a discovery did not start or has no usable result.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// A limit is above its permitted maximum.
    #[error("the discovery limit `{field}` is above its permitted maximum")]
    LimitTooLarge {
        /// The name of the field of [`DiscoveryLimits`].
        field: &'static str,
    },
    /// The root path is not absolute, or it has a `.` or `..` component.
    #[error("the root path is not an absolute path with no `.` and no `..` component")]
    RootPath,
    /// The root cannot be read.
    #[error("the root cannot be read")]
    RootUnavailable(#[source] std::io::Error),
    /// The root is not a directory. A symbolic link is not a directory.
    #[error("the root is not a directory")]
    RootNotDirectory,
    /// The root has another owner than the user of the discovery.
    #[error("the root has another owner")]
    RootOwner,
    /// The root is on another device than the bound volume.
    #[error("the root is not on the bound volume")]
    RootDevice,
    /// The mount flags report the filesystem of the root, or of a directory
    /// above it, as not local: a network filesystem or an automounter map.
    /// A local external disk is local.
    #[error("the root is not on a local filesystem")]
    RootNotLocal,
    /// The mount table cannot be read, or it has no mount for the root or
    /// for a directory above it.
    #[error("the locality of the filesystem of the root is not known")]
    RootLocalityUnknown,
    /// The root does not have the positive classification that the rule
    /// needs, for example the root marker of Svalnir.
    #[error("the root is not classified as a root of the rule")]
    RootNotClassified,
    /// The root is a protected path, is in one, or contains one.
    #[error("the root overlaps a protected path")]
    RootOverlapsProtected,
    /// The object at the root path changed during the discovery. No result
    /// of the discovery is usable.
    #[error("the root changed during the discovery")]
    RootChanged,
    /// A known candidate belongs to another rule revision or another root.
    #[error("a known candidate does not belong to the rule revision and the root")]
    KnownCandidate,
    /// The known candidates are more than the candidate limit.
    #[error("the known candidates are more than the candidate limit")]
    TooManyKnownCandidates,
    /// A value of the rule does not fit its type. This is a defect of the
    /// rule and not a condition of the host.
    #[error("the rule made a value that its type rejects: {0}")]
    Internal(&'static str),
    /// This build has no discovery for the host operating system.
    #[error("the discovery does not support this operating system")]
    Unsupported,
}

/// How a discovery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryCompletion {
    /// The discovery examined each unit of the root or each known
    /// candidate.
    Finished,
    /// The caller cancelled the discovery.
    Cancelled,
    /// The discovery stopped at [`DiscoveryLimits::max_units`].
    UnitLimitReached,
    /// The discovery stopped at [`DiscoveryLimits::max_entries`].
    EntryLimitReached,
    /// The discovery stopped at [`DiscoveryLimits::max_duration`].
    TimeLimitReached,
    /// The discovery stopped at [`DiscoveryLimits::max_candidates`].
    CandidateLimitReached,
}

/// A stable category of the reason a unit is skipped or blocked, as
/// `docs/CLEANUP_RULES.md` section 13 lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipCategory {
    /// The rule revision does not support the version or the layout.
    UnsupportedLayout,
    /// The unit has data that the rule preserves.
    ProtectedData,
    /// The owner is another user, is shared, or is not known.
    UnknownOwnership,
    /// The producer is active.
    ActiveProducer,
    /// The age or the inactivity is not established.
    MissingQuiescence,
    /// The namespace has an object that the rule cannot confine.
    UnsafeNamespace,
    /// The identity changed or the unit is gone.
    StaleIdentity,
    /// The work charge is not known.
    UnknownWorkCharge,
    /// The unit does not fit a work bound.
    BudgetExhaustion,
    /// The operating system denied access.
    MissingAccess,
    /// No authorization covers the unit. A rule does not produce this
    /// category; admission does.
    MissingAuthorization,
    /// The journal is not available. A rule does not produce this
    /// category; admission does.
    UnavailableJournal,
}

/// The reason a unit is skipped, or the reason a candidate is not
/// eligible now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The unit does not have the layout that the rule revision supports.
    UnsupportedLayout,
    /// The lifecycle record or the producer record is absent, is not a
    /// plain file, is too large, or cannot be decoded.
    RecordInvalid,
    /// The record does not name the object that holds it: another
    /// directory identity, another owner, or another kind.
    RecordMismatch,
    /// The unit has an archive, a debug-symbol bundle, signing material, a
    /// database, or other content that the rule preserves.
    ProtectedData,
    /// The record does not state that the content can be made again, or
    /// the sources that make it again are absent.
    NotRegenerable,
    /// The evidence does not establish that the content can be made again.
    RegenerabilityUnknown,
    /// The source that makes the content again is on a filesystem that the
    /// mount table does not report as local, so the rule does not examine
    /// it.
    SourceNotLocal,
    /// A hard exclusion or a user exclusion overlaps the unit.
    ExclusionOverlap,
    /// The unit, or an object in it, has another owner.
    WrongOwner,
    /// More than one producer or project can own the object.
    SharedOwnership,
    /// The producer is active: a process of the producer runs, the lock of
    /// the producer is held, or a live operation has a use lease.
    ActiveProducer,
    /// The evidence does not establish that the producer is inactive.
    ActivityUnknown,
    /// The producer did not seal the unit against further writes.
    NotSealed,
    /// The unit changed after the producer sealed it.
    ModifiedAfterSeal,
    /// The retention time or the quiescence time is not elapsed.
    RetentionNotElapsed,
    /// The age is not known: the clock gave no time, or a record has no
    /// usable time.
    AgeUnknown,
    /// A time of the unit is later than the time now.
    FutureTimestamp,
    /// The unit is a symbolic link, or it has one and the rule does not
    /// support symbolic links.
    SymbolicLink,
    /// The unit has a FIFO, a socket, a device node, or a kind that the
    /// rule does not support.
    UnsupportedObject,
    /// The unit has an entry on another device.
    MountCrossing,
    /// The unit has an object with more than one hard link.
    HardLinked,
    /// The object at the name changed between two steps of the discovery.
    IdentityChanged,
    /// The unit was listed and is gone.
    Vanished,
    /// The measurement of the unit is not complete.
    MeasurementIncomplete,
    /// The unit changed after its measurement, and the mode of the
    /// discovery permits no new measurement.
    MeasurementStale,
    /// The mode of the discovery permits no new measurement, and the
    /// earlier measurement is older than the measurement expiry of the
    /// rule, or its age is not known.
    MeasurementExpired,
    /// The charge of the unit is larger than the candidate ceiling of the
    /// rule. A unit is not split.
    OverCandidateCeiling,
    /// The operating system denied access to the unit or to a part of it.
    AccessDenied,
    /// The unit holds a Git repository: an object with the name `.git`
    /// at some depth (`docs/CLEANUP_RULES.md` section 6, "Repositories in
    /// a unit").
    NestedRepository,
}

impl SkipReason {
    /// The stable category of the reason.
    pub const fn category(self) -> SkipCategory {
        match self {
            Self::UnsupportedLayout | Self::RecordInvalid => SkipCategory::UnsupportedLayout,
            Self::ProtectedData
            | Self::NotRegenerable
            | Self::RegenerabilityUnknown
            | Self::SourceNotLocal
            | Self::ExclusionOverlap
            | Self::NestedRepository => SkipCategory::ProtectedData,
            Self::WrongOwner | Self::SharedOwnership => SkipCategory::UnknownOwnership,
            Self::ActiveProducer => SkipCategory::ActiveProducer,
            Self::ActivityUnknown
            | Self::NotSealed
            | Self::ModifiedAfterSeal
            | Self::RetentionNotElapsed
            | Self::AgeUnknown
            | Self::FutureTimestamp => SkipCategory::MissingQuiescence,
            Self::SymbolicLink | Self::UnsupportedObject | Self::MountCrossing => {
                SkipCategory::UnsafeNamespace
            }
            Self::RecordMismatch | Self::IdentityChanged | Self::Vanished => {
                SkipCategory::StaleIdentity
            }
            Self::HardLinked
            | Self::MeasurementIncomplete
            | Self::MeasurementStale
            | Self::MeasurementExpired => SkipCategory::UnknownWorkCharge,
            Self::OverCandidateCeiling => SkipCategory::BudgetExhaustion,
            Self::AccessDenied => SkipCategory::MissingAccess,
        }
    }
}

/// The identity evidence of the root of a discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RootEvidence {
    /// The identity of the root record.
    pub root_id: RootId,
    /// The path of the root, for display and for the exclusion lists.
    pub path: LosslessPath,
    /// `st_dev` and `st_ino` of the root directory.
    pub object: FileObjectEvidence,
    /// The volume of the root.
    pub volume_id: VolumeId,
    /// The mount generation of the volume.
    pub mount_id: MountId,
}

/// The modification and change times of an object, as `lstat` reports
/// them. The value is evidence that an object did not change between two
/// observations. It is not an age.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChangeStamp {
    /// `st_mtime`, in seconds.
    pub modified_seconds: i64,
    /// The nanosecond part of `st_mtime`.
    pub modified_nanoseconds: i64,
    /// `st_ctime`, in seconds.
    pub changed_seconds: i64,
    /// The nanosecond part of `st_ctime`.
    pub changed_nanoseconds: i64,
}

/// The identity evidence of one unit. The executor examines the object
/// again and compares it with this evidence before each step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetEvidence {
    /// The unit, relative to the approved root.
    pub relative_entry: LosslessPath,
    /// `st_dev` and `st_ino` of the unit.
    pub object: FileObjectEvidence,
    /// The kind of the unit.
    pub object_type: FileObjectType,
    /// The owner of the unit.
    pub owner: Uid,
    /// `st_nlink` of the unit.
    pub link_count: u64,
    /// The times of the unit at the evidence snapshot.
    pub stamp: ChangeStamp,
}

/// The size that a reclaim estimate derives from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeMeasure {
    /// The sum of `st_blocks * 512` of the unit and of each object below
    /// it. This is allocated storage. It is not exclusive storage: APFS
    /// clones and snapshots can share it, and a metadata read cannot
    /// measure that. The estimate uses it when the private allocated bytes
    /// are unavailable.
    AllocatedBytes,
    /// The private allocated bytes of the unit that the APFS backend of the
    /// scanner reported (`docs/RESOURCE_MODEL.md` section 8): the sum of
    /// the private parts, with no block that a clone shares. A snapshot, a
    /// name outside the unit, or an open file can still keep these blocks.
    PrivateAllocatedBytes,
}

/// A prediction of the bytes that the removal of a unit can make
/// available. It is an estimate. The observed capacity change after an
/// action is a different value, and this estimate is not a budget charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReclaimEstimate {
    /// The estimate. The reclaimed bytes can be fewer, down to zero.
    pub bytes: Bytes,
    /// The size that the estimate derives from.
    pub measure: SizeMeasure,
    /// Always `false`: no measure of this build proves exclusive storage,
    /// because a local snapshot can keep each block of the unit.
    pub exclusive_storage_known: bool,
    /// The number of files of the unit whose allocated size is less than
    /// their logical size: sparse, compressed, or dataless files.
    pub files_allocated_below_logical: EntryCount,
}

/// Where the sizes of a candidate come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementSource {
    /// This discovery measured the unit with the scanner.
    Scanned,
    /// An earlier discovery measured the unit, and this discovery found no
    /// change of the identity and of the times of the unit. A change
    /// below the unit that does not change those times is not visible.
    CarriedFromEarlierDiscovery,
}

/// The complete measurement of one unit. A unit with a measurement that
/// is not complete is not a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitMeasurement {
    /// Where the sizes come from.
    pub source: MeasurementSource,
    /// The sum of `st_size` of the files and the symbolic links of the
    /// unit.
    pub logical_bytes: Bytes,
    /// The sum of `st_blocks * 512` of the unit and of each object below
    /// it.
    pub allocated_bytes: Bytes,
    /// The private allocated bytes of the unit, or the cause that they are
    /// unavailable. They count no block that a clone shares. An unavailable
    /// value is not zero.
    pub private_allocated_bytes: PrivateBytes,
    /// The shared parts of the clone families whose members are all in the
    /// unit. Not a reclaim figure: a modified clone outside the unit or a
    /// snapshot can hold them. The estimate never uses them.
    pub complete_family_shared_bytes: PrivateBytes,
    /// The number of names below the unit that are regular files.
    pub files: EntryCount,
    /// The number of names below the unit that are directories.
    pub directories: EntryCount,
    /// The number of names below the unit that are symbolic links. A link
    /// is one entry. The measurement does not follow it and does not count
    /// its target.
    pub symlinks: EntryCount,
    /// The admission charge. The bytes are the checked sum, for each
    /// object, of the larger of its logical size and its allocated size.
    /// The items are each name below the unit and the unit itself. A
    /// charge is not a reclaim value.
    pub charge: WorkCharge,
    /// The reclaim estimate.
    pub estimate: ReclaimEstimate,
    /// The wall-clock time of the measurement, when the clock gave one.
    pub measured_at: Option<WallTime>,
}

/// One candidate of a discovery, with the evidence that the plan builder
/// and the executor need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCandidate {
    /// The candidate in the foundation type. The predicates that a rule
    /// cannot establish (3, 9, and 10) are `unknown`.
    pub candidate: RuleCandidate,
    /// The lifecycle state of the rule revision for the layout of the
    /// candidate. A state that is not validated for a mode permits no
    /// action of that mode.
    pub lifecycle: LifecycleState,
    /// The identity evidence of the root.
    pub root: RootEvidence,
    /// The identity evidence of the unit.
    pub evidence: TargetEvidence,
    /// The sizes, the charge, and the estimate.
    pub measurement: UnitMeasurement,
    /// The reasons the age and the inactivity of the candidate
    /// (predicate 5) are not established, in a stable sequence. An empty
    /// list does not make the candidate eligible: predicates 3, 9, and 10
    /// belong to admission.
    pub blockers: Vec<SkipReason>,
}

impl DiscoveredCandidate {
    /// Whether the lifecycle state of the layout permits `mode`.
    pub fn permits(&self, mode: &RuleMode) -> bool {
        self.lifecycle.permits(mode)
    }

    /// The binding of the unit for a plan target.
    pub fn file_binding(&self) -> FileBinding {
        FileBinding {
            root_id: self.root.root_id.clone(),
            root_path: self.root.path.clone(),
            root_object: self.root.object,
            relative_entry: self.evidence.relative_entry.clone(),
            volume_id: self.root.volume_id.clone(),
            mount_id: self.root.mount_id.clone(),
            object_type: self.evidence.object_type.clone(),
            owner: self.evidence.owner,
            object: Some(self.evidence.object),
            rule: Some(self.candidate.rule.clone()),
            layout: Some(self.candidate.layout.clone()),
            charge: self.measurement.charge,
        }
    }

    /// The candidate with the evidence of the three predicates that
    /// admission owns: the authorized scope (3), the resources (9), and
    /// the fresh check (10).
    ///
    /// # Errors
    ///
    /// Returns the error of [`RuleCandidate::new`] when `rule` is not the
    /// revision of the candidate.
    pub fn with_admission_facts(
        &self,
        rule: &Rule,
        within_authorized_scope: Fact,
        resources_available: Fact,
        fresh_check: Fact,
    ) -> Result<RuleCandidate, RuleCandidateError> {
        let mut record: RuleCandidateRecord = self.candidate.clone().into_inner();
        record.eligibility = CandidateEligibility {
            within_authorized_scope,
            resources_available,
            fresh_check,
            ..record.eligibility
        };
        RuleCandidate::new(rule, record)
    }
}

/// One unit that is not a candidate, with the reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedUnit {
    /// The unit, relative to the approved root.
    pub relative_entry: LosslessPath,
    /// The layout that the rule found, when it found one.
    pub layout: Option<String>,
    /// The reasons, in a stable sequence. The list is not empty.
    pub reasons: Vec<SkipReason>,
    /// The evidence of the eligibility predicates. A predicate that the
    /// rule did not examine is `unknown`.
    pub eligibility: CandidateEligibility,
    /// The identity evidence of the unit, when the rule got it.
    pub evidence: Option<TargetEvidence>,
    /// The first Git marker (`.git`) of the unit, relative to the unit,
    /// when the list has [`SkipReason::NestedRepository`].
    pub repository_marker: Option<LosslessPath>,
}

/// The result of one discovery of one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// The identity evidence of the root.
    pub root: RootEvidence,
    /// How the discovery ended. A value other than `finished` states that
    /// the lists are not complete.
    pub completion: DiscoveryCompletion,
    /// The candidates.
    pub candidates: Vec<DiscoveredCandidate>,
    /// The units that are not candidates.
    pub skipped: Vec<SkippedUnit>,
    /// The number of skipped units that are not in `skipped`.
    pub skipped_omitted: u64,
    /// The number of names of the root, or of known candidates, that the
    /// discovery examined.
    pub units_examined: u64,
    /// The number of names that the measurements examined.
    pub entries_examined: EntryCount,
    /// The wall-clock time at the start of the discovery, when the clock
    /// gave one.
    pub observed_at: Option<WallTime>,
}
