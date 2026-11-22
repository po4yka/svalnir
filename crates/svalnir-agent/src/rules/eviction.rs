//! The discovery of the reviewed rules for an eviction.
//!
//! Owning specifications: `docs/CLEANUP_RULES.md` sections 4, 6, 8, and
//! 11, and `docs/INTERFACES.md` section 4. The `discover` function of a
//! rule examines one bound root. This module does the work around it, one
//! time for the agent and for a client:
//!
//! 1. It resolves the approved roots of each rule declaration against the
//!    home directory and the state directory of the user, and binds each
//!    root that exists to its object, its volume, and its mount generation
//!    ([`resolve_roots`]). No root comes from user input.
//! 2. It makes the evidence that a rule takes from its caller: the process
//!    inventory of `xcode.inactive-derived-data` with its observation time
//!    ([`xcode_evidence`]).
//! 3. It runs each discovery under one set of bounds and one cancellation
//!    flag, in the full mode or for known candidates only.
//! 4. It gives the candidates of all rules to the overlap resolution of
//!    the registry.
//! 5. It makes the use check of `docs/CLEANUP_RULES.md` section 6 for each
//!    candidate, with one process inventory whose scope is the bound
//!    roots ([`super::in_use`]). A unit that a process of the user uses, or
//!    whose use is not known, is a skipped unit with the reason
//!    `unit_in_use` or `unit_use_unknown`.
//! 6. It applies the catalog of protected file locations to each candidate
//!    and sets the three eligibility predicates that a rule leaves
//!    `unknown` (3, 9, and 10).
//!
//! A discovery reads the filesystem and the process table. It changes
//! nothing.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use svalnir_core::action::WorkCharge;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{RootId, RuleId, StepId, TargetId, VolumeId};
use svalnir_core::plan::{CleanupEntry, RuleEvidence, SizeEstimate};
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::{Pid, Uid};
use svalnir_core::quantity::EntryCount;
use svalnir_core::rule::{
    ApprovedRoot as DeclaredRoot, CandidateEligibility, Fact, RootBase, Rule, RuleCandidate,
    RuleCandidateRecord, RuleMode, RuleRef, RuleRegistry,
};
use svalnir_core::time::MonotonicNanos;
use svalnir_core::volume::VolumeIdentity;

use super::expired_temporary::{EXPIRED_TEMPORARY_RULE_ID, TemporaryEvidence, UseLeases};
use super::in_use::{UnitScope, UnitUse, inventory_of, uses_of};
use super::model::{
    DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl, DiscoveryError,
    DiscoveryLimits, DiscoveryMode, DiscoveryScope, RootBinding, SkipReason, SkippedUnit,
};
use super::overlap::{OverlapConflict, OverlapResolution};
use super::registry::ReviewedRules;
use super::xcode::{ProducerProcesses, XCODE_DERIVED_DATA_RULE_ID, XcodeEvidence};
use crate::executor::fs::{ApprovedRoot, ApprovedRoots};
use crate::platform::process::{
    PathInventory, ProcessSource, QueryFailure, refused_process_passes_platform_gate,
};
use crate::platform::volume::volume_at;
use crate::protection::ProtectedLocations;
use crate::scan::{CancellationToken, ScanClock};

/// The user and the locations of one discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryHost {
    /// The user that the discovery acts for.
    pub principal: Uid,
    /// The home directory and the state directory, with their symbolic
    /// links resolved.
    pub locations: ProtectedLocations,
    /// The exclusions of the user configuration, as absolute paths.
    pub user_exclusions: Vec<PathBuf>,
}

impl DiscoveryHost {
    /// The host of a manual discovery: the paths of
    /// `[protections].excluded_paths` are the exclusions.
    #[must_use]
    pub fn manual(principal: Uid, locations: ProtectedLocations, config: &ValidatedConfig) -> Self {
        let user_exclusions: Vec<PathBuf> = expand(
            locations.home_directory(),
            config.protections().excluded_paths.iter(),
        );
        Self {
            principal,
            locations,
            user_exclusions,
        }
    }

    /// The host of an automatic discovery: the paths of
    /// `[protections].excluded_paths` and of `[disk_guard.exclusions].paths`
    /// are the exclusions.
    #[must_use]
    pub fn automatic(
        principal: Uid,
        locations: ProtectedLocations,
        config: &ValidatedConfig,
    ) -> Self {
        let user_exclusions: Vec<PathBuf> = expand(
            locations.home_directory(),
            config
                .protections()
                .excluded_paths
                .iter()
                .chain(&config.disk_guard().exclusions.paths),
        );
        Self {
            principal,
            locations,
            user_exclusions,
        }
    }
}

/// The absolute form of each configuration path. A path that needs a home
/// directory that is not known has no absolute form here; the plan builder
/// then leaves each entry out (`home_directory_unknown`).
fn expand<'a>(
    home: Option<&Path>,
    paths: impl Iterator<Item = &'a svalnir_core::config::ConfigPath>,
) -> Vec<PathBuf> {
    let Some(home) = home else {
        return Vec::new();
    };
    paths.filter_map(|path| path.expand(home).ok()).collect()
}

/// One approved root of a rule declaration that exists on the host, with
/// its binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRoot {
    /// The binding that a discovery takes.
    pub binding: RootBinding,
    /// The device and the inode of the root directory.
    pub object: FileObjectEvidence,
    /// The volume of the root.
    pub volume: VolumeIdentity,
}

impl BoundRoot {
    /// The root record of the filesystem executor.
    ///
    /// # Errors
    ///
    /// Returns [`RootProblem::NotRepresentable`] when the path is not a
    /// lossless path.
    pub fn approved(&self) -> Result<ApprovedRoot, RootProblem> {
        Ok(ApprovedRoot {
            root_id: self.binding.root_id.clone(),
            path: LosslessPath::from_path(&self.binding.path)
                .map_err(|_| RootProblem::NotRepresentable)?,
            object: self.object,
            volume_id: self.binding.volume_id.clone(),
            mount_id: self.binding.mount_id.clone(),
        })
    }
}

/// The reason an approved root of a declaration has no binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootProblem {
    /// The directory does not exist. The rule then has no data at this
    /// root; that is not an error.
    Absent,
    /// The home directory or the state directory of the user is not known.
    BaseUnknown,
    /// The object at the path is not a directory. A symbolic link is not a
    /// directory.
    NotDirectory,
    /// The object cannot be read.
    NotReadable,
    /// The volume of the root has no identity that a plan can bind.
    VolumeIdentityUnavailable,
    /// A value of the root does not fit its type.
    NotRepresentable,
}

impl RootProblem {
    /// The stable name of the problem.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "root_absent",
            Self::BaseUnknown => "root_base_unknown",
            Self::NotDirectory => "root_not_directory",
            Self::NotReadable => "root_not_readable",
            Self::VolumeIdentityUnavailable => "volume_identity_unavailable",
            Self::NotRepresentable => "root_not_representable",
        }
    }
}

/// The identity of a cleanup root: a digest of its path, its device and
/// inode, its volume, and its mount generation.
///
/// The sealed plan binds this identity, the root path, and the root object
/// of each target. A root record with a different path or a different
/// object has a different identity.
#[must_use]
pub fn root_id_of(
    path: &LosslessPath,
    object: FileObjectEvidence,
    volume: &VolumeIdentity,
) -> Option<RootId> {
    let digest = svalnir_core::digest::ContentDigest::of_json(&(
        path,
        object,
        &volume.volume_id,
        &volume.mount_id,
    ))
    .ok()?;
    let text: &str = digest.as_str();
    RootId::new(format!(
        "root-{}",
        text.strip_prefix("sha256:").unwrap_or(text)
    ))
    .ok()
}

/// Binds the directory at `path` as a root: its object, its volume, and
/// its mount generation as they are now.
///
/// # Errors
///
/// Returns a [`RootProblem`].
pub fn bind_root(path: &Path) -> Result<BoundRoot, RootProblem> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RootProblem::Absent
        } else {
            RootProblem::NotReadable
        }
    })?;
    if !metadata.is_dir() {
        return Err(RootProblem::NotDirectory);
    }
    let object: FileObjectEvidence = FileObjectEvidence {
        device: DeviceNumber::new(
            i32::try_from(metadata.dev()).map_err(|_| RootProblem::NotRepresentable)?,
        ),
        inode: InodeNumber::new(metadata.ino()),
    };
    let volume: VolumeIdentity = volume_at(path)
        .map(|mounted| mounted.identity)
        .map_err(|_| RootProblem::VolumeIdentityUnavailable)?;
    let lossless: LosslessPath =
        LosslessPath::from_path(path).map_err(|_| RootProblem::NotRepresentable)?;
    let root_id: RootId =
        root_id_of(&lossless, object, &volume).ok_or(RootProblem::NotRepresentable)?;
    Ok(BoundRoot {
        binding: RootBinding {
            root_id,
            path: path.to_path_buf(),
            volume_id: volume.volume_id.clone(),
            mount_id: volume.mount_id.clone(),
            device: object.device,
        },
        object,
        volume,
    })
}

/// The path of one approved root of a declaration on this host.
///
/// A root is relative to the home directory of the user or to the state
/// directory of Svalnir. For a root of the base `producer_configuration`,
/// the discovery for an eviction reads no configuration of the producer
/// (the inspection of a cache rule does, [`super::caches::resolve`]): the
/// path is the
/// default location below the home directory, which the declaration gives
/// as a discovery hint. A producer that is configured for a different
/// location has no root here, and the rule finds nothing for it. A root of
/// the base `user_selected` or `producer_installation` has no path here.
fn declared_path(root: &DeclaredRoot, locations: &ProtectedLocations) -> Option<PathBuf> {
    let base: &Path = match root.base {
        RootBase::UserHome | RootBase::ProducerConfiguration => locations.home_directory()?,
        RootBase::SvalnirState => locations.state_directory()?,
        // A root in a project that the user selects has no fixed path, and
        // the discovery for an eviction has no selected project. A base
        // that this build does not know gives no path.
        RootBase::UserSelected | RootBase::ProducerInstallation | RootBase::Unrecognized(_) => {
            return None;
        }
    };
    Some(base.join(root.relative.to_path_buf()))
}

/// Resolves and binds each approved root of `rule` on this host.
///
/// The result has one item for each root of the declaration, in the
/// sequence of the declaration.
#[must_use]
pub fn resolve_roots(
    rule: &Rule,
    locations: &ProtectedLocations,
) -> Vec<Result<BoundRoot, RootProblem>> {
    rule.roots
        .iter()
        .map(|root| {
            let path: PathBuf = declared_path(root, locations).ok_or(RootProblem::BaseUnknown)?;
            bind_root(&path)
        })
        .collect()
}

/// The approved roots of this process for an automatic operation: each
/// root of each rule revision of `registry` that permits automatic
/// eviction for a layout and that `approved` names, as it is on the host
/// now.
///
/// A root that is absent or that cannot be bound is not in the set, so an
/// automatic operation has no place to act there. Two rules with one root
/// give one record.
#[must_use]
pub fn automatic_roots(
    registry: &dyn RuleRegistry,
    approved: &[RuleId],
    locations: &ProtectedLocations,
) -> ApprovedRoots {
    let mut roots: Vec<ApprovedRoot> = Vec::new();
    for rule in registry.rules() {
        let permits: bool = approved.contains(&rule.reference.id)
            && rule
                .layouts
                .iter()
                .any(|layout| layout.permits(&RuleMode::AutomaticEviction));
        if !permits {
            continue;
        }
        for bound in resolve_roots(rule, locations).into_iter().flatten() {
            let Ok(root) = bound.approved() else {
                continue;
            };
            if !roots.iter().any(|known| known.root_id == root.root_id) {
                roots.push(root);
            }
        }
    }
    // The set has a bound on its size. A registry with more roots than the
    // bound is a defect of the build; no root is then approved.
    ApprovedRoots::new(roots).unwrap_or_default()
}

/// The process evidence of `xcode.inactive-derived-data`: whether a
/// process of the producer runs for `principal`, and the monotonic time of
/// the inventory.
///
/// The inventory reads the process table one time. It is complete only
/// when each process of the user gave its executable path. A process that
/// exited during the reading is not a process of the inventory. A query
/// that failed for a different cause makes the inventory not complete, and
/// the evidence is then [`ProducerProcesses::Unknown`]: a process whose
/// executable is not known can be a process of the producer.
///
/// The observation time is the time before the first query, so the
/// evidence is never newer than its time says.
///
/// For a denied identity query, the owner query decides: a process of a
/// different user is out of the scope, and a process of the user is out
/// of the inventory only when it passes the platform gate of
/// `docs/CLEANUP_RULES.md` section 6. Each other such process makes the
/// evidence [`ProducerProcesses::Unknown`].
pub fn xcode_evidence<S: ProcessSource>(source: &S, principal: Uid) -> XcodeEvidence {
    let unknown = |observed_at: MonotonicNanos| XcodeEvidence {
        producer_processes: ProducerProcesses::Unknown,
        observed_at,
    };
    let Ok(observed_at) = source.monotonic_now() else {
        return unknown(MonotonicNanos::new(0));
    };
    let Ok(pids) = source.list_pids() else {
        return unknown(observed_at);
    };
    let mut names: Vec<String> = Vec::new();
    for pid in pids {
        let pid: Pid = pid;
        let info = match source.process_info(pid) {
            Ok(info) => info,
            // A process that exited is not a process of the inventory. A
            // denied identity query is a process of a different user.
            Err(QueryFailure::Gone) => continue,
            // A denied identity query: the owner query decides. A process
            // of a different user is out of the scope; a process of the
            // user is out of the inventory only through the platform gate
            // (`docs/CLEANUP_RULES.md` sections 6 and 11).
            Err(failure @ (QueryFailure::PermissionDenied | QueryFailure::AccessDenied)) => {
                match source.process_owner(pid) {
                    Ok((effective, real)) if effective != principal && real != principal => {}
                    Err(QueryFailure::Gone) => {}
                    _ if failure == QueryFailure::PermissionDenied
                        && refused_process_passes_platform_gate(source, pid) => {}
                    _ => return unknown(observed_at),
                }
                continue;
            }
            Err(_) => return unknown(observed_at),
        };
        if info.zombie || (info.effective_uid != principal && info.real_uid != principal) {
            continue;
        }
        match source.executable_path(pid) {
            Ok(path) => {
                let name: &[u8] = path
                    .as_bytes()
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .unwrap_or_default();
                names.push(String::from_utf8_lossy(name).into_owned());
            }
            Err(QueryFailure::Gone) => {}
            Err(_) => return unknown(observed_at),
        }
    }
    XcodeEvidence {
        producer_processes: ProducerProcesses::from_complete_inventory(
            names.iter().map(String::as_str),
        ),
        observed_at,
    }
}

/// What a discovery needs from its environment beside the filesystem: the
/// clock and the process evidence. The two are on one monotonic timeline.
pub trait DiscoveryEnvironment: ScanClock {
    /// The process evidence of `xcode.inactive-derived-data`, read now.
    fn xcode_evidence(&self, principal: Uid) -> XcodeEvidence;

    /// The path-use inventory of the processes of `principal`, read now,
    /// with the paths in `scopes` only (`docs/CLEANUP_RULES.md` section 6).
    fn path_uses(&self, principal: Uid, scopes: &[UnitScope]) -> PathInventory;

    /// The use of the unit at `path` by a process of `principal`, read now.
    ///
    /// The coordinator asks this immediately before each step of an
    /// eviction, after the producer activity. Only
    /// [`UnitUse::NotInUse`] permits the step.
    fn unit_use(&self, principal: Uid, path: &Path) -> UnitUse {
        let scope: UnitScope = UnitScope::new(path);
        uses_of(
            &self.path_uses(principal, std::slice::from_ref(&scope)),
            &scope,
        )
    }

    /// The activity of the producer of `rule` for `principal`, read now.
    ///
    /// The coordinator asks this immediately before each step of an
    /// eviction (`docs/ACTION_CONTRACTS.md` section 7): a producer that
    /// became active after the plan was made inhibits the step. The
    /// evidence is the one that the discovery of the rule takes from its
    /// caller:
    ///
    /// - `xcode.inactive-derived-data`: the process inventory.
    /// - `svalnir.expired-temporary`: the use leases, which this build
    ///   does not record, so the activity is not known.
    /// - A rule that this build does not know: not known.
    fn producer_activity(&self, rule: &RuleId, principal: Uid) -> ProducerActivity {
        if rule.as_str() != XCODE_DERIVED_DATA_RULE_ID {
            return ProducerActivity::Unknown;
        }
        match self.xcode_evidence(principal).producer_processes {
            ProducerProcesses::NotRunning => ProducerActivity::Inactive,
            ProducerProcesses::Running => ProducerActivity::Active,
            ProducerProcesses::Unknown => ProducerActivity::Unknown,
        }
    }
}

/// The environment of a discovery, shared between threads.
pub type SharedEnvironment = std::sync::Arc<dyn DiscoveryEnvironment + Send + Sync>;

/// The environment of the running system: the clocks and the process
/// table of a [`ProcessSource`].
#[derive(Debug, Clone, Copy)]
pub struct SourceEnvironment<S>(pub S);

impl<S: ProcessSource> ScanClock for SourceEnvironment<S> {
    fn now(&self) -> crate::scan::ScanTimestamp {
        crate::scan::ScanTimestamp {
            wall: self.0.wall_now().ok(),
            monotonic_ns: self.0.monotonic_now().ok(),
        }
    }
}

impl<S: ProcessSource> DiscoveryEnvironment for SourceEnvironment<S> {
    fn xcode_evidence(&self, principal: Uid) -> XcodeEvidence {
        xcode_evidence(&self.0, principal)
    }

    fn path_uses(&self, principal: Uid, scopes: &[UnitScope]) -> PathInventory {
        inventory_of(&self.0, principal, scopes)
    }
}

/// Whether the producer of the data of a rule is active now, as the
/// evidence of the caller shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProducerActivity {
    /// Current evidence shows no activity of the producer.
    Inactive,
    /// The producer is active.
    Active,
    /// The evidence does not show whether the producer is active.
    Unknown,
}

/// The request of one discovery for an eviction.
#[derive(Clone, Copy)]
pub struct EvictionRequest<'a> {
    /// The user and the locations.
    pub host: &'a DiscoveryHost,
    /// The mode that a rule must permit for one of its layouts:
    /// [`RuleMode::ManualEviction`] or [`RuleMode::AutomaticEviction`]. A
    /// rule that does not permit it is not examined.
    pub purpose: &'a RuleMode,
    /// When given, only these rules are examined.
    pub rules: Option<&'a [RuleId]>,
    /// When given, only a root on one of these volumes is examined.
    pub volumes: Option<&'a [VolumeId]>,
    /// When given, the discovery uses known candidates only
    /// ([`DiscoveryMode::KnownCandidatesOnly`]): it lists no directory and
    /// measures no tree, and a root with no known candidate is not opened.
    /// This is the only form for a resource emergency.
    pub known: Option<&'a [DiscoveredCandidate]>,
    /// The bounds of the discovery of each root.
    pub limits: DiscoveryLimits,
    /// The flag that stops the discovery from a different thread.
    pub cancel: &'a CancellationToken,
}

impl std::fmt::Debug for EvictionRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvictionRequest")
            .field("purpose", &self.purpose)
            .field("known", &self.known.map(<[DiscoveredCandidate]>::len))
            .finish_non_exhaustive()
    }
}

/// What the discovery found at one root of one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootReport {
    /// The rule revision.
    pub rule: RuleRef,
    /// The path of the root, when it was resolved.
    pub path: Option<PathBuf>,
    /// The result.
    pub result: RootResult,
}

/// The result of the discovery of one root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootResult {
    /// The discovery ran. The skipped units and the counts are here; the
    /// candidates are in [`EvictionDiscovery::candidates`].
    Examined {
        /// How the discovery ended.
        completion: DiscoveryCompletion,
        /// The units that are not candidates.
        skipped: Vec<SkippedUnit>,
        /// The number of skipped units that are not in `skipped`.
        skipped_omitted: u64,
    },
    /// The root has no binding.
    NotBound(RootProblem),
    /// The root is on a volume that the request does not name.
    OtherVolume,
    /// The request is for known candidates, and none is known at the root.
    NothingKnown,
    /// The discovery refused the root. The name is a stable name of the
    /// refusal; it has no path.
    Refused(&'static str),
}

/// One candidate of a discovery for an eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionCandidate {
    /// The candidate as the rule found it, for a later discovery of known
    /// candidates.
    pub discovered: DiscoveredCandidate,
    /// The candidate with the fact of the catalog of protected file
    /// locations and with the three predicates of admission.
    pub candidate: RuleCandidate,
}

impl EvictionCandidate {
    /// The size estimates of the candidate. The estimate of the reclaimed
    /// bytes is the allocated size; shared storage can make the reclaimed
    /// size smaller, down to zero.
    #[must_use]
    pub const fn estimate(&self) -> SizeEstimate {
        let measurement = &self.discovered.measurement;
        SizeEstimate {
            logical_bytes: Some(measurement.logical_bytes),
            allocated_bytes: Some(measurement.allocated_bytes),
            estimated_reclaimable_bytes: Some(measurement.estimate.bytes),
        }
    }

    /// The work charge of the candidate.
    #[must_use]
    pub const fn charge(&self) -> WorkCharge {
        self.discovered.measurement.charge
    }

    /// The entry of the candidate for the plan builder.
    #[must_use]
    pub fn cleanup_entry(&self, target_id: TargetId, step_id: StepId) -> CleanupEntry {
        let discovered: &DiscoveredCandidate = &self.discovered;
        let policy = &self.candidate.candidate;
        CleanupEntry {
            target_id,
            step_id,
            path: policy.path.clone(),
            root_id: discovered.root.root_id.clone(),
            root_path: discovered.root.path.clone(),
            root_object: discovered.root.object,
            relative_entry: discovered.evidence.relative_entry.clone(),
            volume_id: discovered.root.volume_id.clone(),
            mount_id: discovered.root.mount_id.clone(),
            object_type: discovered.evidence.object_type.clone(),
            owner: Some(discovered.evidence.owner),
            object: Some(discovered.evidence.object),
            link_count: Some(EntryCount::new(discovered.evidence.link_count)),
            charge: Some(self.charge()),
            estimate: self.estimate(),
            hard_protection: policy.facts.hard_protection,
            // The root of a rule has no symbolic link in its path, and the
            // rule follows none below it, so the path has no other form.
            resolved_paths: Vec::new(),
            rule: Some(RuleEvidence::of(&self.candidate)),
        }
    }
}

/// The result of one discovery for an eviction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvictionDiscovery {
    /// True when each root that exists was examined, each discovery
    /// examined each unit of its root or each known candidate, and the
    /// overlap resolution ran. A root that is absent has no unit. A result that
    /// is not complete supports no automatic plan.
    pub complete: bool,
    /// The candidates that no overlap conflict rejected.
    pub candidates: Vec<EvictionCandidate>,
    /// What the discovery found at each root of each rule that it
    /// examined.
    pub roots: Vec<RootReport>,
    /// The overlap conflicts.
    pub conflicts: Vec<OverlapConflict>,
    /// The binding of each root that a discovery examined, with its
    /// volume. A client records it with the plan of its candidates.
    pub bound_roots: Vec<BoundRoot>,
}

/// A stable name of a discovery refusal, with no path.
pub(super) const fn refusal_name(error: &DiscoveryError) -> &'static str {
    match error {
        DiscoveryError::LimitTooLarge { .. } => "limit_too_large",
        DiscoveryError::RootPath => "root_path_not_plain",
        DiscoveryError::RootUnavailable(_) => "root_not_readable",
        DiscoveryError::RootNotDirectory => "root_not_directory",
        DiscoveryError::RootOwner => "root_owner",
        DiscoveryError::RootDevice => "root_device",
        DiscoveryError::RootNotLocal => "root_not_local",
        DiscoveryError::RootLocalityUnknown => "root_locality_unknown",
        DiscoveryError::RootNotClassified => "root_not_classified",
        DiscoveryError::RootOverlapsProtected => "root_overlaps_protected",
        DiscoveryError::RootChanged => "root_changed",
        DiscoveryError::KnownCandidate => "known_candidate_mismatch",
        DiscoveryError::TooManyKnownCandidates => "too_many_known_candidates",
        DiscoveryError::Internal(_) => "rule_defect",
        DiscoveryError::Unsupported => "unsupported_platform",
    }
}

/// The use check of the candidates of one discovery: one inventory for
/// all candidates, with the bound roots as its scope, read after the walk
/// of the roots. A unit that is in use, or whose use is not known, is
/// added to the report of its root and is not kept.
fn use_check(
    result: &mut EvictionDiscovery,
    candidates: Vec<DiscoveredCandidate>,
    principal: Uid,
    environment: &dyn DiscoveryEnvironment,
) -> Vec<DiscoveredCandidate> {
    if candidates.is_empty() {
        return candidates;
    }
    let scopes: Vec<UnitScope> = result
        .bound_roots
        .iter()
        .map(|bound| UnitScope::new(&bound.binding.path))
        .collect();
    let inventory: PathInventory = environment.path_uses(principal, &scopes);
    let mut kept: Vec<DiscoveredCandidate> = Vec::new();
    for discovered in candidates {
        let scope: UnitScope = UnitScope::new(&discovered.candidate.candidate.path.to_path_buf());
        match use_skip(&uses_of(&inventory, &scope)) {
            None => kept.push(discovered),
            Some(reason) => {
                if !skip_in_report(&mut result.roots, &discovered, reason) {
                    // A unit with no root report is not shown.
                    result.complete = false;
                }
            }
        }
    }
    kept
}

/// The skip reason of the result of the use check, or `None` when it
/// permits the unit.
const fn use_skip(found: &UnitUse) -> Option<SkipReason> {
    match found {
        UnitUse::NotInUse => None,
        UnitUse::InUse { .. } => Some(SkipReason::UnitInUse),
        UnitUse::Unknown { .. } => Some(SkipReason::UnitUseUnknown),
    }
}

/// Adds `discovered` as a skipped unit with `reason` to the report of its
/// root. Predicate 6 is `not_satisfied` for a use and `unknown` for an
/// unknown use. Returns false when the root has no report that was
/// examined.
fn skip_in_report(
    roots: &mut [RootReport],
    discovered: &DiscoveredCandidate,
    reason: SkipReason,
) -> bool {
    let record = &discovered.candidate;
    let root_path: PathBuf = discovered.root.path.to_path_buf();
    let report: Option<&mut RootReport> = roots.iter_mut().find(|report| {
        report.rule == record.rule && report.path.as_deref() == Some(root_path.as_path())
    });
    let Some(RootReport {
        result: RootResult::Examined { skipped, .. },
        ..
    }) = report
    else {
        return false;
    };
    skipped.push(SkippedUnit {
        relative_entry: discovered.evidence.relative_entry.clone(),
        layout: Some(record.layout.clone()),
        reasons: vec![reason],
        eligibility: CandidateEligibility {
            protocols_valid: if reason == SkipReason::UnitInUse {
                Fact::NotSatisfied
            } else {
                Fact::Unknown
            },
            ..record.eligibility.clone()
        },
        evidence: Some(discovered.evidence.clone()),
        repository_marker: None,
    });
    true
}

/// The candidate with the fact of the catalog and the three predicates of
/// admission.
///
/// - Predicate 3 (authorized scope) is `satisfied` when the catalog of
///   protected file locations gives `not_protected` for the unit. The
///   caller examines only a rule that the request selects, under a root of
///   its declaration. A protected unit gives `not_satisfied`, and an
///   unknown protection gives `unknown`.
/// - Predicate 9 (resources) is `satisfied`: the discovery read the root
///   and the mount table. The coordinator reserves the budget, takes the
///   leases, and records the admission before a step, and refuses the plan
///   when one of them is not available.
/// - Predicate 10 (fresh check) is `satisfied`: this call examined the
///   identity, the records, and the activity of the unit. The executor
///   examines the object again before its step.
fn with_admission(
    rule: &Rule,
    discovered: &DiscoveredCandidate,
    locations: &ProtectedLocations,
) -> Option<RuleCandidate> {
    let mut record: RuleCandidateRecord = discovered.candidate.clone().into_inner();
    let path: PathBuf = record.candidate.path.to_path_buf();
    // The rule compared the unit with the protected paths that the scope
    // names. The catalog adds the locations that no scope names.
    let protection: ProtectionFact = match (
        record.candidate.facts.hard_protection,
        locations.of_text(&path),
    ) {
        (ProtectionFact::NotProtected, catalog) => catalog,
        (other, _) => other,
    };
    record.candidate.facts.hard_protection = protection;
    record.eligibility = CandidateEligibility {
        within_authorized_scope: match protection {
            ProtectionFact::NotProtected => Fact::Satisfied,
            ProtectionFact::Protected => Fact::NotSatisfied,
            ProtectionFact::Unknown => Fact::Unknown,
        },
        resources_available: Fact::Satisfied,
        fresh_check: Fact::Satisfied,
        ..record.eligibility
    };
    RuleCandidate::new(rule, record).ok()
}

impl ReviewedRules {
    /// Runs the discovery of each rule that `request` selects and that
    /// permits the purpose of the request, and gives the candidates with
    /// the facts of admission.
    ///
    /// The function never fails as a whole: a root that cannot be bound,
    /// and a discovery that refuses its root, are in
    /// [`EvictionDiscovery::roots`], and that rule has no candidate.
    pub fn discover_for_eviction(
        &self,
        request: &EvictionRequest<'_>,
        environment: &dyn DiscoveryEnvironment,
    ) -> EvictionDiscovery {
        let host: &DiscoveryHost = request.host;
        let protected: Vec<PathBuf> = host
            .locations
            .state_directory()
            .map(Path::to_path_buf)
            .into_iter()
            .collect();
        let mut result: EvictionDiscovery = EvictionDiscovery {
            complete: true,
            ..EvictionDiscovery::default()
        };
        // With no state directory, the hard exclusion of the control-plane
        // state has no path, so no rule is examined.
        if protected.is_empty() {
            result.complete = false;
            return result;
        }
        let mut found: Vec<DiscoveredCandidate> = Vec::new();
        for rule in self.rules() {
            let selected: bool = request
                .rules
                .is_none_or(|rules| rules.contains(&rule.reference.id))
                && rule
                    .layouts
                    .iter()
                    .any(|layout| layout.permits(request.purpose));
            if !selected {
                continue;
            }
            for (declared, bound) in rule.roots.iter().zip(resolve_roots(rule, &host.locations)) {
                let (root_result, candidates) = match &bound {
                    Ok(bound) => self.examine_root(rule, bound, request, &protected, environment),
                    Err(problem) => (RootResult::NotBound(*problem), Vec::new()),
                };
                if let RootResult::Examined { completion, .. } = &root_result {
                    if *completion != DiscoveryCompletion::Finished {
                        result.complete = false;
                    }
                    result.bound_roots.extend(bound.ok());
                }
                // A root that exists and that was not examined can have
                // units that the result does not show.
                let not_examined: bool = match &root_result {
                    RootResult::Refused(_) => true,
                    RootResult::NotBound(problem) => *problem != RootProblem::Absent,
                    RootResult::Examined { .. }
                    | RootResult::OtherVolume
                    | RootResult::NothingKnown => false,
                };
                if not_examined {
                    result.complete = false;
                }
                found.extend(candidates);
                result.roots.push(RootReport {
                    rule: rule.reference.clone(),
                    path: declared_path(declared, &host.locations),
                    result: root_result,
                });
            }
        }
        let Ok(OverlapResolution {
            candidates,
            conflicts,
            conflicts_omitted,
        }) = self.claim(found)
        else {
            // A candidate list that the registry does not accept gives no
            // candidate.
            result.complete = false;
            return result;
        };
        result.conflicts = conflicts;
        if conflicts_omitted > 0 {
            result.complete = false;
        }
        let candidates: Vec<DiscoveredCandidate> =
            use_check(&mut result, candidates, host.principal, environment);
        for discovered in candidates {
            let candidate: Option<RuleCandidate> = self
                .lookup(&discovered.candidate.rule)
                .ok()
                .and_then(|rule| with_admission(rule, &discovered, &host.locations));
            match candidate {
                Some(candidate) => result.candidates.push(EvictionCandidate {
                    discovered,
                    candidate,
                }),
                // A record that the foundation check rejects is a defect
                // of this module. The unit is then not a candidate.
                None => result.complete = false,
            }
        }
        result
    }

    /// The discovery of one bound root of one rule: the result for the
    /// report, and the candidates.
    fn examine_root(
        &self,
        rule: &Rule,
        bound: &BoundRoot,
        request: &EvictionRequest<'_>,
        protected: &[PathBuf],
        environment: &dyn DiscoveryEnvironment,
    ) -> (RootResult, Vec<DiscoveredCandidate>) {
        if request
            .volumes
            .is_some_and(|volumes| !volumes.contains(&bound.binding.volume_id))
        {
            return (RootResult::OtherVolume, Vec::new());
        }
        // The known candidates of this rule revision at this root. A
        // candidate of a root that was bound again (a different object or
        // mount generation) is not known at the new root.
        let known: Option<Vec<DiscoveredCandidate>> = request.known.map(|known| {
            known
                .iter()
                .filter(|candidate| {
                    candidate.candidate.rule == rule.reference
                        && candidate.root.root_id == bound.binding.root_id
                })
                .cloned()
                .collect()
        });
        if known.as_ref().is_some_and(Vec::is_empty) {
            return (RootResult::NothingKnown, Vec::new());
        }
        let mode: DiscoveryMode<'_> = known
            .as_deref()
            .map_or(DiscoveryMode::Full, DiscoveryMode::KnownCandidatesOnly);
        let scope: DiscoveryScope<'_> = DiscoveryScope {
            root: &bound.binding,
            principal: request.host.principal,
            protected_paths: protected,
            user_exclusions: &request.host.user_exclusions,
        };
        let control: DiscoveryControl<'_> = DiscoveryControl {
            limits: request.limits,
            cancel: request.cancel,
            clock: environment,
        };
        match self.discover_one(rule, &scope, mode, &control, environment) {
            Ok(discovery) => (
                RootResult::Examined {
                    completion: discovery.completion,
                    skipped: discovery.skipped,
                    skipped_omitted: discovery.skipped_omitted,
                },
                discovery.candidates,
            ),
            Err(error) => (RootResult::Refused(refusal_name(&error)), Vec::new()),
        }
    }

    /// The discovery of one rule, with the evidence that the rule takes
    /// from its caller.
    fn discover_one(
        &self,
        rule: &Rule,
        scope: &DiscoveryScope<'_>,
        mode: DiscoveryMode<'_>,
        control: &DiscoveryControl<'_>,
        environment: &dyn DiscoveryEnvironment,
    ) -> Result<Discovery, DiscoveryError> {
        match rule.reference.id.as_str() {
            XCODE_DERIVED_DATA_RULE_ID => {
                // The inventory is read immediately before the discovery
                // of the root, so its age is the time of that discovery.
                let evidence: XcodeEvidence = environment.xcode_evidence(scope.principal);
                self.xcode_derived_data()
                    .discover(scope, evidence, mode, control)
            }
            EXPIRED_TEMPORARY_RULE_ID => {
                // This build has no producer of temporary items and no
                // record of their use leases. The lease state is thus not
                // known, and no item is a candidate that can be evicted.
                let evidence: TemporaryEvidence<'_> = TemporaryEvidence {
                    leases: UseLeases::Unknown,
                };
                self.expired_temporary()
                    .discover(scope, evidence, mode, control)
            }
            _ => Err(DiscoveryError::Unsupported),
        }
    }
}
