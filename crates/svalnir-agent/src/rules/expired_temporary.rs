//! The rule `svalnir.expired-temporary`.
//!
//! `docs/CLEANUP_RULES.md` section 11 owns the contract. The rule finds
//! the disposable items that Svalnir itself made in its temporary
//! namespace. It removes nothing.
//!
//! # Identification
//!
//! A name does not make a directory a candidate. The rule needs two
//! records that Svalnir writes:
//!
//! - The root has the marker file [`ROOT_MARKER_NAME`], a
//!   [`TemporaryRootMarker`] that names the device and the inode of the
//!   root directory and its owner.
//! - Each item is a directory of the root that has the lifecycle record
//!   [`ITEM_RECORD_NAME`], a [`TemporaryItemRecord`] that names the device
//!   and the inode of the item directory, its owner, its content class,
//!   and its lifecycle times.
//!
//! A record that names another directory identity (a copied or substituted
//! record, or a name that was used again) does not match. Policy, grant,
//! journal, and recovery state never have these records, and the caller
//! gives their roots as protected paths, which the root must not overlap.
//!
//! # What the rule can and cannot establish
//!
//! The rule establishes the identity, the owner, the content class that
//! the record states, the seal, the retention, and the complete charge of
//! an item. The use leases come from the caller, who reconciles them with
//! the operation state. A seal coordinates the writers of Svalnir only:
//! another process of the same user can change the item, and the rule
//! sees such a change only when it changes the directory of the item or
//! an examined record.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svalnir_core::action::{Checked, ExecutorRole, FileObjectType, WorkCharge};
use svalnir_core::file::{FileObjectEvidence, LosslessPath};
use svalnir_core::id::{RuleId, RuleRevisionId, TargetId};
use svalnir_core::policy::{ActivityFact, RebuildCost};
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::{
    ActivityCheck, ActivityProtocol, AgeBasis, ApprovedRoot, DeletionMethod, Fact, LayoutSupport,
    LifecycleState, OwnerAttribution, Retention, RootBase, Rule, RuleBudget, RuleDeclaration,
    RuleExclusions, RuleMode, RuleOwner, RuleRef,
};
use svalnir_core::time::WallTime;

use super::model::{
    DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl, DiscoveryError,
    DiscoveryMode, DiscoveryScope, SkipReason,
};
use super::registry::RegistryError;
use super::unit::{
    Assessment, Collector, ObjectKind, ObjectSnapshot, RecordRead, RootView, UnitUnderMeasurement,
    check_known, elapsed_between, establish_charge, list_root, lstat, read_record, reason_of,
    target_evidence,
};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::scan::EntryKind;

/// The identity of the rule.
pub const EXPIRED_TEMPORARY_RULE_ID: &str = "svalnir.expired-temporary";

/// The implementation revision of the rule in this build.
pub const EXPIRED_TEMPORARY_REVISION: &str = "r1";

/// The one layout that the revision supports.
pub const EXPIRED_TEMPORARY_LAYOUT: &str = "temporary-v1";

/// The name of the marker file of the temporary root.
pub const ROOT_MARKER_NAME: &str = ".svalnir-temporary-root.json";

/// The name of the lifecycle record of one item.
pub const ITEM_RECORD_NAME: &str = ".svalnir-lifecycle.json";

/// The `kind` of a [`TemporaryRootMarker`].
pub const ROOT_MARKER_KIND: &str = "svalnir.temporary-root";

/// The `kind` of a [`TemporaryItemRecord`].
pub const ITEM_RECORD_KIND: &str = "svalnir.temporary-item";

/// The schema version of the two records.
pub const TEMPORARY_SCHEMA_VERSION: u32 = 1;

/// The `content` of an item that has only intermediate material that
/// Svalnir can make again.
pub const CONTENT_REGENERABLE_INTERMEDIATE: &str = "regenerable_intermediate";

/// The largest size of a record file, in bytes.
const MAX_RECORD_BYTES: u64 = 16 * 1024;

/// The time after the seal in which the write of the sealed record can
/// still change the directory of the item.
const SEAL_WRITE_TOLERANCE: Nanoseconds = Nanoseconds::new(5_000_000_000);

const HOUR: u64 = 3_600_000_000_000;
const MINUTE: u64 = 60_000_000_000;
const GIBIBYTE: u64 = 1 << 30;

/// The marker of the temporary root. Svalnir writes it when it makes the
/// root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporaryRootMarker {
    /// [`TEMPORARY_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// [`ROOT_MARKER_KIND`].
    pub kind: String,
    /// The owner of the namespace.
    pub owner_uid: u32,
    /// The device and the inode of the root directory.
    pub directory: FileObjectEvidence,
}

/// The lifecycle record of one temporary item. Svalnir writes it when it
/// makes the item, and writes it again when it seals the item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporaryItemRecord {
    /// [`TEMPORARY_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// [`ITEM_RECORD_KIND`].
    pub kind: String,
    /// The lifecycle identity of the item, in the character set of an
    /// opaque identity. A use lease names it.
    pub lifecycle_id: String,
    /// The purpose of the item, for display.
    pub purpose: String,
    /// The owner of the item.
    pub owner_uid: u32,
    /// The device and the inode of the item directory.
    pub directory: FileObjectEvidence,
    /// The content class. Only [`CONTENT_REGENERABLE_INTERMEDIATE`] can be
    /// a candidate.
    pub content: String,
    /// When Svalnir made the item.
    pub created_at: WallTime,
    /// When Svalnir sealed the item against further writes. `None` for an
    /// item that is open, or that a crash left before its seal.
    pub sealed_at: Option<WallTime>,
    /// When the retention of the item ends.
    pub expires_at: WallTime,
}

/// The use leases of the temporary items, from the caller.
#[derive(Debug, Clone, Copy)]
pub enum UseLeases<'a> {
    /// The caller did not reconcile the items with the operation state.
    /// No item is known to be free.
    Unknown,
    /// The lifecycle identities that a live operation has a use lease on,
    /// after the caller reconciled them with the operation state.
    Known(&'a [String]),
}

/// The evidence that the rule takes from the caller.
#[derive(Debug, Clone, Copy)]
pub struct TemporaryEvidence<'a> {
    /// The use leases.
    pub leases: UseLeases<'a>,
}

/// The rule `svalnir.expired-temporary`.
#[derive(Debug, Clone)]
pub struct ExpiredTemporaryRule {
    rule: Rule,
    mounts: MountTableSource,
}

/// The declaration of the revision of this build. Each layout is
/// `proposed`: no validation record exists for the rule.
fn declaration() -> Result<RuleDeclaration, RegistryError> {
    let relative: LosslessPath = LosslessPath::from_bytes("Library/Caches/Svalnir/Temporary")
        .map_err(|_| RegistryError::Declaration("the root path"))?;
    Ok(RuleDeclaration {
        reference: RuleRef {
            id: RuleId::new(EXPIRED_TEMPORARY_RULE_ID)
                .map_err(|_| RegistryError::Declaration("the rule identity"))?,
            revision: RuleRevisionId::new(EXPIRED_TEMPORARY_REVISION)
                .map_err(|_| RegistryError::Declaration("the rule revision"))?,
        },
        owner: RuleOwner {
            producer: "svalnir".to_owned(),
            attribution: OwnerAttribution::SvalnirLifecycleRecord,
        },
        layouts: vec![LayoutSupport {
            layout: EXPIRED_TEMPORARY_LAYOUT.to_owned(),
            lifecycle: LifecycleState::Proposed,
        }],
        roots: vec![ApprovedRoot {
            base: RootBase::UserHome,
            relative,
        }],
        retention: Retention {
            age_basis: AgeBasis::SvalnirLifecycleRecord,
            minimum_age: Nanoseconds::new(HOUR),
        },
        activity: ActivityProtocol {
            checks: vec![ActivityCheck::SealedLifecycleRecord],
            quiescence: Nanoseconds::new(10 * MINUTE),
            evidence_expiry: Nanoseconds::new(MINUTE / 2),
        },
        exclusions: RuleExclusions {
            descendants: Vec::new(),
            supported_object_types: vec![FileObjectType::RegularFile, FileObjectType::Directory],
            skip_hard_linked: true,
        },
        modes: RuleMode::ALL.to_vec(),
        deletion_method: DeletionMethod::BoundedUnlink,
        executor: ExecutorRole::User,
        rebuild_cost: RebuildCost::Low,
        budget: RuleBudget {
            per_candidate: WorkCharge::new(Bytes::new(GIBIBYTE), EntryCount::new(10_000)),
            per_pass: WorkCharge::new(Bytes::new(4 * GIBIBYTE), EntryCount::new(50_000)),
            measurement_expiry: Nanoseconds::new(10 * MINUTE),
        },
    })
}

/// Whether a name below an item is one that this namespace must not have:
/// a database, a journal, or key material. A name is a rejection hint
/// only. The absence of such a name does not show that an item is safe.
fn is_protected_name(name: &str) -> bool {
    const SUFFIXES: [&str; 14] = [
        ".sqlite",
        ".sqlite3",
        ".db",
        "-wal",
        "-shm",
        "-journal",
        ".journal",
        ".key",
        ".pem",
        ".p12",
        ".keychain",
        ".keychain-db",
        ".grant",
        ".policy",
    ];
    let name: String = name.to_ascii_lowercase();
    SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

fn classify_entry(relative: &Path, _kind: EntryKind) -> Option<SkipReason> {
    // A name that is not UTF-8 is not a name that Svalnir writes.
    let Some(name) = relative.file_name()?.to_str() else {
        return Some(SkipReason::ProtectedData);
    };
    is_protected_name(name).then_some(SkipReason::ProtectedData)
}

/// The assessment of one item, or the bound that stopped it.
enum Outcome {
    Assessed(Box<Assessment>),
    Stopped(DiscoveryCompletion),
}

/// Reads the record of the item at `path`. `Err` is the reason the item
/// has no usable record.
fn read_item_record(
    path: &Path,
    scope: &DiscoveryScope<'_>,
) -> Result<(TemporaryItemRecord, Vec<u8>), (Fact, SkipReason)> {
    match read_record(
        &path.join(ITEM_RECORD_NAME),
        MAX_RECORD_BYTES,
        scope.principal,
    ) {
        RecordRead::Absent => Err((Fact::NotSatisfied, SkipReason::UnsupportedLayout)),
        RecordRead::Denied => Err((Fact::Unknown, SkipReason::AccessDenied)),
        RecordRead::Invalid => Err((Fact::NotSatisfied, SkipReason::RecordInvalid)),
        RecordRead::Read { bytes, .. } => {
            let record: TemporaryItemRecord = serde_json::from_slice(&bytes)
                .map_err(|_| (Fact::NotSatisfied, SkipReason::RecordInvalid))?;
            if record.schema_version == TEMPORARY_SCHEMA_VERSION && record.kind == ITEM_RECORD_KIND
            {
                Ok((record, bytes))
            } else {
                Err((Fact::NotSatisfied, SkipReason::UnsupportedLayout))
            }
        }
    }
}

/// The evidence of the age and the inactivity of a sealed item (predicate
/// 5), with the reasons that it is not satisfied.
fn age_and_inactivity(
    rule: &Rule,
    record: &TemporaryItemRecord,
    sealed_at: WallTime,
    now: Option<WallTime>,
    leases: UseLeases<'_>,
) -> (Fact, ActivityFact, BTreeSet<SkipReason>) {
    let mut reasons: BTreeSet<SkipReason> = BTreeSet::new();
    let mut fact: Fact = Fact::Satisfied;
    let mut lower = |fact: &mut Fact, to: Fact, reason: SkipReason| {
        reasons.insert(reason);
        // `not_satisfied` stays: a later unknown does not replace it.
        if *fact != Fact::NotSatisfied {
            *fact = to;
        }
    };
    let mut inactive_for: Option<Nanoseconds> = None;
    match now {
        None => lower(&mut fact, Fact::Unknown, SkipReason::AgeUnknown),
        Some(now) if sealed_at > now || record.created_at > now => {
            lower(&mut fact, Fact::Unknown, SkipReason::FutureTimestamp);
        }
        Some(now) => {
            let required: Nanoseconds = rule.retention.minimum_age.max(rule.activity.quiescence);
            inactive_for = elapsed_between(sealed_at, now);
            if now < record.expires_at || inactive_for.is_none_or(|elapsed| elapsed < required) {
                lower(
                    &mut fact,
                    Fact::NotSatisfied,
                    SkipReason::RetentionNotElapsed,
                );
            }
        }
    }
    let mut is_leased: bool = false;
    match leases {
        UseLeases::Unknown => lower(&mut fact, Fact::Unknown, SkipReason::ActivityUnknown),
        UseLeases::Known(live) => {
            if live.contains(&record.lifecycle_id) {
                is_leased = true;
                lower(&mut fact, Fact::NotSatisfied, SkipReason::ActiveProducer);
            }
        }
    }
    let activity: ActivityFact = match (is_leased, fact.is_satisfied(), inactive_for) {
        (true, _, _) => ActivityFact::Active,
        (false, true, Some(inactive_for)) => ActivityFact::Inactive { inactive_for },
        _ => ActivityFact::Unknown,
    };
    (fact, activity, reasons)
}

impl ExpiredTemporaryRule {
    /// Makes the rule with the declaration of this build.
    pub(super) fn new() -> Result<Self, RegistryError> {
        let rule: Rule = Checked::new(declaration()?).map_err(RegistryError::Incomplete)?;
        Ok(Self {
            rule,
            mounts: MountTable::read,
        })
    }

    /// The rule with another source of the mount table. A test gives a
    /// table with a filesystem that is not local.
    #[cfg(test)]
    pub(super) fn with_mount_table(self, mounts: MountTableSource) -> Self {
        Self { mounts, ..self }
    }

    /// The rule with `lifecycle` for each layout. Only a test build has
    /// this function ([`super::ReviewedRules::with_fixture_lifecycle`]).
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    pub(super) fn with_lifecycle(self, lifecycle: &LifecycleState) -> Result<Self, RegistryError> {
        Ok(Self {
            rule: super::registry::with_lifecycle(&self.rule, lifecycle)?,
            ..self
        })
    }

    /// The checked declaration of the rule revision.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// Finds the candidates of the temporary root of `scope`.
    ///
    /// The discovery reads metadata and the two record files. It changes
    /// nothing. With [`DiscoveryMode::KnownCandidatesOnly`] it lists no
    /// directory and measures no tree.
    ///
    /// # Errors
    ///
    /// Returns a [`DiscoveryError`] when a limit is too large, when the
    /// root fails a check (also when it is not on a local filesystem) or
    /// has no valid marker, when the root changed
    /// during the discovery, or when a known candidate belongs to another
    /// rule revision or root.
    pub fn discover(
        &self,
        scope: &DiscoveryScope<'_>,
        evidence: TemporaryEvidence<'_>,
        mode: DiscoveryMode<'_>,
        control: &DiscoveryControl<'_>,
    ) -> Result<Discovery, DiscoveryError> {
        self.discover_with(scope, evidence, mode, control, &mut |_| {})
    }

    /// [`ExpiredTemporaryRule::discover`] with a function that runs after
    /// the measurement of each item and before its evidence snapshot.
    pub(super) fn discover_with(
        &self,
        scope: &DiscoveryScope<'_>,
        evidence: TemporaryEvidence<'_>,
        mode: DiscoveryMode<'_>,
        control: &DiscoveryControl<'_>,
        after_measurement: &mut dyn FnMut(&Path),
    ) -> Result<Discovery, DiscoveryError> {
        let mut collector: Collector<'_> = Collector::new(control)?;
        let mounts: MountTable =
            (self.mounts)().map_err(|_| DiscoveryError::RootLocalityUnknown)?;
        let root: RootView = RootView::open(scope, &mounts)?;
        check_root_marker(&root, scope)?;
        let mut completion: DiscoveryCompletion = DiscoveryCompletion::Finished;
        let mut item = ItemContext {
            rule: &self.rule,
            root: &root,
            scope,
            leases: evidence.leases,
            after_measurement,
        };
        match mode {
            DiscoveryMode::Full => {
                let names: Vec<PathBuf> =
                    list_root(&root, &collector.bounds, Some(ROOT_MARKER_NAME))
                        .map_err(DiscoveryError::RootUnavailable)?;
                for name in names {
                    if !collector.has_candidate_room() {
                        completion = DiscoveryCompletion::CandidateLimitReached;
                        break;
                    }
                    if let Err(stopped) = collector.bounds.take_unit() {
                        completion = stopped;
                        break;
                    }
                    match item.assess(name, None, &mut collector)? {
                        Outcome::Assessed(assessment) => {
                            collector.add(&self.rule, &root, *assessment)?;
                        }
                        Outcome::Stopped(stopped) => {
                            completion = stopped;
                            break;
                        }
                    }
                }
            }
            DiscoveryMode::KnownCandidatesOnly(known) => {
                let known: &[DiscoveredCandidate] = check_known(&self.rule, &root, control, known)?;
                // A unit of this layout is a direct entry of the root. A
                // path with more components is not a candidate of this
                // rule, and a directory between the root and such an entry
                // has no check: it can be a symbolic link.
                let is_direct_entry = |candidate: &DiscoveredCandidate| {
                    candidate
                        .evidence
                        .relative_entry
                        .to_path_buf()
                        .components()
                        .count()
                        == 1
                };
                if !known.iter().all(is_direct_entry) {
                    return Err(DiscoveryError::KnownCandidate);
                }
                for candidate in known {
                    if let Err(stopped) = collector.bounds.take_unit() {
                        completion = stopped;
                        break;
                    }
                    let relative: PathBuf = candidate.evidence.relative_entry.to_path_buf();
                    match item.assess(relative, Some(candidate), &mut collector)? {
                        Outcome::Assessed(assessment) => {
                            collector.add(&self.rule, &root, *assessment)?;
                        }
                        Outcome::Stopped(stopped) => {
                            completion = stopped;
                            break;
                        }
                    }
                }
            }
        }
        // The marker is read again: a marker that was removed during the
        // discovery, or that has a content that is not valid for this
        // root now, leaves no result. A marker that was replaced by one
        // with the same valid content is a valid marker. A replaced root
        // is reported first, as the end of the discovery does.
        root.verify_unchanged()?;
        check_root_marker(&root, scope)?;
        collector.finish(&self.rule, &root, completion)
    }
}

/// Checks the marker of the root: a valid record of this schema that names
/// the root directory and the user of the discovery.
fn check_root_marker(root: &RootView, scope: &DiscoveryScope<'_>) -> Result<(), DiscoveryError> {
    let bytes: Vec<u8> = match read_record(
        &root.path.join(ROOT_MARKER_NAME),
        MAX_RECORD_BYTES,
        scope.principal,
    ) {
        RecordRead::Read { bytes, .. } => bytes,
        // A marker that cannot be read is a denied capability, not a root
        // of another layout.
        RecordRead::Denied => {
            return Err(DiscoveryError::RootUnavailable(io::Error::from(
                io::ErrorKind::PermissionDenied,
            )));
        }
        RecordRead::Absent | RecordRead::Invalid => {
            return Err(DiscoveryError::RootNotClassified);
        }
    };
    let marker: TemporaryRootMarker =
        serde_json::from_slice(&bytes).map_err(|_| DiscoveryError::RootNotClassified)?;
    let is_valid: bool = marker.schema_version == TEMPORARY_SCHEMA_VERSION
        && marker.kind == ROOT_MARKER_KIND
        && marker.owner_uid == scope.principal.get()
        && marker.directory == root.evidence.object;
    if is_valid {
        Ok(())
    } else {
        Err(DiscoveryError::RootNotClassified)
    }
}

/// The inputs of the assessment of each item of one discovery.
struct ItemContext<'a> {
    rule: &'a Rule,
    root: &'a RootView,
    scope: &'a DiscoveryScope<'a>,
    leases: UseLeases<'a>,
    after_measurement: &'a mut dyn FnMut(&Path),
}

impl ItemContext<'_> {
    /// Assesses the item `relative`. `known` is the candidate of an
    /// earlier discovery: the item is then not measured.
    fn assess(
        &mut self,
        relative: PathBuf,
        known: Option<&DiscoveredCandidate>,
        collector: &mut Collector<'_>,
    ) -> Result<Outcome, DiscoveryError> {
        let path: PathBuf = self.root.path.join(&relative);
        let before: ObjectSnapshot = match lstat(&path) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(Outcome::Assessed(Box::new(Assessment::skip(
                    relative,
                    reason_of(&error),
                ))));
            }
        };
        let mut assessment: Assessment = Assessment::new(relative);
        assessment.evidence = target_evidence(&assessment.relative, &before);

        // A unit is a directory of the root. A link, a file, and a special
        // file are not items of this layout.
        let kind_reason: Option<SkipReason> = match before.kind {
            ObjectKind::Directory => None,
            ObjectKind::SymbolicLink => Some(SkipReason::SymbolicLink),
            ObjectKind::RegularFile => Some(SkipReason::UnsupportedLayout),
            ObjectKind::Other => Some(SkipReason::UnsupportedObject),
        };
        if let Some(reason) = kind_reason {
            assessment.eligibility.rule_supports_layout = Fact::NotSatisfied;
            assessment.reasons.insert(reason);
            return Ok(Outcome::Assessed(Box::new(assessment)));
        }

        let (record, record_bytes) = match read_item_record(&path, self.scope) {
            Ok(read) => read,
            Err((fact, reason)) => {
                assessment.eligibility.rule_supports_layout = fact;
                assessment.reasons.insert(reason);
                return Ok(Outcome::Assessed(Box::new(assessment)));
            }
        };
        assessment.layout = Some(EXPIRED_TEMPORARY_LAYOUT);
        assessment.eligibility.rule_supports_layout = Fact::Satisfied;

        // Predicate 2: the record names this directory and this owner.
        let principal: u32 = self.scope.principal.get();
        if before.owner.get() != principal || record.owner_uid != principal {
            assessment.reasons.insert(SkipReason::WrongOwner);
        }
        if before.object.device != self.root.device() {
            assessment.reasons.insert(SkipReason::MountCrossing);
        }
        if record.directory != before.object {
            assessment.reasons.insert(SkipReason::RecordMismatch);
        }
        // A record with an identity or with times that Svalnir does not
        // write is not a lifecycle record.
        if TargetId::new(record.lifecycle_id.as_str()).is_err()
            || record.created_at > record.expires_at
            || record
                .sealed_at
                .is_some_and(|sealed| sealed < record.created_at)
        {
            assessment.reasons.insert(SkipReason::RecordInvalid);
        }
        assessment.eligibility.identity_matches = if assessment.reasons.is_empty() {
            Fact::Satisfied
        } else {
            Fact::NotSatisfied
        };

        // Predicate 4: the record states the content class.
        assessment.eligibility.regenerable = if record.content == CONTENT_REGENERABLE_INTERMEDIATE {
            Fact::Satisfied
        } else {
            assessment.reasons.insert(SkipReason::NotRegenerable);
            Fact::NotSatisfied
        };

        // Predicate 7: the exclusions that the caller gave.
        assessment.eligibility.no_exclusion_overlap = if self.root.is_excluded(&assessment.relative)
        {
            assessment.reasons.insert(SkipReason::ExclusionOverlap);
            Fact::NotSatisfied
        } else {
            Fact::Satisfied
        };

        // A directory that is not positively an item is not measured.
        if !assessment.reasons.is_empty() {
            return Ok(Outcome::Assessed(Box::new(assessment)));
        }

        // Predicate 8: the complete unit and its charge.
        let stopped: Option<DiscoveryCompletion> = establish_charge(
            &mut assessment,
            known,
            &UnitUnderMeasurement {
                path: &path,
                before: &before,
                principal: self.scope.principal,
            },
            self.rule,
            &mut collector.bounds,
            &mut classify_entry,
        )?;
        if let Some(stopped) = stopped {
            return Ok(Outcome::Stopped(stopped));
        }
        (self.after_measurement)(&path);
        self.assess_seal(&mut assessment, &record, &before, collector.observed_at());

        // The evidence snapshot: the item and its record are the objects
        // that the assessment examined.
        let unchanged: bool = lstat(&path).is_ok_and(|after| after == before)
            && read_item_record(&path, self.scope).is_ok_and(|(_, bytes)| bytes == record_bytes);
        if !unchanged {
            assessment.eligibility.identity_matches = Fact::NotSatisfied;
            assessment.reasons.insert(SkipReason::IdentityChanged);
        }
        Ok(Outcome::Assessed(Box::new(assessment)))
    }

    /// Establishes the seal, the retention, and the leases of an item
    /// (predicates 5 and 6).
    fn assess_seal(
        &self,
        assessment: &mut Assessment,
        record: &TemporaryItemRecord,
        before: &ObjectSnapshot,
        now: Option<WallTime>,
    ) {
        // Predicates 5 and 6: the seal, the retention, and the leases.
        let mut protocol_reasons: BTreeSet<SkipReason> = BTreeSet::new();
        match record.sealed_at {
            None => {
                protocol_reasons.insert(SkipReason::NotSealed);
                assessment.eligibility.age_and_inactivity = Fact::NotSatisfied;
            }
            Some(sealed_at) => {
                // A directory, or an object below it, that changed after
                // the seal had a writer that the seal did not stop. The
                // modification time of a directory shows only a change of
                // its own names, so the newest change of the measured
                // content is compared also.
                let newest: Option<WallTime> = before.modified().map(|modified| {
                    assessment
                        .newest_content_change
                        .map_or(modified, |content| content.max(modified))
                });
                let modified_after_seal: Option<bool> = newest.map(|newest| {
                    elapsed_between(sealed_at, newest)
                        .is_some_and(|after| after > SEAL_WRITE_TOLERANCE)
                });
                match modified_after_seal {
                    Some(false) => {}
                    Some(true) => {
                        protocol_reasons.insert(SkipReason::ModifiedAfterSeal);
                    }
                    None => {
                        protocol_reasons.insert(SkipReason::AgeUnknown);
                    }
                }
                let (fact, activity, reasons) =
                    age_and_inactivity(self.rule, record, sealed_at, now, self.leases);
                assessment.eligibility.age_and_inactivity = fact;
                // An item that changed after its seal, or whose time is
                // not known, is not shown to be inactive since the seal.
                assessment.activity = match activity {
                    ActivityFact::Inactive { .. } if !protocol_reasons.is_empty() => {
                        ActivityFact::Unknown
                    }
                    activity => activity,
                };
                assessment.reasons.extend(reasons);
            }
        }
        if assessment.eligibility.protocols_valid == Fact::Unknown {
            assessment.eligibility.protocols_valid = if protocol_reasons.is_empty() {
                Fact::Satisfied
            } else if protocol_reasons == BTreeSet::from([SkipReason::AgeUnknown]) {
                Fact::Unknown
            } else {
                Fact::NotSatisfied
            };
        }
        assessment.reasons.extend(protocol_reasons);
    }
}
