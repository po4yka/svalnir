//! Tests of the registry and of the two rules.
//!
//! Each test makes its files in a temporary directory that it created. No
//! test reads the home directory, a real `DerivedData` root, or the state
//! directory, and no test removes a file outside its temporary directory.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use svalnir_core::action::{Checked, FileObjectType};
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber};
use svalnir_core::id::{MountId, RootId, RuleRevisionId, VolumeId};
use svalnir_core::policy::{ActivityFact, OwnerFact, ProtectionFact, RuleReadiness};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{EntryCount, Nanoseconds};
use svalnir_core::rule::{
    Fact, LifecycleState, Rule, RuleCandidate, RuleCandidateRecord, RuleDeclaration, RuleMode,
    RuleRef, RuleRefusal, RuleRegistry,
};
use svalnir_core::time::{MonotonicNanos, WallTime};
use tempfile::TempDir;

use super::expired_temporary::{
    CONTENT_REGENERABLE_INTERMEDIATE, EXPIRED_TEMPORARY_LAYOUT, ITEM_RECORD_KIND, ITEM_RECORD_NAME,
    ROOT_MARKER_KIND, ROOT_MARKER_NAME, TEMPORARY_SCHEMA_VERSION, TemporaryEvidence,
    TemporaryItemRecord, TemporaryRootMarker, UseLeases,
};
use super::model::{
    DiscoveredCandidate, Discovery, DiscoveryCompletion, DiscoveryControl, DiscoveryError,
    DiscoveryLimits, DiscoveryMode, DiscoveryScope, MeasurementSource, RootBinding, SizeMeasure,
    SkipCategory, SkipReason, SkippedUnit,
};
use super::native::is_locked_by_another_process;
use super::overlap::{OverlapKind, resolve_overlaps};
use super::plist::parse_project_info;
use super::registry::{ClaimError, ReviewedRules};
use super::unit::{entry_change, with_resolved_forms};
use super::xcode::{
    ProducerProcesses, XCODE_DERIVED_DATA_LAYOUT, XcodeDerivedDataRule, XcodeEvidence,
};
use crate::platform::volume::raw::MOUNT_FLAG_LOCAL;
use crate::platform::volume::{MountTable, MountTableSource, RawMount};
use crate::scan::{CancellationToken, ScanClock, ScanTimestamp};
use svalnir_core::observation::UnavailableReason;

const DAY_SECONDS: i64 = 86_400;
const PROJECT: &str = "App-abcdefghijklmnopqrstuvwxyzab";

/// The monotonic time of [`FixedClock`].
const MONOTONIC_NOW: MonotonicNanos = MonotonicNanos::new(1_000_000_000_000);

/// A clock with a fixed wall-clock time, or with none, and with the fixed
/// monotonic time [`MONOTONIC_NOW`].
struct FixedClock(Option<WallTime>);

impl ScanClock for FixedClock {
    fn now(&self) -> ScanTimestamp {
        ScanTimestamp {
            wall: self.0,
            monotonic_ns: Some(MONOTONIC_NOW),
        }
    }
}

fn real_now() -> WallTime {
    WallTime::try_from(SystemTime::now()).unwrap()
}

/// The real time now with `seconds` added.
fn real_now_plus(seconds: i64) -> WallTime {
    WallTime::from_unix(real_now().unix_seconds() + seconds, 0).unwrap()
}

fn object_of(path: &Path) -> FileObjectEvidence {
    let metadata = fs::symlink_metadata(path).unwrap();
    FileObjectEvidence {
        device: DeviceNumber::new(i32::try_from(metadata.dev()).unwrap()),
        inode: InodeNumber::new(metadata.ino()),
    }
}

/// A temporary directory with one bound root in it.
struct Fixture {
    /// Keeps the temporary directory until the fixture is dropped.
    _directory: TempDir,
    /// The temporary directory with each symbolic link resolved.
    base: PathBuf,
    binding: RootBinding,
    principal: Uid,
    protected: Vec<PathBuf>,
    excluded: Vec<PathBuf>,
}

impl Fixture {
    fn new(root_name: &str) -> Self {
        let directory: TempDir = tempfile::tempdir().unwrap();
        // The temporary directory of macOS is below a symbolic link. A root
        // path has no link in an ancestor, so the fixture resolves it.
        let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let root: PathBuf = base.join(root_name);
        fs::create_dir(&root).unwrap();
        let metadata = fs::metadata(&root).unwrap();
        Self {
            binding: RootBinding {
                root_id: RootId::new("root-1").unwrap(),
                path: root,
                volume_id: VolumeId::new("volume-1").unwrap(),
                mount_id: MountId::new("mount-1").unwrap(),
                device: DeviceNumber::new(i32::try_from(metadata.dev()).unwrap()),
            },
            principal: Uid::new(metadata.uid()),
            _directory: directory,
            base,
            protected: Vec::new(),
            excluded: Vec::new(),
        }
    }

    fn root(&self) -> &Path {
        &self.binding.path
    }

    fn base(&self) -> &Path {
        &self.base
    }

    fn scope(&self) -> DiscoveryScope<'_> {
        DiscoveryScope {
            root: &self.binding,
            principal: self.principal,
            protected_paths: &self.protected,
            user_exclusions: &self.excluded,
        }
    }
}

fn limits() -> DiscoveryLimits {
    DiscoveryLimits::default()
}

fn skip_of<'a>(discovery: &'a Discovery, relative: &str) -> &'a SkippedUnit {
    discovery
        .skipped
        .iter()
        .find(|skipped| skipped.relative_entry.as_utf8() == Some(relative))
        .unwrap_or_else(|| panic!("no skip for {relative}: {:?}", discovery.skipped))
}

fn candidate_of<'a>(discovery: &'a Discovery, relative: &str) -> &'a DiscoveredCandidate {
    discovery
        .candidates
        .iter()
        .find(|candidate| candidate.evidence.relative_entry.as_utf8() == Some(relative))
        .unwrap_or_else(|| panic!("no candidate for {relative}: {:?}", discovery.skipped))
}

// ---------------------------------------------------------------------
// The registry.
// ---------------------------------------------------------------------

fn reference(id: &str, revision: &str) -> RuleRef {
    RuleRef {
        id: id.parse().unwrap(),
        revision: RuleRevisionId::new(revision).unwrap(),
    }
}

#[test]
fn the_registry_has_eighteen_rules_and_each_layout_is_proposed() {
    let registry = ReviewedRules::new().unwrap();
    let rules = registry.rules();
    // The two rules of Milestone 2, the six cache rules,
    // `project.dependency-directory`, and the three rules of the owner
    // tools, `git.linked-worktree`, and the five rules of
    // `rules::producers` with their own declaration.
    // The clear rules come after them.
    let clear: usize = super::clear::CLEAR_SPECS.len();
    assert_eq!(rules.len(), 18 + clear);
    let statuses = registry.statuses();
    // One layout for each of the two rules, two for `pnpm.content-store`
    // and for `yarn.cache`, one for each other cache rule, 32 for
    // `project.dependency-directory` (the catalog and `user-configured`),
    // two for `simulator.devices` and for `container.build-cache`, and one
    // for `homebrew.cleanup` and for `git.linked-worktree`, and the layout
    // of the scope root of each of the ten rules with an owner operation.
    // A clear rule has one layout.
    assert_eq!(statuses.len(), 58 + clear);
    for status in &statuses {
        assert_eq!(status.lifecycle, LifecycleState::Proposed);
        assert_eq!(status.permitted_modes.len(), 0);
        assert_eq!(
            registry.lifecycle(&status.reference, &status.layout),
            Ok(&LifecycleState::Proposed)
        );
        // A proposed layout permits no mode, so no mode resolves.
        for mode in RuleMode::ALL {
            assert_eq!(
                registry
                    .resolve(&status.reference, &status.layout, &mode)
                    .err(),
                Some(RuleRefusal::ModeNotValidated)
            );
        }
    }
}

#[test]
fn the_registry_refuses_an_unknown_rule_revision_and_layout() {
    let registry = ReviewedRules::new().unwrap();
    let known = reference("svalnir.expired-temporary", "r1");
    assert!(registry.lookup(&known).is_ok());
    assert_eq!(
        registry
            .lookup(&reference("all.application-caches", "r1"))
            .err(),
        Some(RuleRefusal::UnknownRule)
    );
    // Another revision of a registered rule is not substituted.
    let other_revision = reference("svalnir.expired-temporary", "r2");
    assert_eq!(
        registry.lookup(&other_revision).err(),
        Some(RuleRefusal::UnknownRevision)
    );
    assert!(registry.rule(&other_revision).is_none());
    assert_eq!(
        registry
            .resolve(
                &other_revision,
                EXPIRED_TEMPORARY_LAYOUT,
                &RuleMode::Inspection
            )
            .err(),
        Some(RuleRefusal::UnknownRevision)
    );
    assert_eq!(
        registry.lifecycle(&known, "temporary-v2").err(),
        Some(RuleRefusal::UnknownLayout)
    );
    // A layout of one rule is not a layout of the other rule.
    assert_eq!(
        registry.lifecycle(&known, XCODE_DERIVED_DATA_LAYOUT).err(),
        Some(RuleRefusal::UnknownLayout)
    );
}

// ---------------------------------------------------------------------
// `svalnir.expired-temporary`.
// ---------------------------------------------------------------------

/// A temporary root with a valid marker.
fn temporary_fixture() -> Fixture {
    let fixture = Fixture::new("Temporary");
    let marker = TemporaryRootMarker {
        schema_version: TEMPORARY_SCHEMA_VERSION,
        kind: ROOT_MARKER_KIND.to_owned(),
        owner_uid: fixture.principal.get(),
        directory: object_of(fixture.root()),
    };
    fs::write(
        fixture.root().join(ROOT_MARKER_NAME),
        serde_json::to_vec(&marker).unwrap(),
    )
    .unwrap();
    fixture
}

/// The record of an item that is sealed now and whose retention ended.
fn sealed_record(fixture: &Fixture, item: &Path, lifecycle_id: &str) -> TemporaryItemRecord {
    TemporaryItemRecord {
        schema_version: TEMPORARY_SCHEMA_VERSION,
        kind: ITEM_RECORD_KIND.to_owned(),
        lifecycle_id: lifecycle_id.to_owned(),
        purpose: "report staging".to_owned(),
        owner_uid: fixture.principal.get(),
        directory: object_of(item),
        content: CONTENT_REGENERABLE_INTERMEDIATE.to_owned(),
        created_at: real_now_plus(-60),
        sealed_at: Some(real_now_plus(0)),
        expires_at: real_now_plus(600),
    }
}

/// Makes the item `name` with two payload files and the record that
/// `change` adjusted.
fn add_item(
    fixture: &Fixture,
    name: &str,
    change: impl FnOnce(&mut TemporaryItemRecord),
) -> PathBuf {
    let item: PathBuf = fixture.root().join(name);
    fs::create_dir(&item).unwrap();
    fs::write(item.join("part-1.bin"), vec![1_u8; 4_096]).unwrap();
    fs::create_dir(item.join("nested")).unwrap();
    fs::write(item.join("nested/part-2.bin"), vec![2_u8; 100]).unwrap();
    let mut record = sealed_record(fixture, &item, &format!("lifecycle-{name}"));
    change(&mut record);
    fs::write(
        item.join(ITEM_RECORD_NAME),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    item
}

const NO_LEASES: TemporaryEvidence<'static> = TemporaryEvidence {
    leases: UseLeases::Known(&[]),
};

/// A clock two days after the real time: each item of [`sealed_record`]
/// is then past its retention.
fn later_clock() -> FixedClock {
    FixedClock(Some(real_now_plus(2 * DAY_SECONDS)))
}

fn discover_temporary_with(
    fixture: &Fixture,
    evidence: TemporaryEvidence<'_>,
    mode: DiscoveryMode<'_>,
    limits: DiscoveryLimits,
    clock: &FixedClock,
) -> Result<Discovery, DiscoveryError> {
    let registry = ReviewedRules::new().unwrap();
    let cancel = CancellationToken::new();
    let control = DiscoveryControl {
        limits,
        cancel: &cancel,
        clock,
    };
    registry
        .expired_temporary()
        .discover(&fixture.scope(), evidence, mode, &control)
}

fn discover_temporary(fixture: &Fixture) -> Discovery {
    discover_temporary_with(
        fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        limits(),
        &later_clock(),
    )
    .unwrap()
}

#[test]
fn a_sealed_expired_item_is_a_candidate_with_its_evidence() {
    let fixture = temporary_fixture();
    let item = add_item(&fixture, "item-a", |_| {});
    let discovery = discover_temporary(&fixture);

    assert_eq!(discovery.completion, DiscoveryCompletion::Finished);
    assert_eq!(discovery.skipped.len(), 0, "{:?}", discovery.skipped);
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(discovery.root.object, object_of(fixture.root()));
    let found = candidate_of(&discovery, "item-a");

    // The identity evidence that the executor examines again.
    assert_eq!(found.evidence.object, object_of(&item));
    assert_eq!(found.evidence.object_type, FileObjectType::Directory);
    assert_eq!(found.evidence.owner, fixture.principal);
    let binding = found.file_binding();
    assert_eq!(binding.root_id, fixture.binding.root_id);
    assert_eq!(binding.relative_entry.as_utf8(), Some("item-a"));
    assert_eq!(binding.object, Some(object_of(&item)));
    assert_eq!(binding.rule.as_ref(), Some(&discovery.rule));
    assert_eq!(binding.charge, found.measurement.charge);

    // The sizes. The items are four names below the item and the item.
    let measurement = &found.measurement;
    assert_eq!(measurement.source, MeasurementSource::Scanned);
    assert_eq!(measurement.charge.items, EntryCount::new(5));
    assert_eq!(measurement.files, EntryCount::new(3));
    assert_eq!(measurement.directories, EntryCount::new(1));
    assert!(measurement.logical_bytes.get() >= 4_196);
    assert!(measurement.charge.work_bytes >= measurement.logical_bytes);
    assert!(measurement.charge.work_bytes >= measurement.allocated_bytes);
    // On a volume that reports the private size, the estimate is the
    // private allocated size; otherwise it is the allocated size. Neither
    // is marked as exclusive. The files of the fixture have no clones, so
    // the two sizes are equal.
    if let Some(private) = measurement.private_allocated_bytes.value() {
        assert_eq!(measurement.estimate.bytes, private);
        assert_eq!(
            measurement.estimate.measure,
            SizeMeasure::PrivateAllocatedBytes
        );
        assert_eq!(private, measurement.allocated_bytes);
    } else {
        assert_eq!(measurement.estimate.bytes, measurement.allocated_bytes);
        assert_eq!(measurement.estimate.measure, SizeMeasure::AllocatedBytes);
    }
    assert!(!measurement.estimate.exclusive_storage_known);

    // The facts. Predicates 3, 9, and 10 belong to admission.
    let record: &RuleCandidateRecord = &found.candidate;
    let facts = &record.eligibility;
    for fact in [
        &facts.rule_supports_layout,
        &facts.identity_matches,
        &facts.regenerable,
        &facts.age_and_inactivity,
        &facts.protocols_valid,
        &facts.no_exclusion_overlap,
        &facts.unit_and_charge_known,
    ] {
        assert_eq!(fact, &Fact::Satisfied);
    }
    for fact in [
        &facts.within_authorized_scope,
        &facts.resources_available,
        &facts.fresh_check,
    ] {
        assert_eq!(fact, &Fact::Unknown);
    }
    assert_eq!(found.blockers.len(), 0);
    assert!(!found.candidate.is_eligible());
    let policy_facts = &record.candidate.facts;
    assert_eq!(policy_facts.owner, OwnerFact::RequestingUser);
    assert_eq!(policy_facts.hard_protection, ProtectionFact::NotProtected);
    assert!(matches!(
        policy_facts.activity,
        ActivityFact::Inactive { .. }
    ));
    assert_eq!(
        record.candidate.estimated_reclaimable_bytes,
        Some(measurement.estimate.bytes)
    );
}

#[test]
fn a_candidate_of_a_proposed_rule_is_not_ready_after_admission_facts() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let discovery = discover_temporary(&fixture);
    let found = candidate_of(&discovery, "item-a");
    let registry = ReviewedRules::new().unwrap();
    let rule: &Rule = registry.lookup(&discovery.rule).unwrap();

    assert_eq!(found.lifecycle, LifecycleState::Proposed);
    for mode in RuleMode::ALL {
        assert!(!found.permits(&mode));
    }
    // Each predicate can be satisfied, and the rule is still not ready for
    // automatic action: the lifecycle state is part of the candidate.
    let admitted: RuleCandidate = found
        .with_admission_facts(rule, Fact::Satisfied, Fact::Satisfied, Fact::Satisfied)
        .unwrap();
    assert!(admitted.is_eligible());
    assert_eq!(
        admitted.candidate.facts.rule_readiness,
        RuleReadiness::NotReady
    );
}

#[test]
fn a_root_with_no_valid_marker_is_not_a_temporary_root() {
    // No marker.
    let fixture = Fixture::new("Temporary");
    let item = fixture.root().join("item-a");
    fs::create_dir(&item).unwrap();
    let error = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        limits(),
        &later_clock(),
    )
    .unwrap_err();
    assert!(matches!(error, DiscoveryError::RootNotClassified));

    // A marker that names another directory: a copied namespace.
    let marker = TemporaryRootMarker {
        schema_version: TEMPORARY_SCHEMA_VERSION,
        kind: ROOT_MARKER_KIND.to_owned(),
        owner_uid: fixture.principal.get(),
        directory: object_of(&item),
    };
    fs::write(
        fixture.root().join(ROOT_MARKER_NAME),
        serde_json::to_vec(&marker).unwrap(),
    )
    .unwrap();
    let error = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        limits(),
        &later_clock(),
    )
    .unwrap_err();
    assert!(matches!(error, DiscoveryError::RootNotClassified));
}

/// The valid marker of the root of `fixture`, as JSON.
fn valid_marker(fixture: &Fixture) -> serde_json::Value {
    serde_json::to_value(TemporaryRootMarker {
        schema_version: TEMPORARY_SCHEMA_VERSION,
        kind: ROOT_MARKER_KIND.to_owned(),
        owner_uid: fixture.principal.get(),
        directory: object_of(fixture.root()),
    })
    .unwrap()
}

#[test]
fn an_item_that_is_a_symbolic_link_a_deep_tree_and_a_large_record_are_not_candidates() {
    let fixture = temporary_fixture();
    // A unit that is a symbolic link to a valid item outside the root.
    let outside = fixture.base().join("outside");
    fs::create_dir(&outside).unwrap();
    let real = outside.join("real-item");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("part.bin"), b"x").unwrap();
    symlink(&real, fixture.root().join("linked-item")).unwrap();
    // A tree that is deeper than `max_depth`.
    let deep = add_item(&fixture, "deep", |_| {});
    fs::create_dir_all(deep.join("l1/l2/l3/l4")).unwrap();
    // A record above the read limit.
    add_item(&fixture, "large-record", |record| {
        record.purpose = "p".repeat(20_000);
    });

    let discovery = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        DiscoveryLimits {
            max_depth: 3,
            ..limits()
        },
        &later_clock(),
    )
    .unwrap();

    assert_eq!(discovery.candidates.len(), 0, "{:?}", discovery.candidates);
    for (name, reason) in [
        ("linked-item", SkipReason::SymbolicLink),
        ("deep", SkipReason::MeasurementIncomplete),
        ("large-record", SkipReason::RecordInvalid),
    ] {
        assert_eq!(skip_of(&discovery, name).reasons, [reason], "{name}");
    }
    assert_eq!(fs::read(real.join("part.bin")).unwrap(), b"x");
}

#[test]
fn a_forged_root_marker_does_not_classify_the_root() {
    // Each marker differs from a valid one in one respect.
    type Forge = fn(&Fixture, &Path);
    let cases: [(&str, Forge); 6] = [
        ("another owner", |fixture, marker| {
            let mut value = valid_marker(fixture);
            value["owner_uid"] = serde_json::json!(fixture.principal.get() ^ 1);
            fs::write(marker, serde_json::to_vec(&value).unwrap()).unwrap();
        }),
        ("another kind", |fixture, marker| {
            let mut value = valid_marker(fixture);
            value["kind"] = serde_json::json!("other_kind");
            fs::write(marker, serde_json::to_vec(&value).unwrap()).unwrap();
        }),
        ("another schema version", |fixture, marker| {
            let mut value = valid_marker(fixture);
            value["schema_version"] = serde_json::json!(TEMPORARY_SCHEMA_VERSION + 1);
            fs::write(marker, serde_json::to_vec(&value).unwrap()).unwrap();
        }),
        ("malformed JSON", |_, marker| {
            fs::write(marker, b"{ not json").unwrap();
        }),
        ("a symbolic link", |fixture, marker| {
            let real = fixture.base().join("real-marker.json");
            fs::write(&real, serde_json::to_vec(&valid_marker(fixture)).unwrap()).unwrap();
            symlink(&real, marker).unwrap();
        }),
        ("a hard link", |fixture, marker| {
            let real = fixture.base().join("real-marker.json");
            fs::write(&real, serde_json::to_vec(&valid_marker(fixture)).unwrap()).unwrap();
            fs::hard_link(&real, marker).unwrap();
        }),
    ];
    // The control: the unchanged valid marker classifies the root.
    let fixture = Fixture::new("Temporary");
    fs::create_dir(fixture.root().join("item-a")).unwrap();
    let marker: PathBuf = fixture.root().join(ROOT_MARKER_NAME);
    fs::write(
        &marker,
        serde_json::to_vec(&valid_marker(&fixture)).unwrap(),
    )
    .unwrap();
    let control = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        limits(),
        &later_clock(),
    );
    assert!(control.is_ok(), "a valid marker: {:?}", control.err());
    for (name, forge) in cases {
        let fixture = Fixture::new("Temporary");
        fs::create_dir(fixture.root().join("item-a")).unwrap();
        forge(&fixture, &fixture.root().join(ROOT_MARKER_NAME));
        let error = discover_temporary_with(
            &fixture,
            NO_LEASES,
            DiscoveryMode::Full,
            limits(),
            &later_clock(),
        )
        .unwrap_err();
        assert!(
            matches!(error, DiscoveryError::RootNotClassified),
            "{name}: {error:?}"
        );
    }
}

#[test]
fn a_root_that_fails_a_check_is_rejected() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let discover = |fixture: &Fixture| {
        discover_temporary_with(
            fixture,
            NO_LEASES,
            DiscoveryMode::Full,
            limits(),
            &later_clock(),
        )
        .unwrap_err()
    };

    // A symbolic link to the root is not the root.
    let mut linked = temporary_fixture();
    let link = linked.base().join("link");
    symlink(fixture.root(), &link).unwrap();
    linked.binding.path = link;
    assert!(matches!(
        discover(&linked),
        DiscoveryError::RootNotDirectory
    ));

    // A path with a symbolic link in an ancestor is not a root: the
    // executor does not follow the link, and the overlap resolution
    // compares plain paths.
    let mut aliased = temporary_fixture();
    let alias = aliased.base().join("alias");
    symlink(fixture.base(), &alias).unwrap();
    aliased.binding.path = alias.join(fixture.root().file_name().unwrap());
    assert!(matches!(discover(&aliased), DiscoveryError::RootPath));

    // A relative path and a path with `..`.
    let mut relative = temporary_fixture();
    relative.binding.path = PathBuf::from("Temporary");
    assert!(matches!(discover(&relative), DiscoveryError::RootPath));
    let mut dotted = temporary_fixture();
    dotted.binding.path = dotted.root().join("../Temporary");
    assert!(matches!(discover(&dotted), DiscoveryError::RootPath));

    // Another device, another owner, and a root that is gone.
    let mut other_device = temporary_fixture();
    other_device.binding.device = DeviceNumber::new(other_device.binding.device.get() ^ 1);
    assert!(matches!(
        discover(&other_device),
        DiscoveryError::RootDevice
    ));
    let mut other_owner = temporary_fixture();
    other_owner.principal = Uid::new(other_owner.principal.get() ^ 1);
    assert!(matches!(discover(&other_owner), DiscoveryError::RootOwner));
    let mut absent = temporary_fixture();
    absent.binding.path = absent.base().join("absent");
    assert!(matches!(
        discover(&absent),
        DiscoveryError::RootUnavailable(_)
    ));

    // A root in a protected path, and a root that contains one.
    let mut inside = temporary_fixture();
    inside.protected = vec![inside.base().to_path_buf()];
    assert!(matches!(
        discover(&inside),
        DiscoveryError::RootOverlapsProtected
    ));
    let mut contains = temporary_fixture();
    contains.protected = vec![contains.root().join("item-a/state")];
    assert!(matches!(
        discover(&contains),
        DiscoveryError::RootOverlapsProtected
    ));
}

#[test]
fn a_directory_with_no_matching_record_is_not_an_item() {
    let fixture = temporary_fixture();
    // A name alone does not make a directory an item.
    fs::create_dir(fixture.root().join("looks-temporary")).unwrap();
    fs::write(fixture.root().join("looks-temporary/data"), b"x").unwrap();
    // A record that is not JSON of the schema.
    let invalid = add_item(&fixture, "invalid", |_| {});
    fs::write(invalid.join(ITEM_RECORD_NAME), b"{\"kind\":").unwrap();
    // A record of another schema version.
    add_item(&fixture, "newer", |record| record.schema_version = 2);
    // A record that names another directory: a copied or substituted
    // record, or a name that was used again.
    let other = add_item(&fixture, "other", |_| {});
    add_item(&fixture, "substituted", |record| {
        record.directory = object_of(&other);
    });
    // A record of another owner.
    add_item(&fixture, "foreign", |record| record.owner_uid ^= 1);
    // A record that is a symbolic link to a valid record.
    let linked = add_item(&fixture, "linked", |_| {});
    fs::rename(linked.join(ITEM_RECORD_NAME), linked.join("real.json")).unwrap();
    symlink(linked.join("real.json"), linked.join(ITEM_RECORD_NAME)).unwrap();
    // A plain file and a symbolic link in the place of an item.
    fs::write(fixture.root().join("stray.txt"), b"x").unwrap();
    symlink(&other, fixture.root().join("alias")).unwrap();

    let discovery = discover_temporary(&fixture);
    let reasons = |name: &str| skip_of(&discovery, name).reasons.clone();
    assert_eq!(reasons("looks-temporary"), [SkipReason::UnsupportedLayout]);
    assert_eq!(reasons("invalid"), [SkipReason::RecordInvalid]);
    assert_eq!(reasons("newer"), [SkipReason::UnsupportedLayout]);
    assert_eq!(reasons("substituted"), [SkipReason::RecordMismatch]);
    assert_eq!(reasons("foreign"), [SkipReason::WrongOwner]);
    assert_eq!(reasons("linked"), [SkipReason::RecordInvalid]);
    assert_eq!(reasons("stray.txt"), [SkipReason::UnsupportedLayout]);
    assert_eq!(reasons("alias"), [SkipReason::SymbolicLink]);
    // Only the item with a valid record is a candidate.
    assert_eq!(discovery.candidates.len(), 1);
    candidate_of(&discovery, "other");

    let substituted = skip_of(&discovery, "substituted");
    assert_eq!(substituted.eligibility.identity_matches, Fact::NotSatisfied);
    // A directory that is not positively an item is not measured.
    assert_eq!(substituted.eligibility.unit_and_charge_known, Fact::Unknown);
    assert_eq!(
        skip_of(&discovery, "looks-temporary")
            .eligibility
            .rule_supports_layout,
        Fact::NotSatisfied
    );
    assert_eq!(
        SkipReason::RecordMismatch.category(),
        SkipCategory::StaleIdentity
    );
}

#[test]
fn a_name_below_an_item_that_is_not_valid_utf8_is_protected_data() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    let fixture = temporary_fixture();
    let item = add_item(&fixture, "odd", |_| {});
    // Some volumes refuse a name that is not valid UTF-8; then no entry is
    // made and the test has nothing to show.
    if fs::write(item.join(OsStr::from_bytes(b"bad-\xff.bin")), b"x").is_err() {
        eprintln!("skipped: the volume refuses a name that is not valid UTF-8");
        return;
    }
    let discovery = discover_temporary(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        skip_of(&discovery, "odd").reasons,
        [SkipReason::ProtectedData]
    );
}

#[test]
fn an_item_with_content_that_the_rule_preserves_is_skipped() {
    let mut fixture = temporary_fixture();
    add_item(&fixture, "export", |record| {
        record.content = "completed_export".to_owned();
    });
    let database = add_item(&fixture, "database", |_| {});
    fs::write(database.join("nested/operations.sqlite"), b"x").unwrap();
    let journal = add_item(&fixture, "journal", |_| {});
    fs::write(journal.join("catalog.db-wal"), b"x").unwrap();
    add_item(&fixture, "excluded", |_| {});
    add_item(&fixture, "excluded-below", |_| {});
    fixture.excluded = vec![
        fixture.root().join("excluded"),
        fixture.root().join("excluded-below/nested/part-2.bin"),
    ];

    let discovery = discover_temporary(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    let export = skip_of(&discovery, "export");
    assert_eq!(export.reasons, [SkipReason::NotRegenerable]);
    assert_eq!(export.eligibility.regenerable, Fact::NotSatisfied);
    for name in ["database", "journal"] {
        let skipped = skip_of(&discovery, name);
        assert_eq!(skipped.reasons, [SkipReason::ProtectedData]);
        assert_eq!(skipped.eligibility.no_exclusion_overlap, Fact::NotSatisfied);
    }
    // An exclusion applies to the unit and to a parent of the excluded
    // entry: the removal of the parent would remove the entry.
    for name in ["excluded", "excluded-below"] {
        let skipped = skip_of(&discovery, name);
        assert_eq!(skipped.reasons, [SkipReason::ExclusionOverlap]);
        assert_eq!(skipped.eligibility.no_exclusion_overlap, Fact::NotSatisfied);
    }
}

#[test]
fn an_item_that_holds_a_repository_is_skipped() {
    let fixture = temporary_fixture();
    let clone: PathBuf = fixture.root().join("clone");
    add_item(&fixture, "clone", |_| {
        fs::create_dir_all(clone.join("nested/dep/.git/objects")).unwrap();
        fs::write(
            clone.join("nested/dep/.git/HEAD"),
            b"ref: refs/heads/main\n",
        )
        .unwrap();
    });
    let gitlink: PathBuf = fixture.root().join("gitlink");
    add_item(&fixture, "gitlink", |_| {
        fs::write(gitlink.join(".git"), b"gitdir: ../elsewhere\n").unwrap();
    });
    add_item(&fixture, "plain", |_| {});

    let discovery = discover_temporary(&fixture);
    candidate_of(&discovery, "plain");
    for (name, marker) in [("clone", "nested/dep/.git"), ("gitlink", ".git")] {
        let skipped = skip_of(&discovery, name);
        assert!(
            skipped.reasons.contains(&SkipReason::NestedRepository),
            "{name}: {:?}",
            skipped.reasons
        );
        assert_eq!(skipped.eligibility.regenerable, Fact::NotSatisfied);
        assert_eq!(
            skipped
                .repository_marker
                .as_ref()
                .and_then(svalnir_core::file::LosslessPath::as_utf8),
            Some(marker)
        );
    }
}

/// The time that a discovery on a FIFO can take. A discovery that opens the
/// FIFO for reading never ends.
const FIFO_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs `discover` on a second thread and waits for its result. The test
/// fails at the timeout, so that a discovery that blocks on a FIFO does not
/// block the test run.
fn discovery_within_timeout(
    fixture: Fixture,
    discover: impl FnOnce(&Fixture) -> Discovery + Send + 'static,
) -> Discovery {
    let (sender, receiver) = std::sync::mpsc::channel::<Discovery>();
    std::thread::spawn(move || {
        // The receiver is gone only after the timeout.
        let discovery: Discovery = discover(&fixture);
        if sender.send(discovery).is_err() {
            // The test has failed at the timeout. Nobody reads the result.
        }
    });
    match receiver.recv_timeout(FIFO_DISCOVERY_TIMEOUT) {
        Ok(discovery) => discovery,
        Err(error) => panic!("the discovery did not end, it can have opened a FIFO: {error}"),
    }
}

/// Makes a FIFO at `path`.
fn make_fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;

    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `name` is a NUL-terminated path that lives through the call,
    // and `mkfifo` keeps no pointer.
    let status: libc::c_int = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(status, 0, "{}", io::Error::last_os_error());
}

#[test]
fn an_item_with_a_fifo_is_skipped_and_the_fifo_is_not_opened() {
    let fixture = temporary_fixture();
    let item = add_item(&fixture, "with-fifo", |_| {});
    make_fifo(&item.join("nested/pipe"));

    // An open of the FIFO for reading would block this test.
    let discovery = discovery_within_timeout(fixture, discover_temporary);

    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        skip_of(&discovery, "with-fifo").reasons,
        [SkipReason::UnsupportedObject]
    );
}

#[test]
fn an_item_with_a_link_or_a_special_object_is_skipped() {
    let fixture = temporary_fixture();
    let outside: PathBuf = fixture.base().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep.bin"), vec![7_u8; 50_000]).unwrap();

    let with_link = add_item(&fixture, "with-link", |_| {});
    symlink(&outside, with_link.join("nested/escape")).unwrap();
    let with_hard_link = add_item(&fixture, "with-hard-link", |_| {});
    fs::hard_link(outside.join("keep.bin"), with_hard_link.join("second-name")).unwrap();

    let discovery = discover_temporary(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    let link = skip_of(&discovery, "with-link");
    assert_eq!(link.reasons, [SkipReason::SymbolicLink]);
    assert_eq!(link.eligibility.protocols_valid, Fact::NotSatisfied);
    assert_eq!(
        SkipReason::SymbolicLink.category(),
        SkipCategory::UnsafeNamespace
    );
    let hard_link = skip_of(&discovery, "with-hard-link");
    assert_eq!(hard_link.reasons, [SkipReason::HardLinked]);
    assert_eq!(
        hard_link.eligibility.unit_and_charge_known,
        Fact::NotSatisfied
    );
    // The discovery changed nothing outside the root.
    assert_eq!(fs::read(outside.join("keep.bin")).unwrap().len(), 50_000);
}

#[test]
fn an_item_that_is_not_sealed_or_changed_after_its_seal_is_skipped() {
    let fixture = temporary_fixture();
    // A crash before the seal leaves an open record.
    add_item(&fixture, "open", |record| record.sealed_at = None);
    // The directory changed long after the recorded seal.
    add_item(&fixture, "written-later", |record| {
        record.created_at = real_now_plus(-3 * DAY_SECONDS);
        record.sealed_at = Some(real_now_plus(-2 * DAY_SECONDS));
    });

    let discovery = discover_temporary(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    let open = skip_of(&discovery, "open");
    assert_eq!(open.reasons, [SkipReason::NotSealed]);
    assert_eq!(open.eligibility.protocols_valid, Fact::NotSatisfied);
    assert_eq!(open.eligibility.age_and_inactivity, Fact::NotSatisfied);
    let later = skip_of(&discovery, "written-later");
    assert_eq!(later.reasons, [SkipReason::ModifiedAfterSeal]);
    assert_eq!(later.eligibility.protocols_valid, Fact::NotSatisfied);
}

#[test]
fn the_age_and_the_leases_decide_predicate_five() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let blockers = |evidence: TemporaryEvidence<'_>, clock: &FixedClock| {
        let discovery =
            discover_temporary_with(&fixture, evidence, DiscoveryMode::Full, limits(), clock)
                .unwrap();
        let found = candidate_of(&discovery, "item-a");
        let record: &RuleCandidateRecord = &found.candidate;
        (
            found.blockers.clone(),
            record.eligibility.age_and_inactivity.clone(),
            record.candidate.facts.activity,
        )
    };

    // The retention of the record did not end: the clock is before the
    // expiry.
    let (reasons, fact, activity) = blockers(NO_LEASES, &FixedClock(Some(real_now_plus(300))));
    assert_eq!(reasons, [SkipReason::RetentionNotElapsed]);
    assert_eq!(fact, Fact::NotSatisfied);
    assert_eq!(activity, ActivityFact::Unknown);

    // The retention ended, and the minimum age of the rule after the seal
    // did not.
    let (reasons, fact, _) = blockers(NO_LEASES, &FixedClock(Some(real_now_plus(1_800))));
    assert_eq!(reasons, [SkipReason::RetentionNotElapsed]);
    assert_eq!(fact, Fact::NotSatisfied);

    // A clock that gives no time: the age is unknown, not elapsed.
    let (reasons, fact, activity) = blockers(NO_LEASES, &FixedClock(None));
    assert_eq!(reasons, [SkipReason::AgeUnknown]);
    assert_eq!(fact, Fact::Unknown);
    assert_eq!(activity, ActivityFact::Unknown);

    // A seal that is later than the time now.
    let (reasons, fact, _) = blockers(NO_LEASES, &FixedClock(Some(real_now_plus(-DAY_SECONDS))));
    assert_eq!(reasons, [SkipReason::FutureTimestamp]);
    assert_eq!(fact, Fact::Unknown);

    // The caller did not reconcile the leases: unknown, not free.
    let unknown = TemporaryEvidence {
        leases: UseLeases::Unknown,
    };
    let (reasons, fact, activity) = blockers(unknown, &later_clock());
    assert_eq!(reasons, [SkipReason::ActivityUnknown]);
    assert_eq!(fact, Fact::Unknown);
    assert_eq!(activity, ActivityFact::Unknown);

    // A live operation has a use lease on the item.
    let live = ["lifecycle-item-a".to_owned()];
    let leased = TemporaryEvidence {
        leases: UseLeases::Known(&live),
    };
    let (reasons, fact, activity) = blockers(leased, &later_clock());
    assert_eq!(reasons, [SkipReason::ActiveProducer]);
    assert_eq!(fact, Fact::NotSatisfied);
    assert_eq!(activity, ActivityFact::Active);

    // A lease on another item does not block this item.
    let other = ["lifecycle-item-b".to_owned()];
    let (reasons, fact, _) = blockers(
        TemporaryEvidence {
            leases: UseLeases::Known(&other),
        },
        &later_clock(),
    );
    assert_eq!(reasons.len(), 0);
    assert_eq!(fact, Fact::Satisfied);
}

#[test]
fn an_item_that_changes_before_the_evidence_snapshot_is_skipped() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let registry = ReviewedRules::new().unwrap();
    let cancel = CancellationToken::new();
    let clock = later_clock();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    // A writer adds a file after the measurement.
    let mut write_after = |item: &Path| fs::write(item.join("late.bin"), b"late").unwrap();
    let discovery = registry
        .expired_temporary()
        .discover_with(
            &fixture.scope(),
            NO_LEASES,
            DiscoveryMode::Full,
            &control,
            &mut write_after,
        )
        .unwrap();
    assert_eq!(discovery.candidates.len(), 0);
    let skipped = skip_of(&discovery, "item-a");
    assert_eq!(skipped.reasons, [SkipReason::IdentityChanged]);
    assert_eq!(skipped.eligibility.identity_matches, Fact::NotSatisfied);

    // The record is replaced after the measurement.
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let mut replace_record = |item: &Path| {
        let mut record = sealed_record(&fixture, item, "lifecycle-other");
        record.purpose = "another purpose".to_owned();
        let staged = item.join("staged.json");
        fs::write(&staged, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::rename(&staged, item.join(ITEM_RECORD_NAME)).unwrap();
    };
    let discovery = registry
        .expired_temporary()
        .discover_with(
            &fixture.scope(),
            NO_LEASES,
            DiscoveryMode::Full,
            &control,
            &mut replace_record,
        )
        .unwrap();
    assert_eq!(
        skip_of(&discovery, "item-a").reasons,
        [SkipReason::IdentityChanged]
    );
}

#[test]
fn a_root_that_is_replaced_during_the_discovery_gives_no_result() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let registry = ReviewedRules::new().unwrap();
    let cancel = CancellationToken::new();
    let clock = later_clock();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let root: PathBuf = fixture.root().to_path_buf();
    let moved: PathBuf = fixture.base().join("moved");
    let mut replace_root = |_: &Path| {
        if root.exists() && !moved.exists() {
            fs::rename(&root, &moved).unwrap();
            fs::create_dir(&root).unwrap();
        }
    };
    let error = registry
        .expired_temporary()
        .discover_with(
            &fixture.scope(),
            NO_LEASES,
            DiscoveryMode::Full,
            &control,
            &mut replace_root,
        )
        .unwrap_err();
    assert!(matches!(error, DiscoveryError::RootChanged));
}

#[test]
fn a_root_marker_that_is_removed_during_the_discovery_gives_no_result() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let registry = ReviewedRules::new().unwrap();
    let cancel = CancellationToken::new();
    let clock = later_clock();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let marker: PathBuf = fixture.root().join(ROOT_MARKER_NAME);
    let marker_bytes: Vec<u8> = fs::read(&marker).unwrap();
    let known = discover_temporary(&fixture).candidates;
    assert_eq!(known.len(), 1);
    for mode in [
        DiscoveryMode::Full,
        DiscoveryMode::KnownCandidatesOnly(&known),
    ] {
        let mut remove_marker = |_: &Path| {
            fs::remove_file(&marker).unwrap();
        };
        let error = registry
            .expired_temporary()
            .discover_with(
                &fixture.scope(),
                NO_LEASES,
                mode,
                &control,
                &mut remove_marker,
            )
            .unwrap_err();
        assert!(matches!(error, DiscoveryError::RootNotClassified));
        // The marker is back for the next run.
        fs::write(&marker, &marker_bytes).unwrap();
    }
}

#[test]
fn a_candidate_with_a_lifecycle_that_is_not_that_of_the_registry_is_not_claimed() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let discovery = discover_temporary(&fixture);
    let candidate: DiscoveredCandidate = candidate_of(&discovery, "item-a").clone();
    let registry = ReviewedRules::new().unwrap();

    // The candidate as discovered is claimed.
    let claimed = registry.claim(vec![candidate.clone()]).unwrap();
    assert_eq!(claimed.candidates.len(), 1);

    // A state that the registry does not record for the layout is refused.
    let mut other_state = candidate.clone();
    other_state.lifecycle = LifecycleState::Disabled {
        inspection_permitted: true,
    };
    assert_eq!(
        registry.claim(vec![other_state]).err(),
        Some(ClaimError::LifecycleMismatch)
    );
}

#[test]
fn the_bounds_stop_a_discovery() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    add_item(&fixture, "item-b", |_| {});
    let discover = |limits: DiscoveryLimits| {
        discover_temporary_with(
            &fixture,
            NO_LEASES,
            DiscoveryMode::Full,
            limits,
            &later_clock(),
        )
        .unwrap()
    };

    // The unit limit: the second name is not examined.
    let one_unit = discover(DiscoveryLimits {
        max_units: 1,
        ..limits()
    });
    assert_eq!(one_unit.completion, DiscoveryCompletion::UnitLimitReached);
    assert_eq!(one_unit.units_examined, 1);
    assert_eq!(one_unit.candidates.len(), 1);

    // The entry limit: the first item has four names, so the second item
    // is not measured, and an item that is not measured is not a
    // candidate.
    let few_entries = discover(DiscoveryLimits {
        max_entries: EntryCount::new(5),
        ..limits()
    });
    assert_eq!(
        few_entries.completion,
        DiscoveryCompletion::EntryLimitReached
    );
    assert_eq!(few_entries.candidates.len(), 1);
    assert!(few_entries.entries_examined <= EntryCount::new(5));
    let no_entries = discover(DiscoveryLimits {
        max_entries: EntryCount::new(2),
        ..limits()
    });
    assert_eq!(
        no_entries.completion,
        DiscoveryCompletion::EntryLimitReached
    );
    assert_eq!(no_entries.candidates.len(), 0);

    // The time limit.
    let no_time = discover(DiscoveryLimits {
        max_duration: Duration::ZERO,
        ..limits()
    });
    assert_eq!(no_time.completion, DiscoveryCompletion::TimeLimitReached);
    assert_eq!(no_time.candidates.len(), 0);
    assert_eq!(no_time.units_examined, 0);

    // The candidate limit.
    let one_candidate = discover(DiscoveryLimits {
        max_candidates: 1,
        ..limits()
    });
    assert_eq!(
        one_candidate.completion,
        DiscoveryCompletion::CandidateLimitReached
    );
    assert_eq!(one_candidate.candidates.len(), 1);

    // The skip limit: a skip above it is counted and not recorded.
    fs::create_dir(fixture.root().join("unknown-1")).unwrap();
    fs::create_dir(fixture.root().join("unknown-2")).unwrap();
    let few_skips = discover(DiscoveryLimits {
        max_skipped: 1,
        ..limits()
    });
    assert_eq!(few_skips.completion, DiscoveryCompletion::Finished);
    assert_eq!(few_skips.skipped.len(), 1);
    assert_eq!(few_skips.skipped_omitted, 1);

    // A limit above its maximum is rejected before any read.
    let error = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        DiscoveryLimits {
            max_depth: u32::MAX,
            ..limits()
        },
        &later_clock(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DiscoveryError::LimitTooLarge { field: "max_depth" }
    ));
}

#[test]
fn a_cancelled_discovery_stops() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    add_item(&fixture, "item-b", |_| {});
    let registry = ReviewedRules::new().unwrap();
    let clock = later_clock();

    // Cancelled before the start.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let discovery = registry
        .expired_temporary()
        .discover(&fixture.scope(), NO_LEASES, DiscoveryMode::Full, &control)
        .unwrap();
    assert_eq!(discovery.completion, DiscoveryCompletion::Cancelled);
    assert_eq!(discovery.candidates.len(), 0);

    // Cancelled after the first item: the second item is not examined.
    let cancel = CancellationToken::new();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let mut cancel_after_first = |_: &Path| cancel.cancel();
    let discovery = registry
        .expired_temporary()
        .discover_with(
            &fixture.scope(),
            NO_LEASES,
            DiscoveryMode::Full,
            &control,
            &mut cancel_after_first,
        )
        .unwrap();
    assert_eq!(discovery.completion, DiscoveryCompletion::Cancelled);
    assert_eq!(discovery.units_examined, 1);
    assert_eq!(discovery.candidates.len(), 1);
}

#[test]
fn a_unit_over_the_candidate_ceiling_is_skipped_and_not_split() {
    let fixture = temporary_fixture();
    let item = add_item(&fixture, "large", |_| {});
    // A sparse file: the logical size is over the byte ceiling of one
    // candidate, and the file uses no storage.
    let sparse = File::create(item.join("sparse.bin")).unwrap();
    sparse.set_len((1 << 30) + 1).unwrap();
    drop(sparse);

    let discovery = discover_temporary(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    let skipped = skip_of(&discovery, "large");
    assert_eq!(skipped.reasons, [SkipReason::OverCandidateCeiling]);
    assert_eq!(
        SkipReason::OverCandidateCeiling.category(),
        SkipCategory::BudgetExhaustion
    );
}

#[test]
fn known_candidates_are_examined_again_with_no_listing_and_no_measurement() {
    let fixture = temporary_fixture();
    let item_a = add_item(&fixture, "item-a", |_| {});
    let item_b = add_item(&fixture, "item-b", |_| {});
    add_item(&fixture, "item-c", |_| {});
    let full = discover_temporary(&fixture);
    assert_eq!(full.candidates.len(), 3);
    // A new item after the full discovery is not known.
    add_item(&fixture, "item-new", |_| {});

    let known = |candidates: &[DiscoveredCandidate]| {
        discover_temporary_with(
            &fixture,
            NO_LEASES,
            DiscoveryMode::KnownCandidatesOnly(candidates),
            limits(),
            &later_clock(),
        )
    };
    let again = known(&full.candidates).unwrap();
    assert_eq!(again.completion, DiscoveryCompletion::Finished);
    assert_eq!(again.units_examined, 3);
    // No name was measured, and no new item was found.
    assert_eq!(again.entries_examined, EntryCount::ZERO);
    assert_eq!(again.candidates.len(), 3);
    let carried = candidate_of(&again, "item-a");
    assert_eq!(
        carried.measurement.source,
        MeasurementSource::CarriedFromEarlierDiscovery
    );
    assert_eq!(
        carried.measurement.charge,
        candidate_of(&full, "item-a").measurement.charge
    );

    // An item that changed has no current charge, and one that is gone is
    // not a candidate. The third item stays a candidate.
    fs::write(item_a.join("more.bin"), vec![0_u8; 10_000]).unwrap();
    fs::remove_dir_all(&item_b).unwrap();
    let changed = known(&full.candidates).unwrap();
    assert_eq!(changed.candidates.len(), 1);
    candidate_of(&changed, "item-c");
    let stale = skip_of(&changed, "item-a");
    assert_eq!(stale.reasons, [SkipReason::MeasurementStale]);
    assert_eq!(stale.eligibility.unit_and_charge_known, Fact::Unknown);
    assert_eq!(skip_of(&changed, "item-b").reasons, [SkipReason::Vanished]);

    // A candidate of another root is refused.
    let other = temporary_fixture();
    add_item(&other, "item-a", |_| {});
    let error = discover_temporary_with(
        &other,
        NO_LEASES,
        DiscoveryMode::KnownCandidatesOnly(&full.candidates),
        limits(),
        &later_clock(),
    )
    .unwrap_err();
    assert!(matches!(error, DiscoveryError::KnownCandidate));

    // More known candidates than the candidate limit are refused.
    let error = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::KnownCandidatesOnly(&full.candidates),
        DiscoveryLimits {
            max_candidates: 2,
            ..limits()
        },
        &later_clock(),
    )
    .unwrap_err();
    assert!(matches!(error, DiscoveryError::TooManyKnownCandidates));
}

#[test]
fn a_carried_measurement_older_than_the_measurement_expiry_gives_no_charge() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let measured_at: WallTime = real_now_plus(2 * DAY_SECONDS);
    let full = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        limits(),
        &FixedClock(Some(measured_at)),
    )
    .unwrap();
    assert_eq!(
        candidate_of(&full, "item-a").measurement.measured_at,
        Some(measured_at)
    );
    let registry = ReviewedRules::new().unwrap();
    let expiry: Nanoseconds = registry
        .expired_temporary()
        .rule()
        .budget
        .measurement_expiry;
    let expiry_seconds: i64 = i64::try_from(expiry.get() / 1_000_000_000).unwrap();
    let at = |seconds: i64| WallTime::from_unix(measured_at.unix_seconds() + seconds, 0).unwrap();
    let known = |clock: FixedClock| {
        discover_temporary_with(
            &fixture,
            NO_LEASES,
            DiscoveryMode::KnownCandidatesOnly(&full.candidates),
            limits(),
            &clock,
        )
        .unwrap()
    };

    // A measurement within the expiry is the charge.
    let fresh = known(FixedClock(Some(at(expiry_seconds))));
    let carried = candidate_of(&fresh, "item-a");
    assert_eq!(
        carried.measurement.source,
        MeasurementSource::CarriedFromEarlierDiscovery
    );
    assert_eq!(
        carried.candidate.eligibility.unit_and_charge_known,
        Fact::Satisfied
    );
    assert_eq!(fresh.entries_examined, EntryCount::ZERO);

    // An older measurement, and a measurement with a time after the time
    // now, give no charge. The discovery still measures nothing.
    for now in [at(expiry_seconds + 1), at(-1)] {
        let old = known(FixedClock(Some(now)));
        assert_eq!(old.candidates.len(), 0, "{now:?}");
        assert_eq!(old.entries_examined, EntryCount::ZERO);
        let skipped = skip_of(&old, "item-a");
        assert_eq!(skipped.reasons, [SkipReason::MeasurementExpired], "{now:?}");
        assert_eq!(skipped.eligibility.unit_and_charge_known, Fact::Unknown);
        assert_eq!(
            SkipReason::MeasurementExpired.category(),
            SkipCategory::UnknownWorkCharge
        );
    }

    // A clock with no wall-clock time gives no age.
    let no_time = known(FixedClock(None));
    assert!(
        skip_of(&no_time, "item-a")
            .reasons
            .contains(&SkipReason::MeasurementExpired)
    );
}

// ---------------------------------------------------------------------
// `xcode.inactive-derived-data`.
// ---------------------------------------------------------------------

fn info_plist(workspace: &Path, last_accessed: WallTime) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>LastAccessedDate</key>\n\t<date>{last_accessed}</date>\n\
         \t<key>WorkspacePath</key>\n\t<string>{}</string>\n\
         </dict>\n</plist>\n",
        workspace.display()
    )
}

/// Makes the Xcode project `NAME.xcodeproj` in the source directory of the
/// fixture, outside the `DerivedData` root.
fn add_workspace(fixture: &Fixture, name: &str) -> PathBuf {
    let workspace: PathBuf = fixture
        .base()
        .join("src")
        .join(name)
        .join(format!("{name}.xcodeproj"));
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("project.pbxproj"), b"// project").unwrap();
    workspace
}

/// Makes the project directory `name` with the three units and an
/// `info.plist` for `workspace`.
fn add_project(fixture: &Fixture, name: &str, workspace: &Path) -> PathBuf {
    let project: PathBuf = fixture.root().join(name);
    let build_data = project.join("Build/Intermediates.noindex/XCBuildData");
    fs::create_dir_all(&build_data).unwrap();
    fs::write(build_data.join("build.db"), vec![0_u8; 2_048]).unwrap();
    fs::create_dir_all(project.join("Build/Intermediates.noindex/App.build")).unwrap();
    fs::write(
        project.join("Build/Intermediates.noindex/App.build/App.o"),
        vec![1_u8; 3_000],
    )
    .unwrap();
    fs::create_dir_all(project.join("Build/Products/Debug/App.app")).unwrap();
    fs::write(
        project.join("Build/Products/Debug/App.app/App"),
        vec![2_u8; 5_000],
    )
    .unwrap();
    fs::create_dir_all(project.join("Index.noindex/DataStore/v5/records")).unwrap();
    fs::write(
        project.join("Index.noindex/DataStore/v5/records/AB"),
        vec![3_u8; 700],
    )
    .unwrap();
    fs::create_dir_all(project.join("Logs/Build")).unwrap();
    fs::write(project.join("Logs/Build/1.xcactivitylog"), b"log").unwrap();
    fs::write(
        project.join("info.plist"),
        info_plist(workspace, real_now_plus(-DAY_SECONDS)),
    )
    .unwrap();
    project
}

/// A `DerivedData` root with one project directory.
fn xcode_fixture() -> (Fixture, PathBuf) {
    let fixture = Fixture::new("DerivedData");
    let workspace = add_workspace(&fixture, "App");
    let project = add_project(&fixture, PROJECT, &workspace);
    (fixture, project)
}

const NOT_RUNNING: XcodeEvidence = XcodeEvidence {
    producer_processes: ProducerProcesses::NotRunning,
    observed_at: MONOTONIC_NOW,
};

/// A clock 30 days after the real time: each unit of [`add_project`] is
/// then older than the minimum age.
fn month_later_clock() -> FixedClock {
    FixedClock(Some(real_now_plus(30 * DAY_SECONDS)))
}

fn discover_xcode_with(
    rule: &XcodeDerivedDataRule,
    fixture: &Fixture,
    evidence: XcodeEvidence,
    mode: DiscoveryMode<'_>,
    clock: &dyn ScanClock,
) -> Result<Discovery, DiscoveryError> {
    let cancel = CancellationToken::new();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock,
    };
    rule.discover(&fixture.scope(), evidence, mode, &control)
}

fn discover_xcode(fixture: &Fixture) -> Discovery {
    let registry = ReviewedRules::new().unwrap();
    discover_xcode_with(
        registry.xcode_derived_data(),
        fixture,
        NOT_RUNNING,
        DiscoveryMode::Full,
        &month_later_clock(),
    )
    .unwrap()
}

fn unit(name: &str) -> String {
    format!("{PROJECT}/{name}")
}

#[test]
fn the_fixed_units_of_a_recognized_project_are_candidates() {
    let (fixture, project) = xcode_fixture();
    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.completion, DiscoveryCompletion::Finished);
    assert_eq!(discovery.skipped.len(), 0, "{:?}", discovery.skipped);

    // Three units. The project directory, its logs, and its `info.plist`
    // are not candidates.
    let mut found: Vec<&str> = discovery
        .candidates
        .iter()
        .map(|candidate| candidate.evidence.relative_entry.as_utf8().unwrap())
        .collect();
    found.sort_unstable();
    assert_eq!(
        found,
        [
            unit("Build/Intermediates.noindex"),
            unit("Build/Products"),
            unit("Index.noindex")
        ]
    );

    let intermediates = candidate_of(&discovery, &unit("Build/Intermediates.noindex"));
    assert_eq!(
        intermediates.evidence.object,
        object_of(&project.join("Build/Intermediates.noindex"))
    );
    assert_eq!(
        intermediates.evidence.object_type,
        FileObjectType::Directory
    );
    // The build database of the build system is part of the unit:
    // `XCBuildData`, `build.db`, `App.build`, `App.o`, and the unit.
    assert_eq!(intermediates.measurement.charge.items, EntryCount::new(5));
    assert_eq!(intermediates.blockers.len(), 0);
    assert_eq!(intermediates.lifecycle, LifecycleState::Proposed);
    let record: &RuleCandidateRecord = &intermediates.candidate;
    assert_eq!(record.layout, XCODE_DERIVED_DATA_LAYOUT);
    assert_eq!(record.eligibility.age_and_inactivity, Fact::Satisfied);
    assert_eq!(
        record.candidate.facts.rule_readiness,
        RuleReadiness::NotReady
    );
    assert_eq!(
        record.candidate.path.to_path_buf(),
        project.join("Build/Intermediates.noindex")
    );
}

/// The result of a discovery of the Xcode rule with `limits`.
fn discover_xcode_limited(fixture: &Fixture, limits: DiscoveryLimits) -> Discovery {
    let registry = ReviewedRules::new().unwrap();
    let cancel = CancellationToken::new();
    let clock = month_later_clock();
    let control = DiscoveryControl {
        limits,
        cancel: &cancel,
        clock: &clock,
    };
    registry
        .xcode_derived_data()
        .discover(&fixture.scope(), NOT_RUNNING, DiscoveryMode::Full, &control)
        .unwrap()
}

/// Asserts that each candidate of `partial` is a candidate of `full` with
/// the same measurement: a stopped discovery has no candidate with a
/// partial measurement.
fn assert_candidates_are_complete(partial: &Discovery, full: &Discovery) {
    for candidate in &partial.candidates {
        let name: &str = candidate.evidence.relative_entry.as_utf8().unwrap();
        let reference = &candidate_of(full, name).measurement;
        assert_eq!(candidate.measurement.charge.items, reference.charge.items);
        assert_eq!(candidate.measurement.logical_bytes, reference.logical_bytes);
    }
}

#[test]
fn an_info_plist_above_the_read_limit_is_a_record_that_is_not_valid() {
    let (fixture, project) = xcode_fixture();
    // The same fixture with a small `info.plist` has three candidates.
    assert_eq!(discover_xcode(&fixture).candidates.len(), 3);

    // A valid property list followed by a comment above 64 KiB.
    let mut text: String = fs::read_to_string(project.join("info.plist")).unwrap();
    text.push_str("<!-- ");
    text.push_str(&"x".repeat(70_000));
    text.push_str(" -->\n");
    fs::write(project.join("info.plist"), text).unwrap();

    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.completion, DiscoveryCompletion::Finished);
    assert_eq!(discovery.candidates.len(), 0, "{:?}", discovery.candidates);
    let skipped = skip_of(&discovery, PROJECT);
    assert_eq!(skipped.reasons, [SkipReason::RecordInvalid]);
    assert_eq!(skipped.eligibility.rule_supports_layout, Fact::NotSatisfied);
    // No unit of the project was measured.
    assert_eq!(discovery.entries_examined, EntryCount::ZERO);
    assert!(project.join("Build/Products/Debug/App.app/App").exists());
}

#[test]
fn a_discovery_that_reaches_the_unit_limit_does_not_examine_the_next_project() {
    let (fixture, _) = xcode_fixture();
    let workspace = fixture.base().join("src/App/App.xcodeproj");
    add_project(&fixture, "Second-abcdefghijklmnopqrstuvwxyzab", &workspace);
    let full = discover_xcode(&fixture);
    assert_eq!(full.completion, DiscoveryCompletion::Finished);
    assert_eq!(full.candidates.len(), 6);

    let one = discover_xcode_limited(
        &fixture,
        DiscoveryLimits {
            max_units: 1,
            ..limits()
        },
    );
    assert_eq!(one.completion, DiscoveryCompletion::UnitLimitReached);
    assert_eq!(one.units_examined, 1);
    // One project directory is one name: its three units are candidates,
    // and the second project directory has none.
    assert_eq!(one.candidates.len(), 3, "{:?}", one.skipped);
    assert_candidates_are_complete(&one, &full);
    let projects: std::collections::BTreeSet<&str> = one
        .candidates
        .iter()
        .filter_map(|candidate| candidate.evidence.relative_entry.as_utf8())
        .filter_map(|name| name.split('/').next())
        .collect();
    assert_eq!(projects.len(), 1);
}

#[test]
fn a_discovery_that_reaches_the_entry_limit_has_no_candidate_with_a_partial_measurement() {
    let (fixture, _) = xcode_fixture();
    let full = discover_xcode(&fixture);
    assert_eq!(full.candidates.len(), 3);

    let mut stopped: u32 = 0;
    for max in 0_u64..=20 {
        let partial = discover_xcode_limited(
            &fixture,
            DiscoveryLimits {
                max_entries: EntryCount::new(max),
                ..limits()
            },
        );
        assert!(partial.entries_examined <= EntryCount::new(max), "{max}");
        assert_candidates_are_complete(&partial, &full);
        if partial.completion == DiscoveryCompletion::EntryLimitReached {
            stopped += 1;
            assert!(partial.candidates.len() < full.candidates.len(), "{max}");
        } else {
            assert_eq!(partial.completion, DiscoveryCompletion::Finished, "{max}");
            assert_eq!(partial.candidates.len(), 3, "{max}");
        }
    }
    // A limit of 2 stops the discovery, and a limit of 20 does not.
    assert!(stopped > 0);
    let none = discover_xcode_limited(
        &fixture,
        DiscoveryLimits {
            max_entries: EntryCount::new(2),
            ..limits()
        },
    );
    assert_eq!(none.completion, DiscoveryCompletion::EntryLimitReached);
    assert_eq!(none.candidates.len(), 0);
}

#[test]
fn a_unit_deeper_than_the_depth_limit_is_not_a_candidate() {
    let (fixture, _) = xcode_fixture();
    let full = discover_xcode(&fixture);
    let shallow = discover_xcode_limited(
        &fixture,
        DiscoveryLimits {
            max_depth: 1,
            ..limits()
        },
    );
    assert_eq!(shallow.completion, DiscoveryCompletion::Finished);
    // The child directories of `Intermediates.noindex` hold only files, so
    // the measurement ends at the first level. The trees of the other two
    // units have more directory levels.
    assert_eq!(shallow.candidates.len(), 1, "{:?}", shallow.skipped);
    assert_eq!(
        shallow.candidates[0].evidence.relative_entry.as_utf8(),
        Some(unit("Build/Intermediates.noindex").as_str())
    );
    for name in ["Build/Products", "Index.noindex"] {
        assert_eq!(
            skip_of(&shallow, &unit(name)).reasons,
            [SkipReason::MeasurementIncomplete],
            "{name}"
        );
    }
    // Each depth gives either the complete measurement or no candidate.
    for depth in 0_u32..=6 {
        let partial = discover_xcode_limited(
            &fixture,
            DiscoveryLimits {
                max_depth: depth,
                ..limits()
            },
        );
        assert_candidates_are_complete(&partial, &full);
        assert_eq!(
            partial.candidates.len() + partial.skipped.len(),
            3,
            "{depth}"
        );
    }
}

#[test]
fn a_cancelled_xcode_discovery_reports_the_stop_and_no_later_candidate() {
    let (fixture, _) = xcode_fixture();
    let full = discover_xcode(&fixture);
    let registry = ReviewedRules::new().unwrap();
    let clock = month_later_clock();

    // Cancelled before the start.
    let cancel = CancellationToken::new();
    cancel.cancel();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let discovery = registry
        .xcode_derived_data()
        .discover(&fixture.scope(), NOT_RUNNING, DiscoveryMode::Full, &control)
        .unwrap();
    assert_eq!(discovery.completion, DiscoveryCompletion::Cancelled);
    assert_eq!(discovery.candidates.len(), 0);

    // Cancelled after the measurement of the first unit.
    let cancel = CancellationToken::new();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let mut cancel_after_first = |_: &Path| cancel.cancel();
    let discovery = registry
        .xcode_derived_data()
        .discover_with(
            &fixture.scope(),
            NOT_RUNNING,
            DiscoveryMode::Full,
            &control,
            &mut cancel_after_first,
        )
        .unwrap();
    assert_eq!(discovery.completion, DiscoveryCompletion::Cancelled);
    assert!(discovery.candidates.len() < full.candidates.len());
    assert_candidates_are_complete(&discovery, &full);
}

#[test]
fn a_unit_that_is_a_symbolic_link_is_not_a_candidate_and_is_not_followed() {
    // A link to a directory in the root, a link to a directory outside the
    // root, and a link in place of `Build`.
    for case in ["inside", "outside", "build"] {
        let (fixture, project) = xcode_fixture();
        assert_eq!(discover_xcode(&fixture).candidates.len(), 3);
        let target: PathBuf = match case {
            "inside" => fixture.root().join("shared-products"),
            _ => fixture.base().join("outside-products"),
        };
        let link: PathBuf = if case == "build" {
            project.join("Build")
        } else {
            project.join("Build/Products")
        };
        fs::rename(&link, &target).unwrap();
        symlink(&target, &link).unwrap();

        let discovery = discover_xcode(&fixture);
        assert_eq!(
            discovery.completion,
            DiscoveryCompletion::Finished,
            "{case}"
        );
        let linked: Vec<&str> = if case == "build" {
            vec!["Build/Intermediates.noindex", "Build/Products"]
        } else {
            vec!["Build/Products"]
        };
        for name in &linked {
            let skipped = skip_of(&discovery, &unit(name));
            assert_eq!(skipped.reasons, [SkipReason::SymbolicLink], "{case}");
            assert_eq!(skipped.eligibility.identity_matches, Fact::NotSatisfied);
        }
        // With `Build` linked, the build database is not examined, so the
        // third unit is not a candidate either.
        let expected: usize = if case == "build" { 0 } else { 2 };
        assert_eq!(discovery.candidates.len(), expected, "{case}");
        // The target of the link is not changed.
        let kept: &str = if case == "build" {
            "Products/Debug/App.app/App"
        } else {
            "Debug/App.app/App"
        };
        assert_eq!(fs::read(target.join(kept)).unwrap().len(), 5_000, "{case}");
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    }
}

#[test]
fn an_xcode_unit_with_a_fifo_is_skipped_and_the_fifo_is_not_opened() {
    let (fixture, project) = xcode_fixture();
    assert_eq!(discover_xcode(&fixture).candidates.len(), 3);
    make_fifo(&project.join("Build/Products/Debug/pipe"));

    // An open of the FIFO for reading would block this test.
    let discovery = discovery_within_timeout(fixture, discover_xcode);

    assert_eq!(discovery.candidates.len(), 2, "{:?}", discovery.skipped);
    assert_eq!(
        skip_of(&discovery, &unit("Build/Products")).reasons,
        [SkipReason::UnsupportedObject]
    );
}

#[test]
fn a_symbolic_link_in_a_unit_is_one_entry_and_is_not_followed() {
    let (fixture, project) = xcode_fixture();
    let before = discover_xcode(&fixture);
    let outside: PathBuf = fixture.base().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("large.bin"), vec![9_u8; 300_000]).unwrap();
    symlink(&outside, project.join("Build/Products/Debug/Linked")).unwrap();

    let after = discover_xcode(&fixture);
    let name = unit("Build/Products");
    let (first, second) = (
        &candidate_of(&before, &name).measurement,
        &candidate_of(&after, &name).measurement,
    );
    assert_eq!(second.symlinks, EntryCount::new(1));
    assert_eq!(
        second.charge.items.get(),
        first.charge.items.get() + 1,
        "the link is one item"
    );
    // The target of the link is not in the sizes.
    assert!(second.logical_bytes.get() < first.logical_bytes.get() + 10_000);
    assert_eq!(fs::read(outside.join("large.bin")).unwrap().len(), 300_000);
}

#[test]
fn a_layout_that_is_not_recognized_is_skipped_with_a_reason() {
    let fixture = Fixture::new("DerivedData");
    let workspace = add_workspace(&fixture, "App");
    // A name with no hash.
    add_project(&fixture, "App", &workspace);
    // A name with a hash and no `info.plist`.
    let no_info = add_project(&fixture, "NoInfo-abcdefghijklmnopqrstuvwxyzab", &workspace);
    fs::remove_file(no_info.join("info.plist")).unwrap();
    // A binary property list.
    let binary = add_project(&fixture, "Binary-abcdefghijklmnopqrstuvwxyzab", &workspace);
    fs::write(binary.join("info.plist"), b"bplist00\xd2\x01\x02\x03\x04").unwrap();
    // A property list with no `WorkspacePath`.
    let partial = add_project(&fixture, "Partial-abcdefghijklmnopqrstuvwxyzab", &workspace);
    fs::write(
        partial.join("info.plist"),
        "<plist version=\"1.0\"><dict><key>LastAccessedDate</key>\
         <date>2026-01-01T00:00:00Z</date></dict></plist>",
    )
    .unwrap();
    // An `info.plist` that is a symbolic link.
    let linked = add_project(&fixture, "Linked-abcdefghijklmnopqrstuvwxyzab", &workspace);
    fs::rename(linked.join("info.plist"), linked.join("real.plist")).unwrap();
    symlink(linked.join("real.plist"), linked.join("info.plist")).unwrap();
    // The shared caches of the root, a stray file, and a link.
    fs::create_dir_all(fixture.root().join("ModuleCache.noindex/ABC")).unwrap();
    fs::write(fixture.root().join("ModuleCache.noindex/ABC/M.pcm"), b"x").unwrap();
    fs::write(fixture.root().join("stray.txt"), b"x").unwrap();
    symlink(
        &no_info,
        fixture.root().join("Alias-abcdefghijklmnopqrstuvwxyzab"),
    )
    .unwrap();

    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0, "{:?}", discovery.candidates);
    let reasons = |name: &str| skip_of(&discovery, name).reasons.clone();
    assert_eq!(reasons("App"), [SkipReason::UnsupportedLayout]);
    assert_eq!(
        reasons("NoInfo-abcdefghijklmnopqrstuvwxyzab"),
        [SkipReason::UnsupportedLayout]
    );
    assert_eq!(
        reasons("Binary-abcdefghijklmnopqrstuvwxyzab"),
        [SkipReason::UnsupportedLayout]
    );
    assert_eq!(
        reasons("Partial-abcdefghijklmnopqrstuvwxyzab"),
        [SkipReason::UnsupportedLayout]
    );
    assert_eq!(
        reasons("Linked-abcdefghijklmnopqrstuvwxyzab"),
        [SkipReason::RecordInvalid]
    );
    assert_eq!(
        reasons("ModuleCache.noindex"),
        [SkipReason::SharedOwnership]
    );
    assert_eq!(reasons("stray.txt"), [SkipReason::UnsupportedLayout]);
    assert_eq!(
        reasons("Alias-abcdefghijklmnopqrstuvwxyzab"),
        [SkipReason::SymbolicLink]
    );
    let skipped = skip_of(&discovery, "App");
    assert_eq!(skipped.layout, None);
    assert_eq!(skipped.eligibility.rule_supports_layout, Fact::NotSatisfied);
    assert_eq!(
        SkipReason::UnsupportedLayout.category(),
        SkipCategory::UnsupportedLayout
    );
    // No name of a layout that is not recognized was measured.
    assert_eq!(discovery.entries_examined, EntryCount::ZERO);
}

#[test]
fn a_unit_with_content_that_the_rule_preserves_is_skipped_as_a_whole() {
    let cases: [(&str, &str, bool); 9] = [
        ("Build/Products", "Debug/App.app.dSYM", true),
        ("Build/Products", "Release/App.xcarchive", true),
        ("Build/Intermediates.noindex", "ArchiveIntermediates", true),
        (
            "Build/Products",
            "Debug/App.app/embedded.mobileprovision",
            false,
        ),
        ("Build/Products", "Debug/App.app/Model.sqlite", false),
        ("Index.noindex", "DataStore/index.db", false),
        ("Build/Products", "Debug/Tests.xcresult", true),
        // A build database at a place that is not the reviewed place.
        ("Build/Products", "Debug/XCBuildData/build.db", false),
        ("Build/Products", "Release/AuthKey.p8", false),
    ];
    for (unit_name, entry, is_directory) in cases {
        let (fixture, project) = xcode_fixture();
        let path = project.join(unit_name).join(entry);
        if is_directory {
            fs::create_dir_all(&path).unwrap();
        } else {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"x").unwrap();
        }
        let discovery = discover_xcode(&fixture);
        let skipped = skip_of(&discovery, &unit(unit_name));
        assert_eq!(skipped.reasons, [SkipReason::ProtectedData], "{entry}");
        assert_eq!(skipped.eligibility.no_exclusion_overlap, Fact::NotSatisfied);
        assert_eq!(
            SkipReason::ProtectedData.category(),
            SkipCategory::ProtectedData
        );
        // The other two units stay candidates: the exclusion is not a
        // reason to remove a larger or a smaller set.
        assert_eq!(discovery.candidates.len(), 2, "{entry}");
        assert!(path.exists());
    }
}

#[test]
fn a_unit_with_only_children_of_the_allow_list_is_a_candidate() {
    let (fixture, project) = xcode_fixture();
    let directories: [&str; 17] = [
        "Build/Products/Release",
        "Build/Products/Debug-iphonesimulator",
        "Build/Products/Release-iphoneos",
        "Build/Products/Debug-maccatalyst",
        "Build/Products/Release-xrsimulator",
        "Build/Intermediates.noindex/Pods.build",
        "Build/Intermediates.noindex/PrecompiledHeaders",
        "Build/Intermediates.noindex/ExplicitPrecompiledModules",
        "Build/Intermediates.noindex/SwiftExplicitPrecompiledModules",
        "Build/Intermediates.noindex/GeneratedModuleMaps",
        "Build/Intermediates.noindex/GeneratedModuleMaps-iphonesimulator",
        "Index.noindex/Build/Products",
        "Index.noindex/PrecompiledHeaders",
        // Below an accepted child, a name of the deny-list only is a
        // reason to skip.
        "Build/Products/Release/Notes",
        "Build/Intermediates.noindex/Pods.build/Backup",
        "Index.noindex/DataStore/v5/units",
        "Build/Products/Debug-iphonesimulator/App.app",
    ];
    for directory in directories {
        fs::create_dir_all(project.join(directory)).unwrap();
    }
    for unit_name in [
        "Build/Products",
        "Build/Intermediates.noindex",
        "Index.noindex",
    ] {
        fs::write(project.join(unit_name).join(".DS_Store"), b"finder").unwrap();
    }

    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.skipped.len(), 0, "{:?}", discovery.skipped);
    assert_eq!(discovery.candidates.len(), 3);
    for unit_name in [
        "Build/Products",
        "Build/Intermediates.noindex",
        "Index.noindex",
    ] {
        let candidate = candidate_of(&discovery, &unit(unit_name));
        assert_eq!(
            candidate.candidate.eligibility.rule_supports_layout,
            Fact::Satisfied
        );
    }
}

#[test]
fn a_unit_with_a_child_that_the_allow_list_does_not_have_is_skipped_as_a_whole() {
    /// The kind of the child that a case makes.
    enum Child {
        File(&'static [u8]),
        Directory,
        /// A symbolic link to a directory outside the root.
        Link,
    }
    let cases: [(&str, &str, Child); 11] = [
        ("Build/Products", "Notes.txt", Child::File(b"notes")),
        // A directory that a person copied, with content.
        ("Build/Products", "Backup", Child::Directory),
        // A database with no suffix.
        (
            "Build/Intermediates.noindex",
            "cache",
            Child::File(b"SQLite format 3\0"),
        ),
        // A configuration of a project that the list does not have.
        ("Build/Products", "Staging-iphoneos", Child::Directory),
        // A known name of the wrong type, and a name that the first list
        // does not have.
        ("Build/Products", "Debug-iphoneos", Child::File(b"x")),
        ("Build/Intermediates.noindex", "Previews", Child::Directory),
        // A name of one unit in another unit.
        ("Index.noindex", "XCBuildData", Child::Directory),
        ("Build/Intermediates.noindex", ".build", Child::Directory),
        // A known name that is a symbolic link, and not a directory.
        ("Build/Products", "Release", Child::Link),
        ("Index.noindex", "PrecompiledHeaders", Child::Link),
        // A known name in another case.
        ("Build/Products", "release-iphoneos", Child::Directory),
    ];
    for (unit_name, child, kind) in cases {
        let (fixture, project) = xcode_fixture();
        let path: PathBuf = project.join(unit_name).join(child);
        match kind {
            Child::File(bytes) => fs::write(&path, bytes).unwrap(),
            Child::Directory => {
                fs::create_dir(&path).unwrap();
                fs::write(path.join("copy.txt"), b"copy").unwrap();
            }
            Child::Link => {
                let outside: PathBuf = fixture.base().join("outside");
                fs::create_dir_all(&outside).unwrap();
                symlink(&outside, &path).unwrap();
            }
        }

        let discovery = discover_xcode(&fixture);
        let skipped = skip_of(&discovery, &unit(unit_name));
        assert_eq!(skipped.reasons, [SkipReason::UnsupportedLayout], "{child}");
        assert_eq!(
            skipped.eligibility.rule_supports_layout,
            Fact::NotSatisfied,
            "{child}"
        );
        // The unit is refused whole: no part of it is a candidate.
        assert!(
            discovery.candidates.iter().all(|candidate| !candidate
                .evidence
                .relative_entry
                .as_utf8()
                .is_some_and(|entry| entry.starts_with(&unit(unit_name)))),
            "{child}"
        );
        assert_eq!(discovery.candidates.len(), 2, "{child}");
        assert!(path.exists());
    }

    // The deny-list is a second check: a child that it has is preserved
    // data, also when the allow-list does not have the child.
    let (fixture, project) = xcode_fixture();
    fs::create_dir(project.join("Build/Products/App.xcarchive")).unwrap();
    let discovery = discover_xcode(&fixture);
    assert_eq!(
        skip_of(&discovery, &unit("Build/Products")).reasons,
        [SkipReason::ProtectedData]
    );
}

#[test]
fn a_unit_with_a_special_file_or_a_hard_link_is_skipped() {
    let (fixture, project) = xcode_fixture();
    let object = project.join("Build/Intermediates.noindex/App.build/App.o");
    fs::hard_link(&object, project.join("Build/Products/Debug/App.o")).unwrap();
    let discovery = discover_xcode(&fixture);
    // The two units have one name each of the same object.
    for name in ["Build/Intermediates.noindex", "Build/Products"] {
        let skipped = skip_of(&discovery, &unit(name));
        assert_eq!(skipped.reasons, [SkipReason::HardLinked]);
    }
    candidate_of(&discovery, &unit("Index.noindex"));
}

#[test]
fn a_project_with_no_source_or_with_source_overlap_is_not_a_candidate() {
    // The project of `WorkspacePath` is gone: the data cannot be made
    // again.
    let (fixture, _) = xcode_fixture();
    fs::remove_dir_all(fixture.base().join("src")).unwrap();
    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    for name in super::xcode::UNIT_PATHS {
        let skipped = skip_of(&discovery, &unit(name));
        assert_eq!(skipped.reasons, [SkipReason::NotRegenerable]);
        assert_eq!(skipped.eligibility.regenerable, Fact::NotSatisfied);
        // A unit that is not positively attributed is not measured.
        assert_eq!(skipped.eligibility.unit_and_charge_known, Fact::Unknown);
    }

    // The path is present and is not a project: unknown, not regenerable.
    let (fixture, _) = xcode_fixture();
    let workspace = fixture.base().join("src/App/App.xcodeproj");
    fs::remove_file(workspace.join("project.pbxproj")).unwrap();
    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    let skipped = skip_of(&discovery, &unit("Index.noindex"));
    assert_eq!(skipped.reasons, [SkipReason::RegenerabilityUnknown]);
    assert_eq!(skipped.eligibility.regenerable, Fact::Unknown);

    // A `DerivedData` root in the directory of the project: a custom root
    // that overlaps source.
    let fixture = Fixture::new("DerivedData");
    let workspace = fixture.base().join("App.xcodeproj");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("project.pbxproj"), b"// project").unwrap();
    add_project(&fixture, PROJECT, &workspace);
    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    let skipped = skip_of(&discovery, &unit("Build/Products"));
    assert_eq!(skipped.reasons, [SkipReason::ExclusionOverlap]);
    assert_eq!(skipped.eligibility.no_exclusion_overlap, Fact::NotSatisfied);

    // A project in the root.
    let fixture = Fixture::new("DerivedData");
    let workspace = fixture.root().join("Sources/App.xcodeproj");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("project.pbxproj"), b"// project").unwrap();
    add_project(&fixture, PROJECT, &workspace);
    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        skip_of(&discovery, &unit("Build/Products")).reasons,
        [SkipReason::ExclusionOverlap]
    );
}

#[test]
fn a_workspace_path_with_a_symbolic_link_leaves_the_source_overlap_unknown() {
    // `WorkspacePath` names the project through a link to its source
    // directory. The text of the path does not show where the project is.
    let fixture = Fixture::new("DerivedData");
    let workspace = add_workspace(&fixture, "App");
    symlink(
        fixture.base().join("src"),
        fixture.base().join("linked-src"),
    )
    .unwrap();
    let linked: PathBuf = fixture
        .base()
        .join("linked-src")
        .join(workspace.strip_prefix(fixture.base().join("src")).unwrap());
    add_project(&fixture, PROJECT, &linked);
    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    for name in super::xcode::UNIT_PATHS {
        let skipped = skip_of(&discovery, &unit(name));
        assert_eq!(skipped.eligibility.regenerable, Fact::Unknown, "{name}");
        assert_eq!(
            skipped.eligibility.no_exclusion_overlap,
            Fact::Unknown,
            "{name}"
        );
        assert_eq!(skipped.reasons, [SkipReason::RegenerabilityUnknown]);
    }
}

#[test]
fn a_user_exclusion_and_a_link_in_the_unit_path_stop_a_unit() {
    let (mut fixture, project) = xcode_fixture();
    fixture.excluded = vec![project.join("Index.noindex/DataStore")];
    // `Build` is a symbolic link to a directory with the two units.
    let real_build = fixture.base().join("RealBuild");
    fs::rename(project.join("Build"), &real_build).unwrap();
    symlink(&real_build, project.join("Build")).unwrap();

    let discovery = discover_xcode(&fixture);
    assert_eq!(discovery.candidates.len(), 0);
    assert_eq!(
        skip_of(&discovery, &unit("Index.noindex")).reasons,
        [SkipReason::ExclusionOverlap]
    );
    for name in ["Build/Intermediates.noindex", "Build/Products"] {
        let skipped = skip_of(&discovery, &unit(name));
        assert_eq!(skipped.reasons, [SkipReason::SymbolicLink]);
        assert_eq!(skipped.eligibility.identity_matches, Fact::NotSatisfied);
    }
    assert_eq!(discovery.entries_examined, EntryCount::ZERO);
}

#[test]
fn a_user_exclusion_in_another_case_still_stops_a_unit() {
    let (mut fixture, project) = xcode_fixture();
    // The directory on disk is `Index.noindex`.
    fixture.excluded = vec![project.join("index.NOINDEX")];

    let discovery = discover_xcode(&fixture);
    assert_eq!(
        skip_of(&discovery, &unit("Index.noindex")).reasons,
        [SkipReason::ExclusionOverlap]
    );
}

// ---------------------------------------------------------------------
// Roots and sources on a filesystem that is not local. No test mounts a
// volume: each test gives the rule a mount table.
// ---------------------------------------------------------------------

/// The mount point of a network volume that only the injected tables of
/// the tests have. No test makes a call on a path below it.
const REMOTE_VOLUME: &str = "/Volumes/svalnir-test-remote";

fn remote_mount(point: &str, filesystem_type: &str, flags: u32) -> RawMount {
    RawMount {
        mount_point: point.as_bytes().to_vec(),
        mounted_from: b"//host/share".to_vec(),
        filesystem_type: filesystem_type.as_bytes().to_vec(),
        fsid: [i32::MIN, 0],
        flags,
        block_size: 4_096,
        blocks: 1,
        blocks_free: 1,
        blocks_available: 1,
    }
}

#[test]
fn an_exclusion_whose_text_is_not_local_is_not_resolved() {
    let directory = tempfile::tempdir().unwrap();
    let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
    let real: PathBuf = base.join("real");
    fs::create_dir(&real).unwrap();
    let link: PathBuf = base.join("link");
    symlink(&real, &link).unwrap();
    let root = || remote_mount("/", "apfs", MOUNT_FLAG_LOCAL);
    // On a local filesystem the resolved form is added.
    let local = MountTable::from_mounts(vec![root()]);
    assert_eq!(
        with_resolved_forms(std::slice::from_ref(&link), &local),
        vec![link.clone(), real]
    );
    // The table reports the path as a network filesystem, or has no mount
    // for it: the path is not resolved, so no call reaches its
    // filesystem.
    let remote = MountTable::from_mounts(vec![
        root(),
        remote_mount(link.to_str().unwrap(), "smbfs", 0),
    ]);
    let empty = MountTable::from_mounts(Vec::new());
    for table in [&remote, &empty] {
        assert_eq!(
            with_resolved_forms(std::slice::from_ref(&link), table),
            vec![link.clone()]
        );
    }
}

/// The table of the host, with each mount reported as not local.
fn no_local_mount() -> Result<MountTable, UnavailableReason> {
    let mounts: Vec<RawMount> = MountTable::read()?
        .mounts()
        .iter()
        .cloned()
        .map(|mut raw| {
            raw.flags &= !MOUNT_FLAG_LOCAL;
            raw
        })
        .collect();
    Ok(MountTable::from_mounts(mounts))
}

/// A table with a local `/` whose identity is not the device of any object.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature of a mount table source"
)]
fn no_mount_for_the_device() -> Result<MountTable, UnavailableReason> {
    let mut root: RawMount = remote_mount("/", "apfs", MOUNT_FLAG_LOCAL);
    root.fsid = [i32::MIN + 1, 0];
    Ok(MountTable::from_mounts(vec![root]))
}

fn no_table() -> Result<MountTable, UnavailableReason> {
    Err(UnavailableReason::TransientFailure)
}

/// The table of the host with a network volume and an automounter map.
fn with_remote_volumes() -> Result<MountTable, UnavailableReason> {
    let mut mounts: Vec<RawMount> = MountTable::read()?.mounts().to_vec();
    mounts.push(remote_mount(REMOTE_VOLUME, "smbfs", 0));
    // The automounter map has the local flag on some hosts.
    mounts.push(remote_mount("/net", "autofs", MOUNT_FLAG_LOCAL));
    Ok(MountTable::from_mounts(mounts))
}

/// Whether a discovery error is the expected one.
type ExpectedError = fn(&DiscoveryError) -> bool;

#[test]
fn a_root_on_a_filesystem_that_is_not_local_is_refused() {
    let temporary = temporary_fixture();
    let (xcode, _) = xcode_fixture();
    let cancel = CancellationToken::new();
    let clock = later_clock();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    let registry = ReviewedRules::new().unwrap();
    let cases: [(MountTableSource, ExpectedError); 3] = [
        (no_local_mount, |error| {
            matches!(error, DiscoveryError::RootNotLocal)
        }),
        (no_mount_for_the_device, |error| {
            matches!(error, DiscoveryError::RootLocalityUnknown)
        }),
        (no_table, |error| {
            matches!(error, DiscoveryError::RootLocalityUnknown)
        }),
    ];
    for (source, expected) in cases {
        let error = registry
            .expired_temporary()
            .clone()
            .with_mount_table(source)
            .discover(&temporary.scope(), NO_LEASES, DiscoveryMode::Full, &control)
            .unwrap_err();
        assert!(expected(&error), "{error:?}");
        let error = registry
            .xcode_derived_data()
            .clone()
            .with_mount_table(source)
            .discover(&xcode.scope(), NOT_RUNNING, DiscoveryMode::Full, &control)
            .unwrap_err();
        assert!(expected(&error), "{error:?}");
    }
    // The table of the host reports the temporary directory as local.
    assert!(
        registry
            .expired_temporary()
            .discover(&temporary.scope(), NO_LEASES, DiscoveryMode::Full, &control)
            .is_ok()
    );
}

#[test]
fn a_project_on_a_filesystem_that_is_not_local_is_not_examined() {
    let (fixture, project) = xcode_fixture();
    let other = add_project(
        &fixture,
        "Other-abcdefghijklmnopqrstuvwxyzab",
        Path::new("/net/host/Other/Other.xcodeproj"),
    );
    fs::write(
        project.join("info.plist"),
        info_plist(
            &Path::new(REMOTE_VOLUME).join("App/App.xcodeproj"),
            real_now_plus(-DAY_SECONDS),
        ),
    )
    .unwrap();
    let registry = ReviewedRules::new().unwrap();
    let rule = registry
        .xcode_derived_data()
        .clone()
        .with_mount_table(with_remote_volumes);
    let discovery = discover_xcode_with(
        &rule,
        &fixture,
        NOT_RUNNING,
        DiscoveryMode::Full,
        &month_later_clock(),
    )
    .unwrap();
    assert_eq!(discovery.candidates.len(), 0, "{:?}", discovery.candidates);
    for name in [PROJECT, "Other-abcdefghijklmnopqrstuvwxyzab"] {
        for unit_path in super::xcode::UNIT_PATHS {
            let skipped = skip_of(&discovery, &format!("{name}/{unit_path}"));
            assert_eq!(skipped.reasons, [SkipReason::SourceNotLocal], "{name}");
            assert_eq!(skipped.eligibility.regenerable, Fact::Unknown);
        }
    }
    assert_eq!(
        SkipReason::SourceNotLocal.category(),
        SkipCategory::ProtectedData
    );
    assert!(other.is_dir());
}

#[expect(clippy::unnecessary_wraps, reason = "the signature of a lock query")]
fn lock_free(_: &File) -> io::Result<bool> {
    Ok(false)
}

#[expect(clippy::unnecessary_wraps, reason = "the signature of a lock query")]
fn lock_held(_: &File) -> io::Result<bool> {
    Ok(true)
}

fn lock_query_fails(_: &File) -> io::Result<bool> {
    Err(io::Error::other("the query failed"))
}

/// A clock with the wall-clock time of [`month_later_clock`] and no
/// monotonic time.
struct WallOnlyClock;

impl ScanClock for WallOnlyClock {
    fn now(&self) -> ScanTimestamp {
        ScanTimestamp {
            wall: month_later_clock().0,
            monotonic_ns: None,
        }
    }
}

/// A process inventory with no process of the producer shows inactivity
/// only for `evidence_expiry` of the rule. Older evidence, evidence with a
/// time after the time of the assessment, and evidence that cannot be
/// compared with a monotonic time give no candidate.
#[test]
fn process_evidence_that_is_older_than_its_expiry_does_not_show_inactivity() {
    let (fixture, _project) = xcode_fixture();
    let clock = month_later_clock();
    let name = unit("Build/Intermediates.noindex");
    let rule = XcodeDerivedDataRule::with_lock_probe(lock_free).unwrap();
    let expiry: Nanoseconds = rule.rule().activity.evidence_expiry;
    let not_running_at = |observed_at: MonotonicNanos| XcodeEvidence {
        producer_processes: ProducerProcesses::NotRunning,
        observed_at,
    };
    let at_expiry = MonotonicNanos::new(MONOTONIC_NOW.get() - expiry.get());
    let expired = MonotonicNanos::new(at_expiry.get() - 1);
    let later = MonotonicNanos::new(MONOTONIC_NOW.get() + 1);

    // Evidence at the limit of the expiry is current.
    let current = discover_xcode_with(
        &rule,
        &fixture,
        not_running_at(at_expiry),
        DiscoveryMode::Full,
        &clock,
    )
    .unwrap();
    assert_eq!(found_blockers(&current, &name), []);

    for stale in [expired, MonotonicNanos::new(0), later] {
        let discovery = discover_xcode_with(
            &rule,
            &fixture,
            not_running_at(stale),
            DiscoveryMode::Full,
            &clock,
        )
        .unwrap();
        assert_eq!(discovery.candidates.len(), 0, "{stale:?}");
        let skipped = skip_of(&discovery, &name);
        assert_eq!(skipped.reasons, [SkipReason::ActivityUnknown], "{stale:?}");
        assert_eq!(skipped.eligibility.age_and_inactivity, Fact::Unknown);
        assert_eq!(skipped.eligibility.protocols_valid, Fact::Unknown);
    }

    // A clock with no monotonic time cannot show that the evidence is
    // current.
    let no_monotonic = discover_xcode_with(
        &rule,
        &fixture,
        NOT_RUNNING,
        DiscoveryMode::Full,
        &WallOnlyClock,
    )
    .unwrap();
    assert_eq!(no_monotonic.candidates.len(), 0);
    assert_eq!(
        skip_of(&no_monotonic, &name).reasons,
        [SkipReason::ActivityUnknown]
    );

    // Evidence of a running producer does not expire into inactivity.
    let running = discover_xcode_with(
        &rule,
        &fixture,
        XcodeEvidence {
            producer_processes: ProducerProcesses::Running,
            observed_at: expired,
        },
        DiscoveryMode::Full,
        &clock,
    )
    .unwrap();
    assert_eq!(
        found_blockers(&running, &name),
        [SkipReason::ActiveProducer]
    );
}

#[test]
fn the_producer_processes_and_the_lock_decide_the_activity() {
    let (fixture, project) = xcode_fixture();
    let clock = month_later_clock();
    let name = unit("Build/Intermediates.noindex");
    let discover = |probe: fn(&File) -> io::Result<bool>, processes: ProducerProcesses| {
        let rule = XcodeDerivedDataRule::with_lock_probe(probe).unwrap();
        let evidence = XcodeEvidence {
            producer_processes: processes,
            observed_at: MONOTONIC_NOW,
        };
        discover_xcode_with(&rule, &fixture, evidence, DiscoveryMode::Full, &clock).unwrap()
    };

    // A process of the producer runs: an old directory is not sufficient.
    let running = discover(lock_free, ProducerProcesses::Running);
    let found = candidate_of(&running, &name);
    assert_eq!(found.blockers, [SkipReason::ActiveProducer]);
    let record: &RuleCandidateRecord = &found.candidate;
    assert_eq!(record.eligibility.age_and_inactivity, Fact::NotSatisfied);
    assert_eq!(record.candidate.facts.activity, ActivityFact::Active);
    assert_eq!(
        SkipReason::ActiveProducer.category(),
        SkipCategory::ActiveProducer
    );

    // Another process holds the lock of the build database.
    let held = discover(lock_held, ProducerProcesses::NotRunning);
    assert_eq!(found_blockers(&held, &name), [SkipReason::ActiveProducer]);
    // The lock is a fact of the project: each unit is blocked.
    assert_eq!(
        found_blockers(&held, &unit("Build/Products")),
        [SkipReason::ActiveProducer]
    );

    // No process inventory: unknown is not inactive, and a check with no
    // result is not a passed check.
    let unknown = discover(lock_free, ProducerProcesses::Unknown);
    assert_eq!(unknown.candidates.len(), 0);
    let skipped = skip_of(&unknown, &name);
    assert_eq!(skipped.reasons, [SkipReason::ActivityUnknown]);
    assert_eq!(skipped.eligibility.age_and_inactivity, Fact::Unknown);
    assert_eq!(skipped.eligibility.protocols_valid, Fact::Unknown);
    assert_eq!(
        SkipReason::ActivityUnknown.category(),
        SkipCategory::MissingQuiescence
    );

    // The lock query fails.
    let failed = discover(lock_query_fails, ProducerProcesses::NotRunning);
    assert_eq!(failed.candidates.len(), 0);
    assert_eq!(
        skip_of(&failed, &name).reasons,
        [SkipReason::ActivityUnknown]
    );

    // A project with intermediates and no build database: the lock check
    // has no result.
    let (bare, bare_project) = xcode_fixture();
    fs::remove_file(bare_project.join("Build/Intermediates.noindex/XCBuildData/build.db")).unwrap();
    let rule = XcodeDerivedDataRule::with_lock_probe(lock_free).unwrap();
    let no_database =
        discover_xcode_with(&rule, &bare, NOT_RUNNING, DiscoveryMode::Full, &clock).unwrap();
    assert_eq!(no_database.candidates.len(), 0);
    assert_eq!(
        skip_of(&no_database, &name).reasons,
        [SkipReason::ActivityUnknown]
    );

    // A file of an open SQLite transaction is next to the database.
    fs::write(
        project.join("Build/Intermediates.noindex/XCBuildData/build.db-journal"),
        b"x",
    )
    .unwrap();
    let journal = discover(lock_free, ProducerProcesses::NotRunning);
    assert_eq!(
        found_blockers(&journal, &name),
        [SkipReason::ActiveProducer]
    );
}

fn found_blockers(discovery: &Discovery, name: &str) -> Vec<SkipReason> {
    candidate_of(discovery, name).blockers.clone()
}

#[test]
fn the_age_of_a_unit_is_the_newest_examined_time() {
    let (fixture, project) = xcode_fixture();
    let registry = ReviewedRules::new().unwrap();
    let name = unit("Index.noindex");
    let blockers = |clock: &FixedClock| {
        let discovery = discover_xcode_with(
            registry.xcode_derived_data(),
            &fixture,
            NOT_RUNNING,
            DiscoveryMode::Full,
            clock,
        )
        .unwrap();
        let found = candidate_of(&discovery, &name);
        let record: &RuleCandidateRecord = &found.candidate;
        (
            found.blockers.clone(),
            record.eligibility.age_and_inactivity.clone(),
        )
    };

    // The files are one day old on this clock: the minimum age is not
    // elapsed, even though `LastAccessedDate` is older.
    let (reasons, fact) = blockers(&FixedClock(Some(real_now_plus(DAY_SECONDS))));
    assert_eq!(reasons, [SkipReason::RetentionNotElapsed]);
    assert_eq!(fact, Fact::NotSatisfied);

    // A time of the unit is later than the time now.
    let (reasons, fact) = blockers(&FixedClock(Some(real_now_plus(-DAY_SECONDS))));
    assert_eq!(reasons, [SkipReason::FutureTimestamp]);
    assert_eq!(fact, Fact::Unknown);

    // No wall-clock time.
    let (reasons, fact) = blockers(&FixedClock(None));
    assert_eq!(reasons, [SkipReason::AgeUnknown]);
    assert_eq!(fact, Fact::Unknown);

    // `LastAccessedDate` is the newest time: Xcode opened the project
    // after the last change of the files.
    let workspace = fixture.base().join("src/App/App.xcodeproj");
    fs::write(
        project.join("info.plist"),
        info_plist(&workspace, real_now_plus(25 * DAY_SECONDS)),
    )
    .unwrap();
    let (reasons, fact) = blockers(&month_later_clock());
    assert_eq!(reasons, [SkipReason::RetentionNotElapsed]);
    assert_eq!(fact, Fact::NotSatisfied);
}

#[test]
fn a_unit_that_changes_before_the_evidence_snapshot_is_skipped() {
    let (fixture, _) = xcode_fixture();
    let registry = ReviewedRules::new().unwrap();
    let cancel = CancellationToken::new();
    let clock = month_later_clock();
    let control = DiscoveryControl {
        limits: limits(),
        cancel: &cancel,
        clock: &clock,
    };
    // A build writes a new object after the measurement of each unit.
    let mut write_after = |unit: &Path| fs::write(unit.join("New.o"), b"new").unwrap();
    let discovery = registry
        .xcode_derived_data()
        .discover_with(
            &fixture.scope(),
            NOT_RUNNING,
            DiscoveryMode::Full,
            &control,
            &mut write_after,
        )
        .unwrap();
    assert_eq!(discovery.candidates.len(), 0);
    for name in super::xcode::UNIT_PATHS {
        let skipped = skip_of(&discovery, &unit(name));
        assert_eq!(skipped.reasons, [SkipReason::IdentityChanged]);
        assert_eq!(skipped.eligibility.identity_matches, Fact::NotSatisfied);
        assert_eq!(
            SkipReason::IdentityChanged.category(),
            SkipCategory::StaleIdentity
        );
    }
}

#[test]
fn known_units_are_examined_again_with_no_measurement() {
    let (fixture, project) = xcode_fixture();
    let registry = ReviewedRules::new().unwrap();
    let full = discover_xcode(&fixture);
    assert_eq!(full.candidates.len(), 3);
    let known = |evidence: XcodeEvidence| {
        discover_xcode_with(
            registry.xcode_derived_data(),
            &fixture,
            evidence,
            DiscoveryMode::KnownCandidatesOnly(&full.candidates),
            &month_later_clock(),
        )
        .unwrap()
    };

    let again = known(NOT_RUNNING);
    assert_eq!(again.entries_examined, EntryCount::ZERO);
    assert_eq!(again.candidates.len(), 3);
    assert!(again.candidates.iter().all(|candidate| {
        candidate.measurement.source == MeasurementSource::CarriedFromEarlierDiscovery
            && candidate.blockers.is_empty()
    }));

    // The activity is examined again: a build that started after the full
    // discovery blocks each known unit.
    let active = known(XcodeEvidence {
        producer_processes: ProducerProcesses::Running,
        observed_at: MONOTONIC_NOW,
    });
    assert_eq!(active.candidates.len(), 3);
    assert!(
        active
            .candidates
            .iter()
            .all(|candidate| candidate.blockers == [SkipReason::ActiveProducer])
    );

    // A unit that changed has no current charge, and a unit that is gone
    // is not a candidate.
    fs::write(project.join("Build/Products/New.o"), b"new").unwrap();
    fs::remove_dir_all(project.join("Index.noindex")).unwrap();
    let changed = known(NOT_RUNNING);
    assert_eq!(
        skip_of(&changed, &unit("Build/Products")).reasons,
        [SkipReason::MeasurementStale]
    );
    assert_eq!(
        skip_of(&changed, &unit("Index.noindex")).reasons,
        [SkipReason::Vanished]
    );
}

#[test]
fn the_process_names_of_the_producer_only_add_activity() {
    assert_eq!(
        ProducerProcesses::from_complete_inventory(["Finder", "xcodebuild"]),
        ProducerProcesses::Running
    );
    assert_eq!(
        ProducerProcesses::from_complete_inventory(["Finder", "Safari"]),
        ProducerProcesses::NotRunning
    );
    // A complete inventory has the process of the caller. An inventory
    // with no process is a failed query, and a failed query is not "no
    // producer".
    assert_eq!(
        ProducerProcesses::from_complete_inventory([]),
        ProducerProcesses::Unknown
    );
}

#[test]
fn the_native_lock_query_reports_a_file_with_no_lock_as_free() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("build.db");
    fs::write(&path, b"database").unwrap();
    let file = File::open(&path).unwrap();
    assert!(!is_locked_by_another_process(&file).unwrap());
}

/// On macOS a `flock` lock of another open file description conflicts
/// with the `fcntl` query, so one process can show a held lock.
#[cfg(target_os = "macos")]
#[test]
fn the_native_lock_query_reports_a_lock_of_another_open_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("build.db");
    fs::write(&path, b"database").unwrap();
    let holder = File::open(&path).unwrap();
    holder.lock().unwrap();
    let file = File::open(&path).unwrap();
    assert!(is_locked_by_another_process(&file).unwrap());
    holder.unlock().unwrap();
    assert!(!is_locked_by_another_process(&file).unwrap());
}

#[test]
fn the_property_list_reader_accepts_one_form_only() {
    let text = |body: &str| format!("<?xml version=\"1.0\"?><plist version=\"1.0\">{body}</plist>");
    let valid = text(
        "<dict><key>LastAccessedDate</key><date>2026-03-04T05:06:07Z</date>\
         <key>Other</key><integer>3</integer><key>Flag</key><true/>\
         <key>WorkspacePath</key><string>/Users/a/R&amp;D/App.xcodeproj</string></dict>",
    );
    let info = parse_project_info(valid.as_bytes()).unwrap();
    assert_eq!(
        info.workspace_path,
        PathBuf::from("/Users/a/R&D/App.xcodeproj")
    );
    assert_eq!(info.last_accessed, "2026-03-04T05:06:07Z".parse().unwrap());

    let rejected: [String; 10] = [
        // A nested container.
        text("<dict><key>A</key><dict></dict></dict>"),
        // A key two times.
        text(
            "<dict><key>WorkspacePath</key><string>/a</string>\
             <key>WorkspacePath</key><string>/b</string>\
             <key>LastAccessedDate</key><date>2026-03-04T05:06:07Z</date></dict>",
        ),
        // A value of another type.
        text(
            "<dict><key>WorkspacePath</key><integer>1</integer>\
             <key>LastAccessedDate</key><date>2026-03-04T05:06:07Z</date></dict>",
        ),
        // A date that is not a date.
        text(
            "<dict><key>WorkspacePath</key><string>/a</string>\
             <key>LastAccessedDate</key><date>yesterday</date></dict>",
        ),
        // An entity that is not one of the five.
        text(
            "<dict><key>WorkspacePath</key><string>/a&nbsp;b</string>\
             <key>LastAccessedDate</key><date>2026-03-04T05:06:07Z</date></dict>",
        ),
        // Content after the root element.
        format!(
            "{}<dict></dict>",
            text(
                "<dict><key>WorkspacePath</key><string>/a</string>\
                 <key>LastAccessedDate</key><date>2026-03-04T05:06:07Z</date></dict>"
            )
        ),
        // Text before the root, and a root with another name.
        format!("junk{}", text("<dict></dict>")),
        "<plistX><dict><key>WorkspacePath</key><string>/a</string>\
         <key>LastAccessedDate</key><date>2026-03-04T05:06:07Z</date></dict></plist>"
            .to_owned(),
        // An array root.
        text("<array></array>"),
        "bplist00".to_owned(),
    ];
    for document in rejected {
        assert_eq!(parse_project_info(document.as_bytes()), None, "{document}");
    }
}

// ---------------------------------------------------------------------
// Overlap.
// ---------------------------------------------------------------------

/// The declaration of `rule` with another identity, so that a test has a
/// second rule that can find the same directory.
fn second_rule(rule: &Rule, id: &str) -> Rule {
    let mut declaration: RuleDeclaration = (**rule).clone();
    declaration.reference = reference(id, "r1");
    Checked::new(declaration).unwrap()
}

/// The candidate as another rule revision found it, below the root
/// `root_path` when one is given.
fn attributed_to(
    candidate: &DiscoveredCandidate,
    rule: &Rule,
    root_path: Option<&Path>,
) -> DiscoveredCandidate {
    let mut record: RuleCandidateRecord = candidate.candidate.clone().into_inner();
    record.rule = rule.reference.clone();
    record.candidate.rule_id = rule.reference.id.clone();
    let mut attributed = candidate.clone();
    attributed.candidate = RuleCandidate::new(rule, record).unwrap();
    if let Some(root_path) = root_path {
        attributed.root.path = svalnir_core::file::LosslessPath::from_path(root_path).unwrap();
    }
    attributed
}

#[test]
fn a_path_that_two_rules_claim_goes_to_one_rule_or_to_no_rule() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    add_item(&fixture, "item-b", |_| {});
    let discovery = discover_temporary(&fixture);
    let registry = ReviewedRules::new().unwrap();
    let rule: &Rule = registry.lookup(&discovery.rule).unwrap();
    let other: Rule = second_rule(rule, "other.cache");
    let item_a = candidate_of(&discovery, "item-a").clone();
    let item_b = candidate_of(&discovery, "item-b").clone();

    // No overlap: each candidate stays.
    let disjoint = resolve_overlaps(vec![item_a.clone(), item_b.clone()]);
    assert_eq!(disjoint.candidates.len(), 2);
    assert_eq!(disjoint.conflicts.len(), 0);

    // Two rules with the same root claim one object: the ownership is
    // ambiguous, and no rule claims it.
    let rival = attributed_to(&item_a, &other, None);
    let ambiguous = resolve_overlaps(vec![item_a.clone(), rival.clone(), item_b.clone()]);
    assert_eq!(ambiguous.candidates, std::slice::from_ref(&item_b));
    assert_eq!(ambiguous.conflicts.len(), 1);
    let conflict = &ambiguous.conflicts[0];
    assert_eq!(conflict.kind, OverlapKind::SameObject);
    assert_eq!(conflict.claimant, None);
    assert_eq!(conflict.rejected.len(), 2);
    assert_ne!(conflict.rejected[0].rule, conflict.rejected[1].rule);

    // The root of one rule is below the root of the other rule: the more
    // specific root claims the path, in each input sequence.
    let wide_root: &Path = fixture.base();
    let wide = attributed_to(&item_a, &other, Some(wide_root));
    for list in [
        vec![item_a.clone(), wide.clone()],
        vec![wide.clone(), item_a.clone()],
    ] {
        let resolved = resolve_overlaps(list);
        assert_eq!(resolved.candidates, std::slice::from_ref(&item_a));
        assert_eq!(resolved.conflicts.len(), 1);
        let claimant = resolved.conflicts[0].claimant.as_ref().unwrap();
        assert_eq!(claimant.rule, item_a.candidate.rule);
        assert_eq!(resolved.conflicts[0].rejected[0].rule, other.reference);
    }

    // The registry refuses a candidate of a rule that is not registered.
    assert_eq!(
        registry.claim(vec![item_a.clone(), rival]).err(),
        Some(ClaimError::Unregistered(RuleRefusal::UnknownRule))
    );
    let claimed = registry.claim(vec![item_a, item_b]).unwrap();
    assert_eq!(claimed.candidates.len(), 2);
}

#[test]
fn a_parent_and_a_descendant_are_not_two_candidates() {
    let (fixture, project) = xcode_fixture();
    let discovery = discover_xcode(&fixture);
    let registry = ReviewedRules::new().unwrap();
    let rule: &Rule = registry.lookup(&discovery.rule).unwrap();
    let products = candidate_of(&discovery, &unit("Build/Products")).clone();
    let index = candidate_of(&discovery, &unit("Index.noindex")).clone();

    // A candidate below `Build/Products`, with its own object identity.
    let nested_path = project.join("Build/Products/Debug");
    let mut record: RuleCandidateRecord = products.candidate.clone().into_inner();
    record.candidate.path = svalnir_core::file::LosslessPath::from_path(&nested_path).unwrap();
    record.candidate.target_id = "file:nested".parse().unwrap();
    let mut nested = products.clone();
    nested.candidate = RuleCandidate::new(rule, record).unwrap();
    nested.evidence.object = object_of(&nested_path);

    // One rule: the parent keeps the claim, in each input sequence.
    for list in [
        vec![nested.clone(), products.clone(), index.clone()],
        vec![products.clone(), index.clone(), nested.clone()],
    ] {
        let resolved = resolve_overlaps(list);
        assert_eq!(resolved.candidates.len(), 2);
        assert!(resolved.candidates.contains(&products));
        assert!(resolved.candidates.contains(&index));
        assert_eq!(resolved.conflicts.len(), 1);
        assert_eq!(resolved.conflicts[0].kind, OverlapKind::Nested);
        assert_eq!(
            resolved.conflicts[0].claimant.as_ref().unwrap().object,
            products.evidence.object
        );
    }

    // A conflict does not name a claimant that another conflict rejected:
    // the parent wins against its descendant and loses against a rival
    // rule, so no candidate keeps a claim.
    let rival_rule: Rule = second_rule(rule, "rival.cache");
    let rival_parent = attributed_to(&products, &rival_rule, None);
    let resolved = resolve_overlaps(vec![products.clone(), nested.clone(), rival_parent]);
    assert_eq!(resolved.candidates.len(), 0);
    assert_eq!(resolved.conflicts.len(), 3);
    assert!(
        resolved
            .conflicts
            .iter()
            .all(|conflict| conflict.claimant.is_none())
    );

    // The same candidate two times: one stays.
    let duplicate = resolve_overlaps(vec![index.clone(), index.clone()]);
    assert_eq!(duplicate.candidates, std::slice::from_ref(&index));
    assert_eq!(duplicate.conflicts[0].kind, OverlapKind::SameObject);

    // Two rules with the same root and nested candidates: ambiguous. The
    // parent is not removed with the data of the other rule in it.
    let other: Rule = second_rule(rule, "other.cache");
    let rival = attributed_to(&nested, &other, None);
    let resolved = resolve_overlaps(vec![products, rival, index.clone()]);
    assert_eq!(resolved.candidates, [index]);
    assert_eq!(resolved.conflicts[0].claimant, None);
}

// ---------------------------------------------------------------------
// The content of a unit: owners, times, and known candidates.
// ---------------------------------------------------------------------

/// Sets the modification time of the file `path`.
fn set_modified(path: &Path, time: SystemTime) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

#[test]
fn a_file_below_an_item_that_was_written_after_the_seal_invalidates_the_item() {
    let fixture = temporary_fixture();
    let item = add_item(&fixture, "item-a", |_| {});
    // A writer rewrites a file in a directory below the item one hour after
    // the seal. The modification time of the item directory does not
    // change.
    set_modified(
        &item.join("nested/part-2.bin"),
        SystemTime::now() + Duration::from_hours(1),
    );

    let discovery = discover_temporary(&fixture);

    assert_eq!(discovery.candidates.len(), 0);
    let skipped = skip_of(&discovery, "item-a");
    assert_eq!(skipped.reasons, [SkipReason::ModifiedAfterSeal]);
    assert_eq!(skipped.eligibility.protocols_valid, Fact::NotSatisfied);
}

#[test]
fn a_file_below_a_unit_that_was_written_in_place_is_the_newest_time_of_the_unit() {
    let (fixture, project) = xcode_fixture();
    // An indexer rewrites a record 25 days after the other files. The
    // times of the unit directory and of `info.plist` do not change.
    set_modified(
        &project.join("Index.noindex/DataStore/v5/records/AB"),
        SystemTime::now() + Duration::from_hours(25 * 24),
    );

    let discovery = discover_xcode(&fixture);

    let index = candidate_of(&discovery, &unit("Index.noindex"));
    assert_eq!(index.blockers, [SkipReason::RetentionNotElapsed]);
    let record: &RuleCandidateRecord = &index.candidate;
    assert_eq!(record.eligibility.age_and_inactivity, Fact::NotSatisfied);
    // The other units have no such file.
    let products = candidate_of(&discovery, &unit("Build/Products"));
    assert_eq!(products.blockers.len(), 0);
}

#[test]
fn the_owner_and_the_times_of_an_entry_below_a_unit_come_from_the_record_of_the_scan() {
    let owner = Uid::new(501);
    let time = |seconds: i64| WallTime::from_unix(seconds, 0).unwrap();
    let path = Path::new("/unit/object.o");
    let entry = crate::scan::EntryRecord {
        path,
        kind: crate::scan::EntryKind::File,
        depth: 1,
        logical_bytes: Some(svalnir_core::quantity::Bytes::new(6)),
        allocated_bytes: Some(svalnir_core::quantity::Bytes::new(4096)),
        link_count: 1,
        object: FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(7),
        },
        counted_in_totals: true,
        owner,
        modified: Some(time(1_794_830_400)),
        changed: Some(time(1_794_830_460)),
    };
    // The newer of the two times is the change of the entry. No file has
    // the path: the function reads the record and not the filesystem.
    assert_eq!(entry_change(&entry, owner), Ok(time(1_794_830_460)));
    let modified_later = crate::scan::EntryRecord {
        modified: Some(time(1_794_830_520)),
        ..entry
    };
    assert_eq!(
        entry_change(&modified_later, owner),
        Ok(time(1_794_830_520))
    );
    // An entry of another owner is not data of the user of the discovery.
    assert_eq!(
        entry_change(&entry, Uid::new(502)),
        Err(SkipReason::WrongOwner)
    );
    // A time that is not valid gives no age.
    for no_time in [
        crate::scan::EntryRecord {
            modified: None,
            ..entry
        },
        crate::scan::EntryRecord {
            changed: None,
            ..entry
        },
    ] {
        assert_eq!(entry_change(&no_time, owner), Err(SkipReason::AgeUnknown));
    }
}

#[test]
fn a_known_candidate_of_the_temporary_rule_is_a_direct_entry_of_the_root() {
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let full = discover_temporary(&fixture);
    assert_eq!(full.candidates.len(), 1);
    // A known candidate that names an entry below a link of the root. The
    // link goes to a directory outside the root.
    let outside = fixture.base().join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, fixture.root().join("sub")).unwrap();
    let mut forged: DiscoveredCandidate = full.candidates[0].clone();
    forged.evidence.relative_entry =
        svalnir_core::file::LosslessPath::from_bytes(b"sub/item").unwrap();

    let error = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::KnownCandidatesOnly(&[forged]),
        limits(),
        &later_clock(),
    )
    .unwrap_err();

    assert!(matches!(error, DiscoveryError::KnownCandidate));
}

#[test]
fn a_root_marker_that_cannot_be_read_is_a_denied_capability() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = temporary_fixture();
    add_item(&fixture, "item-a", |_| {});
    let marker = fixture.root().join(ROOT_MARKER_NAME);
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o000)).unwrap();
    // The superuser reads each file: the case does not exist for it.
    if File::open(&marker).is_ok() {
        return;
    }

    let error = discover_temporary_with(
        &fixture,
        NO_LEASES,
        DiscoveryMode::Full,
        limits(),
        &later_clock(),
    )
    .unwrap_err();

    assert!(
        matches!(&error, DiscoveryError::RootUnavailable(cause)
            if cause.kind() == io::ErrorKind::PermissionDenied),
        "{error:?}"
    );
}
