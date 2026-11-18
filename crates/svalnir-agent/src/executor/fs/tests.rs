//! Tests of the filesystem executor.
//!
//! Each test changes files only below a temporary directory that it made.
//! No test uses the Trash of the operating system: [`FakeTrash`] moves an
//! entry to a directory of the fixture.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use svalnir_core::action::{
    ActionClass, Attribution, Checked, ClientRole, Correlation, DispatchConsumption,
    DispatchReceipt, DispatchState, Durability, EnvelopeContent, ErrorCode, ErrorFamily,
    Escalation, EvidenceBinding, ExecutorRole, FileBinding, FileObjectType, LeaseResource,
    NativeResult, OperationState, PLAN_SCHEMA_VERSION, PlanTarget, Principal, RecordingMode,
    RequestEnvelope, Reservation, ResourceLease, StepLimits, StopReason, TargetBinding,
    TargetEffect, TargetResult, Trigger, WorkCharge, aggregate,
};
use svalnir_core::authority::AuthorityBinding;
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, LosslessPath};
use svalnir_core::id::{
    AdapterId, BootId, ClockDomainId, ExecutorEpochId, LeaseId, MountId, OperationId, PlanId,
    PolicyRevisionId, RootId, RuleId, RuleRevisionId, StepId, TargetId, VolumeId,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::MonotonicNanos;
use tempfile::TempDir;

use super::errors::{CallVerdict, code, mutation_verdict, read_cause};
use super::model::path_components;
use super::native::{self, Kind, Metadata};
use super::remove::{EntryOutcome, settle_unlink};
use super::resolve::{Checkpoint, CheckpointHook, Injection, MetadataHook};
use super::{
    AdmissionRefusal, AdmittedStep, ApprovedRoot, ApprovedRoots, BatchOutcome, ConfigError,
    ExecutorLimits, FsExecutor, FsExecutorConfig, FsTargetOutcome, NeverStop, RootError, Stop,
    TrashBackend, TrashFailure, TrashReply, TrashRequest,
};

const ROOT_ID: &str = "root_1";

fn object_of(path: &Path) -> FileObjectEvidence {
    let metadata = fs::symlink_metadata(path).unwrap();
    FileObjectEvidence {
        device: DeviceNumber::new(i32::try_from(metadata.dev()).unwrap()),
        inode: metadata.ino().into(),
    }
}

fn kind_of(path: &Path) -> FileObjectType {
    let file_type = fs::symlink_metadata(path).unwrap().file_type();
    if file_type.is_symlink() {
        FileObjectType::SymbolicLink
    } else if file_type.is_dir() {
        FileObjectType::Directory
    } else {
        FileObjectType::RegularFile
    }
}

/// The names, the inodes, and the sizes of a tree, to show that a test did
/// not change it.
fn listing(directory: &Path) -> Vec<(PathBuf, u64, u64)> {
    let mut entries: Vec<(PathBuf, u64, u64)> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            entries.push((path.clone(), metadata.ino(), metadata.len()));
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    entries.sort();
    entries
}

/// A temporary directory with an approved root, a home directory, a Trash
/// directory, and a region outside the root that no test is permitted to
/// change.
struct Fixture {
    _temp: TempDir,
    base: PathBuf,
    root: PathBuf,
    outside: PathBuf,
    trash: PathBuf,
    home: PathBuf,
    outside_before: Vec<(PathBuf, u64, u64)>,
}

impl Fixture {
    fn new() -> Self {
        let temp: TempDir = tempfile::tempdir().unwrap();
        // The temporary directory of macOS is below the symbolic link
        // `/var`. An approved root has no symbolic link in its path.
        let base: PathBuf = fs::canonicalize(temp.path()).unwrap();
        let root: PathBuf = base.join("root");
        let outside: PathBuf = base.join("outside");
        let trash: PathBuf = base.join("trash");
        let home: PathBuf = base.join("home");
        for directory in [&root, &outside, &trash, &home] {
            fs::create_dir(directory).unwrap();
        }
        fs::write(outside.join("keep.txt"), b"keep").unwrap();
        fs::create_dir(outside.join("dir")).unwrap();
        fs::write(outside.join("dir").join("inner.txt"), b"inner").unwrap();
        let outside_before = listing(&outside);
        Self {
            _temp: temp,
            base,
            root,
            outside,
            trash,
            home,
            outside_before,
        }
    }

    /// Asserts that the region outside the approved root and the home
    /// directory are as the fixture made them.
    fn assert_outside_unchanged(&self) {
        assert_eq!(listing(&self.outside), self.outside_before);
        assert_eq!(
            fs::read(self.outside.join("keep.txt")).unwrap(),
            b"keep".to_vec()
        );
        assert!(self.home.is_dir());
        assert!(self.root.is_dir());
    }

    fn approved_root(&self) -> ApprovedRoot {
        ApprovedRoot {
            root_id: RootId::new(ROOT_ID).unwrap(),
            path: LosslessPath::from_path(&self.root).unwrap(),
            object: object_of(&self.root),
            volume_id: VolumeId::new("volume_1").unwrap(),
            mount_id: MountId::new("mount_1").unwrap(),
        }
    }

    fn roots(&self) -> ApprovedRoots {
        ApprovedRoots::new(vec![self.approved_root()]).unwrap()
    }

    fn config(&self) -> FsExecutorConfig {
        FsExecutorConfig {
            home_directory: LosslessPath::from_path(&self.home).unwrap(),
            limits: ExecutorLimits::default(),
        }
    }

    fn fake_trash(&self) -> FakeTrash {
        FakeTrash::new(&self.trash, TrashMode::Move)
    }

    fn executor(&self) -> FsExecutor {
        FsExecutor::new(&self.config(), Box::new(self.fake_trash())).unwrap()
    }

    fn executor_with(&self, injection: Injection) -> FsExecutor {
        self.executor().with_injection(injection)
    }

    /// The binding of the entry `relative` as it is now.
    fn binding(&self, relative: &str) -> FileBinding {
        let path: PathBuf = self.root.join(relative);
        binding_with(
            self,
            relative.as_bytes(),
            kind_of(&path),
            Some(object_of(&path)),
        )
    }

    fn envelope(&self, class: ActionClass, relative: &str) -> RequestEnvelope {
        envelope_of(class, relative, self.binding(relative))
    }
}

/// The binding with the root path and the root object of `root`: the plan
/// and the root record then name the same root.
fn under(root: &ApprovedRoot, mut binding: FileBinding) -> FileBinding {
    binding.root_path = root.path.clone();
    binding.root_object = root.object;
    binding
}

fn uid() -> Uid {
    Uid::new(native::effective_uid())
}

fn binding_with(
    fixture: &Fixture,
    relative: &[u8],
    object_type: FileObjectType,
    object: Option<FileObjectEvidence>,
) -> FileBinding {
    FileBinding {
        root_id: RootId::new(ROOT_ID).unwrap(),
        root_path: LosslessPath::from_path(&fixture.root).unwrap(),
        root_object: object_of(&fixture.root),
        relative_entry: LosslessPath::from_bytes(relative).unwrap(),
        volume_id: VolumeId::new("volume_1").unwrap(),
        mount_id: MountId::new("mount_1").unwrap(),
        object_type,
        owner: uid(),
        object,
        rule: Some(RuleRef {
            id: RuleId::new("svalnir.expired-temporary").unwrap(),
            revision: RuleRevisionId::new("rule_rev_1").unwrap(),
        }),
        layout: Some("layout-v1".to_owned()),
        charge: WorkCharge::new(Bytes::new(1), EntryCount::new(1)),
    }
}

fn envelope_content(class: ActionClass, target: &str, file: FileBinding) -> EnvelopeContent {
    let operation_id = OperationId::new("operation_1").unwrap();
    let executor_epoch = ExecutorEpochId::new("epoch_1").unwrap();
    let charge: WorkCharge = file.charge;
    let principal_uid: Uid = file.owner;
    // An identity has letters, digits, `.`, `_`, `:`, and `-` only.
    let identity: String = target
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte)
            } else {
                '_'
            }
        })
        .collect();
    EnvelopeContent {
        schema_version: PLAN_SCHEMA_VERSION,
        action_class: class,
        adapter: AdapterId::new("svalnir.expired-temporary").unwrap(),
        correlation: Correlation {
            plan_id: PlanId::new("plan_1").unwrap(),
            plan_digest: ContentDigest::of_bytes(b"plan"),
            operation_id: operation_id.clone(),
            step_id: StepId::new(format!("step_{identity}")).unwrap(),
            parent_operation_id: None,
        },
        principal: Principal {
            uid: principal_uid,
            session: None,
            role: ClientRole::Cli,
        },
        executor: ExecutorRole::User,
        authority: AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_rev_1").unwrap(),
            action_grants: Vec::new(),
            privilege_grant: None,
        },
        trigger: Trigger::manual(),
        target: PlanTarget {
            target_id: TargetId::new(format!("target_{identity}")).unwrap(),
            binding: TargetBinding::File(file),
        },
        evidence: EvidenceBinding {
            clock_domain: ClockDomainId::new("clock_1").unwrap(),
            boot_id: BootId::new("boot_1").unwrap(),
            executor_epoch: executor_epoch.clone(),
            observed_at: MonotonicNanos::new(1),
            valid_until: MonotonicNanos::new(2),
        },
        limits: StepLimits {
            reservation: Reservation::Work { charge },
            deadline: MonotonicNanos::new(10),
            grace: None,
            verification_window: Nanoseconds::new(1),
            escalation: Escalation::None,
        },
        leases: vec![ResourceLease {
            lease_id: LeaseId::new("lease_1").unwrap(),
            resource: LeaseResource::CleanupRoot(RootId::new(ROOT_ID).unwrap()),
            owner: operation_id,
            executor_epoch,
            expires_at: MonotonicNanos::new(100),
        }],
        recording: RecordingMode::Durable,
    }
}

fn envelope_of(class: ActionClass, target: &str, file: FileBinding) -> RequestEnvelope {
    Checked::new(envelope_content(class, target, file)).unwrap()
}

fn receipt() -> DispatchReceipt {
    DispatchReceipt {
        consumption: DispatchConsumption::Consumed,
        durability: Durability::Durable,
    }
}

fn run(
    executor: &FsExecutor,
    roots: &ApprovedRoots,
    envelope: &RequestEnvelope,
) -> FsTargetOutcome {
    let receipt: DispatchReceipt = receipt();
    let step = AdmittedStep::new(envelope, &receipt).unwrap();
    executor.execute_step(roots, step).unwrap()
}

fn failure_code(result: &TargetResult) -> &str {
    result.failure.as_ref().unwrap().code.as_str()
}

fn failure_family(result: &TargetResult) -> &ErrorFamily {
    &result.failure.as_ref().unwrap().family
}

/// Asserts a `Skipped` result with no submission and the code `code`.
fn assert_skipped(outcome: &FsTargetOutcome, family: &ErrorFamily, code: &str) {
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(result.dispatch, DispatchState::NotSubmitted);
    assert_eq!(result.evidence.native, NativeResult::NotCalled);
    assert_eq!(result.attribution, Attribution::NotApplicable);
    assert_eq!(failure_code(result), code);
    assert_eq!(failure_family(result), family);
    assert_eq!(
        result.failure.as_ref().unwrap().dispatch,
        DispatchState::NotSubmitted
    );
    assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
    assert_eq!(outcome.work.trashed_entries, EntryCount::ZERO);
}

fn assert_removed(outcome: &FsTargetOutcome) {
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Removed);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.evidence.native, NativeResult::Succeeded);
    assert_eq!(result.attribution, Attribution::Established);
    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.durability, Durability::Durable);
    assert!(result.failure.is_none());
    assert!(result.evidence.source.is_some());
    assert!(result.evidence.observed_at.is_some());
}

/// How the fake Trash replies.
#[derive(Debug, Clone, Copy)]
enum TrashMode {
    /// Moves the entry to the Trash directory of the fixture and gives the
    /// item and its identity.
    Move,
    /// Moves the entry and gives no item.
    MoveWithoutItem,
    /// Moves the entry, gives no item, and puts another file at the name
    /// of the source before it replies.
    MoveWithoutItemThenReplace,
    /// Moves nothing and reports a failure.
    Fail(TrashFailure),
    /// Moves nothing and reports a move.
    ClaimMove,
    /// Moves the entry and gives no result.
    MoveAndLoseReply,
    /// Moves the entry to another name than its own, as the Trash does
    /// when an item with that name is already there.
    MoveToAnotherName,
}

/// A Trash backend that moves an entry to a directory of the test.
#[derive(Debug)]
struct FakeTrash {
    directory: PathBuf,
    mode: TrashMode,
    requests: Mutex<Vec<PathBuf>>,
}

impl FakeTrash {
    fn new(directory: &Path, mode: TrashMode) -> Self {
        Self {
            directory: directory.to_path_buf(),
            mode,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn move_entry(&self, source: &Path) -> io::Result<PathBuf> {
        let name: &OsStr = source.file_name().unwrap();
        let item: PathBuf = self.directory.join(name);
        fs::rename(source, &item)?;
        Ok(item)
    }
}

impl TrashBackend for FakeTrash {
    fn move_to_trash(&self, request: &TrashRequest<'_>) -> TrashReply {
        let source: PathBuf = request.path.to_path_buf();
        // The fake Trash refuses each path outside the temporary directory
        // of its fixture.
        assert!(source.starts_with(self.directory.parent().unwrap()));
        self.requests.lock().unwrap().push(source.clone());
        match self.mode {
            TrashMode::Move => match self.move_entry(&source) {
                Ok(item) => TrashReply::Moved {
                    item_object: Some(object_of(&item)),
                    item: Some(LosslessPath::from_path(&item).unwrap()),
                },
                Err(error) => {
                    TrashReply::Failed(TrashFailure::Errno(error.raw_os_error().unwrap()))
                }
            },
            TrashMode::MoveWithoutItem => {
                self.move_entry(&source).unwrap();
                TrashReply::Moved {
                    item: None,
                    item_object: None,
                }
            }
            TrashMode::MoveWithoutItemThenReplace => {
                self.move_entry(&source).unwrap();
                fs::write(&source, b"replacement").unwrap();
                TrashReply::Moved {
                    item: None,
                    item_object: None,
                }
            }
            TrashMode::Fail(failure) => TrashReply::Failed(failure),
            TrashMode::ClaimMove => TrashReply::Moved {
                item: None,
                item_object: None,
            },
            TrashMode::MoveAndLoseReply => {
                self.move_entry(&source).unwrap();
                TrashReply::Unknown
            }
            TrashMode::MoveToAnotherName => {
                let mut name: OsString = source.file_name().unwrap().to_os_string();
                name.push(" 2");
                let item: PathBuf = self.directory.join(name);
                fs::rename(&source, &item).unwrap();
                TrashReply::Moved {
                    item_object: Some(object_of(&item)),
                    item: Some(LosslessPath::from_path(&item).unwrap()),
                }
            }
        }
    }
}

fn once(action: impl Fn(&[u8]) + Send + Sync + 'static, at: Checkpoint) -> CheckpointHook {
    let done = AtomicBool::new(false);
    Box::new(move |checkpoint: Checkpoint, path: &[u8]| {
        if checkpoint == at && !done.swap(true, Ordering::SeqCst) {
            action(path);
        }
    })
}

fn checkpoint_injection(hook: CheckpointHook) -> Injection {
    Injection {
        metadata: None,
        checkpoint: Some(hook),
    }
}

fn metadata_injection(hook: MetadataHook) -> Injection {
    Injection {
        metadata: Some(hook),
        checkpoint: None,
    }
}

/// A hook that gives the entry whose path ends with `suffix` the device
/// number of another filesystem.
fn other_device(suffix: &'static str) -> MetadataHook {
    Box::new(move |path: &[u8], metadata: &mut Metadata| {
        if path.ends_with(suffix.as_bytes()) {
            let device: i32 = metadata.device.unwrap().get();
            metadata.device = Some(DeviceNumber::new(device.wrapping_add(1)));
        }
    })
}

const PERMANENT: [ActionClass; 2] = [
    ActionClass::DeleteSelectedFiles,
    ActionClass::EvictRegenerableData,
];

// ---------------------------------------------------------------------
// Each action class on files and trees
// ---------------------------------------------------------------------

#[test]
fn a_permanent_class_removes_a_regular_file() {
    for class in PERMANENT {
        let fixture = Fixture::new();
        let file: PathBuf = fixture.root.join("cache.bin");
        fs::write(&file, [7_u8; 1000]).unwrap();
        fs::write(fixture.root.join("sibling.bin"), b"sibling").unwrap();
        let envelope = fixture.envelope(class, "cache.bin");

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_removed(&outcome);
        assert!(!file.exists());
        assert!(fixture.root.join("sibling.bin").exists());
        assert_eq!(outcome.work.removed_entries, EntryCount::new(1));
        assert_eq!(outcome.work.removed_logical_bytes, Bytes::new(1000));
        assert_eq!(outcome.work.multiply_linked_entries, EntryCount::ZERO);
        assert_eq!(outcome.work.remaining_entries, EntryCount::ZERO);
        assert!(outcome.work.exact);
        assert!(outcome.trash_item.is_none());
        assert!(fs::read_dir(&fixture.trash).unwrap().next().is_none());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_permanent_class_removes_a_symbolic_link_and_not_its_target() {
    for class in PERMANENT {
        let fixture = Fixture::new();
        let link: PathBuf = fixture.root.join("link");
        symlink(fixture.outside.join("dir"), &link).unwrap();
        let envelope = fixture.envelope(class, "link");

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_removed(&outcome);
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(outcome.work.removed_entries, EntryCount::new(1));
        fixture.assert_outside_unchanged();
    }
}

/// Makes `root/tree` with two nested levels, four regular files, and one
/// symbolic link to a directory outside the root. The tree has eight
/// entries below the target directory.
fn make_tree(fixture: &Fixture) -> PathBuf {
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir_all(tree.join("a").join("b")).unwrap();
    fs::create_dir(tree.join("empty")).unwrap();
    fs::write(tree.join("top.bin"), [1_u8; 10]).unwrap();
    fs::write(tree.join("a").join("one.bin"), [1_u8; 20]).unwrap();
    fs::write(tree.join("a").join("b").join("two.bin"), [1_u8; 30]).unwrap();
    fs::write(tree.join("a").join("b").join("three.bin"), [1_u8; 40]).unwrap();
    symlink(&fixture.outside, tree.join("a").join("escape")).unwrap();
    tree
}

#[test]
fn a_permanent_class_removes_a_tree_bottom_up() {
    for class in PERMANENT {
        let fixture = Fixture::new();
        let tree: PathBuf = make_tree(&fixture);
        let link_length: u64 = fs::symlink_metadata(tree.join("a").join("escape"))
            .unwrap()
            .len();
        let envelope = fixture.envelope(class, "tree");

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_removed(&outcome);
        assert!(!tree.exists());
        // Eight entries and the target directory.
        assert_eq!(outcome.work.removed_entries, EntryCount::new(9));
        assert_eq!(
            outcome.work.removed_logical_bytes,
            Bytes::new(100 + link_length)
        );
        assert_eq!(outcome.work.remaining_entries, EntryCount::ZERO);
        assert!(outcome.work.exact);
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_target_below_nested_directories_is_removed() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.root.join("x").join("y")).unwrap();
    let file: PathBuf = fixture.root.join("x").join("y").join("deep.bin");
    fs::write(&file, b"deep").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "x/y/deep.bin");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_removed(&outcome);
    assert!(!file.exists());
    assert!(fixture.root.join("x").join("y").is_dir());
    fixture.assert_outside_unchanged();
}

#[test]
fn trash_moves_a_file_and_does_not_report_a_removal() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("report.txt");
    fs::write(&file, [1_u8; 123]).unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "report.txt");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Trashed);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Established);
    assert_eq!(result.stop_reason, StopReason::Completed);
    assert!(result.failure.is_none());
    let item: PathBuf = fixture.trash.join("report.txt");
    assert_eq!(
        result.evidence.trash_item,
        Some(LosslessPath::from_path(&item).unwrap())
    );
    assert_eq!(outcome.trash_item, result.evidence.trash_item);
    assert!(!file.exists());
    assert_eq!(fs::read(&item).unwrap().len(), 123);
    // A move to Trash is not a removal and not reclaimed capacity.
    assert_eq!(outcome.work.trashed_entries, EntryCount::new(1));
    assert_eq!(outcome.work.trashed_logical_bytes, Some(Bytes::new(123)));
    assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
    assert_eq!(outcome.work.removed_logical_bytes, Bytes::ZERO);
    assert_eq!(outcome.work.removed_allocated_bytes, Bytes::ZERO);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_file_replaced_by_a_directory_is_skipped() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        let file: PathBuf = fixture.root.join("data.bin");
        fs::write(&file, b"data").unwrap();
        let envelope = fixture.envelope(class, "data.bin");
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        fs::write(file.join("inner.bin"), b"inner").unwrap();

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_skipped(&outcome, &ErrorFamily::Evidence, code::TARGET_TYPE_CHANGED);
        assert!(file.join("inner.bin").exists());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_hard_link_inside_a_tree_loses_one_name_and_keeps_its_content() {
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir(&tree).unwrap();
    let linked: PathBuf = tree.join("linked.bin");
    let kept: PathBuf = fixture.root.join("kept.bin");
    fs::write(&linked, [5_u8; 2048]).unwrap();
    fs::hard_link(&linked, &kept).unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_removed(&outcome);
    assert!(!tree.exists());
    assert_eq!(fs::read(&kept).unwrap(), vec![5_u8; 2048]);
    assert_eq!(outcome.work.multiply_linked_entries, EntryCount::new(1));
    // The removal of one of two names releases no storage of the file.
    assert_eq!(outcome.work.removed_allocated_bytes, Bytes::ZERO);
    fixture.assert_outside_unchanged();
}

#[test]
fn trash_moves_a_symbolic_link_and_not_its_target() {
    let fixture = Fixture::new();
    let link: PathBuf = fixture.root.join("link");
    symlink(fixture.outside.join("keep.txt"), &link).unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "link");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_eq!(outcome.result.effect, TargetEffect::Trashed);
    assert!(fs::symlink_metadata(&link).is_err());
    assert!(
        fs::symlink_metadata(fixture.trash.join("link"))
            .unwrap()
            .is_symlink()
    );
    fixture.assert_outside_unchanged();
}

#[test]
fn trash_moves_one_name_of_a_hard_linked_file() {
    let fixture = Fixture::new();
    let first: PathBuf = fixture.root.join("first.bin");
    let second: PathBuf = fixture.root.join("second.bin");
    fs::write(&first, [3_u8; 100]).unwrap();
    fs::hard_link(&first, &second).unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "first.bin");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_eq!(outcome.result.effect, TargetEffect::Trashed);
    assert!(!first.exists());
    assert_eq!(fs::read(&second).unwrap(), vec![3_u8; 100]);
    assert_eq!(
        fs::read(fixture.trash.join("first.bin")).unwrap().len(),
        100
    );
    assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_trash_item_with_another_name_is_reported_with_its_own_path() {
    let fixture = Fixture::new();
    fs::write(fixture.trash.join("report.txt"), b"older").unwrap();
    let file: PathBuf = fixture.root.join("report.txt");
    fs::write(&file, b"newer").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "report.txt");
    let executor = FsExecutor::new(
        &fixture.config(),
        Box::new(FakeTrash::new(&fixture.trash, TrashMode::MoveToAnotherName)),
    )
    .unwrap();

    let outcome = run(&executor, &fixture.roots(), &envelope);

    let item: PathBuf = fixture.trash.join("report.txt 2");
    assert_eq!(outcome.result.effect, TargetEffect::Trashed);
    assert_eq!(
        outcome.result.evidence.trash_item,
        Some(LosslessPath::from_path(&item).unwrap())
    );
    assert_eq!(fs::read(&item).unwrap(), b"newer");
    // The item that was in the Trash stays as it was.
    assert_eq!(
        fs::read(fixture.trash.join("report.txt")).unwrap(),
        b"older"
    );
    fixture.assert_outside_unchanged();
}

#[test]
fn trash_moves_a_tree_as_one_entry() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_tree(&fixture);
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "tree");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_eq!(outcome.result.effect, TargetEffect::Trashed);
    assert!(!tree.exists());
    let item: PathBuf = fixture.trash.join("tree");
    assert!(item.join("a").join("b").join("two.bin").exists());
    assert_eq!(outcome.work.trashed_entries, EntryCount::new(1));
    // The executor does not measure the content of a directory that it
    // moves: the size is not known, and it is not zero.
    assert_eq!(outcome.work.trashed_logical_bytes, None);
    fixture.assert_outside_unchanged();
}

#[test]
fn trash_without_an_item_reference_has_possible_attribution() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("a.txt"), b"a").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "a.txt");
    let trash = FakeTrash::new(&fixture.trash, TrashMode::MoveWithoutItem);
    let executor = FsExecutor::new(&fixture.config(), Box::new(trash)).unwrap();

    let outcome = run(&executor, &fixture.roots(), &envelope);

    assert_eq!(outcome.result.effect, TargetEffect::Trashed);
    assert_eq!(outcome.result.attribution, Attribution::Possible);
    assert!(outcome.result.evidence.trash_item.is_none());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_failed_trash_move_is_reported_and_is_not_a_removal() {
    let cases = [
        (TrashFailure::Unsupported, code::TRASH_UNSUPPORTED, None),
        (
            TrashFailure::PermissionDenied,
            code::PERMISSION_DENIED,
            None,
        ),
        (
            TrashFailure::ReadOnlyVolume,
            code::READ_ONLY_FILESYSTEM,
            None,
        ),
        (
            TrashFailure::Errno(libc::EBUSY),
            code::RESOURCE_BUSY,
            Some(libc::EBUSY),
        ),
        (
            TrashFailure::Errno(libc::EINTR),
            code::INTERRUPTED,
            Some(libc::EINTR),
        ),
        (TrashFailure::Other, code::TRASH_FAILED, None),
    ];
    for (failure, expected_code, errno) in cases {
        let fixture = Fixture::new();
        let file: PathBuf = fixture.root.join("keep-me.txt");
        fs::write(&file, b"personal").unwrap();
        let envelope = fixture.envelope(ActionClass::MoveToTrash, "keep-me.txt");
        let trash = FakeTrash::new(&fixture.trash, TrashMode::Fail(failure));
        let executor = FsExecutor::new(&fixture.config(), Box::new(trash)).unwrap();

        let outcome = run(&executor, &fixture.roots(), &envelope);

        let result: &TargetResult = &outcome.result;
        assert_eq!(result.effect, TargetEffect::Refused, "{failure:?}");
        assert_eq!(result.dispatch, DispatchState::Submitted);
        assert_eq!(result.stop_reason, StopReason::Failed);
        assert_eq!(failure_code(result), expected_code);
        assert_eq!(failure_family(result), &ErrorFamily::Native);
        let native = errno.map_or(NativeResult::Refused, |errno| NativeResult::Errno { errno });
        assert_eq!(result.evidence.native, native);
        // The file is where it was. No fallback removed it.
        assert_eq!(fs::read(&file).unwrap(), b"personal".to_vec());
        assert_eq!(outcome.work.trashed_entries, EntryCount::ZERO);
        assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
        assert_eq!(outcome.work.remaining_entries, EntryCount::new(1));
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_trash_backend_that_finds_no_entry_is_checked_against_the_open_directory() {
    // The backend resolves the path again. Its reply that the entry is
    // absent is true only when the name is absent in the open parent.
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("a.txt");
    fs::write(&file, b"a").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "a.txt");
    let not_found = || FakeTrash::new(&fixture.trash, TrashMode::Fail(TrashFailure::NotFound));

    // The object of the plan is where it was: nothing was moved, and the
    // target is not in its final condition.
    let executor = FsExecutor::new(&fixture.config(), Box::new(not_found())).unwrap();
    let outcome = run(&executor, &fixture.roots(), &envelope);
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Refused);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(failure_code(result), code::ENTRY_ABSENT);
    assert_eq!(failure_family(result), &ErrorFamily::Evidence);
    assert!(file.exists());
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(1));

    // The name is absent in the open parent also.
    let removed: PathBuf = file.clone();
    let hook = once(
        move |_path: &[u8]| fs::remove_file(&removed).unwrap(),
        Checkpoint::Revalidated,
    );
    let executor = FsExecutor::new(&fixture.config(), Box::new(not_found()))
        .unwrap()
        .with_injection(checkpoint_injection(hook));
    let outcome = run(&executor, &fixture.roots(), &envelope);
    assert_eq!(outcome.result.effect, TargetEffect::AlreadyAbsent);
    assert_eq!(outcome.result.dispatch, DispatchState::Submitted);
    assert_eq!(outcome.result.attribution, Attribution::Possible);
    assert_eq!(outcome.work.vanished_entries, EntryCount::new(1));
    fixture.assert_outside_unchanged();
}

#[test]
fn a_trash_reply_that_the_observation_contradicts_is_an_unknown_outcome() {
    // The backend reports a move and the file is where it was.
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("a.txt");
    fs::write(&file, b"a").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "a.txt");
    let trash = FakeTrash::new(&fixture.trash, TrashMode::ClaimMove);
    let executor = FsExecutor::new(&fixture.config(), Box::new(trash)).unwrap();
    let outcome = run(&executor, &fixture.roots(), &envelope);
    assert_eq!(outcome.result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(failure_code(&outcome.result), code::OUTCOME_UNVERIFIED);
    assert_eq!(failure_family(&outcome.result), &ErrorFamily::Outcome);
    assert!(file.exists());

    // The backend gives no result and the file is gone.
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("b.txt");
    fs::write(&file, b"b").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "b.txt");
    let trash = FakeTrash::new(&fixture.trash, TrashMode::MoveAndLoseReply);
    let executor = FsExecutor::new(&fixture.config(), Box::new(trash)).unwrap();
    let outcome = run(&executor, &fixture.roots(), &envelope);
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(result.evidence.native, NativeResult::Unavailable);
    assert_eq!(failure_code(result), code::TRASH_RESULT_UNKNOWN);
    assert_eq!(
        aggregate(std::slice::from_ref(result)).unwrap(),
        OperationState::UnknownOutcome
    );
    fixture.assert_outside_unchanged();
}

#[test]
fn a_trash_move_of_a_replaced_entry_is_reported_as_not_established() {
    // Between the revalidation and the Trash call, another actor replaces
    // the file. The path-based Trash operation moves the replacement.
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("a.txt");
    fs::write(&file, b"planned").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "a.txt");
    let aside: PathBuf = fixture.root.join("aside.txt");
    let (from, to) = (file.clone(), aside.clone());
    let hook = once(
        move |_path: &[u8]| {
            fs::rename(&from, &to).unwrap();
            fs::write(&from, b"replacement").unwrap();
        },
        Checkpoint::Revalidated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(failure_code(result), code::TRASH_ITEM_IDENTITY_MISMATCH);
    assert!(result.evidence.trash_item.is_none());
    // The outcome names the item that was moved, so a person can find it.
    let item: PathBuf = fixture.trash.join("a.txt");
    assert_eq!(
        outcome.trash_item,
        Some(LosslessPath::from_path(&item).unwrap())
    );
    assert_eq!(fs::read(&item).unwrap(), b"replacement".to_vec());
    assert_eq!(fs::read(&aside).unwrap(), b"planned".to_vec());
    assert_eq!(outcome.work.trashed_entries, EntryCount::ZERO);
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Replacement between planning and execution
// ---------------------------------------------------------------------

#[test]
fn a_directory_replaced_by_a_symbolic_link_is_skipped() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        let directory: PathBuf = fixture.root.join("cache");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("data"), b"data").unwrap();
        let envelope = fixture.envelope(class, "cache");
        fs::rename(&directory, fixture.root.join("moved")).unwrap();
        symlink(&fixture.outside, &directory).unwrap();

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_skipped(&outcome, &ErrorFamily::Evidence, code::TARGET_TYPE_CHANGED);
        assert_eq!(outcome.result.stop_reason, StopReason::TargetSkipped);
        assert!(fs::symlink_metadata(&directory).unwrap().is_symlink());
        assert!(fixture.root.join("moved").join("data").exists());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_file_replaced_by_a_symbolic_link_is_skipped() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        let file: PathBuf = fixture.root.join("data.bin");
        fs::write(&file, b"data").unwrap();
        let envelope = fixture.envelope(class, "data.bin");
        fs::remove_file(&file).unwrap();
        symlink(fixture.outside.join("keep.txt"), &file).unwrap();

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_skipped(&outcome, &ErrorFamily::Evidence, code::TARGET_TYPE_CHANGED);
        assert!(fs::symlink_metadata(&file).unwrap().is_symlink());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_parent_component_replaced_by_a_symbolic_link_is_skipped() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        let parent: PathBuf = fixture.root.join("a").join("dir");
        fs::create_dir_all(&parent).unwrap();
        fs::write(parent.join("inner.txt"), b"inner").unwrap();
        let envelope = fixture.envelope(class, "a/dir/inner.txt");
        // `outside/dir/inner.txt` exists. A path-string check would accept
        // the path, and a path-based call would act outside the root.
        fs::rename(&parent, fixture.root.join("moved")).unwrap();
        symlink(fixture.outside.join("dir"), &parent).unwrap();

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_skipped(&outcome, &ErrorFamily::Evidence, code::PARENT_NOT_DIRECTORY);
        assert!(fixture.root.join("moved").join("inner.txt").exists());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn an_entry_replaced_by_another_inode_with_the_same_name_is_skipped() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        let file: PathBuf = fixture.root.join("data.bin");
        fs::write(&file, b"old").unwrap();
        let envelope = fixture.envelope(class, "data.bin");
        // The new file exists before the old one goes away, so the two
        // have different inode numbers.
        let replacement: PathBuf = fixture.root.join("data.new");
        fs::write(&replacement, b"new content").unwrap();
        fs::rename(&replacement, &file).unwrap();

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_skipped(
            &outcome,
            &ErrorFamily::Evidence,
            code::TARGET_IDENTITY_CHANGED,
        );
        assert_eq!(fs::read(&file).unwrap(), b"new content".to_vec());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_target_that_is_absent_gives_already_absent_with_no_submission() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("dir")).unwrap();
    fs::write(fixture.root.join("dir").join("f"), b"f").unwrap();
    let entry = fixture.envelope(ActionClass::EvictRegenerableData, "dir/f");
    fs::remove_file(fixture.root.join("dir").join("f")).unwrap();
    let executor = fixture.executor();

    let outcome = run(&executor, &fixture.roots(), &entry);
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::AlreadyAbsent);
    assert_eq!(result.dispatch, DispatchState::NotSubmitted);
    assert_eq!(result.attribution, Attribution::NotApplicable);
    assert_eq!(result.evidence.native, NativeResult::NotCalled);
    assert!(result.failure.is_none());
    assert_eq!(
        aggregate(std::slice::from_ref(result)).unwrap(),
        OperationState::NoAction
    );

    // The parent directory is absent also.
    fs::remove_dir(fixture.root.join("dir")).unwrap();
    let outcome = run(&executor, &fixture.roots(), &entry);
    assert_eq!(outcome.result.effect, TargetEffect::AlreadyAbsent);
    assert_eq!(outcome.result.dispatch, DispatchState::NotSubmitted);
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Replacement between the revalidation and the call
// ---------------------------------------------------------------------

#[test]
fn a_directory_replaced_after_the_revalidation_is_not_entered() {
    let fixture = Fixture::new();
    let directory: PathBuf = fixture.root.join("cache");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("data"), b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "cache");
    let (from, to, outside) = (
        directory.clone(),
        fixture.root.join("moved"),
        fixture.outside.clone(),
    );
    let hook = once(
        move |_path: &[u8]| {
            fs::rename(&from, &to).unwrap();
            symlink(&outside, &from).unwrap();
        },
        Checkpoint::Revalidated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::TARGET_IDENTITY_CHANGED,
    );
    assert!(fs::symlink_metadata(&directory).unwrap().is_symlink());
    assert!(fixture.root.join("moved").join("data").exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_directory_replaced_by_another_directory_after_the_revalidation_is_not_entered() {
    let fixture = Fixture::new();
    let directory: PathBuf = fixture.root.join("cache");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("data"), b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::DeleteSelectedFiles, "cache");
    let (from, to) = (directory.clone(), fixture.root.join("moved"));
    let hook = once(
        move |_path: &[u8]| {
            fs::rename(&from, &to).unwrap();
            fs::create_dir(&from).unwrap();
            fs::write(from.join("other"), b"other").unwrap();
        },
        Checkpoint::Revalidated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::TARGET_IDENTITY_CHANGED,
    );
    assert!(directory.join("other").exists());
    assert!(fixture.root.join("moved").join("data").exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_file_replaced_by_a_symbolic_link_after_the_revalidation_does_not_reach_the_link_target() {
    // This is the race that remains: the comparison and `unlinkat` are two
    // calls. The call removes the name in the open parent directory. It
    // does not follow the link, so the target of the link stays.
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"planned").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "data.bin");
    let (from, to, target) = (
        file.clone(),
        fixture.root.join("aside.bin"),
        fixture.outside.join("keep.txt"),
    );
    let hook = once(
        move |_path: &[u8]| {
            fs::rename(&from, &to).unwrap();
            symlink(&target, &from).unwrap();
        },
        Checkpoint::Revalidated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    assert_eq!(outcome.result.effect, TargetEffect::Removed);
    assert!(fs::symlink_metadata(&file).is_err());
    assert_eq!(
        fs::read(fixture.root.join("aside.bin")).unwrap(),
        b"planned".to_vec()
    );
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_entry_replaced_by_a_symbolic_link_during_removal_is_not_followed() {
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("sub").join("inner.txt"), b"inner").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let (sub, moved, outside) = (
        tree.join("sub"),
        fixture.root.join("moved"),
        fixture.outside.join("dir"),
    );
    // The hook runs after the comparison of `tree/sub` and before the
    // executor opens it. `outside/dir/inner.txt` has the measured name.
    let hook: CheckpointHook = {
        let done = AtomicBool::new(false);
        Box::new(move |checkpoint: Checkpoint, path: &[u8]| {
            let is_sub: bool = path.ends_with(b"/tree/sub");
            if checkpoint == Checkpoint::EntryChecked
                && is_sub
                && !done.swap(true, Ordering::SeqCst)
            {
                fs::rename(&sub, &moved).unwrap();
                symlink(&outside, &sub).unwrap();
            }
        })
    };

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Refused);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(failure_code(result), code::TREE_CHANGED);
    assert_eq!(failure_family(result), &ErrorFamily::Evidence);
    assert_eq!(
        result.evidence.native,
        NativeResult::Errno {
            errno: libc::ENOTEMPTY
        }
    );
    assert!(fs::symlink_metadata(tree.join("sub")).unwrap().is_symlink());
    assert!(fixture.root.join("moved").join("inner.txt").exists());
    assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
    // `sub`, `inner.txt`, and the target directory.
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(3));
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Hard links, mount points, and trees that change
// ---------------------------------------------------------------------

#[test]
fn a_hard_link_loses_one_name_and_keeps_its_content() {
    let fixture = Fixture::new();
    let first: PathBuf = fixture.root.join("first.bin");
    let second: PathBuf = fixture.root.join("second.bin");
    fs::write(&first, [9_u8; 4096]).unwrap();
    fs::hard_link(&first, &second).unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "first.bin");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_removed(&outcome);
    assert!(!first.exists());
    assert_eq!(fs::read(&second).unwrap().len(), 4096);
    assert_eq!(outcome.work.removed_entries, EntryCount::new(1));
    assert_eq!(outcome.work.multiply_linked_entries, EntryCount::new(1));
    assert_eq!(outcome.work.removed_logical_bytes, Bytes::new(4096));
    // The removal of one of two names releases no storage of the file.
    assert_eq!(outcome.work.removed_allocated_bytes, Bytes::ZERO);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_target_on_another_device_is_skipped() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        let mount: PathBuf = fixture.root.join("mnt");
        fs::create_dir(&mount).unwrap();
        fs::write(mount.join("data"), b"data").unwrap();
        let envelope = fixture.envelope(class, "mnt");

        let outcome = run(
            &fixture.executor_with(metadata_injection(other_device("/root/mnt"))),
            &fixture.roots(),
            &envelope,
        );

        assert_skipped(&outcome, &ErrorFamily::Evidence, code::MOUNT_CROSSED);
        assert!(mount.join("data").exists());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_mount_point_between_the_root_and_the_target_is_not_crossed() {
    let fixture = Fixture::new();
    let mount: PathBuf = fixture.root.join("mnt");
    fs::create_dir(&mount).unwrap();
    fs::write(mount.join("data"), b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "mnt/data");

    let outcome = run(
        &fixture.executor_with(metadata_injection(other_device("/root/mnt"))),
        &fixture.roots(),
        &envelope,
    );

    assert_skipped(&outcome, &ErrorFamily::Evidence, code::MOUNT_CROSSED);
    assert!(mount.join("data").exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_mount_point_in_a_tree_refuses_the_tree_as_a_whole() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_tree(&fixture);
    let before = listing(&tree);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");

    let outcome = run(
        &fixture.executor_with(metadata_injection(other_device("/tree/a/b"))),
        &fixture.roots(),
        &envelope,
    );

    assert_skipped(&outcome, &ErrorFamily::Evidence, code::MOUNT_CROSSED);
    // No entry was removed: the measurement comes before each removal.
    assert_eq!(listing(&tree), before);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_binding_on_another_device_than_its_root_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let object: FileObjectEvidence = object_of(&file);
    let other = FileObjectEvidence {
        device: DeviceNumber::new(object.device.get().wrapping_add(1)),
        inode: object.inode,
    };
    let binding = binding_with(
        &fixture,
        b"data.bin",
        FileObjectType::RegularFile,
        Some(other),
    );
    let envelope = envelope_of(ActionClass::EvictRegenerableData, "data", binding);

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_skipped(&outcome, &ErrorFamily::Evidence, code::DEVICE_MISMATCH);
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_that_gains_an_entry_during_removal_gives_a_partial_result() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_tree(&fixture);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let new_file: PathBuf = tree.join("a").join("new.bin");
    let created: PathBuf = new_file.clone();
    let hook = once(
        move |_path: &[u8]| fs::write(&created, b"new").unwrap(),
        Checkpoint::TreeEnumerated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    // A part of the tree was removed. The action contract has no effect
    // for that; `Refused` would state that nothing changed.
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.stop_reason, StopReason::Failed);
    // The entry that appeared is a changed target, not a native refusal.
    assert_eq!(failure_code(result), code::TREE_CHANGED);
    assert_eq!(failure_family(result), &ErrorFamily::Evidence);
    assert_eq!(
        result.failure.as_ref().unwrap().dispatch,
        DispatchState::Submitted
    );
    assert_eq!(
        result.evidence.native,
        NativeResult::Errno {
            errno: libc::ENOTEMPTY
        }
    );
    // The entry that appeared stays, with its directories.
    assert_eq!(fs::read(&new_file).unwrap(), b"new".to_vec());
    assert_eq!(listing(&tree).len(), 2);
    // What was removed: each measured entry other than `a` and the target
    // directory. What was not: those two.
    assert_eq!(outcome.work.removed_entries, EntryCount::new(7));
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(2));
    assert_eq!(outcome.work.vanished_entries, EntryCount::ZERO);
    assert!(outcome.work.exact);
    // The operation is not reported as a failure with no effect.
    assert_eq!(
        aggregate(std::slice::from_ref(result)).unwrap(),
        OperationState::UnknownOutcome
    );
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_entry_with_another_inode_during_removal_stays() {
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("one.bin"), b"one").unwrap();
    fs::write(tree.join("two.bin"), b"two").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let (target, replacement) = (tree.join("two.bin"), tree.join("two.new"));
    let hook = once(
        move |_path: &[u8]| {
            fs::write(&replacement, b"written after the measurement").unwrap();
            fs::rename(&replacement, &target).unwrap();
        },
        Checkpoint::TreeEnumerated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    assert_eq!(outcome.result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(failure_code(&outcome.result), code::TREE_CHANGED);
    assert!(!tree.join("one.bin").exists());
    assert_eq!(
        fs::read(tree.join("two.bin")).unwrap(),
        b"written after the measurement".to_vec()
    );
    assert_eq!(outcome.work.removed_entries, EntryCount::new(1));
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(2));
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Sets a mode and restores the mode when it is dropped, also when an
/// assertion fails, so that the temporary directory can be deleted.
struct ModeGuard {
    path: PathBuf,
    restore: u32,
}

impl Drop for ModeGuard {
    fn drop(&mut self) {
        // The test result does not depend on the restore of the mode.
        drop(fs::set_permissions(
            &self.path,
            fs::Permissions::from_mode(self.restore),
        ));
    }
}

fn lock_mode(path: &Path, mode: u32, restore: u32) -> ModeGuard {
    set_mode(path, mode);
    ModeGuard {
        path: path.to_path_buf(),
        restore,
    }
}

/// Tells that a test did not run, so that the output shows it.
fn skip_for_superuser() -> bool {
    // The superuser is not subject to the permission bits.
    let skip: bool = native::effective_uid() == 0;
    if skip {
        eprintln!("skipped: the effective user is root");
    }
    skip
}

#[test]
fn a_read_only_file_is_removed() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("readonly.bin");
    fs::write(&file, b"data").unwrap();
    set_mode(&file, 0o444);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "readonly.bin");

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    // The right to remove a name is a right on its directory.
    assert_removed(&outcome);
    assert!(!file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_read_only_directory_in_a_tree_gives_a_partial_result() {
    if skip_for_superuser() {
        return;
    }
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    let locked: PathBuf = tree.join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("inner.bin"), b"inner").unwrap();
    fs::write(tree.join("free.bin"), b"free").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let guard = lock_mode(&locked, 0o555, 0o755);

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);
    drop(guard);

    // `free.bin` was removed, so the result is not `Refused`.
    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(failure_code(result), code::PERMISSION_DENIED);
    assert_eq!(failure_family(result), &ErrorFamily::Native);
    assert!(locked.join("inner.bin").exists());
    assert!(!tree.join("free.bin").exists());
    assert_eq!(outcome.work.removed_entries, EntryCount::new(1));
    // `inner.bin`, `locked`, and the target directory.
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(3));
    fixture.assert_outside_unchanged();
}

#[test]
fn an_unreadable_directory_in_a_tree_refuses_the_tree_as_a_whole() {
    if skip_for_superuser() {
        return;
    }
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    let closed: PathBuf = tree.join("closed");
    fs::create_dir_all(&closed).unwrap();
    fs::write(closed.join("inner.bin"), b"inner").unwrap();
    fs::write(tree.join("free.bin"), b"free").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let guard = lock_mode(&closed, 0o000, 0o755);

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);
    drop(guard);

    // The tree cannot be measured, so no entry is removed. A read-only
    // call failed: the stop reason is `FAILED` and no call was submitted.
    assert_skipped(&outcome, &ErrorFamily::Native, code::PERMISSION_DENIED);
    assert_eq!(outcome.result.stop_reason, StopReason::Failed);
    assert!(tree.join("free.bin").exists());
    assert!(closed.join("inner.bin").exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_file_in_a_read_only_parent_is_refused_by_the_call() {
    if skip_for_superuser() {
        return;
    }
    let fixture = Fixture::new();
    let parent: PathBuf = fixture.root.join("parent");
    fs::create_dir(&parent).unwrap();
    let file: PathBuf = parent.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::DeleteSelectedFiles, "parent/data.bin");
    let guard = lock_mode(&parent, 0o555, 0o755);

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);
    drop(guard);

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Refused);
    assert_eq!(
        result.evidence.native,
        NativeResult::Errno {
            errno: libc::EACCES
        }
    );
    assert_eq!(failure_code(result), code::PERMISSION_DENIED);
    assert_eq!(result.attribution, Attribution::NotApplicable);
    assert!(file.exists());
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(1));
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Batches and stops
// ---------------------------------------------------------------------

fn batch(
    fixture: &Fixture,
    names: &[&str],
    stop: &dyn super::StopSignal,
) -> (BatchOutcome, Vec<PathBuf>) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut envelopes: Vec<RequestEnvelope> = Vec::new();
    for name in names {
        let file: PathBuf = fixture.root.join(name);
        fs::write(&file, b"data").unwrap();
        envelopes.push(fixture.envelope(ActionClass::EvictRegenerableData, name));
        files.push(file);
    }
    let receipt: DispatchReceipt = receipt();
    let steps: Vec<AdmittedStep<'_>> = envelopes
        .iter()
        .map(|envelope| AdmittedStep::new(envelope, &receipt).unwrap())
        .collect();
    let outcome: BatchOutcome = fixture
        .executor()
        .execute_batch(&fixture.roots(), steps, stop);
    (outcome, files)
}

fn results_of(outcome: &BatchOutcome) -> Vec<TargetResult> {
    outcome
        .outcomes
        .iter()
        .map(|step| step.as_ref().unwrap().result.clone())
        .collect()
}

#[test]
fn a_batch_does_each_step_in_its_sequence() {
    let fixture = Fixture::new();
    let (outcome, files) = batch(&fixture, &["a.bin", "b.bin", "c.bin"], &NeverStop);

    assert_eq!(outcome.stopped, None);
    let results: Vec<TargetResult> = results_of(&outcome);
    assert_eq!(results.len(), 3);
    for (result, name) in results.iter().zip(["a_bin", "b_bin", "c_bin"]) {
        assert_eq!(result.effect, TargetEffect::Removed);
        assert_eq!(result.target_id.as_str(), format!("target_{name}"));
    }
    assert!(files.iter().all(|file| !file.exists()));
    assert_eq!(aggregate(&results).unwrap(), OperationState::Completed);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_stop_between_targets_leaves_the_later_targets_not_started() {
    let fixture = Fixture::new();
    // The first check permits the first target. The second check stops.
    let checks = AtomicU32::new(0);
    let stop = move || (checks.fetch_add(1, Ordering::SeqCst) >= 1).then_some(Stop::Canceled);

    let (outcome, files) = batch(&fixture, &["a.bin", "b.bin", "c.bin"], &stop);

    assert_eq!(outcome.stopped, Some(Stop::Canceled));
    let results: Vec<TargetResult> = results_of(&outcome);
    assert_eq!(results[0].effect, TargetEffect::Removed);
    assert!(!files[0].exists());
    for (result, file) in results.iter().zip(&files).skip(1) {
        assert_eq!(result.effect, TargetEffect::Skipped);
        assert_eq!(result.dispatch, DispatchState::NotSubmitted);
        assert_eq!(result.stop_reason, StopReason::Canceled);
        assert_eq!(result.evidence.native, NativeResult::NotCalled);
        assert!(result.failure.is_none());
        assert!(file.exists());
    }
    // The removal that was done stays reported: the operation is partial,
    // not a claim of no effect.
    assert_eq!(aggregate(&results).unwrap(), OperationState::Partial);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_stop_at_the_batch_boundary_starts_no_target() {
    let stops = [
        (Stop::Canceled, StopReason::Canceled),
        (Stop::Paused, StopReason::Paused),
        (Stop::PolicyChanged, StopReason::PolicyChanged),
        (Stop::TriggerCleared, StopReason::TriggerCleared),
        (Stop::DeadlineExpired, StopReason::DeadlineExpired),
        (Stop::AuthorityMissing, StopReason::AuthorityMissing),
    ];
    for (stop, reason) in stops {
        let fixture = Fixture::new();
        let signal = move || Some(stop);

        let (outcome, files) = batch(&fixture, &["a.bin", "b.bin"], &signal);

        assert_eq!(outcome.stopped, Some(stop));
        let results: Vec<TargetResult> = results_of(&outcome);
        assert_eq!(results.len(), 2);
        for result in &results {
            assert_eq!(result.effect, TargetEffect::Skipped);
            assert_eq!(result.stop_reason, reason);
            assert_eq!(result.dispatch, DispatchState::NotSubmitted);
        }
        assert!(files.iter().all(|file| file.exists()));
        assert_eq!(aggregate(&results).unwrap(), OperationState::NoAction);
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_refused_target_does_not_stop_the_batch() {
    if skip_for_superuser() {
        return;
    }
    let fixture = Fixture::new();
    let parent: PathBuf = fixture.root.join("parent");
    fs::create_dir(&parent).unwrap();
    let mut envelopes: Vec<RequestEnvelope> = Vec::new();
    for name in ["a.bin", "parent/b.bin", "c.bin"] {
        fs::write(fixture.root.join(name), b"data").unwrap();
        envelopes.push(fixture.envelope(ActionClass::EvictRegenerableData, name));
    }
    let receipt: DispatchReceipt = receipt();
    let steps: Vec<AdmittedStep<'_>> = envelopes
        .iter()
        .map(|envelope| AdmittedStep::new(envelope, &receipt).unwrap())
        .collect();
    // The call for the second target is refused by the system.
    let guard = lock_mode(&parent, 0o555, 0o755);

    let outcome = fixture
        .executor()
        .execute_batch(&fixture.roots(), steps, &NeverStop);
    drop(guard);

    let results: Vec<TargetResult> = results_of(&outcome);
    assert_eq!(outcome.stopped, None);
    assert_eq!(results[0].effect, TargetEffect::Removed);
    assert_eq!(results[1].effect, TargetEffect::Refused);
    assert_eq!(results[2].effect, TargetEffect::Removed);
    assert!(parent.join("b.bin").exists());
    assert!(!fixture.root.join("c.bin").exists());
    assert_eq!(aggregate(&results).unwrap(), OperationState::Partial);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_skipped_target_does_not_stop_the_batch() {
    let fixture = Fixture::new();
    let mut envelopes: Vec<RequestEnvelope> = Vec::new();
    for name in ["a.bin", "b.bin", "c.bin"] {
        fs::write(fixture.root.join(name), b"data").unwrap();
        envelopes.push(fixture.envelope(ActionClass::EvictRegenerableData, name));
    }
    // The second entry changes after the plan.
    fs::write(fixture.root.join("b.new"), b"other").unwrap();
    fs::rename(fixture.root.join("b.new"), fixture.root.join("b.bin")).unwrap();
    let receipt: DispatchReceipt = receipt();
    let steps: Vec<AdmittedStep<'_>> = envelopes
        .iter()
        .map(|envelope| AdmittedStep::new(envelope, &receipt).unwrap())
        .collect();

    let outcome = fixture
        .executor()
        .execute_batch(&fixture.roots(), steps, &NeverStop);

    let results: Vec<TargetResult> = results_of(&outcome);
    assert_eq!(results[0].effect, TargetEffect::Removed);
    assert_eq!(results[1].effect, TargetEffect::Skipped);
    assert_eq!(results[1].stop_reason, StopReason::TargetSkipped);
    assert_eq!(results[2].effect, TargetEffect::Removed);
    assert!(fixture.root.join("b.bin").exists());
    assert_eq!(aggregate(&results).unwrap(), OperationState::Partial);
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------

fn executor_with_limits(fixture: &Fixture, limits: ExecutorLimits) -> FsExecutor {
    let config = FsExecutorConfig {
        home_directory: LosslessPath::from_path(&fixture.home).unwrap(),
        limits,
    };
    FsExecutor::new(&config, Box::new(fixture.fake_trash())).unwrap()
}

/// Makes `root/deep` with `levels` nested directory levels, the target
/// directory included, and one file at the bottom.
fn make_deep(fixture: &Fixture, levels: u32) -> PathBuf {
    let top: PathBuf = fixture.root.join("deep");
    let mut bottom: PathBuf = top.clone();
    for level in 1..levels {
        bottom.push(format!("level{level}"));
    }
    fs::create_dir_all(&bottom).unwrap();
    fs::write(bottom.join("leaf.bin"), b"leaf").unwrap();
    top
}

#[test]
fn a_tree_deeper_than_the_depth_bound_is_refused_as_a_whole() {
    let fixture = Fixture::new();
    let top: PathBuf = make_deep(&fixture, 4);
    let before = listing(&top);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "deep");

    let limits = ExecutorLimits::new(3, 1000, 48).unwrap();
    let outcome = run(
        &executor_with_limits(&fixture, limits),
        &fixture.roots(),
        &envelope,
    );
    assert_skipped(&outcome, &ErrorFamily::Limits, code::TREE_DEPTH_LIMIT);
    assert_eq!(outcome.result.stop_reason, StopReason::TargetSkipped);
    assert_eq!(listing(&top), before);

    // The same tree fits a bound of four levels.
    let limits = ExecutorLimits::new(4, 1000, 48).unwrap();
    let outcome = run(
        &executor_with_limits(&fixture, limits),
        &fixture.roots(),
        &envelope,
    );
    assert_removed(&outcome);
    assert!(!top.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_that_needs_more_descriptors_than_the_budget_is_refused_as_a_whole() {
    let fixture = Fixture::new();
    let top: PathBuf = make_deep(&fixture, 4);
    let before = listing(&top);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "deep");

    // Four levels need the parent directory and four streams.
    let limits = ExecutorLimits::new(32, 1000, 4).unwrap();
    let outcome = run(
        &executor_with_limits(&fixture, limits),
        &fixture.roots(),
        &envelope,
    );
    assert_skipped(&outcome, &ErrorFamily::Limits, code::DESCRIPTOR_LIMIT);
    assert_eq!(listing(&top), before);

    let limits = ExecutorLimits::new(32, 1000, 5).unwrap();
    let outcome = run(
        &executor_with_limits(&fixture, limits),
        &fixture.roots(),
        &envelope,
    );
    assert_removed(&outcome);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_with_more_entries_than_the_entry_bound_is_refused_as_a_whole() {
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir(&tree).unwrap();
    for index in 0..5 {
        fs::write(tree.join(format!("f{index}")), b"x").unwrap();
    }
    let before = listing(&tree);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");

    let limits = ExecutorLimits::new(32, 4, 48).unwrap();
    let outcome = run(
        &executor_with_limits(&fixture, limits),
        &fixture.roots(),
        &envelope,
    );
    assert_skipped(&outcome, &ErrorFamily::Limits, code::TREE_ENTRY_LIMIT);
    assert_eq!(listing(&tree), before);

    let limits = ExecutorLimits::new(32, 5, 48).unwrap();
    let outcome = run(
        &executor_with_limits(&fixture, limits),
        &fixture.roots(),
        &envelope,
    );
    assert_removed(&outcome);
    assert_eq!(outcome.work.removed_entries, EntryCount::new(6));
    fixture.assert_outside_unchanged();
}

#[test]
fn the_limits_have_bounds() {
    assert!(ExecutorLimits::new(1, 1, 3).is_ok());
    assert!(ExecutorLimits::new(128, 1_000_000, 1024).is_ok());
    for (depth, entries, descriptors) in [
        (0, 1, 3),
        (129, 1, 3),
        (1, 0, 3),
        (1, 1_000_001, 3),
        (1, 1, 2),
        (1, 1, 1025),
    ] {
        assert!(ExecutorLimits::new(depth, entries, descriptors).is_err());
    }
    let limits = ExecutorLimits::default();
    assert_eq!(limits.max_tree_depth(), 32);
    assert_eq!(limits.max_tree_entries(), 100_000);
    assert_eq!(limits.max_open_descriptors(), 48);
}

// ---------------------------------------------------------------------
// Names that are not UTF-8
// ---------------------------------------------------------------------

#[test]
fn a_name_that_is_not_utf8_keeps_its_bytes_in_the_components() {
    let components = path_components(b"dir/n\xff.bin", false).unwrap();
    assert_eq!(components.len(), 2);
    assert_eq!(components[1].as_bytes(), b"n\xff.bin");
    let root = path_components(b"/r\xfe/cache", true).unwrap();
    assert_eq!(root[0].as_bytes(), b"r\xfe");
}

#[test]
fn an_entry_with_a_name_that_is_not_utf8_is_removed() {
    // APFS rejects a name that is not valid UTF-8. On a filesystem that
    // accepts it, the executor addresses the entry with its exact bytes.
    let fixture = Fixture::new();
    let name: &OsStr = OsStr::from_bytes(b"n\xff.bin");
    let file: PathBuf = fixture.root.join(name);
    match fs::write(&file, b"data") {
        Ok(()) => {}
        // The filesystem of the temporary directory does not accept the
        // name. Each other error is a failure of the test.
        Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => return,
        Err(error) => panic!("the fixture file was not made: {error}"),
    }
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join(OsStr::from_bytes(b"\xfe\xfd")), b"data").unwrap();

    let binding = binding_with(
        &fixture,
        b"n\xff.bin",
        FileObjectType::RegularFile,
        Some(object_of(&file)),
    );
    let envelope = envelope_of(ActionClass::EvictRegenerableData, "file", binding);
    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);
    assert_removed(&outcome);
    assert!(fs::symlink_metadata(&file).is_err());

    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);
    assert_removed(&outcome);
    assert!(!tree.exists());
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Hard refusals
// ---------------------------------------------------------------------

#[test]
fn a_relative_entry_that_is_not_normalized_is_refused() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.root.join("dir")).unwrap();
    let file: PathBuf = fixture.root.join("dir").join("data.bin");
    fs::write(&file, b"data").unwrap();
    let object = Some(object_of(&file));
    let outside_file: Vec<u8> = fixture
        .outside
        .join("keep.txt")
        .as_os_str()
        .as_bytes()
        .to_vec();
    let entries: [&[u8]; 9] = [
        b"/",
        b".",
        b"..",
        b"dir/../dir/data.bin",
        b"./dir/data.bin",
        b"dir//data.bin",
        b"dir/data.bin/",
        b"../outside/keep.txt",
        &outside_file,
    ];
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        for entry in entries {
            let binding = binding_with(&fixture, entry, FileObjectType::RegularFile, object);
            let envelope = envelope_of(class.clone(), "entry", binding);

            let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

            assert_skipped(
                &outcome,
                &ErrorFamily::Request,
                code::RELATIVE_ENTRY_INVALID,
            );
        }
    }
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_root_path_that_is_not_an_anchored_directory_is_rejected() {
    let fixture = Fixture::new();
    let with_path = |path: &[u8]| {
        let mut root: ApprovedRoot = fixture.approved_root();
        root.path = LosslessPath::from_bytes(path).unwrap();
        ApprovedRoots::new(vec![root]).map(|roots| roots.len())
    };
    for path in [
        b"/".as_slice(),
        b"relative/root",
        b"/a/../b",
        b"/a/./b",
        b"/a//b",
        b"/a/b/",
        b"//",
    ] {
        assert_eq!(with_path(path), Err(RootError::Path));
    }
    assert_eq!(with_path(b"/a/b"), Ok(1));

    let twice = vec![fixture.approved_root(), fixture.approved_root()];
    assert_eq!(
        ApprovedRoots::new(twice).map(|roots| roots.len()),
        Err(RootError::Duplicate)
    );
    let many: Vec<ApprovedRoot> = (0..=super::MAX_APPROVED_ROOTS)
        .map(|index| {
            let mut root: ApprovedRoot = fixture.approved_root();
            root.root_id = RootId::new(format!("root_{index}")).unwrap();
            root
        })
        .collect();
    assert_eq!(
        ApprovedRoots::new(many).map(|roots| roots.len()),
        Err(RootError::TooMany)
    );
    assert!(ApprovedRoots::default().is_empty());
    assert!(
        fixture
            .roots()
            .root(&RootId::new(ROOT_ID).unwrap())
            .is_some()
    );
}

#[test]
fn a_home_directory_that_is_not_an_anchored_path_is_rejected() {
    let fixture = Fixture::new();
    let make = |path: &[u8]| {
        let config = FsExecutorConfig {
            home_directory: LosslessPath::from_bytes(path).unwrap(),
            limits: ExecutorLimits::default(),
        };
        FsExecutor::new(&config, Box::new(fixture.fake_trash())).err()
    };
    for path in [b"/".as_slice(), b"home", b"/Users/../a"] {
        assert_eq!(make(path), Some(ConfigError::HomeDirectory));
    }
    // The executor needs the identity of the home directory. A home path
    // that is absent, or that has a symbolic link, gives no executor.
    let absent: PathBuf = fixture.base.join("no-such-home");
    assert_eq!(
        make(absent.as_os_str().as_bytes()),
        Some(ConfigError::HomeUnavailable)
    );
    let link: PathBuf = fixture.base.join("home-link");
    symlink(&fixture.home, &link).unwrap();
    assert_eq!(
        make(link.as_os_str().as_bytes()),
        Some(ConfigError::HomeUnavailable)
    );
    assert_eq!(make(fixture.home.as_os_str().as_bytes()), None);
}

#[test]
fn the_home_directory_and_each_directory_that_contains_it_are_refused() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        // The home directory is `root/users/me`.
        let home: PathBuf = fixture.root.join("users").join("me");
        fs::create_dir_all(home.join("Documents")).unwrap();
        fs::write(home.join("Documents").join("thesis.txt"), b"thesis").unwrap();
        let config = FsExecutorConfig {
            home_directory: LosslessPath::from_path(&home).unwrap(),
            limits: ExecutorLimits::default(),
        };
        let executor = FsExecutor::new(&config, Box::new(fixture.fake_trash())).unwrap();
        let before = listing(&fixture.root);

        for relative in ["users/me", "users"] {
            let envelope = fixture.envelope(class.clone(), relative);
            let outcome = run(&executor, &fixture.roots(), &envelope);
            assert_skipped(
                &outcome,
                &ErrorFamily::Eligibility,
                code::HOME_DIRECTORY_PROTECTED,
            );
        }
        assert_eq!(listing(&fixture.root), before);

        // An entry below the home directory is not the home directory.
        if class.is_permanent_removal() {
            let envelope = fixture.envelope(class.clone(), "users/me/Documents/thesis.txt");
            let outcome = run(&executor, &fixture.roots(), &envelope);
            assert_removed(&outcome);
        }
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn the_home_directory_is_refused_under_another_name() {
    // The approved root is the directory that contains the home directory
    // of the fixture.
    let fixture = Fixture::new();
    let mut root: ApprovedRoot = fixture.approved_root();
    root.path = LosslessPath::from_path(&fixture.base).unwrap();
    root.object = object_of(&fixture.base);
    let roots = ApprovedRoots::new(vec![root.clone()]).unwrap();
    let home_object: FileObjectEvidence = object_of(&fixture.home);
    fs::write(fixture.home.join("letter.txt"), b"letter").unwrap();
    let executor = fixture.executor();

    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        // A name that is not the home path, with the identity of the home
        // directory in the binding.
        let binding = under(
            &root,
            binding_with(
                &fixture,
                b"outside",
                FileObjectType::Directory,
                Some(home_object),
            ),
        );
        let envelope = envelope_of(class.clone(), "alias", binding);
        let outcome = run(&executor, &roots, &envelope);
        assert_skipped(
            &outcome,
            &ErrorFamily::Eligibility,
            code::HOME_DIRECTORY_PROTECTED,
        );

        // On a filesystem that ignores case, `HOME` is the home directory.
        // The comparison of path components does not see that.
        let same_directory: bool = fs::symlink_metadata(fixture.base.join("HOME"))
            .is_ok_and(|metadata| metadata.ino() == u64::from(home_object.inode));
        if same_directory {
            let binding = under(
                &root,
                binding_with(
                    &fixture,
                    b"HOME",
                    FileObjectType::Directory,
                    Some(home_object),
                ),
            );
            let envelope = envelope_of(class, "upper", binding);
            let outcome = run(&executor, &roots, &envelope);
            assert_skipped(
                &outcome,
                &ErrorFamily::Eligibility,
                code::HOME_DIRECTORY_PROTECTED,
            );
        } else {
            eprintln!("skipped: the volume distinguishes the case of a name");
        }
    }
    assert!(fixture.home.join("letter.txt").exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn the_executor_can_move_to_a_worker_thread() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FsExecutor>();
}

#[test]
fn a_target_whose_root_is_not_approved_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "data.bin");
    let executor = fixture.executor();

    // No root at all.
    let outcome = run(&executor, &ApprovedRoots::default(), &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Eligibility,
        code::OUTSIDE_APPROVED_ROOTS,
    );

    // Another root only.
    let mut other: ApprovedRoot = fixture.approved_root();
    other.root_id = RootId::new("root_2").unwrap();
    let roots = ApprovedRoots::new(vec![other]).unwrap();
    let outcome = run(&executor, &roots, &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Eligibility,
        code::OUTSIDE_APPROVED_ROOTS,
    );
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn an_approved_root_that_is_not_the_root_of_the_plan_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let executor = fixture.executor();
    let roots = fixture.roots();
    // A second directory with the same entry name. A root record with the
    // identity of the plan root and this place would send the step there.
    let other: PathBuf = fixture.root.parent().unwrap().join("other-root");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("data.bin"), b"data").unwrap();

    // The plan binds a different root path.
    let mut binding = fixture.binding("data.bin");
    binding.root_path = LosslessPath::from_path(&other).unwrap();
    let envelope = envelope_of(ActionClass::EvictRegenerableData, "data", binding);
    let outcome = run(&executor, &roots, &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::APPROVED_ROOT_MISMATCH,
    );

    // The plan binds a different root object.
    let mut binding = fixture.binding("data.bin");
    binding.root_object = object_of(&other);
    let envelope = envelope_of(ActionClass::EvictRegenerableData, "data", binding);
    let outcome = run(&executor, &roots, &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::APPROVED_ROOT_MISMATCH,
    );

    // The root record names the second directory under the identity of
    // the plan root.
    let mut moved: ApprovedRoot = fixture.approved_root();
    moved.path = LosslessPath::from_path(&other).unwrap();
    moved.object = object_of(&other);
    let moved = ApprovedRoots::new(vec![moved]).unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "data.bin");
    let outcome = run(&executor, &moved, &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::APPROVED_ROOT_MISMATCH,
    );
    assert!(file.exists());
    assert!(other.join("data.bin").exists());
}

#[test]
fn the_approved_root_itself_is_refused() {
    for class in ActionClass::ALL
        .into_iter()
        .filter(ActionClass::is_filesystem)
    {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("data.bin"), b"data").unwrap();
        // A binding cannot name the root by its path: the relative entry
        // has a minimum of one component. This binding has the identity of
        // the root.
        let binding = binding_with(
            &fixture,
            b"data.bin",
            FileObjectType::Directory,
            Some(object_of(&fixture.root)),
        );
        let envelope = envelope_of(class, "root", binding);

        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

        assert_skipped(
            &outcome,
            &ErrorFamily::Eligibility,
            code::APPROVED_ROOT_IS_TARGET,
        );
        assert!(fixture.root.join("data.bin").exists());
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_binding_without_identity_evidence_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let binding = binding_with(&fixture, b"data.bin", FileObjectType::RegularFile, None);
    let envelope = envelope_of(ActionClass::EvictRegenerableData, "data", binding);

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::IDENTITY_EVIDENCE_ABSENT,
    );
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_binding_of_another_volume_or_mount_generation_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let mut other_volume: FileBinding = fixture.binding("data.bin");
    other_volume.volume_id = VolumeId::new("volume_2").unwrap();
    let mut other_mount: FileBinding = fixture.binding("data.bin");
    other_mount.mount_id = MountId::new("mount_2").unwrap();
    for binding in [other_volume, other_mount] {
        let envelope = envelope_of(ActionClass::EvictRegenerableData, "data", binding);
        let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);
        assert_skipped(&outcome, &ErrorFamily::Evidence, code::VOLUME_MISMATCH);
    }
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_root_whose_identity_changed_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let executor = fixture.executor();
    // The plan binds the root of each record: the refusal is then for the
    // root on the disk, and not for a record that the plan does not name.
    let envelope_under = |root: &ApprovedRoot| {
        envelope_of(
            ActionClass::EvictRegenerableData,
            "data",
            under(root, fixture.binding("data.bin")),
        )
    };

    // The evidence of the root names another inode.
    let mut stale: ApprovedRoot = fixture.approved_root();
    stale.object = object_of(&fixture.outside);
    let envelope = envelope_under(&stale);
    let roots = ApprovedRoots::new(vec![stale]).unwrap();
    let outcome = run(&executor, &roots, &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::ROOT_IDENTITY_CHANGED,
    );

    // The path of the root has a symbolic link.
    let link: PathBuf = fixture.base.join("link");
    symlink(&fixture.root, &link).unwrap();
    let mut through_link: ApprovedRoot = fixture.approved_root();
    through_link.path = LosslessPath::from_path(&link).unwrap();
    let envelope = envelope_under(&through_link);
    let roots = ApprovedRoots::new(vec![through_link]).unwrap();
    let outcome = run(&executor, &roots, &envelope);
    assert_skipped(
        &outcome,
        &ErrorFamily::Evidence,
        code::ROOT_IDENTITY_CHANGED,
    );

    // The root is absent.
    let mut absent: ApprovedRoot = fixture.approved_root();
    absent.path = LosslessPath::from_path(&fixture.base.join("no-such-root")).unwrap();
    let envelope = envelope_under(&absent);
    let roots = ApprovedRoots::new(vec![absent]).unwrap();
    let outcome = run(&executor, &roots, &envelope);
    assert_skipped(&outcome, &ErrorFamily::Evidence, code::ROOT_UNAVAILABLE);

    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_principal_that_is_not_the_effective_user_is_refused() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    // The envelope of the user executor has the owner of the entry as its
    // principal. This one is for another user.
    let mut binding: FileBinding = fixture.binding("data.bin");
    binding.owner = Uid::new(native::effective_uid().wrapping_add(1));
    let envelope = envelope_of(ActionClass::EvictRegenerableData, "data", binding);

    let outcome = run(&fixture.executor(), &fixture.roots(), &envelope);

    assert_skipped(&outcome, &ErrorFamily::Authority, code::PRINCIPAL_MISMATCH);
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn an_entry_whose_owner_or_type_is_not_supported_is_skipped() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "data.bin");

    let other_owner: MetadataHook = Box::new(|path: &[u8], metadata: &mut Metadata| {
        if path.ends_with(b"/data.bin") {
            metadata.owner = metadata.owner.wrapping_add(1);
        }
    });
    let outcome = run(
        &fixture.executor_with(metadata_injection(other_owner)),
        &fixture.roots(),
        &envelope,
    );
    assert_skipped(&outcome, &ErrorFamily::Evidence, code::TARGET_OWNER_CHANGED);

    let socket: MetadataHook = Box::new(|path: &[u8], metadata: &mut Metadata| {
        if path.ends_with(b"/data.bin") {
            metadata.kind = Kind::Other;
        }
    });
    let outcome = run(
        &fixture.executor_with(metadata_injection(socket)),
        &fixture.roots(),
        &envelope,
    );
    assert_skipped(
        &outcome,
        &ErrorFamily::Eligibility,
        code::UNSUPPORTED_FILE_TYPE,
    );
    assert!(file.exists());
    fixture.assert_outside_unchanged();
}

/// The path suffix of an entry, a change of its measurement, and the
/// family and the code of the refusal.
type UnsupportedCase = (
    &'static str,
    fn(&mut Metadata),
    &'static ErrorFamily,
    &'static str,
);

#[test]
fn a_tree_with_an_entry_that_is_not_supported_is_refused_as_a_whole() {
    let cases: [UnsupportedCase; 2] = [
        (
            "/tree/a/one.bin",
            |metadata| metadata.kind = Kind::Other,
            &ErrorFamily::Eligibility,
            code::UNSUPPORTED_FILE_TYPE,
        ),
        (
            "/tree/a/b",
            |metadata| metadata.dataless = true,
            &ErrorFamily::Eligibility,
            code::DATALESS_DIRECTORY,
        ),
    ];
    for (suffix, change, family, expected) in cases {
        let fixture = Fixture::new();
        let tree: PathBuf = make_tree(&fixture);
        let before = listing(&tree);
        let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
        let hook: MetadataHook = Box::new(move |path: &[u8], metadata: &mut Metadata| {
            if path.ends_with(suffix.as_bytes()) {
                change(metadata);
            }
        });

        let outcome = run(
            &fixture.executor_with(metadata_injection(hook)),
            &fixture.roots(),
            &envelope,
        );

        assert_skipped(&outcome, family, expected);
        assert_eq!(listing(&tree), before);
        fixture.assert_outside_unchanged();
    }
}

#[test]
fn a_tree_with_a_directory_that_is_the_home_directory_is_refused_as_a_whole() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_tree(&fixture);
    let before = listing(&tree);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    // The directory `tree/a/b` shows the identity of the home directory,
    // as one name of a directory with more than one name does.
    let home = fs::metadata(&fixture.home).unwrap();
    let hook: MetadataHook = Box::new(move |path: &[u8], metadata: &mut Metadata| {
        if path.ends_with(b"/tree/a/b") {
            metadata.device = Some(DeviceNumber::new(i32::try_from(home.dev()).unwrap()));
            metadata.inode = home.ino();
        }
    });

    let outcome = run(
        &fixture.executor_with(metadata_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    assert_skipped(
        &outcome,
        &ErrorFamily::Eligibility,
        code::HOME_DIRECTORY_PROTECTED,
    );
    assert_eq!(listing(&tree), before);
    assert!(fixture.home.is_dir());
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------

#[test]
fn a_step_needs_a_receipt_of_a_durable_consumption_by_this_caller() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("data.bin"), b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "data.bin");
    let cases = [
        (
            DispatchConsumption::AlreadyConsumed,
            Durability::Durable,
            AdmissionRefusal::NotConsumed,
        ),
        (
            DispatchConsumption::Fenced,
            Durability::Durable,
            AdmissionRefusal::NotConsumed,
        ),
        (
            DispatchConsumption::Consumed,
            Durability::Volatile,
            AdmissionRefusal::NotDurable,
        ),
        (
            DispatchConsumption::Consumed,
            Durability::PersistenceFailed,
            AdmissionRefusal::NotDurable,
        ),
        (
            DispatchConsumption::Consumed,
            Durability::from_wire("cached"),
            AdmissionRefusal::NotDurable,
        ),
    ];
    for (consumption, durability, refusal) in cases {
        let receipt = DispatchReceipt {
            consumption,
            durability,
        };
        assert_eq!(AdmittedStep::new(&envelope, &receipt).err(), Some(refusal));
    }
    let receipt: DispatchReceipt = receipt();
    let step = AdmittedStep::new(&envelope, &receipt).unwrap();
    assert_eq!(step.action_class(), &ActionClass::EvictRegenerableData);
    assert_eq!(step.target_id().as_str(), "target_data_bin");
    assert_eq!(step.file().relative_entry.as_bytes(), b"data.bin");
    assert_eq!(step.envelope(), &envelope);
    // No refused step changed the file.
    assert!(fixture.root.join("data.bin").exists());
}

// ---------------------------------------------------------------------
// Error numbers
// ---------------------------------------------------------------------

#[test]
fn each_code_is_a_valid_error_code_and_is_unique() {
    let mut seen: Vec<&str> = Vec::new();
    for text in code::ALL {
        assert!(ErrorCode::new(text).is_ok(), "{text}");
        assert!(!seen.contains(&text), "{text}");
        seen.push(text);
    }
}

#[test]
fn an_error_number_of_a_mutation_call_is_not_reduced_to_one_family() {
    let no_effect = |errno: i32| match mutation_verdict(Some(errno)) {
        CallVerdict::NoEffect(cause) => (cause.family, cause.code),
        other => panic!("{errno}: {other:?}"),
    };
    assert_eq!(
        no_effect(libc::EACCES),
        (ErrorFamily::Native, code::PERMISSION_DENIED)
    );
    assert_eq!(
        no_effect(libc::EPERM),
        (ErrorFamily::Native, code::OPERATION_NOT_PERMITTED)
    );
    assert_eq!(
        no_effect(libc::EROFS),
        (ErrorFamily::Native, code::READ_ONLY_FILESYSTEM)
    );
    assert_eq!(
        no_effect(libc::EBUSY),
        (ErrorFamily::Native, code::RESOURCE_BUSY)
    );
    assert_eq!(
        no_effect(libc::ENOTEMPTY),
        (ErrorFamily::Native, code::DIRECTORY_NOT_EMPTY)
    );
    assert_eq!(
        no_effect(libc::ENOSPC),
        (ErrorFamily::Native, code::NO_SPACE)
    );
    assert_eq!(
        no_effect(libc::EMFILE),
        (ErrorFamily::Limits, code::DESCRIPTORS_EXHAUSTED)
    );
    assert_eq!(
        no_effect(libc::EDEADLK),
        (ErrorFamily::Eligibility, code::DATALESS_OBJECT)
    );
    assert_eq!(mutation_verdict(Some(libc::ENOENT)), CallVerdict::Absent);

    // An interrupted call, an I/O error, an error number that the table
    // does not have, and a failure with no error number do not establish
    // that nothing happened.
    for errno in [
        Some(libc::EINTR),
        Some(libc::EIO),
        Some(libc::ETIMEDOUT),
        Some(libc::ESTALE),
        Some(libc::EPROTO),
        None,
    ] {
        match mutation_verdict(errno) {
            CallVerdict::Indeterminate(cause) => assert_eq!(cause.family, ErrorFamily::Outcome),
            other => panic!("{errno:?}: {other:?}"),
        }
    }

    // A read-only call has no effect on the target.
    assert_eq!(read_cause(Some(libc::EINTR)).family, ErrorFamily::Native);
    assert_eq!(read_cause(Some(libc::EINTR)).code, code::INTERRUPTED);
    assert_eq!(read_cause(Some(libc::EACCES)).code, code::PERMISSION_DENIED);
    assert_eq!(read_cause(Some(libc::EMFILE)).family, ErrorFamily::Limits);
}

/// Opens `directory` through the native layer of the executor.
fn open_directory(directory: &Path) -> std::os::fd::OwnedFd {
    let mut descriptor = native::open_filesystem_root().unwrap();
    for component in path_components(directory.as_os_str().as_bytes(), true).unwrap() {
        descriptor = native::open_directory_at(descriptor.as_fd(), &component).unwrap();
    }
    descriptor
}

#[test]
fn an_interrupted_call_is_settled_by_one_observation_and_is_not_repeated() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let object = Some(object_of(&file));
    let parent = open_directory(&fixture.root);
    let name = c"data.bin";
    let injection = Injection::default();
    let settle = |result: io::Result<()>| {
        settle_unlink(&result, parent.as_fd(), name, object, &injection, b"")
    };
    let interrupted = || Err(io::Error::from_raw_os_error(libc::EINTR));

    // The call was interrupted and the object has the name. That does not
    // establish that nothing happened. The file is still present after
    // the settlement, so no second call was issued.
    assert_eq!(
        settle(interrupted()),
        EntryOutcome::Unknown {
            errno: Some(libc::EINTR),
            cause: super::errors::Cause::outcome(code::INTERRUPTED),
        }
    );
    assert!(file.exists());

    // The call returned success and the object is where it was.
    assert_eq!(
        settle(Ok(())),
        EntryOutcome::Unknown {
            errno: None,
            cause: super::errors::Cause::outcome(code::OUTCOME_UNVERIFIED),
        }
    );

    // The call was interrupted and another object has the name.
    fs::write(fixture.root.join("data.new"), b"other").unwrap();
    fs::rename(fixture.root.join("data.new"), &file).unwrap();
    assert_eq!(
        settle(interrupted()),
        EntryOutcome::Unknown {
            errno: Some(libc::EINTR),
            cause: super::errors::Cause::outcome(code::INTERRUPTED),
        }
    );
    // A call that returned success, and another object has the name: an
    // actor changed the name near the call, so the removed object is not
    // established.
    assert_eq!(
        settle(Ok(())),
        EntryOutcome::Removed {
            attribution: Attribution::Possible,
            errno: None,
        }
    );

    // The call was interrupted and the name is absent: the entry was
    // removed, and the cause is possible, not established.
    fs::remove_file(&file).unwrap();
    assert_eq!(
        settle(interrupted()),
        EntryOutcome::Removed {
            attribution: Attribution::Possible,
            errno: Some(libc::EINTR),
        }
    );
    assert_eq!(
        settle(Err(io::Error::from_raw_os_error(libc::ENOENT))),
        EntryOutcome::Absent
    );
    assert_eq!(
        settle(Err(io::Error::from_raw_os_error(libc::EACCES))),
        EntryOutcome::NoEffect {
            errno: Some(libc::EACCES),
            cause: super::errors::Cause::native(code::PERMISSION_DENIED),
        }
    );
    fixture.assert_outside_unchanged();
}

#[test]
fn an_entry_that_goes_away_before_the_call_gives_already_absent_after_a_submission() {
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("data.bin");
    fs::write(&file, b"data").unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "data.bin");
    let removed: PathBuf = file.clone();
    let hook = once(
        move |_path: &[u8]| fs::remove_file(&removed).unwrap(),
        Checkpoint::Revalidated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::AlreadyAbsent);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    // Another actor removed the entry: the cause is not established.
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(
        result.evidence.native,
        NativeResult::Errno {
            errno: libc::ENOENT
        }
    );
    assert_eq!(outcome.work.vanished_entries, EntryCount::new(1));
    assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
    fixture.assert_outside_unchanged();
}

// ---------------------------------------------------------------------
// Results that must not overstate or understate the effect
// ---------------------------------------------------------------------

#[test]
fn a_trash_move_with_no_item_and_another_object_at_the_name_is_an_unknown_outcome() {
    // The backend gives no item identity, and after the call another
    // object has the name of the source. Only the absence of the name can
    // show that the object of the plan was moved.
    let fixture = Fixture::new();
    let file: PathBuf = fixture.root.join("a.txt");
    fs::write(&file, b"planned").unwrap();
    let envelope = fixture.envelope(ActionClass::MoveToTrash, "a.txt");
    let trash = FakeTrash::new(&fixture.trash, TrashMode::MoveWithoutItemThenReplace);
    let executor = FsExecutor::new(&fixture.config(), Box::new(trash)).unwrap();

    let outcome = run(&executor, &fixture.roots(), &envelope);

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(failure_code(result), code::OUTCOME_UNVERIFIED);
    assert_eq!(outcome.work.trashed_entries, EntryCount::ZERO);
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(1));
    assert_eq!(fs::read(&file).unwrap(), b"replacement".to_vec());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_whose_directory_goes_away_after_its_entries_were_removed_is_not_a_no_op() {
    // Another actor moves the target directory after its comparison. The
    // executor removes the measured file through the open descriptor, and
    // the call on the name of the directory then finds no entry.
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("only.bin"), [1_u8; 10]).unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let aside: PathBuf = fixture.root.join("aside");
    let (from, to) = (tree.clone(), aside.clone());
    let hook: CheckpointHook = Box::new(move |checkpoint: Checkpoint, path: &[u8]| {
        if checkpoint == Checkpoint::EntryChecked && path.ends_with(b"only.bin") {
            fs::rename(&from, &to).unwrap();
        }
    });

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    let result: &TargetResult = &outcome.result;
    // `AlreadyAbsent` states a no-op. The executor removed an entry.
    assert_eq!(result.effect, TargetEffect::Removed);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(
        result.evidence.native,
        NativeResult::Errno {
            errno: libc::ENOENT
        }
    );
    assert_eq!(outcome.work.removed_entries, EntryCount::new(1));
    assert_eq!(outcome.work.removed_logical_bytes, Bytes::new(10));
    assert_eq!(outcome.work.vanished_entries, EntryCount::new(1));
    assert!(!tree.exists());
    assert!(aside.is_dir());
    assert!(fs::read_dir(&aside).unwrap().next().is_none());
    fixture.assert_outside_unchanged();
}

#[test]
fn the_removed_bytes_are_those_of_the_comparison_before_the_call() {
    // The file grows between the measurement of the tree and its removal.
    let fixture = Fixture::new();
    let tree: PathBuf = fixture.root.join("tree");
    fs::create_dir(&tree).unwrap();
    let file: PathBuf = tree.join("grow.bin");
    fs::write(&file, [1_u8; 10]).unwrap();
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let grown: PathBuf = file.clone();
    let hook = once(
        move |_path: &[u8]| fs::write(&grown, [2_u8; 100]).unwrap(),
        Checkpoint::TreeEnumerated,
    );

    let outcome = run(
        &fixture.executor_with(checkpoint_injection(hook)),
        &fixture.roots(),
        &envelope,
    );

    assert_removed(&outcome);
    assert_eq!(outcome.work.removed_entries, EntryCount::new(2));
    assert_eq!(outcome.work.removed_logical_bytes, Bytes::new(100));
    fixture.assert_outside_unchanged();
}

/// Makes `root/tree` with the directories `d1` and `d2`, each with one
/// file.
fn make_two_directories(fixture: &Fixture) -> PathBuf {
    let tree: PathBuf = fixture.root.join("tree");
    for name in ["d1", "d2"] {
        fs::create_dir_all(tree.join(name)).unwrap();
        fs::write(tree.join(name).join("file.bin"), [1_u8; 10]).unwrap();
    }
    tree
}

/// A signal that gives `Canceled` from its reading number `first_stop`.
fn stop_from(first_stop: u32) -> impl Fn() -> Option<Stop> {
    let checks = AtomicU32::new(0);
    move || (checks.fetch_add(1, Ordering::SeqCst) + 1 >= first_stop).then_some(Stop::Canceled)
}

#[test]
fn a_stop_inside_a_directory_target_issues_no_later_call_and_reports_the_part_that_was_done() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_two_directories(&fixture);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let receipt: DispatchReceipt = receipt();
    let step = AdmittedStep::new(&envelope, &receipt).unwrap();
    // The executor reads the signal before each directory below the
    // target. The second reading stops.
    let signal = stop_from(2);

    let outcome = fixture
        .executor()
        .execute_step_until(&fixture.roots(), step, &signal)
        .unwrap();

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::UnknownOutcome);
    assert_eq!(result.dispatch, DispatchState::Submitted);
    assert_eq!(result.attribution, Attribution::Possible);
    assert_eq!(result.stop_reason, StopReason::Canceled);
    assert!(result.failure.is_none());
    // One directory with its file was removed. The other directory, its
    // file, and the target directory stay.
    assert_eq!(outcome.work.removed_entries, EntryCount::new(2));
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(3));
    assert!(tree.is_dir());
    let left: Vec<PathBuf> = ["d1", "d2"]
        .iter()
        .map(|name| tree.join(name))
        .filter(|directory| directory.exists())
        .collect();
    assert_eq!(left.len(), 1);
    assert!(left[0].join("file.bin").exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_stop_before_the_first_call_of_a_directory_target_is_a_skipped_target() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_two_directories(&fixture);
    let before = listing(&tree);
    let envelope = fixture.envelope(ActionClass::EvictRegenerableData, "tree");
    let receipt: DispatchReceipt = receipt();
    let step = AdmittedStep::new(&envelope, &receipt).unwrap();
    let signal = stop_from(1);

    let outcome = fixture
        .executor()
        .execute_step_until(&fixture.roots(), step, &signal)
        .unwrap();

    let result: &TargetResult = &outcome.result;
    assert_eq!(result.effect, TargetEffect::Skipped);
    assert_eq!(result.dispatch, DispatchState::NotSubmitted);
    assert_eq!(result.evidence.native, NativeResult::NotCalled);
    assert_eq!(result.stop_reason, StopReason::Canceled);
    assert_eq!(outcome.work.removed_entries, EntryCount::ZERO);
    assert_eq!(outcome.work.remaining_entries, EntryCount::new(5));
    assert_eq!(listing(&tree), before);
    fixture.assert_outside_unchanged();
}

#[test]
fn a_stop_inside_a_directory_target_stops_the_batch() {
    let fixture = Fixture::new();
    let tree: PathBuf = make_two_directories(&fixture);
    let later: PathBuf = fixture.root.join("later.bin");
    fs::write(&later, b"later").unwrap();
    let envelopes = [
        fixture.envelope(ActionClass::EvictRegenerableData, "tree"),
        fixture.envelope(ActionClass::EvictRegenerableData, "later.bin"),
    ];
    let receipt: DispatchReceipt = receipt();
    let steps: Vec<AdmittedStep<'_>> = envelopes
        .iter()
        .map(|envelope| AdmittedStep::new(envelope, &receipt).unwrap())
        .collect();
    // The first reading is that of the batch before the tree. The third
    // reading is before the second directory of the tree.
    let stop = stop_from(3);

    let outcome: BatchOutcome = fixture
        .executor()
        .execute_batch(&fixture.roots(), steps, &stop);

    assert_eq!(outcome.stopped, Some(Stop::Canceled));
    let first: &TargetResult = &outcome.outcomes[0].as_ref().unwrap().result;
    assert_eq!(first.effect, TargetEffect::UnknownOutcome);
    assert_eq!(first.stop_reason, StopReason::Canceled);
    let second: &TargetResult = &outcome.outcomes[1].as_ref().unwrap().result;
    assert_eq!(second.effect, TargetEffect::Skipped);
    assert_eq!(second.dispatch, DispatchState::NotSubmitted);
    assert_eq!(second.stop_reason, StopReason::Canceled);
    assert!(tree.is_dir());
    assert!(later.exists());
    fixture.assert_outside_unchanged();
}

#[test]
fn a_tree_with_an_entry_of_another_owner_is_refused_as_a_whole() {
    for class in PERMANENT {
        let fixture = Fixture::new();
        let tree: PathBuf = make_tree(&fixture);
        let before = listing(&tree);
        let envelope = fixture.envelope(class, "tree");
        // The measurement reports another owner for one file of the tree.
        let hook: MetadataHook = Box::new(|path: &[u8], metadata: &mut Metadata| {
            if path.ends_with(b"tree/a/one.bin") {
                metadata.owner = metadata.owner.wrapping_add(1);
            }
        });

        let outcome = run(
            &fixture.executor_with(metadata_injection(hook)),
            &fixture.roots(),
            &envelope,
        );

        assert_skipped(
            &outcome,
            &ErrorFamily::Eligibility,
            code::TREE_ENTRY_OWNER_MISMATCH,
        );
        assert_eq!(listing(&tree), before);
        fixture.assert_outside_unchanged();
    }
}
