//! Tests of the scanner. Each test works in its own temporary directory.
//! No test reads a directory of the user.

use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Value, json};
use svalnir_core::file::{DeviceNumber, LosslessPath};
use svalnir_core::id::{
    AdapterId, BootId, ClockDomainId, CollectorEpochId, MountId, SampleId, ScanId, VolumeId,
    WorkerId,
};
use svalnir_core::observation::{
    Coverage, MetricKind, Reading, Sample, ScopeKind, Source, UnavailableReason, Unit,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount};
use svalnir_core::time::{MonotonicNanos, WallTime};
use svalnir_core::volume::{CapacityDomainMembership, VolumeIdentity};

use super::native::{PrivateAttributes, RawMetadata};
use super::private::{CloneShare, FilePart, file_part};
use super::top::TopList;
use super::walk::{Injection, MetadataHook, PrivateHook, budget_from_limit, join_name, scan_with};
use super::{
    CancellationToken, DirectoryRecord, EntryKind, EntryRecord, LargeFile, NoObserver,
    PrivateBytes, PrivateSizeUnavailable, RegionCause, RegionKind, ScanClock, ScanCompletion,
    ScanError, ScanLimits, ScanObserver, ScanRequest, ScanResult, ScanTimestamp, WallScanClock,
    run_scan,
};

static NEXT_TREE: AtomicU32 = AtomicU32::new(0);

/// A temporary directory that the test owns. `Drop` removes it.
struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(tag: &str) -> Self {
        let base: PathBuf = std::env::temp_dir().canonicalize().unwrap();
        let root: PathBuf = base.join(format!(
            "svalnir-scan-test-{}-{}-{tag}",
            std::process::id(),
            NEXT_TREE.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn dir(&self, relative: &str) -> PathBuf {
        let path: PathBuf = self.path(relative);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Makes a file of `length` bytes and writes it to the disk, so that
    /// its block count does not change after the test reads it.
    fn file(&self, relative: &str, length: usize) -> PathBuf {
        let path: PathBuf = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, vec![0x5a_u8; length]).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
        path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        restore_access(&self.root);
        drop(fs::remove_dir_all(&self.root));
    }
}

/// Gives the owner access to each directory again, so that `Drop` can
/// remove a tree that a failed test left with a mode 000 directory.
fn restore_access(directory: &Path) {
    drop(fs::set_permissions(
        directory,
        fs::Permissions::from_mode(0o700),
    ));
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            restore_access(&entry.path());
        }
    }
}

/// The totals of a tree from `std::fs`, as a second measurement.
#[derive(Debug, Default, PartialEq, Eq)]
struct Expected {
    logical: u64,
    allocated: u64,
    entries: u64,
}

fn expected(root: &Path) -> Expected {
    let mut total = Expected {
        allocated: fs::metadata(root).unwrap().blocks() * 512,
        ..Expected::default()
    };
    add_expected(root, &mut HashSet::new(), &mut total);
    total
}

fn add_expected(directory: &Path, seen: &mut HashSet<u64>, total: &mut Expected) {
    for entry in fs::read_dir(directory).unwrap() {
        let path: PathBuf = entry.unwrap().path();
        let metadata: fs::Metadata = fs::symlink_metadata(&path).unwrap();
        total.entries += 1;
        if metadata.is_dir() {
            total.allocated += metadata.blocks() * 512;
            add_expected(&path, seen, total);
        } else if metadata.is_file() || metadata.is_symlink() {
            if metadata.nlink() > 1 && !seen.insert(metadata.ino()) {
                continue;
            }
            total.logical += metadata.len();
            total.allocated += metadata.blocks() * 512;
        }
    }
}

fn request(root: &Path, limits: ScanLimits) -> ScanRequest {
    ScanRequest {
        scan_id: ScanId::new("scan_test").unwrap(),
        root: LosslessPath::from_path(root).unwrap(),
        limits,
        volume: None,
    }
}

fn scan(root: &Path) -> ScanResult {
    scan_limited(root, ScanLimits::default())
}

fn scan_limited(root: &Path, limits: ScanLimits) -> ScanResult {
    run_scan(
        &request(root, limits),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
    )
    .unwrap()
}

fn scan_observed(root: &Path, observer: &mut dyn ScanObserver) -> ScanResult {
    run_scan(
        &request(root, ScanLimits::default()),
        &CancellationToken::new(),
        &WallScanClock,
        observer,
    )
    .unwrap()
}

/// Scans with changed metadata for each entry whose file name is `name`.
fn scan_injected(
    root: &Path,
    name: &'static str,
    change: impl Fn(&mut RawMetadata) + 'static,
) -> ScanResult {
    let hook: MetadataHook = Box::new(move |path: &Path, metadata: &mut RawMetadata| {
        if path.file_name() == Some(OsStr::new(name)) {
            change(metadata);
        }
    });
    scan_with(
        &request(root, ScanLimits::default()),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        Injection {
            metadata: Some(hook),
            ..Injection::default()
        },
    )
    .unwrap()
}

fn lossless(path: &Path) -> LosslessPath {
    LosslessPath::from_path(path).unwrap()
}

fn count(value: u64) -> EntryCount {
    EntryCount::new(value)
}

fn assert_complete(result: &ScanResult) {
    assert_eq!(result.completion, ScanCompletion::Finished);
    assert_eq!(result.coverage, Coverage::Complete);
    assert_eq!(result.regions, []);
    assert_eq!(result.regions_omitted, count(0));
}

/// Each name is in one kind count.
fn assert_kind_counts_agree(result: &ScanResult) {
    let totals = result.totals;
    assert_eq!(
        totals.entries.get(),
        totals.files.get()
            + totals.directories.get()
            + totals.symlinks.get()
            + totals.other_entries.get()
    );
}

#[test]
fn a_nested_tree_has_known_totals() {
    let tree = TempTree::new("nested");
    tree.file("a.bin", 1_000);
    tree.file("sub/b.bin", 5_000);
    let largest: PathBuf = tree.file("sub/deep/c.bin", 70_000);
    tree.dir("empty");

    let result: ScanResult = scan(&tree.root);
    let oracle: Expected = expected(&tree.root);

    assert_complete(&result);
    assert_eq!(result.totals.logical_bytes, Bytes::new(76_000));
    assert_eq!(oracle.logical, 76_000);
    assert_eq!(result.totals.allocated_bytes, Bytes::new(oracle.allocated));
    assert_eq!(result.totals.entries, count(6));
    assert_eq!(result.entries_examined, count(6));
    assert_eq!(result.totals.files, count(3));
    assert_eq!(result.totals.directories, count(3));
    assert_eq!(result.totals.symlinks, count(0));
    assert_kind_counts_agree(&result);
    assert!(!result.shared_storage.hard_linked_data_found());
    assert_eq!(result.boundaries, []);

    let first: &LargeFile = &result.largest_files[0];
    assert_eq!(first.path, lossless(&largest));
    assert_eq!(first.logical_bytes, Bytes::new(70_000));
    assert_eq!(first.link_count, count(1));
    assert_eq!(
        first.object.inode.get(),
        fs::metadata(&largest).unwrap().ino()
    );
    assert_eq!(result.largest_files.len(), 3);

    let sub = &result.largest_directories[0];
    assert_eq!(sub.path, lossless(&tree.path("sub")));
    assert_eq!(sub.logical_bytes, Bytes::new(75_000));
    assert_eq!(sub.entries, count(3));
    assert_eq!(sub.coverage, Coverage::Complete);
    assert_eq!(
        sub.allocated_bytes,
        Bytes::new(expected(&tree.path("sub")).allocated)
    );
    // The root is not in the list of the largest directories.
    assert_eq!(result.largest_directories.len(), 3);

    let root_metadata: fs::Metadata = fs::metadata(&tree.root).unwrap();
    assert_eq!(
        i64::from(result.volume.device.get()),
        i64::try_from(root_metadata.dev()).unwrap()
    );
    assert_eq!(result.volume.root_object.inode.get(), root_metadata.ino());
    assert_eq!(result.root, lossless(&tree.root));
    assert!(result.started.wall.is_some());
    assert!(result.finished.wall >= result.started.wall);
    assert!(result.elapsed.is_some());
}

#[cfg(target_os = "macos")]
#[test]
fn the_volume_evidence_has_the_filesystem_type_and_the_mount_point() {
    let tree = TempTree::new("volume");
    let result: ScanResult = scan(&tree.root);
    let filesystem_type: String = result.volume.filesystem_type.unwrap();
    assert_ne!(filesystem_type, "");
    // The path of the root can be a firmlink path that does not start with
    // the mount point, so the test compares the devices.
    let mount_point: PathBuf = result.volume.mount_point.unwrap().to_path_buf();
    assert!(mount_point.is_absolute());
    assert_eq!(
        fs::metadata(&mount_point).unwrap().dev(),
        fs::metadata(&tree.root).unwrap().dev()
    );
}

#[test]
fn an_empty_root_has_measured_zero_totals() {
    let tree = TempTree::new("empty");
    let result: ScanResult = scan(&tree.root);
    assert_complete(&result);
    assert_eq!(result.totals.logical_bytes, Bytes::ZERO);
    assert_eq!(result.totals.entries, count(0));
    assert_eq!(result.largest_files, []);
    assert_eq!(result.largest_directories, []);
}

#[derive(Default)]
struct Recorder {
    entries: Vec<(PathBuf, EntryKind, u32, bool, u64)>,
    opened: Vec<PathBuf>,
    finished: Vec<(PathBuf, u64, Coverage)>,
}

impl ScanObserver for Recorder {
    fn directory_opened(&mut self, path: &Path) {
        self.opened.push(path.to_path_buf());
    }

    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        assert_eq!(entry.lossless_path().unwrap(), lossless(entry.path));
        self.entries.push((
            entry.path.to_path_buf(),
            entry.kind,
            entry.depth,
            entry.counted_in_totals,
            entry.link_count,
        ));
    }

    fn directory_finished(&mut self, directory: &DirectoryRecord<'_>) {
        self.finished.push((
            directory.path.to_path_buf(),
            directory.entries.get(),
            directory.coverage.clone(),
        ));
    }
}

/// An observer that keeps the owner and the times of each entry.
#[derive(Default)]
struct Owners {
    entries: Vec<(PathBuf, Uid, Option<WallTime>, Option<WallTime>)>,
}

impl ScanObserver for Owners {
    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        self.entries.push((
            entry.path.to_path_buf(),
            entry.owner,
            entry.modified,
            entry.changed,
        ));
    }
}

#[test]
fn an_entry_record_has_the_owner_and_the_times_of_its_object() {
    let tree = TempTree::new("owner");
    tree.file("f.bin", 10);
    tree.dir("sub");
    symlink("f.bin", tree.path("link")).unwrap();

    let mut owners = Owners::default();
    let result: ScanResult = scan_observed(&tree.root, &mut owners);
    assert_complete(&result);
    assert_eq!(owners.entries.len(), 3);
    for (path, owner, modified, changed) in owners.entries {
        // The values are those of the object itself: a symbolic link is
        // not followed.
        let metadata = fs::symlink_metadata(&path).unwrap();
        let time = |seconds: i64, nanoseconds: i64| {
            WallTime::from_unix(seconds, u32::try_from(nanoseconds).unwrap()).unwrap()
        };
        assert_eq!(owner, Uid::new(metadata.uid()), "{}", path.display());
        assert_eq!(
            modified,
            Some(time(metadata.mtime(), metadata.mtime_nsec())),
            "{}",
            path.display()
        );
        assert_eq!(
            changed,
            Some(time(metadata.ctime(), metadata.ctime_nsec())),
            "{}",
            path.display()
        );
    }
}

#[test]
fn a_hard_linked_file_is_counted_one_time() {
    let tree = TempTree::new("hardlink");
    let first: PathBuf = tree.file("f.bin", 8_192);
    fs::hard_link(&first, tree.path("g.bin")).unwrap();
    tree.dir("sub");
    fs::hard_link(&first, tree.path("sub/h.bin")).unwrap();

    let mut recorder = Recorder::default();
    let result: ScanResult = scan_observed(&tree.root, &mut recorder);
    let oracle: Expected = expected(&tree.root);

    assert_complete(&result);
    assert_eq!(result.totals.logical_bytes, Bytes::new(8_192));
    assert_eq!(result.totals.allocated_bytes, Bytes::new(oracle.allocated));
    // Each name is an entry. The sizes have the object one time.
    assert_eq!(result.totals.entries, count(4));
    assert_eq!(result.totals.files, count(3));
    assert_kind_counts_agree(&result);
    assert!(result.shared_storage.hard_linked_data_found());
    assert_eq!(result.shared_storage.hard_linked_objects, count(1));
    assert_eq!(
        result.shared_storage.hard_link_names_not_counted_again,
        count(2)
    );
    assert_eq!(result.largest_files.len(), 1);
    assert_eq!(result.largest_files[0].link_count, count(3));
    assert_eq!(result.largest_files[0].logical_bytes, Bytes::new(8_192));

    let files: Vec<_> = recorder
        .entries
        .iter()
        .filter(|entry| entry.1 == EntryKind::File)
        .collect();
    assert_eq!(files.len(), 3);
    assert_eq!(files.iter().filter(|entry| entry.3).count(), 1);
    assert!(files.iter().all(|entry| entry.4 == 3));
}

#[test]
fn a_symlink_is_recorded_and_not_followed() {
    let outside = TempTree::new("symlink-outside");
    outside.file("big.bin", 100_000);
    let tree = TempTree::new("symlink");
    tree.file("real.bin", 10);
    symlink(&outside.root, tree.path("to-outside-dir")).unwrap();
    symlink(outside.path("big.bin"), tree.path("to-outside-file")).unwrap();
    symlink(tree.path("loop-b"), tree.path("loop-a")).unwrap();
    symlink(tree.path("loop-a"), tree.path("loop-b")).unwrap();
    symlink(".", tree.path("to-self")).unwrap();
    symlink("missing-target", tree.path("dangling")).unwrap();

    let mut recorder = Recorder::default();
    let result: ScanResult = scan_observed(&tree.root, &mut recorder);
    let oracle: Expected = expected(&tree.root);

    assert_complete(&result);
    assert_eq!(result.totals.symlinks, count(6));
    assert_eq!(result.totals.files, count(1));
    assert_eq!(result.totals.directories, count(0));
    assert_eq!(result.totals.entries, count(7));
    // The logical size has the 10 bytes of the file and the length of each
    // link text. It has nothing of the 100 000 bytes outside the root.
    assert_eq!(result.totals.logical_bytes, Bytes::new(oracle.logical));
    assert!(result.totals.logical_bytes < Bytes::new(100_000));
    assert_eq!(result.totals.allocated_bytes, Bytes::new(oracle.allocated));
    // Only the root was opened.
    assert_eq!(recorder.opened, std::slice::from_ref(&tree.root));
    assert_eq!(result.largest_files.len(), 1);
}

#[test]
fn a_root_that_is_a_symlink_is_resolved() {
    let tree = TempTree::new("root-link-target");
    tree.file("x.bin", 300);
    let holder = TempTree::new("root-link");
    let link: PathBuf = holder.path("link");
    symlink(&tree.root, &link).unwrap();

    let result: ScanResult = scan(&link);
    assert_complete(&result);
    assert_eq!(result.totals.logical_bytes, Bytes::new(300));
    assert_eq!(result.root, lossless(&link));
    assert_eq!(result.largest_files[0].path, lossless(&link.join("x.bin")));
    assert_eq!(
        result.volume.root_object.inode.get(),
        fs::metadata(&tree.root).unwrap().ino()
    );
}

#[test]
fn an_unreadable_directory_is_an_inaccessible_region() {
    let tree = TempTree::new("unreadable");
    tree.file("ok/x.bin", 100);
    tree.file("locked/y.bin", 200);
    let locked: PathBuf = tree.path("locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&locked).is_ok() {
        // The test runs as a user that the mode does not restrict.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }

    let result: ScanResult = scan(&tree.root);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(result.completion, ScanCompletion::Finished);
    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    let region = &result.regions[0];
    assert_eq!(region.path, lossless(&locked));
    assert_eq!(region.cause, RegionCause::PermissionDenied);
    assert_eq!(region.kind(), RegionKind::Inaccessible);
    assert_eq!(region.native_errno, Some(libc::EACCES));
    // The measured part stays. The directory is a counted name, and the
    // file in it is not a zero-size entry: it is not an entry.
    assert_eq!(result.totals.logical_bytes, Bytes::new(100));
    assert_eq!(result.totals.entries, count(3));
    assert_eq!(result.totals.directories, count(2));
    assert_eq!(result.totals.files, count(1));
    assert_eq!(result.largest_directories.len(), 1);
    assert_eq!(result.largest_directories[0].coverage, Coverage::Complete);
}

/// Runs an action when the scan lists or measures a name.
struct OnName<F: FnMut(&Path)> {
    name: &'static str,
    at_measure: bool,
    action: F,
}

impl<F: FnMut(&Path)> ScanObserver for OnName<F> {
    fn entry_listed(&mut self, path: &Path) {
        if !self.at_measure && path.file_name() == Some(OsStr::new(self.name)) {
            (self.action)(path);
        }
    }

    fn entry_measured(&mut self, entry: &EntryRecord<'_>) {
        if self.at_measure && entry.path.file_name() == Some(OsStr::new(self.name)) {
            (self.action)(entry.path);
        }
    }
}

#[test]
fn an_entry_removed_during_the_scan_is_a_changed_region() {
    let tree = TempTree::new("removed");
    tree.file("keep.bin", 400);
    let victim: PathBuf = tree.file("victim.bin", 900);
    let mut observer = OnName {
        name: "victim.bin",
        at_measure: false,
        action: |path: &Path| fs::remove_file(path).unwrap(),
    };

    let result: ScanResult = scan_observed(&tree.root, &mut observer);

    assert_eq!(result.completion, ScanCompletion::Finished);
    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].path, lossless(&victim));
    assert_eq!(result.regions[0].cause, RegionCause::Disappeared);
    assert_eq!(result.regions[0].kind(), RegionKind::Changed);
    assert_eq!(result.regions[0].native_errno, Some(libc::ENOENT));
    assert_eq!(result.totals.logical_bytes, Bytes::new(400));
    assert_eq!(result.totals.entries, count(1));
    assert_eq!(result.entries_examined, count(2));
}

#[test]
fn a_directory_replaced_by_a_symlink_does_not_redirect_the_scan() {
    let outside = TempTree::new("replaced-outside");
    outside.file("secret.bin", 50_000);
    let tree = TempTree::new("replaced");
    tree.file("target/inner.bin", 700);
    tree.file("keep.bin", 30);
    let moved: PathBuf = outside.path("moved");
    let outside_root: PathBuf = outside.root.clone();
    // After the scan measures `target` and before it opens it, another
    // actor moves the directory away and puts a symbolic link at the name.
    let mut observer = OnName {
        name: "target",
        at_measure: true,
        action: move |path: &Path| {
            fs::rename(path, &moved).unwrap();
            symlink(&outside_root, path).unwrap();
        },
    };

    let result: ScanResult = scan_observed(&tree.root, &mut observer);

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].path, lossless(&tree.path("target")));
    assert_eq!(result.regions[0].cause, RegionCause::IdentityChanged);
    assert_eq!(result.regions[0].kind(), RegionKind::Changed);
    // The no-follow open of a symbolic link fails with `ENOTDIR` on macOS
    // and with `ELOOP` on Linux.
    assert!(matches!(
        result.regions[0].native_errno,
        Some(libc::ELOOP | libc::ENOTDIR)
    ));
    // Nothing outside the root is in the totals.
    assert_eq!(result.totals.logical_bytes, Bytes::new(30));
    assert_eq!(result.totals.files, count(1));
    assert_eq!(result.largest_files.len(), 1);
}

#[test]
fn a_directory_replaced_by_another_directory_is_a_changed_region() {
    let tree = TempTree::new("swapped");
    tree.file("swapped/inner.bin", 700);
    tree.file("keep.bin", 30);
    let result: ScanResult = scan_injected(&tree.root, "swapped", |metadata| {
        // The measurement saw another object than the one that the open
        // call finds.
        metadata.inode += 1;
    });

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].cause, RegionCause::IdentityChanged);
    assert_eq!(result.regions[0].native_errno, None);
    assert_eq!(result.totals.logical_bytes, Bytes::new(30));
}

#[test]
fn a_mount_boundary_is_recorded_and_not_crossed() {
    let tree = TempTree::new("boundary");
    tree.file("other/inner.bin", 100);
    tree.file("keep/x.bin", 50);
    let root_device: i32 = i32::try_from(fs::metadata(&tree.root).unwrap().dev()).unwrap();
    let other_device = DeviceNumber::new(root_device.wrapping_add(1));
    let result: ScanResult = scan_injected(&tree.root, "other", move |metadata| {
        metadata.device = Some(other_device);
    });

    // A boundary is outside the scope, so the coverage stays complete.
    assert_complete(&result);
    assert_eq!(result.boundaries.len(), 1);
    assert_eq!(result.boundaries[0].path, lossless(&tree.path("other")));
    assert_eq!(result.boundaries[0].device, Some(other_device));
    assert_eq!(result.boundaries_omitted, count(0));
    assert_eq!(result.totals.logical_bytes, Bytes::new(50));
    assert_eq!(result.totals.entries, count(2));
    assert_eq!(result.entries_examined, count(3));
    assert_eq!(result.largest_directories.len(), 1);
}

#[test]
fn the_boundary_list_is_bounded() {
    let tree = TempTree::new("boundary-bound");
    for index in 0..4 {
        tree.file(&format!("d{index}/other"), 10);
    }
    let limits = ScanLimits {
        max_recorded_boundaries: 1,
        ..ScanLimits::default()
    };
    let hook: MetadataHook = Box::new(|path: &Path, metadata: &mut RawMetadata| {
        if path.file_name() == Some(OsStr::new("other")) {
            metadata.device = None;
        }
    });
    let result: ScanResult = scan_with(
        &request(&tree.root, limits),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        Injection {
            metadata: Some(hook),
            ..Injection::default()
        },
    )
    .unwrap();

    assert_eq!(result.boundaries.len(), 1);
    assert_eq!(result.boundaries[0].device, None);
    assert_eq!(result.boundaries_omitted, count(3));
    assert_eq!(result.totals.files, count(0));
}

#[test]
fn metadata_that_is_not_valid_is_a_region_and_not_a_zero() {
    let tree = TempTree::new("inconsistent");
    tree.file("keep.bin", 30);
    tree.file("bad.bin", 60);

    for change in [
        (|metadata: &mut RawMetadata| metadata.size = -1) as fn(&mut RawMetadata),
        |metadata: &mut RawMetadata| metadata.blocks = -8,
        |metadata: &mut RawMetadata| metadata.blocks = i64::MAX,
    ] {
        let result: ScanResult = scan_injected(&tree.root, "bad.bin", change);
        assert_eq!(result.coverage, Coverage::Partial);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].path, lossless(&tree.path("bad.bin")));
        assert_eq!(result.regions[0].cause, RegionCause::InconsistentMetadata);
        assert_eq!(result.totals.logical_bytes, Bytes::new(30));
        assert_eq!(result.totals.files, count(1));
        assert_eq!(result.totals.entries, count(1));
        assert_eq!(result.largest_files.len(), 1);
    }
}

#[test]
fn a_field_that_overflows_keeps_the_other_fields() {
    let tree = TempTree::new("overflow");
    tree.file("huge-a", 1);
    tree.file("huge-b", 1);
    // Each file gets 2^63 allocated bytes. The sum of the two is above the
    // largest byte count.
    let hook: MetadataHook = Box::new(|path: &Path, metadata: &mut RawMetadata| {
        if path.file_name().is_some_and(|name| name != "overflow") {
            metadata.blocks = 1_i64 << 54;
        }
    });
    let result: ScanResult = scan_with(
        &request(&tree.root, ScanLimits::default()),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        Injection {
            metadata: Some(hook),
            ..Injection::default()
        },
    )
    .unwrap();

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].cause, RegionCause::Overflow);
    assert_eq!(result.regions[0].kind(), RegionKind::Incomplete);
    // The allocated total keeps its earlier value, and the second file still
    // adds its logical size, its entry, and its kind count.
    assert_eq!(result.totals.files, count(2));
    assert_eq!(result.totals.entries, count(2));
    assert_eq!(result.totals.logical_bytes, Bytes::new(2));
    assert_kind_counts_agree(&result);
    let root_allocated: u64 = fs::metadata(&tree.root).unwrap().blocks() * 512;
    assert_eq!(
        result.totals.allocated_bytes,
        Bytes::new((1_u64 << 63) + root_allocated)
    );
}

#[test]
fn a_hard_linked_object_whose_allocation_overflows_is_still_tracked() {
    let tree = TempTree::new("overflow-hardlink");
    for object in ["b", "c"] {
        let first: PathBuf = tree.file(&format!("{object}-1"), 1);
        fs::hard_link(&first, tree.path(&format!("{object}-2"))).unwrap();
    }
    // Each object gets 2^63 allocated bytes, so only one object fits the
    // allocated total. The other object keeps its other fields, its entry,
    // and its place in the hard-link set; one region records the overflow.
    let hook: MetadataHook = Box::new(|path: &Path, metadata: &mut RawMetadata| {
        if metadata.kind == EntryKind::File && path.file_name().is_some() {
            metadata.blocks = 1_i64 << 54;
        }
    });
    let result: ScanResult = scan_with(
        &request(&tree.root, ScanLimits::default()),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        Injection {
            metadata: Some(hook),
            ..Injection::default()
        },
    )
    .unwrap();

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].cause, RegionCause::Overflow);
    assert_eq!(result.shared_storage.hard_linked_objects, count(2));
    assert_eq!(
        result.shared_storage.hard_link_names_not_counted_again,
        count(2)
    );
    assert_eq!(result.totals.files, count(4));
    assert_eq!(result.totals.entries, count(4));
    assert_kind_counts_agree(&result);
}

#[cfg(target_os = "macos")]
#[test]
fn the_materialization_guard_changes_the_thread_policy_and_puts_it_back() {
    use super::native::{MaterializationOff, materialization_policy_of_this_thread};

    let before: libc::c_int = materialization_policy_of_this_thread();
    assert!(before >= 0);
    let guard = MaterializationOff::for_this_thread();
    // 1 is `IOPOL_MATERIALIZE_DATALESS_FILES_OFF`.
    assert_eq!(materialization_policy_of_this_thread(), 1);
    drop(guard);
    assert_eq!(materialization_policy_of_this_thread(), before);
}

#[test]
fn a_dataless_directory_is_not_opened() {
    let tree = TempTree::new("dataless");
    tree.file("cloud/inner.bin", 100);
    let result: ScanResult = scan_injected(&tree.root, "cloud", |metadata| {
        metadata.dataless = true;
    });

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].cause, RegionCause::NotHydrated);
    assert_eq!(result.regions[0].kind(), RegionKind::Inaccessible);
    assert_eq!(result.totals.directories, count(1));
    assert_eq!(result.totals.files, count(0));
}

#[test]
fn compressed_and_sparse_files_are_evidence_of_non_exclusive_allocation() {
    let tree = TempTree::new("sparse");
    tree.file("packed.bin", 5_000);
    let sparse: PathBuf = tree.path("sparse.bin");
    fs::File::create(&sparse)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();

    let result: ScanResult = scan_injected(&tree.root, "packed.bin", |metadata| {
        metadata.compressed = true;
    });
    let sparse_metadata: fs::Metadata = fs::metadata(&sparse).unwrap();

    assert_complete(&result);
    assert_eq!(result.shared_storage.compressed_files, count(1));
    assert_eq!(
        result.totals.logical_bytes,
        Bytes::new(5_000 + 8 * 1024 * 1024)
    );
    assert_eq!(
        result.totals.allocated_bytes,
        Bytes::new(expected(&tree.root).allocated)
    );
    let sparse_item: &LargeFile = result
        .largest_files
        .iter()
        .find(|file| file.path == lossless(&sparse))
        .unwrap();
    assert_eq!(sparse_item.logical_bytes, Bytes::new(8 * 1024 * 1024));
    assert_eq!(
        sparse_item.allocated_bytes,
        Bytes::new(sparse_metadata.blocks() * 512)
    );
    if sparse_metadata.blocks() * 512 < sparse_metadata.len() {
        // The filesystem made a sparse file.
        assert_eq!(
            result.shared_storage.files_allocated_below_logical,
            count(1)
        );
    }
}

#[test]
fn an_entry_that_is_not_a_file_a_directory_or_a_link_has_no_size() {
    let tree = TempTree::new("fifo");
    tree.file("keep.bin", 30);
    let fifo: PathBuf = tree.path("pipe");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|status| status.success()) {
        return;
    }

    let mut recorder = Recorder::default();
    let result: ScanResult = scan_observed(&tree.root, &mut recorder);

    assert_complete(&result);
    assert_eq!(result.totals.other_entries, count(1));
    assert_eq!(result.totals.entries, count(2));
    assert_eq!(result.totals.logical_bytes, Bytes::new(30));
    assert_kind_counts_agree(&result);
    assert!(
        recorder
            .entries
            .iter()
            .any(|entry| entry.0 == fifo && entry.1 == EntryKind::Other)
    );
}

#[test]
fn a_scan_cancelled_before_it_starts_has_no_measured_entry() {
    let tree = TempTree::new("cancel-early");
    tree.file("a.bin", 100);
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result: ScanResult = run_scan(
        &request(&tree.root, ScanLimits::default()),
        &cancel,
        &WallScanClock,
        &mut NoObserver,
    )
    .unwrap();

    assert_eq!(result.completion, ScanCompletion::Cancelled);
    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.entries_examined, count(0));
    assert_eq!(result.totals.entries, count(0));
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].path, lossless(&tree.root));
    assert_eq!(result.regions[0].cause, RegionCause::Cancelled);
    assert_eq!(result.regions[0].kind(), RegionKind::Incomplete);
}

/// Cancels the scan when it leaves the first directory below the root.
struct CancelAfterFirstDirectory {
    cancel: CancellationToken,
}

impl ScanObserver for CancelAfterFirstDirectory {
    fn directory_finished(&mut self, directory: &DirectoryRecord<'_>) {
        if directory.depth == 1 {
            self.cancel.cancel();
        }
    }
}

#[test]
fn a_cancelled_scan_keeps_the_measured_part() {
    let tree = TempTree::new("cancel-mid");
    for directory in ["d1", "d2", "d3"] {
        for index in 0..5 {
            tree.file(&format!("{directory}/f{index}.bin"), 100);
        }
    }
    let cancel = CancellationToken::new();
    let mut observer = CancelAfterFirstDirectory {
        cancel: cancel.clone(),
    };

    let result: ScanResult = run_scan(
        &request(&tree.root, ScanLimits::default()),
        &cancel,
        &WallScanClock,
        &mut observer,
    )
    .unwrap();

    assert_eq!(result.completion, ScanCompletion::Cancelled);
    assert_eq!(result.coverage, Coverage::Partial);
    // The scan finished one directory of five files and then stopped.
    assert_eq!(result.totals.directories, count(1));
    assert_eq!(result.totals.files, count(5));
    assert_eq!(result.totals.logical_bytes, Bytes::new(500));
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].path, lossless(&tree.root));
    assert_eq!(result.regions[0].cause, RegionCause::Cancelled);
    assert_eq!(result.largest_directories.len(), 1);
    assert_eq!(result.largest_directories[0].coverage, Coverage::Complete);
    assert_eq!(result.largest_files.len(), 5);
}

#[test]
fn a_directory_below_the_depth_limit_is_an_incomplete_region() {
    let tree = TempTree::new("depth");
    tree.file("a/b/c/deep.bin", 100);
    tree.file("a/near.bin", 20);

    let one = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 1,
            ..ScanLimits::default()
        },
    );
    assert_eq!(one.completion, ScanCompletion::Finished);
    assert_eq!(one.coverage, Coverage::Partial);
    assert_eq!(one.regions.len(), 1);
    assert_eq!(one.regions[0].path, lossless(&tree.path("a/b")));
    assert_eq!(one.regions[0].cause, RegionCause::DepthLimit);
    assert_eq!(one.regions[0].kind(), RegionKind::Incomplete);
    assert_eq!(one.totals.directories, count(2));
    assert_eq!(one.totals.logical_bytes, Bytes::new(20));
    // The directory above the region is partial.
    assert_eq!(one.largest_directories.len(), 1);
    assert_eq!(one.largest_directories[0].coverage, Coverage::Partial);

    let zero = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 0,
            ..ScanLimits::default()
        },
    );
    assert_eq!(zero.regions.len(), 1);
    assert_eq!(zero.regions[0].path, lossless(&tree.path("a")));
    assert_eq!(zero.totals.entries, count(1));
    assert_eq!(zero.largest_directories, []);

    let deep_enough = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 3,
            ..ScanLimits::default()
        },
    );
    assert_complete(&deep_enough);
    assert_eq!(deep_enough.totals.logical_bytes, Bytes::new(120));
}

#[test]
fn the_entry_limit_stops_the_scan() {
    let tree = TempTree::new("entries");
    for index in 0..10 {
        tree.file(&format!("f{index}.bin"), 100);
    }

    let stopped = scan_limited(
        &tree.root,
        ScanLimits {
            max_entries: count(4),
            ..ScanLimits::default()
        },
    );
    assert_eq!(stopped.completion, ScanCompletion::EntryLimitReached);
    assert_eq!(stopped.coverage, Coverage::Partial);
    assert_eq!(stopped.entries_examined, count(4));
    assert_eq!(stopped.totals.entries, count(4));
    assert_eq!(stopped.totals.logical_bytes, Bytes::new(400));
    assert_eq!(stopped.regions.len(), 1);
    assert_eq!(stopped.regions[0].path, lossless(&tree.root));
    assert_eq!(stopped.regions[0].cause, RegionCause::EntryLimit);

    // A limit equal to the number of names stops nothing.
    let exact = scan_limited(
        &tree.root,
        ScanLimits {
            max_entries: count(10),
            ..ScanLimits::default()
        },
    );
    assert_complete(&exact);
    assert_eq!(exact.totals.entries, count(10));
}

#[test]
fn the_lists_of_the_largest_items_are_bounded_and_ordered() {
    let tree = TempTree::new("largest");
    for index in 1..=10_usize {
        tree.file(&format!("d{index}/f{index}.bin"), index * 20_000);
    }

    let result = scan_limited(
        &tree.root,
        ScanLimits {
            max_largest_files: 3,
            max_largest_directories: 2,
            ..ScanLimits::default()
        },
    );
    assert_complete(&result);
    let files: Vec<Bytes> = result
        .largest_files
        .iter()
        .map(|file| file.logical_bytes)
        .collect();
    assert_eq!(
        files,
        [
            Bytes::new(200_000),
            Bytes::new(180_000),
            Bytes::new(160_000)
        ]
    );
    assert!(
        result
            .largest_files
            .windows(2)
            .all(|pair| pair[0].allocated_bytes >= pair[1].allocated_bytes)
    );
    let directories: Vec<LosslessPath> = result
        .largest_directories
        .iter()
        .map(|directory| directory.path.clone())
        .collect();
    assert_eq!(
        directories,
        [lossless(&tree.path("d10")), lossless(&tree.path("d9"))]
    );
    // The totals have each file, not only the listed files.
    assert_eq!(result.totals.logical_bytes, Bytes::new(55 * 20_000));

    let none = scan_limited(
        &tree.root,
        ScanLimits {
            max_largest_files: 0,
            max_largest_directories: 0,
            ..ScanLimits::default()
        },
    );
    assert_complete(&none);
    assert_eq!(none.largest_files, []);
    assert_eq!(none.largest_directories, []);
    assert_eq!(none.totals.logical_bytes, Bytes::new(55 * 20_000));
}

#[test]
fn the_region_list_is_bounded() {
    let tree = TempTree::new("regions");
    for index in 0..5 {
        tree.file(&format!("d{index}/sub/f.bin"), 10);
    }
    let result = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 1,
            max_recorded_regions: 2,
            ..ScanLimits::default()
        },
    );
    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 2);
    assert_eq!(result.regions_omitted, count(3));

    // With no recorded region the coverage is still partial.
    let unrecorded = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 1,
            max_recorded_regions: 0,
            ..ScanLimits::default()
        },
    );
    assert_eq!(unrecorded.coverage, Coverage::Partial);
    assert_eq!(unrecorded.regions, []);
    assert_eq!(unrecorded.regions_omitted, count(5));
}

#[test]
fn the_hard_link_set_is_bounded() {
    let tree = TempTree::new("hardlink-bound");
    for index in 0..3 {
        let first: PathBuf = tree.file(&format!("f{index}-a"), 4_096);
        fs::hard_link(&first, tree.path(&format!("f{index}-b"))).unwrap();
    }
    let result = scan_limited(
        &tree.root,
        ScanLimits {
            max_hard_link_objects: 1,
            ..ScanLimits::default()
        },
    );

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.shared_storage.hard_linked_objects, count(1));
    assert_eq!(
        result.shared_storage.hard_link_names_not_counted_again,
        count(1)
    );
    assert_eq!(result.shared_storage.hard_link_names_not_tracked, count(4));
    assert!(result.shared_storage.hard_linked_data_found());
    assert_eq!(result.regions.len(), 4);
    assert!(
        result
            .regions
            .iter()
            .all(|region| region.cause == RegionCause::HardLinkLimit)
    );
    // The names that are not tracked are not counted two times and are not
    // zero-size entries.
    assert_eq!(result.totals.files, count(2));
    assert_eq!(result.totals.logical_bytes, Bytes::new(4_096));
}

#[test]
fn a_limit_above_its_maximum_is_rejected() {
    let tree = TempTree::new("limits");
    let cases: [(ScanLimits, &str); 6] = [
        (
            ScanLimits {
                max_depth: super::MAX_DEPTH_LIMIT + 1,
                ..ScanLimits::default()
            },
            "max_depth",
        ),
        (
            ScanLimits {
                max_largest_files: super::MAX_LARGEST_ITEMS_LIMIT + 1,
                ..ScanLimits::default()
            },
            "max_largest_files",
        ),
        (
            ScanLimits {
                max_largest_directories: super::MAX_LARGEST_ITEMS_LIMIT + 1,
                ..ScanLimits::default()
            },
            "max_largest_directories",
        ),
        (
            ScanLimits {
                max_recorded_regions: super::MAX_RECORDED_REGIONS_LIMIT + 1,
                ..ScanLimits::default()
            },
            "max_recorded_regions",
        ),
        (
            ScanLimits {
                max_recorded_boundaries: super::MAX_RECORDED_REGIONS_LIMIT + 1,
                ..ScanLimits::default()
            },
            "max_recorded_boundaries",
        ),
        (
            ScanLimits {
                max_hard_link_objects: super::MAX_HARD_LINK_OBJECTS_LIMIT + 1,
                ..ScanLimits::default()
            },
            "max_hard_link_objects",
        ),
    ];
    for (limits, name) in cases {
        let error: ScanError = run_scan(
            &request(&tree.root, limits),
            &CancellationToken::new(),
            &WallScanClock,
            &mut NoObserver,
        )
        .unwrap_err();
        assert!(matches!(error, ScanError::LimitTooLarge { field } if field == name));
    }
    ScanLimits::default().validate().unwrap();
}

#[test]
fn a_root_that_cannot_be_scanned_is_an_error() {
    let tree = TempTree::new("root-errors");
    let file: PathBuf = tree.file("plain.bin", 10);
    let run = |path: &Path| {
        run_scan(
            &request(path, ScanLimits::default()),
            &CancellationToken::new(),
            &WallScanClock,
            &mut NoObserver,
        )
    };

    assert!(matches!(run(&file), Err(ScanError::RootNotDirectory)));
    let missing = run(&tree.path("missing")).unwrap_err();
    assert!(
        matches!(missing, ScanError::RootUnavailable(error) if error.raw_os_error() == Some(libc::ENOENT))
    );
}

fn volume_identity(device: DeviceNumber) -> VolumeIdentity {
    VolumeIdentity {
        volume_id: VolumeId::new("vol_test").unwrap(),
        mount_id: MountId::new("mount_test").unwrap(),
        mount_point: LosslessPath::from_bytes("/").unwrap(),
        device,
        filesystem_type: "apfs".to_owned(),
        volume_uuid: None,
        capacity_domain: CapacityDomainMembership::Unknown,
    }
}

#[test]
fn the_volume_identity_of_the_request_must_be_for_the_root_device() {
    let tree = TempTree::new("volume-identity");
    let device = DeviceNumber::new(i32::try_from(fs::metadata(&tree.root).unwrap().dev()).unwrap());
    let mut scan_request: ScanRequest = request(&tree.root, ScanLimits::default());
    let run = |scan_request: &ScanRequest| {
        run_scan(
            scan_request,
            &CancellationToken::new(),
            &WallScanClock,
            &mut NoObserver,
        )
    };

    scan_request.volume = Some(volume_identity(device));
    let result: ScanResult = run(&scan_request).unwrap();
    assert_eq!(result.volume.identity, scan_request.volume);
    assert_eq!(result.volume.device, device);

    scan_request.volume = Some(volume_identity(DeviceNumber::new(
        device.get().wrapping_add(1),
    )));
    assert!(matches!(run(&scan_request), Err(ScanError::VolumeMismatch)));
}

#[test]
fn a_name_that_is_not_utf8_keeps_its_bytes() {
    // The path join keeps the bytes of a name on each filesystem.
    let mut path: Vec<u8> = b"/root/dir".to_vec();
    join_name(&mut path, 5, b"n\xff.bin\0");
    assert_eq!(path, b"/root/n\xff.bin");
    let joined: LosslessPath = LosslessPath::from_bytes(path.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&joined).unwrap(),
        json!({ "encoding": "hex", "value": "2f726f6f742f6eff2e62696e" })
    );
    // A root that ends with a separator gets no second separator.
    let mut at_root: Vec<u8> = b"/".to_vec();
    join_name(&mut at_root, 1, b"name");
    assert_eq!(at_root, b"/name");

    // APFS rejects a name that is not valid UTF-8. On a filesystem that
    // accepts it, the scan reports the exact bytes.
    let tree = TempTree::new("non-utf8");
    let name: &OsStr = OsStr::from_bytes(b"n\xff.bin");
    let file: PathBuf = tree.root.join(name);
    if fs::write(&file, [0_u8; 64]).is_err() {
        return;
    }
    let result: ScanResult = scan(&tree.root);
    assert_complete(&result);
    assert_eq!(result.totals.files, count(1));
    let listed: &LosslessPath = &result.largest_files[0].path;
    assert!(listed.as_bytes().ends_with(b"/n\xff.bin"));
    assert_eq!(listed.as_utf8(), None);
    assert_eq!(
        serde_json::to_value(listed).unwrap()["encoding"],
        json!("hex")
    );
    let restored: ScanResult =
        serde_json::from_value(serde_json::to_value(&result).unwrap()).unwrap();
    assert_eq!(restored, result);
}

/// A clock that gives a new known time for each call.
struct StepClock {
    calls: Cell<u64>,
}

impl ScanClock for StepClock {
    fn now(&self) -> ScanTimestamp {
        let call: u64 = self.calls.get();
        self.calls.set(call + 1);
        ScanTimestamp {
            wall: Some(
                WallTime::from_unix(1_800_000_000 + i64::try_from(call).unwrap(), 0).unwrap(),
            ),
            monotonic_ns: Some(MonotonicNanos::new(5_000 + call * 1_000)),
        }
    }
}

#[test]
fn the_result_has_the_times_of_the_clock_of_the_caller() {
    let tree = TempTree::new("clock");
    let clock = StepClock {
        calls: Cell::new(0),
    };
    let result: ScanResult = run_scan(
        &request(&tree.root, ScanLimits::default()),
        &CancellationToken::new(),
        &clock,
        &mut NoObserver,
    )
    .unwrap();

    assert_eq!(clock.calls.get(), 2);
    assert_eq!(
        result.started.monotonic_ns,
        Some(MonotonicNanos::new(5_000))
    );
    assert_eq!(
        result.finished.monotonic_ns,
        Some(MonotonicNanos::new(6_000))
    );
    assert_eq!(
        result.started.wall,
        Some(WallTime::from_unix(1_800_000_000, 0).unwrap())
    );
    assert_eq!(
        result.finished.wall,
        Some(WallTime::from_unix(1_800_000_001, 0).unwrap())
    );
}

#[test]
fn the_result_round_trips_as_json() {
    let tree = TempTree::new("json");
    tree.file("a/b.bin", 1_234);
    tree.file("a/deep/c.bin", 10);
    let first: PathBuf = tree.file("link-a", 2_000);
    fs::hard_link(&first, tree.path("link-b")).unwrap();
    let result = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 1,
            ..ScanLimits::default()
        },
    );

    let value: Value = serde_json::to_value(&result).unwrap();
    assert_eq!(value["schema_version"], json!(2));
    assert_eq!(value["scan_id"], json!("scan_test"));
    assert_eq!(value["completion"], json!("finished"));
    assert_eq!(value["coverage"], json!("partial"));
    // Exact integer quantities are base-10 strings.
    assert_eq!(value["totals"]["logical_bytes"], json!("3234"));
    assert_eq!(value["totals"]["entries"], json!("5"));
    assert_eq!(value["shared_storage"]["hard_linked_objects"], json!("1"));
    assert_eq!(value["regions"][0]["cause"], json!("depth_limit"));
    assert_eq!(value["regions"][0]["native_errno"], Value::Null);
    assert_eq!(value["root"]["encoding"], json!("utf8"));
    assert_eq!(value["limits"]["max_depth"], json!(1));
    assert!(value["largest_files"][0]["allocated_bytes"].is_string());
    assert!(value.get("exclusive_bytes").is_none());

    let restored: ScanResult = serde_json::from_value(value).unwrap();
    assert_eq!(restored, result);
}

#[test]
fn the_totals_are_observations_of_the_scan_scope() {
    let tree = TempTree::new("observations");
    tree.file("a.bin", 600);
    tree.file("locked/b.bin", 1);
    let result = scan_limited(
        &tree.root,
        ScanLimits {
            max_depth: 0,
            ..ScanLimits::default()
        },
    );
    let source = Source {
        adapter_id: AdapterId::new("svalnir.scan").unwrap(),
        adapter_revision: "1".to_owned(),
        native_api: "fstatat".to_owned(),
        native_field: "st_size".to_owned(),
        worker_id: WorkerId::new("worker_test").unwrap(),
    };
    let sample = Sample {
        sample_id: SampleId::new("sample_test").unwrap(),
        clock_domain: ClockDomainId::new("clock_test").unwrap(),
        boot_id: BootId::new("boot_test").unwrap(),
        collector_epoch: CollectorEpochId::new("collector_test").unwrap(),
        started_monotonic_ns: MonotonicNanos::new(1),
        finished_monotonic_ns: MonotonicNanos::new(2),
        captured_at: WallTime::UNIX_EPOCH,
    };

    let observations = result.observations(&source, &sample).unwrap();

    assert_eq!(
        observations.logical_bytes.metric_id.as_str(),
        "scan.logical_bytes"
    );
    assert_eq!(observations.logical_bytes.scope.kind, ScopeKind::Scan);
    assert_eq!(
        observations.logical_bytes.scope.identity_id.as_str(),
        "scan_test"
    );
    assert_eq!(observations.logical_bytes.value(), Some(&Bytes::new(600)));
    assert_eq!(observations.logical_bytes.coverage, Coverage::Partial);
    assert_eq!(
        observations.allocated_bytes.value(),
        Some(&result.totals.allocated_bytes)
    );
    assert_eq!(observations.entries.value(), Some(&count(2)));
    assert_eq!(observations.entries.unit, Unit::Entry);
    // The exclusive size is the private allocated bytes of the scan, with
    // the coverage of the scan.
    assert_eq!(
        observations.exclusive_bytes.value(),
        result.private_allocation.bytes.value().as_ref()
    );
    assert_eq!(observations.exclusive_bytes.coverage, Coverage::Partial);
}

#[test]
fn each_region_cause_has_a_class_and_a_stable_reason() {
    let causes: [(RegionCause, RegionKind, UnavailableReason); 12] = [
        (
            RegionCause::PermissionDenied,
            RegionKind::Inaccessible,
            UnavailableReason::PermissionDenied,
        ),
        (
            RegionCause::ReadFailed,
            RegionKind::Inaccessible,
            UnavailableReason::TransientFailure,
        ),
        (
            RegionCause::ResourceLimit,
            RegionKind::Inaccessible,
            UnavailableReason::TransientFailure,
        ),
        (
            RegionCause::NotHydrated,
            RegionKind::Inaccessible,
            UnavailableReason::NotCollected,
        ),
        (
            RegionCause::Disappeared,
            RegionKind::Changed,
            UnavailableReason::ResourceGone,
        ),
        (
            RegionCause::IdentityChanged,
            RegionKind::Changed,
            UnavailableReason::IdentityChanged,
        ),
        (
            RegionCause::InconsistentMetadata,
            RegionKind::Changed,
            UnavailableReason::InconsistentData,
        ),
        (
            RegionCause::DepthLimit,
            RegionKind::Incomplete,
            UnavailableReason::NotCollected,
        ),
        (
            RegionCause::EntryLimit,
            RegionKind::Incomplete,
            UnavailableReason::NotCollected,
        ),
        (
            RegionCause::Cancelled,
            RegionKind::Incomplete,
            UnavailableReason::NotCollected,
        ),
        (
            RegionCause::HardLinkLimit,
            RegionKind::Incomplete,
            UnavailableReason::NotCollected,
        ),
        (
            RegionCause::Overflow,
            RegionKind::Incomplete,
            UnavailableReason::Overflow,
        ),
    ];
    for (cause, kind, reason) in causes {
        assert_eq!(cause.kind(), kind);
        assert_eq!(cause.unavailable_reason(), reason);
    }
}

fn large_file(path: &str, allocated: u64, logical: u64) -> LargeFile {
    LargeFile {
        path: LosslessPath::from_bytes(path).unwrap(),
        logical_bytes: Bytes::new(logical),
        allocated_bytes: Bytes::new(allocated),
        link_count: count(1),
        object: svalnir_core::file::FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: svalnir_core::file::InodeNumber::new(1),
        },
    }
}

#[test]
fn the_top_list_does_not_depend_on_the_order_of_its_input() {
    let items: [LargeFile; 5] = [
        large_file("/r/e", 100, 10),
        large_file("/r/b", 300, 10),
        large_file("/r/c", 300, 10),
        large_file("/r/a", 300, 20),
        large_file("/r/d", 200, 10),
    ];
    let paths = |order: &[usize]| -> Vec<String> {
        let mut list: TopList<LargeFile> = TopList::new(3);
        for index in order {
            list.offer(items[*index].clone());
        }
        list.into_largest_first()
            .iter()
            .map(|file| file.path.as_utf8().unwrap().to_owned())
            .collect()
    };

    // Allocated size first, then logical size, then the path.
    let wanted: [&str; 3] = ["/r/a", "/r/b", "/r/c"];
    assert_eq!(paths(&[0, 1, 2, 3, 4]), wanted);
    assert_eq!(paths(&[4, 3, 2, 1, 0]), wanted);
    assert_eq!(paths(&[2, 4, 0, 3, 1]), wanted);

    let mut empty: TopList<LargeFile> = TopList::new(0);
    empty.offer(items[0].clone());
    assert_eq!(empty.into_largest_first(), []);
}

/// A manual check on a directory that the developer selects, for example a
/// directory with APFS clones or with a mounted volume below it. The test
/// does nothing without `SVALNIR_SCAN_MANUAL_ROOT`.
#[test]
#[ignore = "manual check; set SVALNIR_SCAN_MANUAL_ROOT and optionally SVALNIR_SCAN_MANUAL_DEPTH"]
fn manual_scan_of_a_selected_root() {
    let Some(root) = std::env::var_os("SVALNIR_SCAN_MANUAL_ROOT") else {
        return;
    };
    let max_depth: u32 = std::env::var("SVALNIR_SCAN_MANUAL_DEPTH")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(ScanLimits::default().max_depth);
    let result = scan_limited(
        Path::new(&root),
        ScanLimits {
            max_depth,
            max_largest_files: 5,
            max_largest_directories: 5,
            max_recorded_regions: 20,
            ..ScanLimits::default()
        },
    );
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}

/// Makes a file that has the apparent size of `i64::MAX` bytes in the
/// injected metadata. The file on the disk is small.
fn huge_logical_hook(names: &'static [&'static str]) -> MetadataHook {
    Box::new(move |path: &Path, metadata: &mut RawMetadata| {
        if metadata.kind == EntryKind::File
            && path
                .file_name()
                .is_some_and(|name| names.iter().any(|huge| name == OsStr::new(huge)))
        {
            metadata.size = i64::MAX;
        }
    })
}

fn scan_with_injection(root: &Path, limits: ScanLimits, injection: Injection) -> ScanResult {
    scan_with(
        &request(root, limits),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        injection,
    )
    .unwrap()
}

#[test]
fn a_logical_overflow_in_a_directory_keeps_the_allocation_and_the_count() {
    let tree = TempTree::new("logical-overflow");
    for name in ["huge1", "huge2", "huge3"] {
        tree.file(name, 1);
    }
    let result: ScanResult = scan_with_injection(
        &tree.root,
        ScanLimits::default(),
        Injection {
            metadata: Some(huge_logical_hook(&["huge1", "huge2", "huge3"])),
            ..Injection::default()
        },
    );

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].cause, RegionCause::Overflow);
    // Two files fit the logical total, and the third keeps the earlier value.
    assert_eq!(result.totals.logical_bytes, Bytes::new(2 * i64::MAX as u64));
    assert_eq!(
        result.totals.allocated_bytes.get(),
        expected(&tree.root).allocated
    );
    assert_eq!(result.totals.entries, count(3));
    assert_eq!(result.totals.files, count(3));
    assert_kind_counts_agree(&result);
}

#[test]
fn a_logical_overflow_in_a_subtree_keeps_its_allocation_and_its_entries() {
    let tree = TempTree::new("subtree-overflow");
    tree.file("a/huge1", 1);
    tree.file("a/huge2", 1);
    tree.file("b/huge3", 1);
    tree.file("b/huge4", 1);
    let result: ScanResult = scan_with_injection(
        &tree.root,
        ScanLimits::default(),
        Injection {
            metadata: Some(huge_logical_hook(&["huge1", "huge2", "huge3", "huge4"])),
            ..Injection::default()
        },
    );

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].cause, RegionCause::Overflow);
    assert_eq!(
        result.totals.allocated_bytes.get(),
        expected(&tree.root).allocated
    );
    assert_eq!(result.totals.entries, count(6));
    assert_kind_counts_agree(&result);
}

#[test]
fn the_descriptor_budget_leaves_most_of_the_limit_to_the_process() {
    assert_eq!(budget_from_limit(1_024, Some(256)), 64);
    assert_eq!(budget_from_limit(3, Some(256)), 4);
    assert_eq!(budget_from_limit(1_024, Some(10_240)), 1_025);
    assert_eq!(budget_from_limit(1_024, None), 32);
    assert_eq!(budget_from_limit(0, Some(0)), 1);
}

#[test]
fn a_directory_deeper_than_the_descriptor_budget_is_a_resource_limit_region() {
    let tree = TempTree::new("descriptor-budget");
    tree.file("d1/d2/d3/d4/d5/deep.bin", 10);
    let result: ScanResult = scan_with_injection(
        &tree.root,
        ScanLimits::default(),
        Injection {
            descriptor_budget: Some(3),
            ..Injection::default()
        },
    );

    // The root, `d1`, and `d2` are open. `d3` is a name that the scan does
    // not open.
    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].path, lossless(&tree.path("d1/d2/d3")));
    assert_eq!(result.regions[0].cause, RegionCause::ResourceLimit);
    assert_eq!(result.totals.directories, count(3));
    assert_eq!(result.totals.files, count(0));
}

#[test]
fn a_directory_that_is_already_open_on_the_stack_is_not_entered_again() {
    let tree = TempTree::new("cycle");
    tree.file("a/loop/inside.bin", 10);
    tree.file("keep.bin", 10);
    let root_inode: u64 = fs::metadata(&tree.root).unwrap().ino();
    // A bind mount cannot be made without rights. The injection gives the
    // directory `loop` the identity of the root, as a bind mount does.
    let same_as_root = move || -> MetadataHook {
        Box::new(move |path: &Path, metadata: &mut RawMetadata| {
            if path.file_name() == Some(OsStr::new("loop")) {
                metadata.inode = root_inode;
            }
        })
    };
    let result: ScanResult = scan_with_injection(
        &tree.root,
        ScanLimits::default(),
        Injection {
            metadata: Some(same_as_root()),
            opened: Some(same_as_root()),
            ..Injection::default()
        },
    );

    assert_eq!(result.coverage, Coverage::Partial);
    assert_eq!(result.regions.len(), 1);
    assert_eq!(result.regions[0].path, lossless(&tree.path("a/loop")));
    assert_eq!(result.regions[0].cause, RegionCause::IdentityChanged);
    assert_eq!(result.totals.files, count(1));
}

// The private allocated bytes (`docs/RESOURCE_MODEL.md` section 8). The
// tests make clones with `cp -c`, which calls `clonefile(2)`, in their own
// temporary directories on the volume of the temporary directory.

/// Clones `source` to `target` with `clonefile(2)`.
fn clone_file(source: &Path, target: &Path) {
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let status = std::process::Command::new("/bin/cp")
        .arg("-c")
        .arg(source)
        .arg(target)
        .status()
        .unwrap();
    assert!(status.success());
}

fn allocated_of(path: &Path) -> u64 {
    fs::symlink_metadata(path).unwrap().blocks() * 512
}

fn private_bytes(result: &ScanResult) -> u64 {
    result
        .private_allocation
        .bytes
        .value()
        .expect("the private allocated bytes are available")
        .get()
}

/// Scans with a changed private-size result for each file whose name is
/// `name`.
fn scan_private_injected(
    root: &Path,
    name: &'static str,
    change: impl Fn(&mut std::io::Result<PrivateAttributes>) + 'static,
) -> ScanResult {
    let hook: PrivateHook = Box::new(
        move |path: &Path, result: &mut std::io::Result<PrivateAttributes>| {
            if path.file_name() == Some(OsStr::new(name)) {
                change(result);
            }
        },
    );
    scan_with(
        &request(root, ScanLimits::default()),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        Injection {
            private: Some(hook),
            ..Injection::default()
        },
    )
    .unwrap()
}

#[test]
fn a_file_without_clones_has_its_allocated_size_as_private_bytes() {
    let tree = TempTree::new("private-plain");
    tree.file("a.bin", 300_000);
    tree.file("d/b.bin", 5_000);

    let result: ScanResult = scan(&tree.root);

    assert_complete(&result);
    // APFS reports a private size for each file. A file that shares no
    // block has a private size equal to its allocated size.
    assert_eq!(private_bytes(&result), result.totals.allocated_bytes.get());
    assert_eq!(result.private_allocation.files_by_private_size, count(2));
    assert_eq!(result.private_allocation.clone_families, count(0));
}

#[test]
fn a_clone_family_inside_the_unit_counts_its_shared_blocks_one_time() {
    let tree = TempTree::new("private-clone-inside");
    let original: PathBuf = tree.file("a.bin", 1_048_576);
    let clone: PathBuf = tree.path("d/b.bin");
    clone_file(&original, &clone);

    let result: ScanResult = scan(&tree.root);

    assert_complete(&result);
    // The allocated total has the shared blocks two times.
    assert_eq!(
        result.totals.allocated_bytes.get(),
        expected(&tree.root).allocated
    );
    assert_eq!(
        private_bytes(&result),
        result.totals.allocated_bytes.get() - allocated_of(&clone)
    );
    assert_eq!(result.private_allocation.clone_families, count(1));
    assert_eq!(result.private_allocation.clone_families_complete, count(1));
    assert_eq!(result.private_allocation.files_by_private_size, count(2));
}

#[test]
fn a_clone_with_a_member_outside_the_unit_adds_only_its_private_bytes() {
    let tree = TempTree::new("private-clone-outside");
    let original: PathBuf = tree.file("unit/a.bin", 1_048_576);
    clone_file(&original, &tree.path("outside/b.bin"));
    tree.file("unit/c.bin", 4_096);

    let unit: PathBuf = tree.path("unit");
    let result: ScanResult = scan(&unit);

    assert_complete(&result);
    // `a.bin` shares each block with the clone outside, so it adds zero.
    assert_eq!(
        private_bytes(&result),
        result.totals.allocated_bytes.get() - allocated_of(&original)
    );
    assert_eq!(result.private_allocation.clone_families, count(1));
    assert_eq!(result.private_allocation.clone_families_complete, count(0));
}

#[test]
fn a_clone_family_above_the_tracked_number_adds_only_private_bytes() {
    let tree = TempTree::new("private-clone-limit");
    let original: PathBuf = tree.file("a.bin", 1_048_576);
    let clone: PathBuf = tree.path("b.bin");
    clone_file(&original, &clone);

    let result: ScanResult = scan_with(
        &request(&tree.root, ScanLimits::default()),
        &CancellationToken::new(),
        &WallScanClock,
        &mut NoObserver,
        Injection {
            clone_family_limit: Some(0),
            ..Injection::default()
        },
    )
    .unwrap();

    assert_eq!(
        private_bytes(&result),
        result.totals.allocated_bytes.get() - allocated_of(&original) - allocated_of(&clone)
    );
    assert_eq!(result.private_allocation.clone_families, count(0));
    assert_eq!(
        result.private_allocation.clone_families_not_tracked,
        count(2)
    );
}

#[test]
fn a_hard_linked_file_with_each_name_inside_counts_one_time() {
    let tree = TempTree::new("private-links-inside");
    let first: PathBuf = tree.file("a.bin", 200_000);
    tree.dir("d");
    fs::hard_link(&first, tree.path("d/b.bin")).unwrap();

    let result: ScanResult = scan(&tree.root);

    assert_complete(&result);
    assert_eq!(private_bytes(&result), result.totals.allocated_bytes.get());
    assert_eq!(
        result
            .private_allocation
            .hard_linked_objects_with_names_outside,
        count(0)
    );
    assert_eq!(result.private_allocation.files_by_private_size, count(1));
}

#[test]
fn a_hard_linked_file_with_a_name_outside_adds_zero_and_a_note() {
    let tree = TempTree::new("private-links-outside");
    let inside: PathBuf = tree.file("unit/a.bin", 200_000);
    tree.dir("outside");
    fs::hard_link(&inside, tree.path("outside/b.bin")).unwrap();

    let unit: PathBuf = tree.path("unit");
    let result: ScanResult = scan(&unit);

    assert_complete(&result);
    assert_eq!(
        private_bytes(&result),
        result.totals.allocated_bytes.get() - allocated_of(&inside)
    );
    assert_eq!(
        result
            .private_allocation
            .hard_linked_objects_with_names_outside,
        count(1)
    );
}

#[test]
fn a_compressed_file_adds_its_allocated_size() {
    let tree = TempTree::new("private-compressed");
    tree.file("packed.bin", 64_000);

    let result: ScanResult = scan_injected(&tree.root, "packed.bin", |metadata| {
        metadata.compressed = true;
    });

    assert_eq!(private_bytes(&result), result.totals.allocated_bytes.get());
    assert_eq!(result.private_allocation.files_by_allocated_size, count(1));
    assert_eq!(result.private_allocation.files_by_private_size, count(0));
}

#[test]
fn a_volume_that_does_not_report_the_private_size_makes_it_unavailable() {
    let tree = TempTree::new("private-unsupported");
    tree.file("a.bin", 10_000);
    tree.file("b.bin", 10_000);

    let result: ScanResult = scan_private_injected(&tree.root, "a.bin", |result| {
        if let Ok(attributes) = result {
            attributes.private_size = None;
            attributes.clone_id = None;
            attributes.clone_count = None;
        }
    });

    // The other totals stay; the private quantity is not a zero.
    assert_complete(&result);
    assert_eq!(
        result.private_allocation.bytes,
        PrivateBytes::Unavailable {
            cause: PrivateSizeUnavailable::NotReported
        }
    );
    let value: Value = serde_json::to_value(result.private_allocation).unwrap();
    assert_eq!(value["bytes"]["availability"], json!("unavailable"));
    assert_eq!(value["bytes"]["cause"], json!("not_reported"));
}

#[test]
fn a_failed_or_replaced_private_size_query_makes_it_unavailable() {
    let tree = TempTree::new("private-failed");
    tree.file("a.bin", 10_000);

    let denied: ScanResult = scan_private_injected(&tree.root, "a.bin", |result| {
        *result = Err(std::io::Error::from_raw_os_error(libc::EACCES));
    });
    let replaced: ScanResult = scan_private_injected(&tree.root, "a.bin", |result| {
        if let Ok(attributes) = result {
            attributes.file_id = attributes.file_id.map(|id| id ^ 1);
        }
    });
    let negative: ScanResult = scan_private_injected(&tree.root, "a.bin", |result| {
        if let Ok(attributes) = result {
            attributes.private_size = Some(-1);
        }
    });

    let cause = |result: &ScanResult| {
        if let PrivateBytes::Unavailable { cause } = result.private_allocation.bytes {
            Some(cause)
        } else {
            None
        }
    };
    assert_eq!(
        cause(&denied),
        Some(PrivateSizeUnavailable::PermissionDenied)
    );
    assert_eq!(
        cause(&replaced),
        Some(PrivateSizeUnavailable::IdentityChanged)
    );
    assert_eq!(
        cause(&negative),
        Some(PrivateSizeUnavailable::InconsistentValue)
    );
}

#[test]
fn a_private_size_above_the_allocated_size_adds_the_allocated_size() {
    let part = file_part(
        Ok(PrivateAttributes {
            file_id: Some(7),
            private_size: Some(9_000),
            clone_id: Some(3),
            clone_count: Some(2),
        }),
        7,
        Bytes::new(8_192),
    );
    assert_eq!(part, Ok(FilePart::Allocated(Bytes::new(8_192))));

    let shared = file_part(
        Ok(PrivateAttributes {
            file_id: Some(7),
            private_size: Some(4_096),
            clone_id: Some(3),
            clone_count: Some(2),
        }),
        7,
        Bytes::new(8_192),
    );
    assert_eq!(
        shared,
        Ok(FilePart::Private {
            private: Bytes::new(4_096),
            clone: Some(CloneShare {
                family: 3,
                members: 2,
                shared: Bytes::new(4_096),
            }),
        })
    );
}

#[test]
fn the_exclusive_observation_is_the_private_allocated_bytes() {
    let tree = TempTree::new("private-observation");
    tree.file("a.bin", 10_000);
    let source = Source {
        adapter_id: AdapterId::new("svalnir.scan").unwrap(),
        adapter_revision: "1".to_owned(),
        native_api: "getattrlistat".to_owned(),
        native_field: "ATTR_CMNEXT_PRIVATESIZE".to_owned(),
        worker_id: WorkerId::new("worker_test").unwrap(),
    };
    let sample = Sample {
        sample_id: SampleId::new("sample_test").unwrap(),
        clock_domain: ClockDomainId::new("clock_test").unwrap(),
        boot_id: BootId::new("boot_test").unwrap(),
        collector_epoch: CollectorEpochId::new("collector_test").unwrap(),
        started_monotonic_ns: MonotonicNanos::new(1),
        finished_monotonic_ns: MonotonicNanos::new(2),
        captured_at: WallTime::UNIX_EPOCH,
    };

    let measured: ScanResult = scan(&tree.root);
    let unsupported: ScanResult = scan_private_injected(&tree.root, "a.bin", |result| {
        if let Ok(attributes) = result {
            attributes.private_size = None;
        }
    });
    let available = measured.observations(&source, &sample).unwrap();
    let unavailable = unsupported.observations(&source, &sample).unwrap();

    assert_eq!(available.exclusive_bytes.kind, MetricKind::Estimate);
    assert_eq!(
        available.exclusive_bytes.value(),
        Some(&Bytes::new(private_bytes(&measured)))
    );
    assert_eq!(
        unavailable.exclusive_bytes.reading,
        Reading::Unavailable(UnavailableReason::Unsupported)
    );
}
