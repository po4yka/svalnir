//! The exception for the checkouts of Swift Package Manager
//! (`docs/CLEANUP_RULES.md` section 6, "Repositories in a unit").
//!
//! Swift Package Manager keeps a clone of each remote dependency in
//! `checkouts/IDENTITY` of its build directory, and a bare mirror of the
//! same dependency in `repositories/NAME`. `swift package resolve` and
//! `xcodebuild -resolvePackageDependencies` make both again from the pins
//! of `Package.resolved`. A clone is thus a repository that can be made
//! again only when it holds nothing that the pins do not restore.
//!
//! [`check_checkout`] accepts a checkout only when each of these is true:
//!
//! - Its `.git` directory is the object that the walk measured.
//! - A pin of `Package.resolved` has the identity of the checkout: the
//!   name of its directory in lower case.
//! - The configuration of the repository names no filter driver.
//! - `HEAD` is the revision of the pin.
//! - Its one remote, `origin`, is the location of that pin, or is a mirror
//!   that [`check_mirror`] accepts in the `repositories` directory beside
//!   `checkouts`, whose one remote is the location of the pin. Two
//!   absolute paths must name the same directory; two URLs must be equal,
//!   apart from one trailing slash.
//! - It has no stash and no linked worktree.
//! - `git status` reports no changed, untracked, or ignored file, and no
//!   file has the `assume-unchanged` or the `skip-worktree` flag.
//! - `core.logAllRefUpdates` is not false, and each entry of the reflogs
//!   of its remote-tracking references is a fetch or a clone: a push from
//!   the checkout leaves another entry.
//! - Each commit of its references and reflogs is reachable from a
//!   remote-tracking reference of `origin`, from `HEAD` (with a pin only), or
//!   from a tag that the mirror has with the same object.
//! - It has no `.git/modules` entry: a submodule is not admitted.
//! - With no pin, its origin is a remote URL, or a mirror that
//!   [`check_mirror`] accepts beside it.
//!
//! [`check_mirror`] accepts a mirror only when its Git directory is the
//! object that the walk measured (before and after the queries), it is
//! bare, its one remote is the location of a pin (with no pins: a remote
//! URL), the remote has `mirror = true`, it has no `worktrees` and no
//! `modules` entry, no commit is only in its reflogs, and each entry of its
//! reflogs is a fetch or a clone. The mirrors that Swift Package Manager
//! makes have `mirror = true` and `fetch = +refs/*:refs/*`. A bare repository records no reflog
//! by default, so a push into a mirror from another repository is not
//! seen: that is a residual risk.
//!
//! Each Git query is a read-only command of [`GitTool`], with its fixed
//! environment and arguments. The arguments turn off each configuration
//! key that can run a program for these commands where Git permits it
//! (`rules::git`). The check of the filter driver is still necessary,
//! because no command-line value turns off a filter driver that the
//! configuration names: `git status` can run it on a changed file.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use svalnir_core::file::FileObjectEvidence;

use super::{MarkerKind, RefusalReason};
use crate::rules::git::{GitOutput, GitTool};

/// The largest `Package.resolved` file that [`read_pins`] reads, in bytes.
pub const MAX_PINS_BYTES: u64 = 1 << 20;

/// The largest output of one Git query, in bytes.
const MAX_QUERY_OUTPUT: usize = 256 * 1024;

/// The directory of the checkouts of one build directory, and the file
/// that pins them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftPmCheckouts {
    checkouts: PathBuf,
    /// The pin file. `None` for the pin-less mode of a project directory
    /// whose workspace is gone, and of the shared cache: no pin then gives
    /// the revision or the location.
    resolved: Option<PathBuf>,
}

impl SwiftPmCheckouts {
    /// The checkouts directory `checkouts` and the pin file `resolved`.
    #[must_use]
    pub const fn new(checkouts: PathBuf, resolved: PathBuf) -> Self {
        Self {
            checkouts,
            resolved: Some(resolved),
        }
    }

    /// The pin-less mode for the project directory `project` of
    /// `DerivedData` whose workspace is gone: the checkouts are in
    /// `SourcePackages/checkouts` and the mirrors in
    /// `SourcePackages/repositories`. No pin file is read.
    #[must_use]
    pub fn of_orphan_project(project: &Path) -> Self {
        Self {
            checkouts: project.join("SourcePackages/checkouts"),
            resolved: None,
        }
    }

    /// The pin-less mode for the `repositories` directory of the shared
    /// cache of Swift Package Manager, `cache` being its parent
    /// (`org.swift.swiftpm`). Only the mirrors directly in `repositories`
    /// are managed; the cache has no checkout.
    #[must_use]
    pub fn of_shared_cache(cache: &Path) -> Self {
        Self {
            checkouts: cache.join("checkouts"),
            resolved: None,
        }
    }

    /// The checkouts of the build directory `build` of a package: `.build`
    /// beside `Package.swift`. The pins are in `Package.resolved` beside
    /// `Package.swift`. `None` when the parent of `build` has no regular
    /// file `Package.swift`.
    #[must_use]
    pub fn of_package_build(build: &Path) -> Option<Self> {
        let package: &Path = build.parent()?;
        let manifest: fs::Metadata = fs::symlink_metadata(package.join("Package.swift")).ok()?;
        manifest
            .is_file()
            .then(|| Self::new(build.join("checkouts"), package.join("Package.resolved")))
    }

    /// The checkouts of the `DerivedData` project directory `project`,
    /// whose `info.plist` names `workspace` (`WorkspacePath`). Xcode keeps
    /// them in `SourcePackages/checkouts`. The pins are in
    /// `xcshareddata/swiftpm/Package.resolved` of a workspace, in
    /// `project.xcworkspace/xcshareddata/swiftpm/Package.resolved` of a
    /// project, and in `Package.resolved` of a package directory. `None`
    /// when `workspace` is not absolute.
    #[must_use]
    pub fn of_xcode_project(project: &Path, workspace: &Path) -> Option<Self> {
        if !workspace.is_absolute() {
            return None;
        }
        let shared = |container: PathBuf| container.join("xcshareddata/swiftpm/Package.resolved");
        let resolved: PathBuf = match workspace.extension().and_then(OsStr::to_str) {
            Some("xcworkspace") => shared(workspace.to_path_buf()),
            Some("xcodeproj") => shared(workspace.join("project.xcworkspace")),
            _ => workspace.join("Package.resolved"),
        };
        Some(Self::new(
            project.join("SourcePackages/checkouts"),
            resolved,
        ))
    }

    /// The checkouts directory.
    #[must_use]
    pub fn checkouts(&self) -> &Path {
        &self.checkouts
    }

    /// The pin file, or `None` in the pin-less mode.
    #[must_use]
    pub fn resolved(&self) -> Option<&Path> {
        self.resolved.as_deref()
    }

    /// What Swift Package Manager keeps at `work_tree`: a checkout, which
    /// is a work tree with a `.git` directory directly in the checkouts
    /// directory, or a mirror, which is a Git directory with no `.git`
    /// name directly in the `repositories` directory beside it.
    pub(super) fn managed(&self, work_tree: &Path, marker: MarkerKind) -> Option<Managed> {
        let parent: &Path = work_tree.parent()?;
        match marker {
            MarkerKind::Directory if parent == self.checkouts.as_path() => work_tree
                .file_name()?
                .to_str()
                .map(|name| Managed::Checkout(name.to_owned())),
            MarkerKind::Bare if Some(parent) == self.repositories().as_deref() => {
                Some(Managed::Mirror)
            }
            _ => None,
        }
    }

    /// The directory of the mirrors beside the checkouts directory.
    fn repositories(&self) -> Option<PathBuf> {
        self.checkouts
            .parent()
            .map(|parent| parent.join("repositories"))
    }
}

/// A repository that Swift Package Manager keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Managed {
    /// A checkout, with the name of its directory.
    Checkout(String),
    /// A bare mirror.
    Mirror,
}

/// What `Package.resolved` pins for one package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pin {
    /// The identity of the package, in lower case.
    pub identity: String,
    /// The URL or the path that Swift Package Manager clones.
    pub location: String,
    /// The commit, in lower case.
    pub revision: String,
}

/// Why [`read_pins`] gave no pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinsProblem {
    /// The file is absent or cannot be opened.
    Unavailable,
    /// The file is not a regular file, or is larger than
    /// [`MAX_PINS_BYTES`].
    NotSupported,
    /// The content is not a pin file of version 1, 2, or 3.
    Invalid,
}

#[derive(Deserialize)]
struct PinState {
    revision: Option<String>,
}

/// One pin of version 1.
#[derive(Deserialize)]
struct PinV1 {
    #[serde(rename = "repositoryURL")]
    repository_url: String,
    state: PinState,
}

#[derive(Deserialize)]
struct ObjectV1 {
    pins: Vec<PinV1>,
}

/// One pin of version 2 or 3.
#[derive(Deserialize)]
struct PinV2 {
    identity: String,
    location: Option<String>,
    state: PinState,
}

#[derive(Deserialize)]
struct Resolved {
    version: u32,
    object: Option<ObjectV1>,
    pins: Option<Vec<PinV2>>,
}

/// The identity that Swift Package Manager derives from a location: its last path
/// component with no `.git` suffix, in lower case.
fn identity_of_location(location: &str) -> Option<String> {
    let last: &str = location.trim_end_matches('/').rsplit(['/', ':']).next()?;
    let stem: &str = last.strip_suffix(".git").unwrap_or(last);
    (!stem.is_empty()).then(|| stem.to_ascii_lowercase())
}

/// The pins of the content `bytes` of a `Package.resolved` file. A pin
/// with no revision, as of a registry package, is not in the list.
///
/// # Errors
///
/// Returns [`PinsProblem::Invalid`] when `bytes` is not a pin file of
/// version 1, 2, or 3.
pub fn parse_pins(bytes: &[u8]) -> Result<Vec<Pin>, PinsProblem> {
    let resolved: Resolved = serde_json::from_slice(bytes).map_err(|_| PinsProblem::Invalid)?;
    let pin = |identity: String, location: String, revision: Option<String>| {
        revision
            .filter(|revision| !revision.is_empty())
            .map(|revision| Pin {
                identity,
                location,
                revision: revision.to_ascii_lowercase(),
            })
    };
    match (resolved.version, resolved.object, resolved.pins) {
        (1, Some(object), None) => Ok(object
            .pins
            .into_iter()
            .filter_map(|entry| {
                let identity: String = identity_of_location(&entry.repository_url)?;
                pin(identity, entry.repository_url, entry.state.revision)
            })
            .collect()),
        (2 | 3, None, Some(pins)) => Ok(pins
            .into_iter()
            .filter_map(|entry| {
                let location: String = entry.location?;
                pin(
                    entry.identity.to_ascii_lowercase(),
                    location,
                    entry.state.revision,
                )
            })
            .collect()),
        _ => Err(PinsProblem::Invalid),
    }
}

/// Reads the pins of the `Package.resolved` file at `path`.
///
/// The file must be a regular file of no more than [`MAX_PINS_BYTES`]; the
/// open does not follow a symbolic link in the last component.
///
/// # Errors
///
/// Returns a [`PinsProblem`] when the file cannot be read or is not a pin
/// file of version 1, 2, or 3.
pub fn read_pins(path: &Path) -> Result<Vec<Pin>, PinsProblem> {
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PinsProblem::Unavailable)?;
    let metadata: fs::Metadata = file.metadata().map_err(|_| PinsProblem::Unavailable)?;
    if !metadata.is_file() || metadata.size() > MAX_PINS_BYTES {
        return Err(PinsProblem::NotSupported);
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.take(MAX_PINS_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PinsProblem::Unavailable)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_PINS_BYTES) {
        return Err(PinsProblem::NotSupported);
    }
    parse_pins(&bytes)
}

/// Whether `text` is a URL with a scheme, or an address of the form
/// `host:path`, which Git recognizes by a colon before the first slash.
fn is_remote_url(text: &str) -> bool {
    let colon: Option<usize> = text.find(':');
    let slash: Option<usize> = text.find('/');
    if let Some(position) = text.find("://") {
        let scheme: &str = &text[..position];
        return !scheme.is_empty()
            && scheme
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "+.-".contains(character));
    }
    colon.is_some_and(|colon| colon > 0 && slash.is_none_or(|slash| colon < slash))
}

/// The device and the inode of the directory at `path`, with each symbolic
/// link resolved.
fn directory_identity(path: &str) -> Option<(u64, u64)> {
    let metadata: fs::Metadata = fs::metadata(path).ok()?;
    metadata.is_dir().then(|| (metadata.dev(), metadata.ino()))
}

/// Whether the remote `url` of a clone is the location `location` of a pin.
///
/// Two absolute paths must name the same directory. Two remote URLs must
/// be equal, apart from one trailing slash on either. Each other pair is
/// not the same: a relative path depends on the directory where Git runs,
/// and a difference of case, of white space, or of a `.git` suffix can
/// name a different repository.
fn same_location(url: &str, location: &str) -> bool {
    if url.starts_with('/') && location.starts_with('/') {
        return directory_identity(url)
            .zip(directory_identity(location))
            .is_some_and(|(first, second)| first == second);
    }
    is_remote_url(url)
        && is_remote_url(location)
        && url.strip_suffix('/').unwrap_or(url) == location.strip_suffix('/').unwrap_or(location)
}

/// The Git queries of one repository.
struct Queries<'a> {
    git: &'a GitTool,
    git_dir: PathBuf,
    work_tree: Option<&'a Path>,
}

impl Queries<'_> {
    /// Runs one query. A query that fails or whose output is cut gives
    /// [`RefusalReason::GitFailed`].
    fn run(&self, arguments: &[&OsStr]) -> Result<GitOutput, RefusalReason> {
        let output: GitOutput = self
            .git
            .run(&self.git_dir, self.work_tree, arguments, MAX_QUERY_OUTPUT)
            .map_err(|_| RefusalReason::GitFailed)?;
        if output.truncated {
            return Err(RefusalReason::GitFailed);
        }
        Ok(output)
    }

    /// Runs one query that must end with the exit code 0.
    fn output(&self, arguments: &[&str]) -> Result<Vec<u8>, RefusalReason> {
        let arguments: Vec<&OsStr> = arguments.iter().map(OsStr::new).collect();
        let output: GitOutput = self.run(&arguments)?;
        if output.code != 0 {
            return Err(RefusalReason::GitFailed);
        }
        Ok(output.stdout)
    }

    /// Whether a query that exits with 0 when it finds something and with
    /// 1 when it finds nothing found something.
    fn finds(&self, arguments: &[&str]) -> Result<bool, RefusalReason> {
        let arguments: Vec<&OsStr> = arguments.iter().map(OsStr::new).collect();
        match self.run(&arguments)?.code {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(RefusalReason::GitFailed),
        }
    }

    /// The one URL of the remote `origin`, when the repository has exactly
    /// one remote, `origin`, with exactly one URL.
    fn origin_url(&self) -> Result<Option<String>, RefusalReason> {
        if self.output(&["remote"])? != b"origin\n" {
            return Ok(None);
        }
        let values: Vec<u8> = self.output(&["config", "-z", "--get-all", "remote.origin.url"])?;
        let mut parts = values.split(|byte| *byte == 0);
        let (Some(url), Some(b""), None) = (parts.next(), parts.next(), parts.next()) else {
            return Ok(None);
        };
        Ok(std::str::from_utf8(url).ok().map(str::to_owned))
    }

    /// The object of each tag, by the name of its reference.
    fn tags(&self) -> Result<Vec<(String, String)>, RefusalReason> {
        let output: Vec<u8> = self.output(&[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/tags",
        ])?;
        let text: &str = std::str::from_utf8(&output).map_err(|_| RefusalReason::GitFailed)?;
        Ok(text
            .lines()
            .filter_map(|line| {
                let (object, name) = line.split_once(' ')?;
                Some((name.to_owned(), object.to_owned()))
            })
            .collect())
    }
}

/// The device and the inode of `metadata`.
fn identity_of(metadata: &fs::Metadata) -> Option<FileObjectEvidence> {
    i32::try_from(metadata.dev())
        .ok()
        .map(|device| FileObjectEvidence {
            device: svalnir_core::file::DeviceNumber::new(device),
            inode: metadata.ino().into(),
        })
}

/// Whether the object at `path`, read with no symbolic link followed, is a
/// directory with the identity `expected`.
fn has_identity(path: &Path, expected: Option<FileObjectEvidence>) -> Result<(), RefusalReason> {
    let metadata: fs::Metadata =
        fs::symlink_metadata(path).map_err(|_| RefusalReason::IdentityChanged)?;
    let found: Option<FileObjectEvidence> = identity_of(&metadata);
    if !metadata.is_dir() || expected.is_none() || found != expected {
        return Err(RefusalReason::IdentityChanged);
    }
    Ok(())
}

/// Refuses a repository whose reflogs of `selection` have an entry that is
/// not a fetch or a clone.
fn reflogs_are_fetches(queries: &Queries<'_>, selection: &str) -> Result<(), RefusalReason> {
    let entries: Vec<u8> = queries.output(&[
        "log",
        "-g",
        "--no-show-signature",
        "--format=x%gs",
        selection,
    ])?;
    // Each entry has the fixed prefix `x`, so an entry with an empty
    // subject, as `git update-ref` with no message writes, is not dropped.
    let is_fetch = |line: &[u8]| line.starts_with(b"xfetch") || line.starts_with(b"xclone");
    if entries
        .split(|byte| *byte == b'\n')
        .filter(|line| line != b"")
        .all(is_fetch)
    {
        Ok(())
    } else {
        Err(RefusalReason::ReflogNotFetch)
    }
}

/// Accepts the mirror with the Git directory `git_dir` and gives its tags,
/// or gives the reason that Swift Package Manager cannot make it again
/// from `pins`. The module documentation lists the conditions. `expected`
/// is the identity of the Git directory that the walk measured.
///
/// # Errors
///
/// Returns the reason of the first condition that is not true, or
/// [`RefusalReason::GitFailed`] when a query fails.
pub fn check_mirror(
    git: &GitTool,
    git_dir: &Path,
    pins: Option<&[Pin]>,
    expected: Option<FileObjectEvidence>,
) -> Result<Vec<(String, String)>, RefusalReason> {
    has_identity(git_dir, expected)?;
    let queries: Queries<'_> = Queries {
        git,
        git_dir: git_dir.to_path_buf(),
        work_tree: None,
    };
    if queries.output(&["rev-parse", "--is-bare-repository"])? != b"true\n" {
        return Err(RefusalReason::NotMirror);
    }
    let Some(origin) = queries.origin_url()? else {
        return Err(RefusalReason::NotMirror);
    };
    // The pin-less mode has no pin: the origin must be a remote URL, so a
    // mirror of a local path is not a copy that a remote restores.
    match pins {
        Some(pins) => {
            if !pins.iter().any(|pin| same_location(&origin, &pin.location)) {
                return Err(RefusalReason::LocationNotPinned);
            }
        }
        None => {
            if !is_remote_url(&origin) {
                return Err(RefusalReason::LocationNotPinned);
            }
        }
    }
    // Swift Package Manager writes `mirror = true` in the remote of each
    // mirror that it makes.
    let mirror_flag: GitOutput = queries.run(&[
        OsStr::new("config"),
        OsStr::new("--type=bool"),
        OsStr::new("--get"),
        OsStr::new("remote.origin.mirror"),
    ])?;
    if mirror_flag.code != 0 || mirror_flag.stdout != b"true\n" {
        return Err(RefusalReason::NotMirror);
    }
    // A linked worktree of a mirror has its own work tree and commits.
    match fs::symlink_metadata(git_dir.join("worktrees")) {
        Ok(_) => return Err(RefusalReason::LinkedWorktrees),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(RefusalReason::GitFailed),
    }
    // A Git directory below the mirror is not a part of it: the executor
    // refuses it, so the check refuses it here.
    if has_modules(git_dir)? {
        return Err(RefusalReason::NestedRepository);
    }
    if !queries
        .output(&["rev-list", "-n", "1", "--reflog", "--not", "--all"])?
        .is_empty()
    {
        return Err(RefusalReason::LocalCommits);
    }
    reflogs_are_fetches(&queries, "--all")?;
    let tags: Vec<(String, String)> = queries.tags()?;
    // The queries ran after the first identity check. The Git directory
    // must still be the measured object.
    has_identity(git_dir, expected)?;
    Ok(tags)
}

/// Whether the Git directory `git_dir` has a `modules` entry, where Git
/// keeps the Git directories of submodules. Submodules are not admitted.
fn has_modules(git_dir: &Path) -> Result<bool, RefusalReason> {
    match fs::symlink_metadata(git_dir.join("modules")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(RefusalReason::GitFailed),
    }
}

/// The tags of the mirror at the remote `url` of a checkout, when `url`
/// names a directory directly in the `repositories` directory of
/// `checkouts` and [`check_mirror`] accepts it for `pin`. `None` when
/// `url` names no such directory.
fn mirror_of_origin(
    git: &GitTool,
    url: &str,
    pin: Option<&Pin>,
    checkouts: &SwiftPmCheckouts,
) -> Result<Option<Vec<(String, String)>>, RefusalReason> {
    if !url.starts_with('/') {
        return Ok(None);
    }
    let (Ok(mirror), Some(Ok(repositories))) = (
        fs::canonicalize(url),
        checkouts.repositories().map(fs::canonicalize),
    ) else {
        return Ok(None);
    };
    if mirror.parent() != Some(repositories.as_path()) {
        return Ok(None);
    }
    // The path has no symbolic link after `canonicalize`, so its identity
    // now is the identity that the checks examine.
    let metadata: fs::Metadata =
        fs::symlink_metadata(&mirror).map_err(|_| RefusalReason::IdentityChanged)?;
    let expected: Option<FileObjectEvidence> = identity_of(&metadata);
    match check_mirror(git, &mirror, pin.map(std::slice::from_ref), expected) {
        Ok(tags) => Ok(Some(tags)),
        Err(RefusalReason::NotMirror | RefusalReason::LocationNotPinned) => Ok(None),
        Err(reason) => Err(reason),
    }
}

/// Whether the work tree has a file that its `HEAD` does not restore: a
/// changed, untracked, or ignored file, or a file with a flag that hides
/// its changes from `git status`.
fn has_changes(queries: &Queries<'_>) -> Result<bool, RefusalReason> {
    // Each option that would hide a change is set, so the configuration of
    // the repository cannot change it.
    let status: Vec<u8> = queries.output(&[
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=all",
    ])?;
    if !status.is_empty() {
        return Ok(true);
    }
    let files: Vec<u8> = queries.output(&["ls-files", "-v", "-z"])?;
    // `S` is `skip-worktree`, and a lower-case tag is `assume-unchanged`.
    Ok(files
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.first())
        .any(|tag| *tag == b'S' || tag.is_ascii_lowercase()))
}

/// Whether the configuration value `value` of a Boolean key is false, as
/// Git reads it.
fn is_false(value: &[u8]) -> bool {
    let value: String = String::from_utf8_lossy(value.trim_ascii()).to_ascii_lowercase();
    matches!(value.as_str(), "" | "false" | "no" | "off" | "0")
}

/// Accepts the checkout at `work_tree` with the name `name`, or gives the
/// reason that Swift Package Manager cannot make it again from `pins`. The
/// module documentation lists the conditions. `expected` is the identity of
/// the `.git` directory that the walk measured.
///
/// # Errors
///
/// Returns the reason of the first condition that is not true, or
/// [`RefusalReason::GitFailed`] when a query fails.
pub fn check_checkout(
    git: &GitTool,
    work_tree: &Path,
    name: &str,
    pins: Option<&[Pin]>,
    checkouts: &SwiftPmCheckouts,
    expected: Option<FileObjectEvidence>,
) -> Result<(), RefusalReason> {
    let git_dir: PathBuf = work_tree.join(super::GIT_MARKER);
    // The queries name the Git directory by its path. The path must still
    // name the directory that the walk measured, and not a symbolic link
    // or a replacement.
    has_identity(&git_dir, expected)?;
    let identity: String = name.to_ascii_lowercase();
    // The pin-less mode has no pin: the checks against pins are not made,
    // and the commits must be reachable from the remote instead.
    let pin: Option<&Pin> = match pins {
        Some(pins) => match pins.iter().find(|pin| pin.identity == identity) {
            Some(pin) => Some(pin),
            None => return Err(RefusalReason::NotPinned),
        },
        None => None,
    };
    match fs::symlink_metadata(git_dir.join("worktrees")) {
        Ok(_) => return Err(RefusalReason::LinkedWorktrees),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(RefusalReason::GitFailed),
    }
    // Submodules are out of scope: the executor refuses a Git directory in
    // `.git/modules`, so the check refuses it before the plan.
    if has_modules(&git_dir)? {
        return Err(RefusalReason::NestedRepository);
    }
    let queries: Queries<'_> = Queries {
        git,
        git_dir: git_dir.clone(),
        work_tree: Some(work_tree),
    };
    // A filter driver is a program of the configuration that `git status`
    // runs on a changed file, and no command-line value turns it off. The
    // query reads the configuration and its includes; the system and
    // global files are off in the environment of the query.
    if queries.finds(&["config", "--get-regexp", r"^filter\."])? {
        return Err(RefusalReason::FilterDriver);
    }
    let head: Vec<u8> = queries.output(&["rev-parse", "--verify", "HEAD^{commit}"])?;
    if pin.is_some_and(|pin| head.trim_ascii() != pin.revision.as_bytes()) {
        return Err(RefusalReason::RevisionNotPinned);
    }
    let Some(origin) = queries.origin_url()? else {
        return Err(if pin.is_some() {
            RefusalReason::LocationNotPinned
        } else {
            RefusalReason::OriginMissing
        });
    };
    let mirror_tags: Vec<(String, String)> = match pin {
        Some(pin) if same_location(&origin, &pin.location) => Vec::new(),
        Some(_) => match mirror_of_origin(git, &origin, pin, checkouts)? {
            Some(tags) => tags,
            None => return Err(RefusalReason::LocationNotPinned),
        },
        // The origin is a remote URL, or a mirror that [`check_mirror`]
        // accepts beside the checkout (whose own origin is a remote URL).
        // The mirror, when it is the origin, gives its tags.
        None => match mirror_of_origin(git, &origin, None, checkouts)? {
            Some(tags) => tags,
            None if is_remote_url(&origin) => Vec::new(),
            None => return Err(RefusalReason::OriginMissing),
        },
    };
    if queries.finds(&["rev-parse", "--verify", "--quiet", "refs/stash"])? {
        return Err(RefusalReason::Stash);
    }
    if has_changes(&queries)? {
        return Err(RefusalReason::ChangedWorkTree);
    }
    // Without a reflog, a push from the checkout leaves no record.
    let logged = queries.run(&[
        OsStr::new("config"),
        OsStr::new("--get"),
        OsStr::new("core.logAllRefUpdates"),
    ])?;
    match logged.code {
        0 if is_false(&logged.stdout) => return Err(RefusalReason::ReflogDisabled),
        0 | 1 => {}
        _ => return Err(RefusalReason::GitFailed),
    }
    // A push from the checkout updates a remote-tracking reference with an
    // entry that is not a fetch, and that reference then holds a commit
    // that the location of the pin may not have.
    reflogs_are_fetches(&queries, "--glob=refs/remotes/origin/*")?;
    let mut arguments: Vec<OsString> = [
        "rev-list",
        "-n",
        "1",
        "--all",
        "--reflog",
        "--not",
        "--glob=refs/remotes/origin/*",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    // With a pin, `HEAD` is the revision of the pin, which the pins restore.
    // Without a pin, `HEAD` must be reachable from the remote like each
    // other commit.
    if pin.is_some() {
        arguments.push(OsString::from("HEAD"));
    }
    for (name, object) in queries.tags()? {
        if mirror_tags.contains(&(name, object.clone())) {
            arguments.push(OsString::from(object));
        }
    }
    let arguments: Vec<&OsStr> = arguments.iter().map(OsString::as_os_str).collect();
    let output: GitOutput = queries.run(&arguments)?;
    if output.code != 0 {
        return Err(RefusalReason::GitFailed);
    }
    if !output.stdout.is_empty() {
        return Err(RefusalReason::LocalCommits);
    }
    // The queries ran after the first identity check. The Git directory
    // must still be the measured object.
    has_identity(&git_dir, expected)?;
    Ok(())
}
