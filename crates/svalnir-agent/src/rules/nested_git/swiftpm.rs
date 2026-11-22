//! The exception for the checkouts of Swift Package Manager
//! (`docs/CLEANUP_RULES.md` section 6, "Repositories in a unit").
//!
//! Swift Package Manager keeps a clone of each remote dependency in
//! `checkouts/IDENTITY` of its build directory, and a bare mirror of the
//! same dependency in `repositories/NAME`. `swift package resolve` and
//! `xcodebuild -resolvePackageDependencies` make both again from the pins
//! of `Package.resolved`. A checkout is thus a repository that can be made
//! again only when it holds nothing that the pins do not restore.
//!
//! [`check_checkout`] accepts a checkout only when each of these is true:
//!
//! - A pin of `Package.resolved` has the identity of the checkout: the
//!   name of its directory in lower case.
//! - Its one remote, `origin`, is the location of that pin, or is a mirror
//!   of Swift Package Manager in the `repositories` directory beside `checkouts` whose
//!   one remote is the location of the pin. Two absolute paths must name
//!   the same directory; two URLs must be equal, apart from one trailing
//!   slash.
//! - `HEAD` is the revision of the pin.
//! - The configuration of the repository names no filter driver, so that
//!   `git status` runs no program of the repository.
//! - `git status` reports no changed, untracked, or ignored file, and no
//!   file has the `assume-unchanged` or the `skip-worktree` flag.
//! - It has no stash and no linked worktree.
//! - Each commit of its references and reflogs is reachable from a
//!   remote-tracking reference of `origin`, from `HEAD`, or from a tag that
//!   the mirror has with the same object, and no reflog of a
//!   remote-tracking reference records a push.
//!
//! Each Git query is a read-only command of [`GitTool`], with its fixed
//! environment and arguments.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
    resolved: PathBuf,
}

impl SwiftPmCheckouts {
    /// The checkouts directory `checkouts` and the pin file `resolved`.
    #[must_use]
    pub const fn new(checkouts: PathBuf, resolved: PathBuf) -> Self {
        Self {
            checkouts,
            resolved,
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

    /// The pin file.
    #[must_use]
    pub fn resolved(&self) -> &Path {
        &self.resolved
    }

    /// The name of the checkout at `work_tree` when it is a work tree with
    /// a `.git` directory directly in the checkouts directory.
    pub(super) fn checkout_name(&self, work_tree: &Path, marker: MarkerKind) -> Option<String> {
        if marker != MarkerKind::Directory || work_tree.parent() != Some(self.checkouts.as_path()) {
            return None;
        }
        work_tree.file_name()?.to_str().map(str::to_owned)
    }

    /// The directory of the mirrors beside the checkouts directory.
    fn repositories(&self) -> Option<PathBuf> {
        self.checkouts
            .parent()
            .map(|parent| parent.join("repositories"))
    }
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

/// The tags of the mirror at `url` when it is a mirror of Swift Package Manager of the
/// location of `pin`: a bare repository directly in the `repositories`
/// directory of `checkouts`, with one remote, `origin`, that is the
/// location of the pin, and no commit that only its reflogs hold.
fn accepted_mirror(
    git: &GitTool,
    url: &str,
    pin: &Pin,
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
    let queries: Queries<'_> = Queries {
        git,
        git_dir: mirror,
        work_tree: None,
    };
    if queries.output(&["rev-parse", "--is-bare-repository"])? != b"true\n" {
        return Ok(None);
    }
    let Some(origin) = queries.origin_url()? else {
        return Ok(None);
    };
    if !same_location(&origin, &pin.location) {
        return Ok(None);
    }
    if !queries
        .output(&["rev-list", "-n", "1", "--reflog", "--not", "--all"])?
        .is_empty()
    {
        return Ok(None);
    }
    queries.tags().map(Some)
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

/// Accepts the checkout at `work_tree` with the name `name`, or gives the
/// reason that Swift Package Manager cannot make it again from `pins`. The module
/// documentation lists the conditions.
///
/// # Errors
///
/// Returns the reason of the first condition that is not true, or
/// [`RefusalReason::GitFailed`] when a query fails.
pub fn check_checkout(
    git: &GitTool,
    work_tree: &Path,
    name: &str,
    pins: &[Pin],
    checkouts: &SwiftPmCheckouts,
) -> Result<(), RefusalReason> {
    let identity: String = name.to_ascii_lowercase();
    let Some(pin) = pins.iter().find(|pin| pin.identity == identity) else {
        return Err(RefusalReason::NotPinned);
    };
    let git_dir: PathBuf = work_tree.join(super::GIT_MARKER);
    match fs::symlink_metadata(git_dir.join("worktrees")) {
        Ok(_) => return Err(RefusalReason::LinkedWorktrees),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(RefusalReason::GitFailed),
    }
    let queries: Queries<'_> = Queries {
        git,
        git_dir,
        work_tree: Some(work_tree),
    };
    // A filter driver is a program of the configuration that `git status`
    // runs on a changed file. The query reads the configuration and its
    // includes; the system and global files are off in the environment of
    // the query.
    if queries.finds(&["config", "--get-regexp", r"^filter\."])? {
        return Err(RefusalReason::FilterDriver);
    }
    let head: Vec<u8> = queries.output(&["rev-parse", "--verify", "HEAD^{commit}"])?;
    if head.trim_ascii() != pin.revision.as_bytes() {
        return Err(RefusalReason::RevisionNotPinned);
    }
    let Some(origin) = queries.origin_url()? else {
        return Err(RefusalReason::LocationNotPinned);
    };
    let mirror_tags: Vec<(String, String)> = if same_location(&origin, &pin.location) {
        Vec::new()
    } else {
        match accepted_mirror(git, &origin, pin, checkouts)? {
            Some(tags) => tags,
            None => return Err(RefusalReason::LocationNotPinned),
        }
    };
    if queries.finds(&["rev-parse", "--verify", "--quiet", "refs/stash"])? {
        return Err(RefusalReason::Stash);
    }
    if has_changes(&queries)? {
        return Err(RefusalReason::ChangedWorkTree);
    }
    // A push from the checkout updates a remote-tracking reference, which
    // then holds a commit that the location of the pin may not have.
    let pushes: Vec<u8> =
        queries.output(&["log", "-g", "--format=%gs", "--glob=refs/remotes/origin/*"])?;
    if pushes
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"update by push"))
    {
        return Err(RefusalReason::LocalCommits);
    }
    let mut arguments: Vec<OsString> = [
        "rev-list",
        "-n",
        "1",
        "--all",
        "--reflog",
        "--not",
        "--glob=refs/remotes/origin/*",
        "HEAD",
    ]
    .iter()
    .map(OsString::from)
    .collect();
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
    Ok(())
}
