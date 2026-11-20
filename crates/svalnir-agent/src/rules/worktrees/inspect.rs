//! The inspection of `git.linked-worktree`.
//!
//! The inspection is read-only. It reads directory entries below the
//! search roots, the records of the linked worktrees of each repository
//! (`.git/worktrees/NAME/gitdir`, `HEAD`, `locked`, and `index`), the
//! metadata of the files of each work tree, and the output of three
//! read-only Git queries of [`crate::rules::git`]. It changes nothing and
//! gives no candidate.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use svalnir_core::policy::ProtectionFact;
use svalnir_core::process::Uid;
use svalnir_core::rule::{LayoutSupport, RuleRef};

use super::WorktreeRule;
use super::index::{compare, parse};
use crate::platform::volume::{MountTable, MountTableSource};
use crate::protection::ProtectedLocations;
use crate::rules::git::{GitFailure, GitOutput, GitTool, GitToolProblem, git_file_target};
use crate::rules::projects::{
    GitAvailability, SearchCompletion, SearchRootOutcome, SearchRootReport, SearchRoots,
    open_search_root,
};
use crate::rules::unit::{ObjectKind, ObjectSnapshot, RecordRead, lstat, read_record, walk_local};
use crate::scan::CancellationToken;

/// The largest record file (`gitdir`, `HEAD`, `.git`), in bytes.
const MAX_RECORD_BYTES: u64 = 4 * 1024;

/// The largest index file, in bytes.
const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;

/// The largest configuration file of a repository, in bytes.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// The host facts of an inspection.
#[derive(Debug, Clone, Copy)]
pub struct WorktreeHost<'a> {
    /// The user. Each directory and each record must have this owner.
    pub principal: Uid,
    /// The home directory and the state directory, resolved.
    pub locations: &'a ProtectedLocations,
    /// The paths of `[protections]` and of the disk guard exclusions.
    pub user_exclusions: &'a [PathBuf],
    /// The Git executable, or why none was accepted.
    pub git: Result<&'a GitTool, GitToolProblem>,
}

/// The bounds of an inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorktreeLimits {
    /// The deepest directory level below a search root that the walk
    /// reads.
    pub max_depth: u32,
    /// The largest number of directories that the walk reads.
    pub max_directories: usize,
    /// The largest number of linked worktrees of one repository.
    pub max_worktrees: usize,
    /// The longest time of the inspection.
    pub max_duration: Duration,
    /// The largest output of the list of the files that Git does not
    /// track, in bytes.
    pub max_untracked_output: usize,
}

impl Default for WorktreeLimits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_directories: 50_000,
            max_worktrees: 256,
            max_duration: Duration::from_secs(120),
            max_untracked_output: 256 * 1024,
        }
    }
}

/// One fact of a worktree, or why it is not known. A fact that is not
/// known is never read as the absence of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Evidence<T> {
    /// The fact.
    Known(T),
    /// The stable name of the cause.
    Unknown(&'static str),
}

/// The files that Git does not track and does not ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UntrackedFiles {
    /// The number of files in the list.
    pub count: u64,
    /// Whether the list was longer than its bound, so that there are more.
    pub more: bool,
}

/// The `HEAD` of a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorktreeHead {
    /// The worktree has a local branch.
    Branch {
        /// The name below `refs/heads/`.
        name: String,
    },
    /// The worktree has no branch.
    Detached {
        /// The commit.
        commit: String,
    },
    /// The record has no `HEAD` in a known form.
    Unknown,
}

/// Whether the directory of a worktree exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreePresence {
    /// The directory exists, and its `.git` file names the record.
    Present,
    /// The directory does not exist. `git worktree prune` removes such a
    /// record.
    Missing,
    /// The directory exists, and its `.git` file is absent or names
    /// another record, or the directory fails a check.
    NotMatching,
}

/// The summary of the evidence of a worktree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeVerdict {
    /// The worktree has work that a removal would lose: changes that no
    /// commit has, files that Git does not track, or commits that no
    /// branch has.
    HasWork,
    /// A fact is not known, so the absence of work is not shown.
    NotKnown,
    /// Each fact is known, and none shows work that a removal would lose.
    NoWorkSeen,
}

/// The report of one linked worktree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorktreeReport {
    /// The name of the record in `.git/worktrees`.
    pub name: String,
    /// The record directory.
    pub record: PathBuf,
    /// The directory of the worktree, when the record names one.
    pub path: Option<PathBuf>,
    /// The `HEAD`.
    pub head: WorktreeHead,
    /// Whether the record has the file `locked`.
    pub locked: bool,
    /// Whether the directory exists.
    pub presence: WorktreePresence,
    /// Whether the index has changes that the commit of `HEAD` does not
    /// have.
    pub staged_changes: Evidence<bool>,
    /// The tracked files whose metadata differs from the index. The
    /// content of such a file can be the same.
    pub changed_files: Evidence<u64>,
    /// The files that Git does not track and does not ignore.
    pub untracked_files: Evidence<UntrackedFiles>,
    /// The commits of `HEAD` that no local branch has.
    pub unique_commits: Evidence<u64>,
    /// The summary.
    pub verdict: WorktreeVerdict,
    /// The owner workflow, as a text for the user. Svalnir does not run
    /// it.
    pub owner_workflow: &'static str,
}

/// The report of one repository with linked worktrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepositoryReport {
    /// The main work tree.
    pub work_tree: PathBuf,
    /// The Git directory.
    pub git_dir: PathBuf,
    /// Why the records were not read, when they were not.
    pub refused: Option<&'static str>,
    /// The linked worktrees, in the sequence of their names.
    pub worktrees: Vec<WorktreeReport>,
    /// Whether the worktree bound stopped the reading.
    pub truncated: bool,
}

/// The inspection of `git.linked-worktree`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorktreeInspection {
    /// The exact rule revision.
    pub rule: RuleRef,
    /// Each layout of the declaration with its lifecycle state.
    pub layouts: Vec<LayoutSupport>,
    /// The Git executable.
    pub git: GitAvailability,
    /// The search roots, in the sequence of the caller.
    pub roots: Vec<SearchRootReport>,
    /// The repositories with linked worktrees, in the sequence of the
    /// walk.
    pub repositories: Vec<RepositoryReport>,
}

const WORKFLOW_WITH_WORK: &str = "Keep the work first: commit or stash the changes in the worktree, add the files that Git does not track or move them out, and give each commit that no branch has a branch (`git branch NAME COMMIT`). Then run `git worktree remove PATH`, after `git worktree unlock PATH` for a locked worktree. Svalnir does not run them.";
const WORKFLOW_NOT_KNOWN: &str = "Run `git -C PATH status` and `git -C PATH log --branches --not` to see the work of the worktree, keep it, then run `git worktree remove PATH`. Svalnir does not run them.";
const WORKFLOW_CLEAN: &str = "Run `git worktree remove PATH`, after `git worktree unlock PATH` for a locked worktree. Git refuses a worktree with changes or with files that it does not track unless `--force` is given. Svalnir does not run it.";
const WORKFLOW_MISSING: &str = "The directory of the worktree is absent. Give a branch to each commit that no branch has, then run `git worktree prune --dry-run` and `git worktree prune` to remove the record. Svalnir does not run them.";

/// The text of a record file, with the line end removed.
fn record_text(path: &Path, principal: Uid) -> Option<String> {
    let RecordRead::Read { bytes, .. } = read_record(path, MAX_RECORD_BYTES, principal) else {
        return None;
    };
    let text: String = String::from_utf8(bytes).ok()?;
    let line: &str = text.strip_suffix('\n').unwrap_or(&text);
    (!line.is_empty() && !line.contains(['\n', '\0'])).then(|| line.to_owned())
}

/// The `HEAD` of the record at `record`.
fn head(record: &Path, principal: Uid) -> WorktreeHead {
    let Some(text) = record_text(&record.join("HEAD"), principal) else {
        return WorktreeHead::Unknown;
    };
    if let Some(name) = text
        .strip_prefix("ref: refs/heads/")
        .filter(|name| !name.is_empty())
    {
        return WorktreeHead::Branch {
            name: name.to_owned(),
        };
    }
    if matches!(text.len(), 40 | 64) && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return WorktreeHead::Detached { commit: text };
    }
    WorktreeHead::Unknown
}

/// The directory of the worktree that the `gitdir` file of `record` names:
/// the parent of the `.git` file that it names.
fn worktree_path(record: &Path, principal: Uid) -> Option<PathBuf> {
    let text: String = record_text(&record.join("gitdir"), principal)?;
    let mut content: Vec<u8> = b"gitdir: ".to_vec();
    content.extend_from_slice(text.as_bytes());
    let dot_git: PathBuf = git_file_target(&content, record)?;
    (dot_git.file_name() == Some(OsStr::new(".git")))
        .then(|| dot_git.parent().map(Path::to_path_buf))
        .flatten()
}

impl WorktreeRule {
    /// Inspects the linked worktrees of the repositories below the search
    /// roots `roots`.
    ///
    /// The function never fails as a whole: each search root, repository,
    /// and worktree has its result.
    pub fn inspect(
        &self,
        host: WorktreeHost<'_>,
        roots: &SearchRoots,
        limits: WorktreeLimits,
        cancel: &CancellationToken,
    ) -> WorktreeInspection {
        self.inspect_with_mounts(host, roots, limits, cancel, MountTable::read)
    }

    /// [`WorktreeRule::inspect`] with another source of the mount table.
    pub(crate) fn inspect_with_mounts(
        &self,
        host: WorktreeHost<'_>,
        roots: &SearchRoots,
        limits: WorktreeLimits,
        cancel: &CancellationToken,
        mounts: MountTableSource,
    ) -> WorktreeInspection {
        let mut inspection: WorktreeInspection = WorktreeInspection {
            rule: self.rule().reference.clone(),
            layouts: self.rule().layouts.clone(),
            git: match host.git {
                Ok(tool) => GitAvailability::Located {
                    executable: tool.executable().to_path_buf(),
                },
                Err(problem) => GitAvailability::NotAvailable { problem },
            },
            roots: Vec::new(),
            repositories: Vec::new(),
        };
        let home: Option<&Path> = host.locations.home_directory();
        let table: Option<MountTable> = mounts().ok();
        let (Some(home), Some(table)) = (home, table) else {
            let reason: &'static str = if home.is_none() {
                "home_unknown"
            } else {
                "root_locality_unknown"
            };
            inspection.roots = roots
                .paths()
                .iter()
                .map(|relative| SearchRootReport {
                    relative: relative.clone(),
                    path: home.map(|home| home.join(relative)),
                    outcome: SearchRootOutcome::Refused(reason),
                    unreadable_directories: 0,
                })
                .collect();
            return inspection;
        };
        let mut walker: Walker<'_> = Walker {
            host,
            limits,
            cancel,
            mounts: table,
            deadline: Instant::now() + limits.max_duration,
            directories: 0,
            repositories: Vec::new(),
        };
        for relative in roots.paths() {
            let path: PathBuf = home.join(relative);
            let mut report: SearchRootReport = SearchRootReport {
                relative: relative.clone(),
                path: Some(path.clone()),
                outcome: SearchRootOutcome::Absent,
                unreadable_directories: 0,
            };
            match open_search_root(
                &path,
                host.locations,
                host.user_exclusions,
                host.principal,
                &walker.mounts,
            ) {
                Ok(snapshot) => {
                    let completion: SearchCompletion = walker.walk(&path, snapshot, &mut report);
                    report.outcome = SearchRootOutcome::Examined(completion);
                }
                Err(outcome) => report.outcome = outcome,
            }
            inspection.roots.push(report);
        }
        inspection.repositories = walker.repositories;
        inspection
    }
}

/// The walk of the search roots.
struct Walker<'a> {
    host: WorktreeHost<'a>,
    limits: WorktreeLimits,
    cancel: &'a CancellationToken,
    mounts: MountTable,
    deadline: Instant,
    directories: usize,
    repositories: Vec<RepositoryReport>,
}

impl Walker<'_> {
    fn stop(&self) -> Option<SearchCompletion> {
        if self.cancel.is_cancelled() {
            Some(SearchCompletion::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(SearchCompletion::DeadlineReached)
        } else if self.directories >= self.limits.max_directories {
            Some(SearchCompletion::DirectoryLimitReached)
        } else {
            None
        }
    }

    /// Reads the directories below `root` breadth first. A directory with
    /// a `.git` directory is a repository; the walk does not enter its
    /// work tree, because its linked worktrees are in its records.
    fn walk(
        &mut self,
        root: &Path,
        snapshot: ObjectSnapshot,
        report: &mut SearchRootReport,
    ) -> SearchCompletion {
        let device = snapshot.object.device;
        let mut queue: VecDeque<(PathBuf, u32)> = VecDeque::from([(root.to_path_buf(), 0)]);
        let mut depth_limited: bool = false;
        while let Some((directory, depth)) = queue.pop_front() {
            if let Some(stop) = self.stop() {
                return stop;
            }
            self.directories += 1;
            let Ok(entries) = fs::read_dir(&directory) else {
                report.unreadable_directories += 1;
                continue;
            };
            let names: BTreeSet<OsString> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect();
            if names.contains(OsStr::new(".git")) {
                let git_dir: PathBuf = directory.join(".git");
                if lstat(&git_dir).is_ok_and(|found| {
                    found.kind == ObjectKind::Directory && found.owner == self.host.principal
                }) && let Some(repository) = self.repository(&directory, &git_dir)
                {
                    self.repositories.push(repository);
                }
                // A `.git` file is a linked worktree or a submodule; its
                // repository has its record.
                continue;
            }
            for name in &names {
                if name == "node_modules" {
                    continue;
                }
                let child: PathBuf = directory.join(name);
                let Ok(found) = lstat(&child) else {
                    continue;
                };
                if found.kind != ObjectKind::Directory
                    || found.object.device != device
                    || found.owner != self.host.principal
                    || self.host.locations.of_text(&child) != ProtectionFact::NotProtected
                    || self
                        .host
                        .user_exclusions
                        .iter()
                        .any(|excluded| child.starts_with(excluded))
                {
                    continue;
                }
                if depth >= self.limits.max_depth {
                    depth_limited = true;
                    continue;
                }
                queue.push_back((child, depth + 1));
            }
        }
        if depth_limited {
            SearchCompletion::DepthLimitReached
        } else {
            SearchCompletion::Complete
        }
    }

    /// The report of the repository at `work_tree`, when it has linked
    /// worktrees.
    fn repository(&self, work_tree: &Path, git_dir: &Path) -> Option<RepositoryReport> {
        let records: PathBuf = git_dir.join("worktrees");
        let found: ObjectSnapshot = lstat(&records).ok()?;
        let mut report: RepositoryReport = RepositoryReport {
            work_tree: work_tree.to_path_buf(),
            git_dir: git_dir.to_path_buf(),
            refused: None,
            worktrees: Vec::new(),
            truncated: false,
        };
        if found.kind != ObjectKind::Directory || found.owner != self.host.principal {
            report.refused = Some("records_not_directory_of_user");
            return Some(report);
        }
        let Ok(entries) = fs::read_dir(&records) else {
            report.refused = Some("records_not_readable");
            return Some(report);
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        report.truncated = names.len() > self.limits.max_worktrees;
        names.truncate(self.limits.max_worktrees);
        // The object format of the repository: this build reads only an
        // index with SHA-1 object names.
        let object_format_known: bool = match read_record(
            &git_dir.join("config"),
            MAX_CONFIG_BYTES,
            self.host.principal,
        ) {
            RecordRead::Read { bytes, .. } => !String::from_utf8_lossy(&bytes)
                .to_ascii_lowercase()
                .contains("objectformat"),
            RecordRead::Absent => true,
            RecordRead::Denied | RecordRead::Invalid => false,
        };
        for name in names {
            let record: PathBuf = records.join(&name);
            if !lstat(&record).is_ok_and(|entry| {
                entry.kind == ObjectKind::Directory && entry.owner == self.host.principal
            }) {
                continue;
            }
            report
                .worktrees
                .push(self.worktree(name, &record, object_format_known));
        }
        Some(report)
    }

    /// The report of the linked worktree with the record `record`.
    fn worktree(&self, name: String, record: &Path, object_format_known: bool) -> WorktreeReport {
        let principal: Uid = self.host.principal;
        let path: Option<PathBuf> = worktree_path(record, principal);
        let presence: WorktreePresence = match &path {
            None => WorktreePresence::NotMatching,
            Some(path) => self.presence(path, record),
        };
        let mut report: WorktreeReport = WorktreeReport {
            head: head(record, principal),
            locked: lstat(&record.join("locked")).is_ok(),
            name,
            record: record.to_path_buf(),
            path: path.clone(),
            presence,
            staged_changes: Evidence::Unknown("work_tree_not_examined"),
            changed_files: Evidence::Unknown("work_tree_not_examined"),
            untracked_files: Evidence::Unknown("work_tree_not_examined"),
            unique_commits: Evidence::Unknown("git_not_available"),
            verdict: WorktreeVerdict::NotKnown,
            owner_workflow: WORKFLOW_NOT_KNOWN,
        };
        if let Ok(git) = self.host.git {
            // The commits need no work tree, so a worktree whose
            // directory is absent has this fact too.
            report.unique_commits = unique_commits(git, record);
            if let (WorktreePresence::Present, Some(path)) = (presence, &path) {
                report.staged_changes = staged_changes(git, record, path);
                report.untracked_files =
                    untracked_files(git, record, path, self.limits.max_untracked_output);
            }
        } else {
            report.staged_changes = Evidence::Unknown("git_not_available");
            report.untracked_files = Evidence::Unknown("git_not_available");
        }
        if let (WorktreePresence::Present, Some(path)) = (presence, &path) {
            report.changed_files = if object_format_known {
                self.changed_files(record, path)
            } else {
                Evidence::Unknown("object_format_not_supported")
            };
        }
        let has_work: bool = report.staged_changes == Evidence::Known(true)
            || matches!(report.changed_files, Evidence::Known(count) if count > 0)
            || matches!(
                report.untracked_files,
                Evidence::Known(UntrackedFiles { count, more }) if count > 0 || more
            )
            || matches!(report.unique_commits, Evidence::Known(count) if count > 0);
        let all_known: bool = !matches!(report.staged_changes, Evidence::Unknown(_))
            && !matches!(report.changed_files, Evidence::Unknown(_))
            && !matches!(report.untracked_files, Evidence::Unknown(_))
            && !matches!(report.unique_commits, Evidence::Unknown(_));
        report.verdict = if has_work {
            WorktreeVerdict::HasWork
        } else if all_known {
            WorktreeVerdict::NoWorkSeen
        } else {
            WorktreeVerdict::NotKnown
        };
        // The files of an absent directory are already gone; its index
        // and its commits are the work that is left.
        report.owner_workflow = match (presence, report.verdict) {
            (WorktreePresence::Missing, _) => WORKFLOW_MISSING,
            (_, WorktreeVerdict::HasWork) => WORKFLOW_WITH_WORK,
            (_, WorktreeVerdict::NoWorkSeen) => WORKFLOW_CLEAN,
            (_, WorktreeVerdict::NotKnown) => WORKFLOW_NOT_KNOWN,
        };
        report
    }

    /// Whether the directory `path` exists and its `.git` file names
    /// `record`.
    fn presence(&self, path: &Path, record: &Path) -> WorktreePresence {
        if self.host.locations.of_text(path) != ProtectionFact::NotProtected {
            return WorktreePresence::NotMatching;
        }
        match walk_local(path, &self.mounts) {
            Err(crate::rules::unit::WalkStop::Absent) => return WorktreePresence::Missing,
            Ok(found)
                if found.kind == ObjectKind::Directory && found.owner == self.host.principal => {}
            _ => return WorktreePresence::NotMatching,
        }
        let RecordRead::Read { bytes, .. } =
            read_record(&path.join(".git"), MAX_RECORD_BYTES, self.host.principal)
        else {
            return WorktreePresence::NotMatching;
        };
        if git_file_target(&bytes, path).as_deref() == Some(record) {
            WorktreePresence::Present
        } else {
            WorktreePresence::NotMatching
        }
    }

    /// The tracked files of the work tree at `path` whose metadata differs
    /// from the index of `record`.
    fn changed_files(&self, record: &Path, path: &Path) -> Evidence<u64> {
        let (bytes, snapshot) =
            match read_record(&record.join("index"), MAX_INDEX_BYTES, self.host.principal) {
                RecordRead::Read { bytes, snapshot } => (bytes, snapshot),
                RecordRead::Absent => return Evidence::Unknown("index_absent"),
                RecordRead::Denied | RecordRead::Invalid => {
                    return Evidence::Unknown("index_not_readable");
                }
            };
        let entries = match parse(&bytes) {
            Ok(entries) => entries,
            Err(reason) => return Evidence::Unknown(reason),
        };
        match compare(
            &entries,
            path,
            snapshot.stamp.modified_seconds,
            self.deadline,
        ) {
            Ok(comparison) => Evidence::Known(comparison.changed),
            Err(reason) => Evidence::Unknown(reason),
        }
    }
}

/// Runs `arguments` for the worktree with the record `record`.
fn query(
    git: &GitTool,
    record: &Path,
    work_tree: Option<&Path>,
    arguments: &[&str],
    max_output: usize,
) -> Result<GitOutput, &'static str> {
    let arguments: Vec<&OsStr> = arguments.iter().map(OsStr::new).collect();
    git.run(record, work_tree, &arguments, max_output)
        .map_err(GitFailure::as_str)
}

/// Whether the index of `record` has changes that the commit of `HEAD`
/// does not have. The comparison reads the index and the objects, not the
/// work tree.
fn staged_changes(git: &GitTool, record: &Path, work_tree: &Path) -> Evidence<bool> {
    match query(
        git,
        record,
        Some(work_tree),
        &["diff-index", "--cached", "--quiet", "HEAD", "--"],
        0,
    ) {
        Ok(output) if output.code == 0 => Evidence::Known(false),
        Ok(output) if output.code == 1 => Evidence::Known(true),
        Ok(_) => Evidence::Unknown("git_query_failed"),
        Err(reason) => Evidence::Unknown(reason),
    }
}

/// The files of the work tree that Git does not track and does not
/// ignore, with the ignore rules of each level of the repository.
fn untracked_files(
    git: &GitTool,
    record: &Path,
    work_tree: &Path,
    max_output: usize,
) -> Evidence<UntrackedFiles> {
    match query(
        git,
        record,
        Some(work_tree),
        &["ls-files", "-z", "--others", "--exclude-standard"],
        max_output,
    ) {
        Ok(output) if output.code == 0 => {
            // Each name ends with a NUL byte; a cut list ends with a part
            // of a name, which counts as one more.
            let count: usize = output.stdout.split_inclusive(|byte| *byte == 0).count();
            Evidence::Known(UntrackedFiles {
                count: u64::try_from(count).unwrap_or(u64::MAX),
                more: output.truncated,
            })
        }
        Ok(_) => Evidence::Unknown("git_query_failed"),
        Err(reason) => Evidence::Unknown(reason),
    }
}

/// The commits of the `HEAD` of `record` that no local branch has.
fn unique_commits(git: &GitTool, record: &Path) -> Evidence<u64> {
    match query(
        git,
        record,
        None,
        &["rev-list", "--count", "HEAD", "--not", "--branches", "--"],
        64,
    ) {
        Ok(output) if output.code == 0 && !output.truncated => {
            match std::str::from_utf8(&output.stdout)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
            {
                Some(count) => Evidence::Known(count),
                None => Evidence::Unknown("git_output_not_valid"),
            }
        }
        Ok(_) => Evidence::Unknown("git_query_failed"),
        Err(reason) => Evidence::Unknown(reason),
    }
}
