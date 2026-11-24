//! The project activity of `docs/CLEANUP_RULES.md` section 6 ("Project
//! activity"): when a person or a coding agent last worked in a project,
//! and whether the project is quiet, active, or busy.
//!
//! # Sources
//!
//! Three sources give the evidence, each behind a small trait, so a test
//! can give its own evidence:
//!
//! - [`HeadActivity`]: the newest modification time of the reflog of `HEAD`
//!   and of `HEAD`, which `git rev-parse --git-path` names. Neither file is a
//!   failure, not an absence of evidence. The native source
//!   ([`GitHeadActivity`]) runs the query through the constrained runner of
//!   [`crate::rules::git`], so it runs no program from the configuration of
//!   the repository.
//! - [`TranscriptActivity`]: the newest modification time of a Claude Code
//!   transcript of the project. The native source ([`ClaudeTranscripts`])
//!   reads only the names and the metadata of directory entries below
//!   `~/.claude/projects` and below `projects` of each configured
//!   `claude_config_dirs` folder; it never opens a transcript.
//! - [`AgentStatus`]: the Paseo agents that run. The native source
//!   ([`PaseoAgents`]) is off unless the configuration turns it on. When it
//!   is on, it runs `paseo` only from the path of the configuration or from
//!   a fixed path, after the checks of the owner-operation executables (see
//!   [`PaseoAgents`]), with fixed arguments, a constrained environment, a
//!   deadline, and an output bound.
//!
//! # States
//!
//! [`assess`] gives one [`ProjectRecency`]. A project is `busy` when the
//! Paseo source is on and lists a running agent in it, or fails. It is
//! `quiet` only when the newest time is known, each source gave a result,
//! and the newest time is at least the quiet period old. Each other case is
//! `active`: an unknown last activity is never quiet.

use std::cell::OnceCell;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Serialize;
use svalnir_core::config::{ConfigPath, ProjectCleanup};
use svalnir_core::process::Uid;
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::Fact;
use svalnir_core::time::WallTime;

use crate::executor::owner::{
    ExecutableKind, ExecutableProblem, ensure_trusted_directories, trusted_kind,
};
use crate::rules::git::{GitFailure, GitOutput, GitTool, GitToolProblem, Repository, run_bounded};

/// The largest output of the Git query, in bytes.
const MAX_GIT_OUTPUT: usize = 4 * 1024;

/// The largest number of entries of `~/.claude/projects` that the
/// transcript source reads.
pub const MAX_TRANSCRIPT_FOLDERS: usize = 10_000;

/// The largest number of directory entries that the transcript source
/// reads for one project, in all its folders.
pub const MAX_TRANSCRIPT_ENTRIES: usize = 20_000;

/// The deepest subfolder of a transcript folder that the source reads.
const TRANSCRIPT_DEPTH: u32 = 2;

/// The paths of the executables that [`PaseoAgents`] examines when the
/// configuration names none. Each one must pass the trust rule of
/// [`PaseoAgents`].
pub const PASEO_CANDIDATES: [&str; 2] = ["/usr/local/bin/paseo", "/opt/homebrew/bin/paseo"];

/// The fixed arguments of the Paseo listing.
pub const PASEO_ARGUMENTS: [&str; 4] = ["ls", "--json", "--global", "--background"];

/// The deadline of the Paseo listing.
pub const PASEO_DEADLINE: Duration = Duration::from_secs(15);

/// The largest output of the Paseo listing, in bytes.
pub const MAX_PASEO_OUTPUT: usize = 1024 * 1024;

/// A source of the project activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivitySource {
    /// The reflog of `HEAD`, or `HEAD`.
    GitHead,
    /// The Claude Code transcripts of the project.
    ClaudeCodeTranscripts,
    /// The Paseo agents.
    PaseoAgents,
}

/// The result of one source of the last activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceReading {
    /// The source gives this time.
    Observed {
        /// The newest time of the source.
        at: WallTime,
    },
    /// The source ran and has no evidence for the project.
    NoEvidence,
    /// The source failed. The reason is a stable name.
    Failed {
        /// The reason.
        reason: &'static str,
    },
}

/// The Paseo listing of one inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentListing {
    /// The source is off.
    Off,
    /// The working directories of the agents that are `running` or
    /// `initializing`.
    Listed {
        /// Each absolute working directory, as Paseo gives it and, when it
        /// resolves, also resolved.
        busy: Vec<PathBuf>,
    },
    /// The listing failed. Each project is then busy.
    Failed {
        /// The stable name of the cause.
        reason: &'static str,
    },
}

/// The evidence of the reflog of `HEAD` for one repository.
pub trait HeadActivity {
    /// The newest modification time of the reflog of `HEAD` and of `HEAD`.
    fn head_activity(&self, repository: &Repository) -> SourceReading;
}

/// The evidence of the Claude Code transcripts for one project root.
pub trait TranscriptActivity {
    /// The newest modification time of a transcript of `root` or of a
    /// directory below it.
    fn transcript_activity(&self, root: &Path) -> SourceReading;
}

/// The evidence of the Paseo agents.
pub trait AgentStatus {
    /// The listing of the agents.
    fn agent_listing(&self) -> AgentListing;
}

/// The sources and the quiet period of an assessment.
#[derive(Clone, Copy)]
#[expect(
    missing_debug_implementations,
    reason = "the sources are trait objects with no `Debug` bound"
)]
pub struct RecencyHost<'a> {
    /// The time with no activity after which a project is quiet.
    pub quiet_period: Nanoseconds,
    /// The Git source.
    pub head: &'a dyn HeadActivity,
    /// The transcript source.
    pub transcripts: &'a dyn TranscriptActivity,
    /// The Paseo source.
    pub agents: &'a dyn AgentStatus,
}

/// The quiet period of the settings `settings`, as nanoseconds. The
/// validation bounds it to 90 days, so it always fits.
#[must_use]
pub fn quiet_period(settings: &ProjectCleanup) -> Nanoseconds {
    Nanoseconds::try_from(settings.quiet_period).unwrap_or(Nanoseconds::MAX)
}

/// The state of a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecencyState {
    /// Nobody worked in the project for the quiet period.
    Quiet,
    /// Somebody worked in the project in the quiet period, or the last
    /// activity is not known.
    Active,
    /// A Paseo agent runs in the project, or the Paseo listing failed. The
    /// project is never a candidate.
    Busy,
}

/// The Paseo evidence for one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentReading {
    /// The source is off.
    Off,
    /// No running or starting agent works in the project.
    NotBusy,
    /// A running or starting agent works in the project.
    Busy,
    /// The listing failed.
    Failed {
        /// The stable name of the cause.
        reason: &'static str,
    },
}

/// The project activity of one project root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectRecency {
    /// The project root: the top directory of the work tree.
    pub root: PathBuf,
    /// The state.
    pub state: RecencyState,
    /// Why the project has this state, as a stable name.
    pub reason: &'static str,
    /// The newest time of the sources, when one gave a time.
    pub last_activity: Option<WallTime>,
    /// The source of that time.
    pub source: Option<ActivitySource>,
    /// The Git source.
    pub git: SourceReading,
    /// The transcript source.
    pub transcripts: SourceReading,
    /// The Paseo source.
    pub agents: AgentReading,
    /// The quiet period of the assessment.
    pub quiet_period: Nanoseconds,
}

impl ProjectRecency {
    /// The value of the project activity for predicate 5 of
    /// `docs/CLEANUP_RULES.md` section 6: `satisfied` only for a quiet
    /// project, `not_satisfied` for a busy project or for a project with a
    /// known recent activity, and `unknown` for each other case.
    #[must_use]
    pub fn fact(&self) -> Fact {
        match (self.state, self.reason) {
            (RecencyState::Quiet, _) => Fact::Satisfied,
            (RecencyState::Busy, _) | (RecencyState::Active, REASON_RECENT) => Fact::NotSatisfied,
            (RecencyState::Active, _) => Fact::Unknown,
        }
    }
}

const REASON_RECENT: &str = "recent_activity";

/// The time `time` in nanoseconds since the Unix epoch.
fn nanos(time: WallTime) -> i128 {
    i128::from(time.unix_seconds()) * 1_000_000_000 + i128::from(time.subsecond_nanoseconds())
}

/// The Paseo evidence for `root` from `listing`.
fn agent_reading(listing: &AgentListing, root: &Path) -> AgentReading {
    match listing {
        AgentListing::Off => AgentReading::Off,
        AgentListing::Failed { reason } => AgentReading::Failed { reason },
        AgentListing::Listed { busy } => {
            if has_busy_agent_in(busy, root) {
                AgentReading::Busy
            } else {
                AgentReading::NotBusy
            }
        }
    }
}

/// Whether a working directory of `busy` is `root` or below it. `root` is
/// also compared in its resolved form.
pub(super) fn has_busy_agent_in(busy: &[PathBuf], root: &Path) -> bool {
    let resolved: Option<PathBuf> = fs::canonicalize(root).ok();
    let roots: Vec<&Path> = std::iter::once(root).chain(resolved.as_deref()).collect();
    busy.iter()
        .any(|directory| roots.iter().any(|root| is_at_or_below(directory, root)))
}

/// Whether `path` is `root` or below it, by component, with the case of
/// ASCII letters ignored, as on the default volume. A difference of case
/// thus gives a busy project and not a miss.
pub(super) fn is_at_or_below(path: &Path, root: &Path) -> bool {
    let mut path = path.components();
    root.components().all(|component| {
        path.next().is_some_and(|other| {
            other
                .as_os_str()
                .as_bytes()
                .eq_ignore_ascii_case(component.as_os_str().as_bytes())
        })
    })
}

/// The project activity of `repository` at the wall-clock time `now`, with
/// the Paseo listing `listing` of the caller.
#[must_use]
pub fn assess(
    host: &RecencyHost<'_>,
    listing: &AgentListing,
    repository: &Repository,
    now: Option<WallTime>,
) -> ProjectRecency {
    let git: SourceReading = host.head.head_activity(repository);
    assess_with_head(host, listing, repository, git, now)
}

/// [`assess`] with the reading `git` of the Git source, which the caller
/// read, for example from a cache of one inspection.
#[must_use]
pub fn assess_with_head(
    host: &RecencyHost<'_>,
    listing: &AgentListing,
    repository: &Repository,
    git: SourceReading,
    now: Option<WallTime>,
) -> ProjectRecency {
    let root: &Path = &repository.work_tree;
    let transcripts: SourceReading = host.transcripts.transcript_activity(root);
    let agents: AgentReading = agent_reading(listing, root);
    let newest: Option<(WallTime, ActivitySource)> = [
        (git, ActivitySource::GitHead),
        (transcripts, ActivitySource::ClaudeCodeTranscripts),
    ]
    .into_iter()
    .filter_map(|(reading, source)| match reading {
        SourceReading::Observed { at } => Some((at, source)),
        SourceReading::NoEvidence | SourceReading::Failed { .. } => None,
    })
    .max_by_key(|(at, _)| *at);
    let failed: bool = [git, transcripts]
        .iter()
        .any(|reading| matches!(reading, SourceReading::Failed { .. }));
    let (state, reason): (RecencyState, &'static str) = match (agents, newest, now) {
        (AgentReading::Busy, _, _) => (RecencyState::Busy, "agent_running"),
        // The reason of the failure, so that each report shows why each
        // project is busy.
        (AgentReading::Failed { reason }, _, _) => (RecencyState::Busy, reason),
        (_, _, None) => (RecencyState::Active, "clock_unknown"),
        (_, Some((at, _)), Some(now))
            if nanos(now) - nanos(at) < i128::from(host.quiet_period.get()) =>
        {
            // A time after `now` is also recent.
            (RecencyState::Active, REASON_RECENT)
        }
        _ if failed => (RecencyState::Active, "activity_source_failed"),
        (_, None, _) => (RecencyState::Active, "no_activity_evidence"),
        (_, Some(_), Some(_)) => (RecencyState::Quiet, "quiet_period_passed"),
    };
    ProjectRecency {
        root: root.to_path_buf(),
        state,
        reason,
        last_activity: newest.map(|(at, _)| at),
        source: newest.map(|(_, source)| source),
        git,
        transcripts,
        agents,
        quiet_period: host.quiet_period,
    }
}

/// The modification time of the object at `path`, with no resolution of a
/// symbolic link at its end. `None` when the object does not exist.
///
/// # Errors
///
/// Returns the error of the call or of a time that does not convert.
fn modified(path: &Path) -> io::Result<Option<WallTime>> {
    let metadata: fs::Metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let time = metadata.modified()?;
    WallTime::try_from(time)
        .map(Some)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

/// The Git source: `git rev-parse --git-path logs/HEAD --git-path HEAD`
/// through the verified Git executable.
#[derive(Debug, Clone, Copy)]
pub struct GitHeadActivity<'a> {
    git: Result<&'a GitTool, GitToolProblem>,
}

impl<'a> GitHeadActivity<'a> {
    /// The source with the Git executable `git`, or why none was accepted.
    #[must_use]
    pub const fn new(git: Result<&'a GitTool, GitToolProblem>) -> Self {
        Self { git }
    }
}

impl HeadActivity for GitHeadActivity<'_> {
    fn head_activity(&self, repository: &Repository) -> SourceReading {
        let failed = |reason: &'static str| SourceReading::Failed { reason };
        let Ok(git) = self.git else {
            return failed("git_not_available");
        };
        let output: GitOutput = match git.run(
            &repository.git_dir,
            Some(&repository.work_tree),
            &[
                OsStr::new("rev-parse"),
                OsStr::new("--git-path"),
                OsStr::new("logs/HEAD"),
                OsStr::new("--git-path"),
                OsStr::new("HEAD"),
            ],
            MAX_GIT_OUTPUT,
        ) {
            Ok(output) => output,
            Err(failure) => return failed(failure.as_str()),
        };
        if output.code != 0 || output.truncated {
            return failed("git_query_failed");
        }
        let lines: Vec<&[u8]> = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        // One path for each `--git-path`, in the sequence of the arguments.
        if lines.len() != 2 {
            return failed("git_output_not_supported");
        }
        let paths: Vec<PathBuf> = lines
            .into_iter()
            .map(|line| {
                let named: &Path = Path::new(OsStr::from_bytes(line));
                if named.is_absolute() {
                    named.to_path_buf()
                } else {
                    repository.work_tree.join(named)
                }
            })
            .collect();
        head_reading(&paths)
    }
}

/// The newest modification time of the files `paths`. A file that does not
/// exist is skipped; when none exists, the reading fails with
/// `git_head_missing`, because a repository with no `HEAD` gives no
/// evidence of quiet.
pub(super) fn head_reading(paths: &[PathBuf]) -> SourceReading {
    let mut newest: Option<WallTime> = None;
    for path in paths {
        match modified(path) {
            Ok(time) => newest = newest.max(time),
            Err(_) => {
                return SourceReading::Failed {
                    reason: "git_head_not_readable",
                };
            }
        }
    }
    newest.map_or(
        SourceReading::Failed {
            reason: "git_head_missing",
        },
        |at| SourceReading::Observed { at },
    )
}

/// The longest folder name that Claude Code keeps, in UTF-16 code units.
/// Claude Code 2.1.330 cuts a longer encoded name to this length and adds
/// `-` and a hash of the path.
pub const MAX_FOLDER_UNITS: usize = 200;

/// The encoded name of `text` that Claude Code gives its folder: each
/// UTF-16 code unit that is not an ASCII letter or digit is `-`, so a
/// character outside the Basic Multilingual Plane gives `--`.
fn encode_text(text: &str) -> String {
    let mut encoded: String = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            encoded.push(character);
        } else {
            for _ in 0..character.len_utf16() {
                encoded.push('-');
            }
        }
    }
    encoded
}

/// The encoded name of the directory `path` that Claude Code gives its
/// folder, before Claude Code cuts a long name. The result is ASCII, so
/// each byte is one UTF-16 code unit.
#[must_use]
pub fn encode_folder(path: &Path) -> String {
    encode_text(&path.to_string_lossy())
}

/// The Unicode NFC and NFD forms of `text`, when the platform gives them.
#[cfg(target_os = "macos")]
fn normal_forms(text: &str) -> [Option<String>; 2] {
    use objc2_foundation::NSString;
    objc2::rc::autoreleasepool(|_| {
        let string = NSString::from_str(text);
        [
            Some(string.precomposedStringWithCanonicalMapping().to_string()),
            Some(string.decomposedStringWithCanonicalMapping().to_string()),
        ]
    })
}

/// The Unicode NFC and NFD forms of `text`, when the platform gives them.
#[cfg(not(target_os = "macos"))]
fn normal_forms(_text: &str) -> [Option<String>; 2] {
    [None, None]
}

/// The encoded keys of the root `root`: of the path as the walk found it
/// and of its resolved form, each also in its NFC and NFD forms when they
/// differ. More keys can only match more folders.
pub(super) fn folder_keys(root: &Path) -> Vec<String> {
    let mut paths: Vec<PathBuf> = vec![root.to_path_buf()];
    if let Ok(resolved) = fs::canonicalize(root)
        && resolved != root
    {
        paths.push(resolved);
    }
    let mut keys: Vec<String> = Vec::new();
    for path in &paths {
        let text: String = path.to_string_lossy().into_owned();
        let [nfc, nfd] = normal_forms(&text);
        for form in [Some(text), nfc, nfd].into_iter().flatten() {
            let key: String = encode_text(&form);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

/// Whether the folder `name` is of the encoded root `key` or of a directory
/// below it. A key that is longer than [`MAX_FOLDER_UNITS`] is cut to that
/// length, so a folder that Claude Code cut matches. The case of ASCII
/// letters is ignored. Each of these rules can only match more folders.
pub(super) fn matches_folder(name: &[u8], key: &[u8]) -> bool {
    let key: &[u8] = &key[..key.len().min(MAX_FOLDER_UNITS)];
    name.len() >= key.len()
        && name[..key.len()].eq_ignore_ascii_case(key)
        && (name.len() == key.len() || name[key.len()] == b'-')
}

/// The transcript source: `~/.claude/projects` of the home directory and the
/// `projects` directory of each configured Claude Code configuration folder
/// (`[cleanup.projects].claude_config_dirs`). The source reads no environment
/// variable.
#[derive(Debug)]
pub struct ClaudeTranscripts {
    /// The `projects` directories, with no one twice. `None` with no home
    /// directory.
    projects: Option<Vec<PathBuf>>,
    /// The folders, each with the index of its `projects` directory, read on
    /// the first use.
    folders: OnceCell<Result<Vec<(usize, OsString)>, &'static str>>,
}

impl ClaudeTranscripts {
    /// The source for the home directory `home`. With no home directory,
    /// each read fails.
    #[must_use]
    pub fn for_home(home: Option<&Path>) -> Self {
        Self {
            projects: home.map(|home| vec![home.join(".claude/projects")]),
            folders: OnceCell::new(),
        }
    }

    /// The source that also reads the configuration folders `dirs`. A folder
    /// that gives a `projects` directory that the source has already is
    /// left out, so that no directory is read twice.
    #[must_use]
    pub fn with_config_dirs(mut self, dirs: &[ConfigPath]) -> Self {
        if let Some(projects) = &mut self.projects {
            for dir in dirs {
                let Ok(expanded) = dir.expand(Path::new("/")) else {
                    continue;
                };
                let candidate: PathBuf = expanded.join("projects");
                let known: bool = projects.iter().any(|known| {
                    known
                        .as_os_str()
                        .as_bytes()
                        .eq_ignore_ascii_case(candidate.as_os_str().as_bytes())
                });
                if !known {
                    projects.push(candidate);
                }
            }
        }
        self
    }

    /// The number of `projects` directories.
    #[cfg(test)]
    pub(crate) fn directory_count(&self) -> usize {
        self.projects.as_ref().map_or(0, Vec::len)
    }

    /// The folders of each `projects` directory. A directory that does not
    /// exist has none.
    fn folders(&self) -> &Result<Vec<(usize, OsString)>, &'static str> {
        self.folders.get_or_init(|| {
            let Some(directories) = &self.projects else {
                return Err("home_unknown");
            };
            let mut names: Vec<(usize, OsString)> = Vec::new();
            for (index, projects) in directories.iter().enumerate() {
                match fs::symlink_metadata(projects) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(_) => return Err("transcripts_not_readable"),
                    Ok(metadata) if !metadata.file_type().is_dir() => {
                        return Err("transcripts_not_readable");
                    }
                    Ok(_) => {}
                }
                let entries = fs::read_dir(projects).map_err(|_| "transcripts_not_readable")?;
                for (count, entry) in entries.enumerate() {
                    if count >= MAX_TRANSCRIPT_FOLDERS {
                        return Err("transcripts_bound_reached");
                    }
                    let entry = entry.map_err(|_| "transcripts_not_readable")?;
                    names.push((index, entry.file_name()));
                }
            }
            Ok(names)
        })
    }
}

impl TranscriptActivity for ClaudeTranscripts {
    fn transcript_activity(&self, root: &Path) -> SourceReading {
        let failed = |reason: &'static str| SourceReading::Failed { reason };
        let folders: &[(usize, OsString)] = match self.folders() {
            Ok(folders) => folders,
            Err(reason) => return failed(reason),
        };
        let Some(directories) = &self.projects else {
            return failed("home_unknown");
        };
        let keys: Vec<String> = folder_keys(root);
        let mut newest: Option<WallTime> = None;
        let mut budget: usize = MAX_TRANSCRIPT_ENTRIES;
        for (index, name) in folders {
            if !keys
                .iter()
                .any(|key| matches_folder(name.as_bytes(), key.as_bytes()))
            {
                continue;
            }
            match newest_transcript(&directories[*index].join(name), &mut budget) {
                Ok(Some(at)) => newest = newest.max(Some(at)),
                Ok(None) => {}
                Err(reason) => return failed(reason),
            }
        }
        newest.map_or(SourceReading::NoEvidence, |at| SourceReading::Observed {
            at,
        })
    }
}

/// The newest modification time of a `.jsonl` file in the folder `folder`
/// and its subfolders to [`TRANSCRIPT_DEPTH`]. Only names and metadata are
/// read; no symbolic link is followed. Each entry spends one unit of
/// `budget`.
///
/// # Errors
///
/// Returns a stable reason when a folder cannot be read or the budget is
/// spent.
pub(super) fn newest_transcript(
    folder: &Path,
    budget: &mut usize,
) -> Result<Option<WallTime>, &'static str> {
    let mut newest: Option<WallTime> = None;
    let mut queue: Vec<(PathBuf, u32)> = vec![(folder.to_path_buf(), 0)];
    while let Some((directory, depth)) = queue.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            // A folder that is not a directory, or that is gone, has no
            // transcript.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(_) => return Err("transcripts_not_readable"),
        };
        for entry in entries {
            *budget = budget.checked_sub(1).ok_or("transcripts_bound_reached")?;
            let entry = entry.map_err(|_| "transcripts_not_readable")?;
            let path: PathBuf = entry.path();
            let metadata: fs::Metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err("transcripts_not_readable"),
            };
            if metadata.file_type().is_dir() {
                if depth < TRANSCRIPT_DEPTH {
                    queue.push((path, depth + 1));
                }
                continue;
            }
            let is_transcript: bool = metadata.file_type().is_file()
                && Path::new(&entry.file_name())
                    .extension()
                    .is_some_and(|extension| extension == "jsonl");
            if !is_transcript {
                continue;
            }
            let at: WallTime = metadata
                .modified()
                .ok()
                .and_then(|time| WallTime::try_from(time).ok())
                .ok_or("transcripts_not_readable")?;
            newest = newest.max(Some(at));
        }
    }
    Ok(newest)
}

/// The command of the Paseo listing: the program, and the script that the
/// program reads when `paseo` is a `#!` script.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PaseoLaunch {
    /// The resolved program: `paseo`, or its interpreter.
    program: PathBuf,
    /// The resolved script, for the interpreter.
    script: Option<PathBuf>,
    /// The directory of the interpreter, which starts `PATH`.
    interpreter_directory: Option<PathBuf>,
}

/// The Paseo source.
///
/// The executable is the path `paseo_executable` of the configuration, or
/// else the first of [`PASEO_CANDIDATES`] that passes the checks. The folder
/// of the unresolved path and each folder above it must be a folder, not a
/// link, with root or the user as its owner and no write bit for the group
/// or for others; this check comes before the link is resolved and before the
/// interpreter is looked up. The symbolic link of the path is then resolved,
/// and the resolved file must be a regular file with an execute bit, owned by
/// root or by the user, with no write bit for the group or for others, with
/// each folder above it of the same rule. The check reads only metadata and
/// the first bytes of the file; no digest is computed. A Mach-O file runs
/// directly. A `#!` script runs through its interpreter: for
/// `#!/usr/bin/env NAME` the file `NAME` in the folder of the unresolved
/// path (where `npm` puts `node` beside `paseo`), and for an absolute
/// interpreter path that path. The interpreter must be a Mach-O file that
/// passes the same rule.
///
/// The binding at the start is by path only: the check does not hold the
/// file, so the owner rule of the folders above the file and of the link
/// folder is the protection against a replacement between the check and the
/// start. The modules that the interpreter loads (the `node_modules` of
/// Paseo) are not checked.
#[derive(Debug, Clone)]
pub struct PaseoAgents {
    enabled: bool,
    home: Option<PathBuf>,
    candidates: Vec<PathBuf>,
    /// The executable of the configuration, which is the only candidate.
    configured: Option<ConfigPath>,
    principal: Uid,
    deadline: Duration,
    /// An executable that a test gives, with no check.
    #[cfg(test)]
    unchecked: Option<PathBuf>,
}

impl PaseoAgents {
    /// The source with the setting `[cleanup.projects].paseo_agents` and the
    /// home directory `home`.
    #[must_use]
    pub fn new(enabled: bool, home: Option<&Path>) -> Self {
        Self {
            enabled,
            home: home.map(Path::to_path_buf),
            candidates: PASEO_CANDIDATES.iter().map(PathBuf::from).collect(),
            configured: None,
            principal: crate::observe::current_uid(),
            deadline: PASEO_DEADLINE,
            #[cfg(test)]
            unchecked: None,
        }
    }

    /// The source of the settings `settings` for the home directory `home`.
    #[must_use]
    pub fn from_settings(settings: &ProjectCleanup, home: Option<&Path>) -> Self {
        let mut source: Self = Self::new(settings.paseo_agents, home);
        source.configured.clone_from(&settings.paseo_executable);
        source
    }

    /// The source with other paths of the executable.
    #[cfg(test)]
    pub(crate) fn with_candidates(mut self, candidates: Vec<PathBuf>) -> Self {
        self.candidates = candidates;
        self
    }

    /// The source with the executable `configured` of the configuration.
    #[cfg(test)]
    pub(crate) fn with_configured(mut self, configured: ConfigPath) -> Self {
        self.configured = Some(configured);
        self
    }

    /// The source with the executable `executable`, which is not checked,
    /// and the deadline `deadline`.
    #[cfg(test)]
    pub(crate) fn with_unchecked(mut self, executable: PathBuf, deadline: Duration) -> Self {
        self.unchecked = Some(executable);
        self.deadline = deadline;
        self
    }

    /// The command that passes the checks.
    fn launch(&self, home: &Path) -> Result<PaseoLaunch, &'static str> {
        #[cfg(test)]
        if let Some(executable) = &self.unchecked {
            return Ok(PaseoLaunch {
                program: executable.clone(),
                script: None,
                interpreter_directory: None,
            });
        }
        let candidates: Vec<PathBuf> = match &self.configured {
            Some(configured) => vec![configured.expand(home).map_err(|_| "paseo_not_installed")?],
            None => self.candidates.clone(),
        };
        let mut problem: &'static str = "paseo_not_installed";
        for candidate in &candidates {
            match self.check_candidate(candidate) {
                Ok(launch) => return Ok(launch),
                Err("paseo_not_installed") => {}
                Err(reason) => {
                    if problem == "paseo_not_installed" {
                        problem = reason;
                    }
                }
            }
        }
        Err(problem)
    }

    /// Resolves and checks the executable at `candidate`.
    fn check_candidate(&self, candidate: &Path) -> Result<PaseoLaunch, &'static str> {
        match fs::symlink_metadata(candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err("paseo_not_installed");
            }
            Err(_) => return Err("paseo_not_trusted"),
        }
        ensure_trusted_directories(candidate, self.principal).map_err(|problem| match problem {
            ExecutableProblem::NotFound => "paseo_not_installed",
            _ => "paseo_not_trusted",
        })?;
        let resolved: PathBuf = fs::canonicalize(candidate).map_err(|_| "paseo_not_installed")?;
        let kind: ExecutableKind =
            trusted_kind(&resolved, self.principal).map_err(|problem| match problem {
                ExecutableProblem::NotFound => "paseo_not_installed",
                ExecutableProblem::NotExecutable => "paseo_not_executable",
                _ => "paseo_not_trusted",
            })?;
        let (interpreter, argument): (PathBuf, Option<String>) = match kind {
            ExecutableKind::MachO => {
                return Ok(PaseoLaunch {
                    program: resolved,
                    script: None,
                    interpreter_directory: None,
                });
            }
            ExecutableKind::Script {
                interpreter,
                argument,
            } => (interpreter, argument),
        };
        let located: PathBuf = if interpreter == Path::new("/usr/bin/env") {
            let name: String = argument.ok_or("paseo_interpreter_not_found")?;
            let plain: bool = !name.is_empty()
                && !name.starts_with('-')
                && !name.contains(['/', '='])
                && name != "."
                && name != "..";
            let beside: Option<&Path> = candidate.parent();
            match beside {
                Some(directory) if plain => directory.join(name),
                _ => return Err("paseo_interpreter_not_found"),
            }
        } else if argument.is_none() {
            interpreter
        } else {
            return Err("paseo_interpreter_not_found");
        };
        let interpreter: PathBuf =
            fs::canonicalize(&located).map_err(|_| "paseo_interpreter_not_found")?;
        match trusted_kind(&interpreter, self.principal) {
            Ok(ExecutableKind::MachO) => {}
            Err(ExecutableProblem::NotFound) => return Err("paseo_interpreter_not_found"),
            Ok(_) | Err(_) => return Err("paseo_interpreter_not_trusted"),
        }
        let directory: Option<PathBuf> = interpreter.parent().map(Path::to_path_buf);
        Ok(PaseoLaunch {
            program: interpreter,
            script: Some(resolved),
            interpreter_directory: directory,
        })
    }
}

impl AgentStatus for PaseoAgents {
    fn agent_listing(&self) -> AgentListing {
        if !self.enabled {
            return AgentListing::Off;
        }
        let failed = |reason: &'static str| AgentListing::Failed { reason };
        let Some(home) = &self.home else {
            return failed("home_unknown");
        };
        let launch: PaseoLaunch = match self.launch(home) {
            Ok(launch) => launch,
            Err(reason) => return failed(reason),
        };
        let mut path: OsString = OsString::new();
        if let Some(directory) = &launch.interpreter_directory {
            path.push(directory);
            path.push(":");
        }
        path.push("/usr/bin:/bin");
        let mut command: Command = Command::new(&launch.program);
        if let Some(script) = &launch.script {
            command.arg(script);
        }
        command
            .env_clear()
            .env("HOME", home)
            .env("PATH", path)
            .env("LC_ALL", "C")
            .env("NO_COLOR", "1")
            .current_dir("/")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .args(PASEO_ARGUMENTS);
        let output: GitOutput = match run_bounded(command, MAX_PASEO_OUTPUT, self.deadline) {
            Ok(output) => output,
            Err(GitFailure::NotStarted) => return failed("paseo_not_started"),
            Err(GitFailure::Timeout) => return failed("paseo_timeout"),
            Err(GitFailure::Signaled) => return failed("paseo_signaled"),
            Err(GitFailure::ReadFailed) => return failed("paseo_read_failed"),
        };
        if output.code != 0 {
            return failed("paseo_failed");
        }
        if output.truncated {
            return failed("paseo_output_too_long");
        }
        parse_listing(&output.stdout, home)
    }
}

/// Whether an agent of the status `status` can work in its directory, or
/// `None` for a status that Paseo does not define.
fn is_working(status: &str) -> Option<bool> {
    match status {
        "initializing" | "running" => Some(true),
        "idle" | "error" | "closed" => Some(false),
        _ => None,
    }
}

/// The listing of the output `output` of `paseo ls --json`. A path that
/// starts with `~/` is relative to `home`.
pub(crate) fn parse_listing(output: &[u8], home: &Path) -> AgentListing {
    let failed = |reason: &'static str| AgentListing::Failed { reason };
    let Ok(serde_json::Value::Array(entries)) = serde_json::from_slice(output) else {
        return failed("paseo_output_not_array");
    };
    let mut busy: Vec<PathBuf> = Vec::new();
    for entry in &entries {
        let serde_json::Value::Object(fields) = entry else {
            return failed("paseo_entry_not_object");
        };
        let Some(serde_json::Value::String(status)) = fields.get("status") else {
            return failed("paseo_entry_status");
        };
        let Some(working) = is_working(status) else {
            return failed("paseo_entry_status");
        };
        let directory: Option<&str> = match fields.get("cwd") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(directory)) => Some(directory),
            Some(_) => return failed("paseo_entry_cwd"),
        };
        if !working {
            continue;
        }
        let path: Option<PathBuf> = directory.map(|directory| {
            if directory == "~" {
                home.to_path_buf()
            } else if let Some(rest) = directory.strip_prefix("~/") {
                home.join(rest)
            } else {
                PathBuf::from(directory)
            }
        });
        let Some(path) = path.filter(|path| path.is_absolute()) else {
            return failed("paseo_agent_without_directory");
        };
        if let Ok(resolved) = fs::canonicalize(&path)
            && resolved != path
        {
            busy.push(resolved);
        }
        busy.push(path);
    }
    AgentListing::Listed { busy }
}
