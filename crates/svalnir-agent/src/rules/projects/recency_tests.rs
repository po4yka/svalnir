//! Tests of the project activity. Each test makes its repositories, its
//! transcript folders, and its Paseo programs in a temporary directory; no
//! test reads a project, a transcript, or a Paseo agent of the host.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::Fact;
use svalnir_core::time::WallTime;
use tempfile::TempDir;

use super::MAX_FOLDER_UNITS;
use super::recency::{folder_keys, head_reading, matches_folder, newest_transcript, parse_listing};
use super::tests::{DAY, Home, NoActivity, quiet, refusal, unit};
use super::{
    ActivitySource, AgentListing, AgentReading, AgentStatus, ClaudeTranscripts, GitHeadActivity,
    HeadActivity, PaseoAgents, ProjectLimits, ProjectRecency, ProjectUnitOutcome, RecencyHost,
    RecencyState, SourceReading, TranscriptActivity, assess, encode_folder,
};
use crate::rules::git::{GitToolProblem, Repository};
use crate::scan::{ScanClock, ScanTimestamp};

/// The base time of the tests.
const BASE: i64 = 1_800_000_000;

fn at(unix_seconds: i64) -> WallTime {
    WallTime::from_unix(unix_seconds, 0).unwrap()
}

fn system_time(time: WallTime) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(time.unix_seconds()).unwrap())
}

/// Sets the modification time of the file at `path`.
fn set_modified(path: &Path, time: WallTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(system_time(time))
        .unwrap();
}

/// A clock with a fixed wall-clock time.
struct At(Option<WallTime>);

impl ScanClock for At {
    fn now(&self) -> ScanTimestamp {
        ScanTimestamp {
            wall: self.0,
            monotonic_ns: None,
        }
    }
}

/// Sources that give fixed readings.
struct Fixed {
    git: SourceReading,
    transcripts: SourceReading,
}

impl HeadActivity for Fixed {
    fn head_activity(&self, _repository: &Repository) -> SourceReading {
        self.git
    }
}

impl TranscriptActivity for Fixed {
    fn transcript_activity(&self, _root: &Path) -> SourceReading {
        self.transcripts
    }
}

/// A Paseo source with a fixed listing.
struct Agents(AgentListing);

impl AgentStatus for Agents {
    fn agent_listing(&self) -> AgentListing {
        self.0.clone()
    }
}

fn repository(root: &str) -> Repository {
    Repository {
        work_tree: PathBuf::from(root),
        git_dir: PathBuf::from(root).join(".git"),
    }
}

/// The assessment of `/work/app` with the readings `git` and `transcripts`,
/// the listing `listing`, and the time `now`.
fn assess_with(
    git: SourceReading,
    transcripts: SourceReading,
    listing: &AgentListing,
    now: Option<WallTime>,
) -> ProjectRecency {
    let sources = Fixed { git, transcripts };
    let host = RecencyHost {
        quiet_period: DAY,
        head: &sources,
        transcripts: &sources,
        agents: &NoActivity,
    };
    assess(&host, listing, &repository("/work/app"), now)
}

fn observed(time: WallTime) -> SourceReading {
    SourceReading::Observed { at: time }
}

const DAY_SECONDS: i64 = 86_400;

// ---------------------------------------------------------------------
// The quiet predicate.
// ---------------------------------------------------------------------

#[test]
fn a_project_is_quiet_from_the_end_of_the_quiet_period() {
    let last: WallTime = at(BASE);
    // Exactly the quiet period: quiet.
    let recency = assess_with(
        observed(last),
        SourceReading::NoEvidence,
        &AgentListing::Off,
        Some(at(BASE + DAY_SECONDS)),
    );
    assert_eq!(recency.state, RecencyState::Quiet);
    assert_eq!(recency.reason, "quiet_period_passed");
    assert_eq!(recency.last_activity, Some(last));
    assert_eq!(recency.source, Some(ActivitySource::GitHead));
    assert_eq!(recency.fact(), Fact::Satisfied);
    assert_eq!(recency.agents, AgentReading::Off);

    // One nanosecond less: active.
    let now: WallTime = WallTime::from_unix(BASE + DAY_SECONDS - 1, 999_999_999).unwrap();
    let recency = assess_with(
        observed(last),
        SourceReading::NoEvidence,
        &AgentListing::Off,
        Some(now),
    );
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.reason, "recent_activity");
    assert_eq!(recency.fact(), Fact::NotSatisfied);
}

#[test]
fn the_newest_time_of_the_sources_decides() {
    let recency = assess_with(
        observed(at(BASE)),
        observed(at(BASE + DAY_SECONDS)),
        &AgentListing::Off,
        Some(at(BASE + DAY_SECONDS + 60)),
    );
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.last_activity, Some(at(BASE + DAY_SECONDS)));
    assert_eq!(recency.source, Some(ActivitySource::ClaudeCodeTranscripts));
}

#[test]
fn an_unknown_last_activity_is_active() {
    let recency = assess_with(
        SourceReading::NoEvidence,
        SourceReading::NoEvidence,
        &AgentListing::Off,
        Some(at(BASE)),
    );
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.reason, "no_activity_evidence");
    assert_eq!(recency.last_activity, None);
    assert_eq!(recency.fact(), Fact::Unknown);
}

#[test]
fn a_failed_source_keeps_an_old_project_active() {
    let failed = SourceReading::Failed {
        reason: "transcripts_not_readable",
    };
    let recency = assess_with(
        observed(at(BASE)),
        failed,
        &AgentListing::Off,
        Some(at(BASE + 30 * DAY_SECONDS)),
    );
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.reason, "activity_source_failed");
    assert_eq!(recency.transcripts, failed);
    assert_eq!(recency.fact(), Fact::Unknown);

    // A recent time of the other source is known recent activity.
    let recency = assess_with(
        failed,
        observed(at(BASE)),
        &AgentListing::Off,
        Some(at(BASE + 60)),
    );
    assert_eq!(recency.reason, "recent_activity");
    assert_eq!(recency.fact(), Fact::NotSatisfied);
}

#[test]
fn a_time_after_now_and_an_unknown_clock_are_active() {
    let recency = assess_with(
        observed(at(BASE + 10 * DAY_SECONDS)),
        SourceReading::NoEvidence,
        &AgentListing::Off,
        Some(at(BASE)),
    );
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.reason, "recent_activity");

    let recency = assess_with(
        observed(at(BASE)),
        SourceReading::NoEvidence,
        &AgentListing::Off,
        None,
    );
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.reason, "clock_unknown");
    assert_eq!(recency.fact(), Fact::Unknown);
}

#[test]
fn a_running_paseo_agent_in_the_project_makes_it_busy() {
    let old = observed(at(BASE));
    let now = Some(at(BASE + 30 * DAY_SECONDS));
    let listed = |busy: &[&str]| AgentListing::Listed {
        busy: busy.iter().map(PathBuf::from).collect(),
    };
    for busy in [&["/work/app"][..], &["/work/app/src/lib"], &["/WORK/App"]] {
        let recency = assess_with(old, SourceReading::NoEvidence, &listed(busy), now);
        assert_eq!(recency.state, RecencyState::Busy, "{busy:?}");
        assert_eq!(recency.reason, "agent_running");
        assert_eq!(recency.agents, AgentReading::Busy);
        assert_eq!(recency.fact(), Fact::NotSatisfied);
    }
    // A sibling with a longer name, a directory above, and another project
    // are not in the project.
    let recency = assess_with(
        old,
        SourceReading::NoEvidence,
        &listed(&["/work/app-two", "/work", "/other"]),
        now,
    );
    assert_eq!(recency.state, RecencyState::Quiet);
    assert_eq!(recency.agents, AgentReading::NotBusy);
}

#[test]
fn a_failed_paseo_listing_makes_each_project_busy() {
    let recency = assess_with(
        observed(at(BASE)),
        SourceReading::NoEvidence,
        &AgentListing::Failed {
            reason: "paseo_timeout",
        },
        Some(at(BASE + 30 * DAY_SECONDS)),
    );
    assert_eq!(recency.state, RecencyState::Busy);
    // The reason of the failure shows why each project is busy.
    assert_eq!(recency.reason, "paseo_timeout");
    assert_eq!(
        recency.agents,
        AgentReading::Failed {
            reason: "paseo_timeout"
        }
    );
    assert_eq!(recency.fact(), Fact::NotSatisfied);
}

// ---------------------------------------------------------------------
// The Paseo listing.
// ---------------------------------------------------------------------

fn failure(listing: &AgentListing) -> &'static str {
    match listing {
        AgentListing::Failed { reason } => reason,
        other => panic!("the listing did not fail: {other:?}"),
    }
}

#[test]
fn the_paseo_listing_keeps_only_running_and_starting_agents() {
    let home = Path::new("/Users/test");
    let listing = parse_listing(
        br#"[
            {"status": "running", "cwd": "/work/one"},
            {"status": "initializing", "cwd": "~/two"},
            {"status": "idle", "cwd": "/work/three"},
            {"status": "error"},
            {"status": "closed", "cwd": null},
            {"status": "running", "cwd": "~"}
        ]"#,
        home,
    );
    assert_eq!(
        listing,
        AgentListing::Listed {
            busy: vec![
                PathBuf::from("/work/one"),
                PathBuf::from("/Users/test/two"),
                PathBuf::from("/Users/test"),
            ],
        }
    );
    assert_eq!(
        parse_listing(b"[]", home),
        AgentListing::Listed { busy: Vec::new() }
    );
}

#[test]
fn a_malformed_paseo_listing_fails() {
    let home = Path::new("/Users/test");
    for (output, reason) in [
        (&b"not json"[..], "paseo_output_not_array"),
        (b"null", "paseo_output_not_array"),
        (b"{\"status\": \"running\"}", "paseo_output_not_array"),
        (b"[null]", "paseo_entry_not_object"),
        (b"[\"running\"]", "paseo_entry_not_object"),
        (b"[{\"cwd\": \"/work\"}]", "paseo_entry_status"),
        (
            b"[{\"Status\": \"running\", \"cwd\": \"/work\"}]",
            "paseo_entry_status",
        ),
        (
            b"[{\"status\": 1, \"cwd\": \"/work\"}]",
            "paseo_entry_status",
        ),
        (
            b"[{\"status\": \"sleeping\", \"cwd\": \"/work\"}]",
            "paseo_entry_status",
        ),
        (b"[{\"status\": \"idle\", \"cwd\": 7}]", "paseo_entry_cwd"),
        (
            b"[{\"status\": \"running\"}]",
            "paseo_agent_without_directory",
        ),
        (
            b"[{\"status\": \"running\", \"cwd\": null}]",
            "paseo_agent_without_directory",
        ),
        (
            b"[{\"status\": \"running\", \"cwd\": \"work\"}]",
            "paseo_agent_without_directory",
        ),
        (
            b"[{\"status\": \"running\", \"cwd\": \"~other/work\"}]",
            "paseo_agent_without_directory",
        ),
    ] {
        assert_eq!(
            failure(&parse_listing(output, home)),
            reason,
            "{}",
            String::from_utf8_lossy(output)
        );
    }
}

/// A program at `directory/paseo` with the shell text `body`.
fn program(directory: &Path, body: &str) -> PathBuf {
    let path: PathBuf = directory.join("paseo");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn the_paseo_source_is_off_unless_the_configuration_turns_it_on() {
    let directory: TempDir = TempDir::new().unwrap();
    let executable: PathBuf = program(directory.path(), "exit 1");
    let source = PaseoAgents::new(false, Some(directory.path()))
        .with_unchecked(executable, Duration::from_secs(5));
    assert_eq!(source.agent_listing(), AgentListing::Off);
}

#[test]
fn the_paseo_source_accepts_only_a_protected_executable_of_a_fixed_path() {
    let directory: TempDir = TempDir::new().unwrap();
    let home: &Path = directory.path();
    let source =
        PaseoAgents::new(true, Some(home)).with_candidates(vec![home.join("absent/paseo")]);
    assert_eq!(failure(&source.agent_listing()), "paseo_not_installed");
    // A program that the user can change is refused, and it does not run.
    let marker: PathBuf = home.join("ran");
    let executable: PathBuf = program(home, &format!("touch '{}'", marker.display()));
    let source = PaseoAgents::new(true, Some(home)).with_candidates(vec![executable]);
    assert_eq!(failure(&source.agent_listing()), "paseo_not_trusted");
    assert!(!marker.exists());
    assert_eq!(
        failure(&PaseoAgents::new(true, None).agent_listing()),
        "home_unknown"
    );
}

#[test]
fn the_paseo_command_has_a_constrained_environment_and_bounds() {
    let directory: TempDir = TempDir::new().unwrap();
    let home: &Path = directory.path();
    let run = |body: &str, deadline: Duration| {
        PaseoAgents::new(true, Some(home))
            .with_unchecked(program(home, body), deadline)
            .agent_listing()
    };
    // The arguments are fixed, and only the fixed variables are set.
    let listing = run(
        r#"[ "$*" = "ls --json --global --background" ] || exit 9
printf '[{"status":"running","cwd":"%s"},{"status":"running","cwd":"/%s"}]' "$PATH" "${USER:-none}${TMPDIR:-}""#,
        Duration::from_secs(5),
    );
    assert_eq!(
        listing,
        AgentListing::Listed {
            busy: vec![PathBuf::from("/usr/bin:/bin"), PathBuf::from("/none")],
        }
    );
    let listing = run(
        r#"printf '[{"status":"initializing","cwd":"~/Code/app"}]'"#,
        Duration::from_secs(5),
    );
    assert_eq!(
        listing,
        AgentListing::Listed {
            busy: vec![home.join("Code/app")],
        }
    );
    assert_eq!(
        failure(&run("printf '[]'; exit 3", Duration::from_secs(5))),
        "paseo_failed"
    );
    assert_eq!(
        failure(&run("printf 'Error: no daemon'", Duration::from_secs(5))),
        "paseo_output_not_array"
    );
    assert_eq!(
        failure(&run("exec /bin/sleep 30", Duration::from_millis(300))),
        "paseo_timeout"
    );
    assert_eq!(
        failure(&run(
            "/usr/bin/yes '[]' | /usr/bin/head -c 2000000",
            Duration::from_secs(10)
        )),
        "paseo_output_too_long"
    );
}

// ---------------------------------------------------------------------
// The Git source.
// ---------------------------------------------------------------------

#[test]
fn the_git_source_reads_the_reflog_of_head_then_head() {
    let home = Home::new();
    home.write("Code/app/README", b"app\n");
    home.repository("Code/app");
    let work_tree: PathBuf = home.path.join("Code/app");
    let repository = Repository {
        git_dir: work_tree.join(".git"),
        work_tree: work_tree.clone(),
    };
    let reflog: PathBuf = work_tree.join(".git/logs/HEAD");
    let head: PathBuf = work_tree.join(".git/HEAD");
    set_modified(&reflog, at(BASE));
    set_modified(&head, at(BASE + 100));
    // A write of the index does not count.
    set_modified(&work_tree.join(".git/index"), at(BASE + 200));
    let source = GitHeadActivity::new(Ok(&home.git));
    // The newest of the two files applies.
    assert_eq!(source.head_activity(&repository), observed(at(BASE + 100)));
    set_modified(&reflog, at(BASE + 150));
    assert_eq!(source.head_activity(&repository), observed(at(BASE + 150)));
    fs::remove_file(&reflog).unwrap();
    assert_eq!(source.head_activity(&repository), observed(at(BASE + 100)));
    fs::remove_file(&head).unwrap();
    // With no `HEAD`, Git does not accept the directory as a repository.
    assert!(matches!(
        source.head_activity(&repository),
        SourceReading::Failed { .. }
    ));
    assert_eq!(
        GitHeadActivity::new(Err(GitToolProblem::NotInstalled)).head_activity(&repository),
        SourceReading::Failed {
            reason: "git_not_available"
        }
    );
}

// ---------------------------------------------------------------------
// The transcript source.
// ---------------------------------------------------------------------

#[test]
fn the_folder_name_replaces_each_character_that_is_not_a_letter_or_digit() {
    assert_eq!(
        encode_folder(Path::new("/Users/a/GitHub/svalnir")),
        "-Users-a-GitHub-svalnir"
    );
    assert_eq!(
        encode_folder(Path::new("/Users/a/GitHub/svalnir/.claude/worktrees/w_1")),
        "-Users-a-GitHub-svalnir--claude-worktrees-w-1"
    );
    assert_eq!(encode_folder(Path::new("/tmp/\u{e9} x")), "-tmp---x");
    // A character outside the Basic Multilingual Plane has two UTF-16 code
    // units, so it gives `--`.
    assert_eq!(encode_folder(Path::new("/tmp/\u{1F600}a")), "-tmp---a");
}

#[test]
fn neither_head_file_is_a_failure_and_not_a_quiet_project() {
    let directory: TempDir = TempDir::new().unwrap();
    let paths: Vec<PathBuf> = vec![
        directory.path().join("logs/HEAD"),
        directory.path().join("HEAD"),
    ];
    assert_eq!(
        head_reading(&paths),
        SourceReading::Failed {
            reason: "git_head_missing"
        }
    );
    fs::write(&paths[1], b"ref: refs/heads/main\n").unwrap();
    set_modified(&paths[1], at(BASE));
    assert_eq!(head_reading(&paths), observed(at(BASE)));
    let recency = assess_with(
        SourceReading::Failed {
            reason: "git_head_missing",
        },
        SourceReading::NoEvidence,
        &AgentListing::Off,
        Some(at(BASE)),
    );
    assert_eq!(recency.reason, "activity_source_failed");
    assert_eq!(recency.fact(), Fact::Unknown);
}

#[test]
fn a_root_in_nfc_or_nfd_matches_the_folders_of_both_forms() {
    let nfc: &str = "/tmp/x\u{e9}y";
    let nfd: &str = "/tmp/xe\u{301}y";
    for root in [nfc, nfd] {
        let keys: Vec<String> = folder_keys(Path::new(root));
        assert!(keys.contains(&"-tmp-x-y".to_owned()), "{root}: {keys:?}");
        assert!(keys.contains(&"-tmp-xe-y".to_owned()), "{root}: {keys:?}");
    }
    // A name with no character that normalization changes has one key.
    assert_eq!(
        folder_keys(Path::new("/tmp/absent/app")),
        ["-tmp-absent-app"]
    );
}

#[test]
fn a_folder_that_claude_code_cut_matches_its_long_root() {
    let short: String = "-a".repeat(50);
    assert!(matches_folder(short.as_bytes(), short.as_bytes()));
    assert!(matches_folder(
        format!("{short}-x").as_bytes(),
        short.as_bytes()
    ));
    assert!(!matches_folder(
        format!("{short}x").as_bytes(),
        short.as_bytes()
    ));
    // A key of more than 200 code units: Claude Code keeps 200 and adds `-`
    // and a hash of the path.
    let long: String = format!("-{}", "b".repeat(300));
    let cut: String = format!("{}-1x9z0q", &long[..MAX_FOLDER_UNITS]);
    assert!(matches_folder(cut.as_bytes(), long.as_bytes()));
    // A descendant of a long root has the same first 200 code units.
    let below: String = format!("{}-k2", &format!("{long}-src")[..MAX_FOLDER_UNITS]);
    assert!(matches_folder(below.as_bytes(), long.as_bytes()));
    // A key of exactly 200 code units is not cut.
    let exact: String = long[..MAX_FOLDER_UNITS].to_owned();
    assert!(matches_folder(exact.as_bytes(), exact.as_bytes()));
    assert!(matches_folder(
        format!("{exact}-h").as_bytes(),
        exact.as_bytes()
    ));
    assert!(!matches_folder(&exact.as_bytes()[..199], exact.as_bytes()));
}

#[test]
fn the_transcript_source_finds_the_cut_folder_of_a_long_root() {
    let home = Home::new();
    let mut relative: String = "Code".to_owned();
    while encode_folder(&home.path.join(&relative)).len() <= MAX_FOLDER_UNITS {
        relative.push_str("/directory-of-a-long-path");
    }
    let root: PathBuf = home.path.join(&relative);
    let key: String = encode_folder(&root);
    let folder: String = format!("{}-3k2l9a", &key[..MAX_FOLDER_UNITS]);
    let transcript: PathBuf = home.write(&format!(".claude/projects/{folder}/a.jsonl"), b"");
    set_modified(&transcript, at(BASE));
    let source = ClaudeTranscripts::for_home(Some(&home.path));
    assert_eq!(source.transcript_activity(&root), observed(at(BASE)));
}

#[test]
fn the_transcript_source_reads_the_newest_transcript_of_the_root_and_below() {
    let home = Home::new();
    let root: PathBuf = home.path.join("Code/app");
    let key: String = encode_folder(&root);
    let transcript = |folder: &str, name: &str, time: WallTime| {
        let path: PathBuf = home.write(
            &format!(".claude/projects/{folder}/{name}"),
            b"{\"secret\": true}\n",
        );
        set_modified(&path, time);
    };
    let source = ClaudeTranscripts::for_home(Some(&home.path));
    // No projects directory: no evidence.
    assert_eq!(source.transcript_activity(&root), SourceReading::NoEvidence);

    transcript(&key, "a.jsonl", at(BASE));
    transcript(&key, "s1/subagents/b.jsonl", at(BASE + 10));
    // A file that is not a transcript, a folder of another project, and a
    // folder above the root do not count.
    transcript(&key, "notes.md", at(BASE + 1_000));
    transcript("-elsewhere", "c.jsonl", at(BASE + 1_000));
    transcript(
        &encode_folder(&home.path.join("Code")),
        "d.jsonl",
        at(BASE + 1_000),
    );
    // A subfolder deeper than the bound does not count.
    transcript(&key, "s1/x/y/deep.jsonl", at(BASE + 1_000));
    // A folder of a directory below the root counts.
    transcript(
        &format!("{key}--claude-worktrees-w"),
        "e.jsonl",
        at(BASE + 20),
    );
    let source = ClaudeTranscripts::for_home(Some(&home.path));
    assert_eq!(source.transcript_activity(&root), observed(at(BASE + 20)));
    assert_eq!(
        source.transcript_activity(&home.path.join("Code/other")),
        SourceReading::NoEvidence
    );
}

#[test]
fn an_unreadable_transcript_folder_or_a_spent_bound_fails() {
    let home = Home::new();
    let root: PathBuf = home.path.join("Code/app");
    let folder: PathBuf = home
        .path
        .join(".claude/projects")
        .join(encode_folder(&root));
    for index in 0..5 {
        home.write(
            &format!(".claude/projects/{}/{index}.jsonl", encode_folder(&root)),
            b"",
        );
    }
    let mut budget: usize = 3;
    assert_eq!(
        newest_transcript(&folder, &mut budget),
        Err("transcripts_bound_reached")
    );
    let mut budget: usize = 5;
    assert!(newest_transcript(&folder, &mut budget).unwrap().is_some());

    fs::set_permissions(&folder, fs::Permissions::from_mode(0o000)).unwrap();
    let source = ClaudeTranscripts::for_home(Some(&home.path));
    let result = source.transcript_activity(&root);
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        result,
        SourceReading::Failed {
            reason: "transcripts_not_readable"
        }
    );
    assert_eq!(
        ClaudeTranscripts::for_home(None).transcript_activity(&root),
        SourceReading::Failed {
            reason: "home_unknown"
        }
    );
}

// ---------------------------------------------------------------------
// The inspection.
// ---------------------------------------------------------------------

/// A Node project whose `HEAD` and reflog have the time `time`.
fn old_project(home: &Home, name: &str, time: WallTime) -> PathBuf {
    let project: PathBuf = home.node_project(name);
    set_modified(&project.join(".git/logs/HEAD"), time);
    set_modified(&project.join(".git/HEAD"), time);
    project
}

fn inspect(home: &Home, agents: &dyn AgentStatus, now: WallTime) -> super::ProjectInspection {
    home.inspect_recency(
        &quiet(),
        Ok(&home.git),
        ProjectLimits::default(),
        agents,
        DAY,
        &At(Some(now)),
    )
}

#[test]
fn the_inspection_reports_the_project_activity_of_each_unit() {
    let home = Home::new();
    let project: PathBuf = old_project(&home, "app", at(BASE));
    let now: WallTime = at(BASE + 2 * DAY_SECONDS);
    let inspection = inspect(&home, &Agents(AgentListing::Off), now);
    let report = unit(&inspection, &project.join("node_modules"));
    assert!(matches!(report.outcome, ProjectUnitOutcome::Measured(_)));
    let recency: &ProjectRecency = report.recency.as_ref().unwrap();
    assert_eq!(recency.root, project);
    assert_eq!(recency.state, RecencyState::Quiet);
    assert_eq!(recency.last_activity, Some(at(BASE)));
    assert_eq!(recency.source, Some(ActivitySource::GitHead));
    assert_eq!(recency.transcripts, SourceReading::NoEvidence);
    assert_eq!(recency.quiet_period, DAY);

    // A transcript of the last hour makes the project active. An active
    // project is still measured.
    let transcript: PathBuf = home.write(
        &format!(".claude/projects/{}/t.jsonl", encode_folder(&project)),
        b"",
    );
    set_modified(&transcript, at(BASE + 2 * DAY_SECONDS - 3_600));
    let inspection = inspect(&home, &Agents(AgentListing::Off), now);
    let report = unit(&inspection, &project.join("node_modules"));
    assert!(matches!(report.outcome, ProjectUnitOutcome::Measured(_)));
    let recency: &ProjectRecency = report.recency.as_ref().unwrap();
    assert_eq!(recency.state, RecencyState::Active);
    assert_eq!(recency.source, Some(ActivitySource::ClaudeCodeTranscripts));
    // The report has no content of a transcript and no transcript path.
    let text: String = serde_json::to_string(&inspection).unwrap();
    assert!(!text.contains("t.jsonl"));
    assert!(!text.contains(".claude/projects"));
}

#[test]
fn a_busy_project_refuses_its_unit() {
    let home = Home::new();
    let project: PathBuf = old_project(&home, "app", at(BASE));
    let other: PathBuf = old_project(&home, "other", at(BASE));
    let now: WallTime = at(BASE + 2 * DAY_SECONDS);
    let running = Agents(AgentListing::Listed {
        busy: vec![project.join("src")],
    });
    let inspection = inspect(&home, &running, now);
    let report = unit(&inspection, &project.join("node_modules"));
    assert_eq!(refusal(report), "project_busy");
    assert_eq!(report.recency.as_ref().unwrap().state, RecencyState::Busy);
    let report = unit(&inspection, &other.join("node_modules"));
    assert!(matches!(report.outcome, ProjectUnitOutcome::Measured(_)));

    let failed = Agents(AgentListing::Failed {
        reason: "paseo_output_not_array",
    });
    let inspection = inspect(&home, &failed, now);
    for project in [&project, &other] {
        let report = unit(&inspection, &project.join("node_modules"));
        assert_eq!(refusal(report), "project_busy");
        assert_eq!(
            report.recency.as_ref().unwrap().reason,
            "paseo_output_not_array"
        );
    }
}

#[test]
fn the_quiet_period_of_the_settings_is_its_duration() {
    let settings = svalnir_core::config::parse_and_validate(
        "schema_version = 1\n[cleanup.projects]\nquiet_period = \"2d\"\n",
    );
    let config = settings.config().unwrap();
    assert_eq!(
        super::quiet_period(&config.cleanup().projects),
        Nanoseconds::new(2 * 86_400_000_000_000)
    );
}

/// A Git source that counts its reads.
struct Counted<'a> {
    inner: GitHeadActivity<'a>,
    reads: std::cell::Cell<u32>,
}

impl HeadActivity for Counted<'_> {
    fn head_activity(&self, repository: &Repository) -> SourceReading {
        self.reads.set(self.reads.get() + 1);
        self.inner.head_activity(repository)
    }
}

#[test]
fn the_inspection_reads_the_git_source_one_time_for_each_git_directory() {
    let home = Home::new();
    home.write("Code/mono/.gitignore", b"node_modules/\n");
    for name in ["one", "two"] {
        home.write(&format!("Code/mono/{name}/package.json"), b"{}");
    }
    home.repository("Code/mono");
    for name in ["one", "two"] {
        home.write(&format!("Code/mono/{name}/node_modules/p/index.js"), b"1\n");
    }
    old_project(&home, "solo", at(BASE));
    let head = Counted {
        inner: GitHeadActivity::new(Ok(&home.git)),
        reads: std::cell::Cell::new(0),
    };
    let transcripts = ClaudeTranscripts::for_home(Some(&home.path));
    let inspection = home.inspect_sources(
        &quiet(),
        Ok(&home.git),
        ProjectLimits::default(),
        RecencyHost {
            quiet_period: DAY,
            head: &head,
            transcripts: &transcripts,
            agents: &NoActivity,
        },
        &At(Some(at(BASE + 2 * DAY_SECONDS))),
    );
    let measured: usize = inspection
        .units
        .iter()
        .filter(|unit| unit.recency.is_some())
        .count();
    assert_eq!(measured, 3, "{:#?}", inspection.units);
    // Two units in `mono` share one Git directory.
    assert_eq!(head.reads.get(), 2);
}
