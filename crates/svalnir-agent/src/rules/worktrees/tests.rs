//! Fixture tests of `git.linked-worktree`. Each test makes a home
//! directory and disposable Git repositories in a temporary directory; no
//! test reads or changes a repository of the host.

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use svalnir_core::process::Uid;
use svalnir_core::rule::{LifecycleState, RootBase, RuleMode, RuleRefusal, RuleRegistry};
use tempfile::TempDir;

use super::index::{compare, parse};
use super::{
    Evidence, UntrackedFiles, WorktreeHead, WorktreeHost, WorktreeInspection, WorktreeLimits,
    WorktreePresence, WorktreeReport, WorktreeVerdict,
};
use crate::protection::ProtectedLocations;
use crate::rules::ReviewedRules;
use crate::rules::fixture::{automatic_eviction_validated, manual_action_validated};
use crate::rules::git::{GitTool, GitToolProblem};
use crate::rules::projects::SearchRoots;
use crate::scan::CancellationToken;

struct Home {
    _directory: TempDir,
    path: PathBuf,
    locations: ProtectedLocations,
    principal: Uid,
    git: GitTool,
}

impl Home {
    fn new() -> Self {
        let directory: TempDir = TempDir::new().unwrap();
        let path: PathBuf = fs::canonicalize(directory.path()).unwrap();
        let state: PathBuf = path.join("Library/Application Support/Svalnir");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(path.join("Code")).unwrap();
        let principal: Uid = Uid::new(fs::metadata(&path).unwrap().uid());
        Self {
            locations: ProtectedLocations::from_resolved(Some(path.clone()), Some(state)),
            _directory: directory,
            path,
            principal,
            git: GitTool::locate().expect("the developer tools of the host have Git"),
        }
    }

    fn write(&self, relative: &str, content: &[u8]) {
        let path: PathBuf = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    /// Runs the Git of the test in `directory`, with no configuration of
    /// the host.
    fn git(&self, directory: &str, arguments: &[&str]) {
        let status = Command::new(self.git.executable())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(self.path.join(directory))
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(arguments)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?} in {directory}");
    }

    /// A repository `Code/repo` with one commit.
    fn repository(&self) {
        self.write("Code/repo/README", b"start\n");
        self.write("Code/repo/.gitignore", b"*.log\n");
        self.git("Code/repo", &["init", "-q"]);
        self.git("Code/repo", &["add", "-A"]);
        self.git("Code/repo", &["commit", "-q", "-m", "start"]);
    }

    /// A linked worktree `Code/NAME` on a new branch `NAME`.
    fn worktree(&self, name: &str) {
        self.git(
            "Code/repo",
            &["worktree", "add", "-q", "-b", name, &format!("../{name}")],
        );
    }

    /// Waits until the second of the last index write has passed, then
    /// lets Git refresh the index of each worktree, so that no entry is
    /// racy.
    fn settle(&self, worktrees: &[&str]) {
        std::thread::sleep(Duration::from_millis(1_100));
        for worktree in worktrees {
            self.git(&format!("Code/{worktree}"), &["status", "--porcelain"]);
        }
    }

    fn inspect_with(&self, git: Result<&GitTool, GitToolProblem>) -> WorktreeInspection {
        let registry: ReviewedRules = ReviewedRules::new().unwrap();
        registry.worktrees().inspect(
            WorktreeHost {
                principal: self.principal,
                locations: &self.locations,
                user_exclusions: &[],
                git,
            },
            &SearchRoots::new(vec![PathBuf::from("Code")]).unwrap(),
            WorktreeLimits::default(),
            &CancellationToken::new(),
        )
    }

    fn inspect(&self) -> WorktreeInspection {
        self.inspect_with(Ok(&self.git))
    }
}

fn worktree<'a>(inspection: &'a WorktreeInspection, name: &str) -> &'a WorktreeReport {
    inspection
        .repositories
        .iter()
        .flat_map(|repository| &repository.worktrees)
        .find(|worktree| worktree.name == name)
        .unwrap_or_else(|| panic!("no worktree {name}: {:#?}", inspection.repositories))
}

#[test]
fn the_rule_is_proposed_with_the_inspection_mode_only() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let rule = registry.worktrees().rule();
    assert_eq!(rule.reference.id.as_str(), "git.linked-worktree");
    assert_eq!(rule.modes, [RuleMode::Inspection]);
    assert_eq!(rule.roots[0].base, RootBase::UserSelected);
    for mode in RuleMode::ALL {
        assert_eq!(
            registry
                .resolve(&rule.reference, "git-linked-worktree", &mode)
                .err(),
            Some(RuleRefusal::ModeNotValidated)
        );
    }
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(&state).unwrap();
        assert_eq!(
            registry.worktrees().rule().layouts[0].lifecycle,
            LifecycleState::Proposed
        );
    }
}

#[test]
fn each_linked_worktree_reports_the_work_that_a_removal_would_lose() {
    let home = Home::new();
    home.repository();
    for name in ["clean", "staged", "dirty", "untracked"] {
        home.worktree(name);
    }
    home.git(
        "Code/repo",
        &["worktree", "add", "-q", "--detach", "../detached"],
    );
    home.settle(&["clean", "staged", "dirty", "untracked", "detached"]);
    home.write("Code/staged/README", b"staged change\n");
    home.git("Code/staged", &["add", "README"]);
    home.write("Code/dirty/README", b"a change that no commit has\n");
    home.write("Code/untracked/notes.txt", b"notes\n");
    home.write("Code/detached/new.txt", b"new\n");
    home.git("Code/detached", &["add", "new.txt"]);
    home.git("Code/detached", &["commit", "-q", "-m", "only here"]);
    home.git("Code/repo", &["worktree", "lock", "../clean"]);
    let records: PathBuf = home.path.join("Code/repo/.git/worktrees");
    let indexes = || {
        ["clean", "staged", "dirty", "untracked", "detached"]
            .map(|name| fs::read(records.join(name).join("index")).unwrap())
    };
    let before = indexes();

    let inspection: WorktreeInspection = home.inspect();
    // No query wrote an index.
    assert_eq!(indexes(), before);
    assert_eq!(inspection.repositories.len(), 1);
    assert_eq!(
        inspection.repositories[0].work_tree,
        home.path.join("Code/repo")
    );
    assert_eq!(inspection.repositories[0].worktrees.len(), 5);

    let clean = worktree(&inspection, "clean");
    assert_eq!(clean.path, Some(home.path.join("Code/clean")));
    assert_eq!(
        clean.head,
        WorktreeHead::Branch {
            name: "clean".to_owned()
        }
    );
    assert!(clean.locked);
    assert_eq!(clean.presence, WorktreePresence::Present);
    assert_eq!(clean.staged_changes, Evidence::Known(false));
    assert_eq!(clean.changed_files, Evidence::Known(0));
    assert_eq!(
        clean.untracked_files,
        Evidence::Known(UntrackedFiles {
            count: 0,
            more: false
        })
    );
    assert_eq!(clean.unique_commits, Evidence::Known(0));
    assert_eq!(clean.verdict, WorktreeVerdict::NoWorkSeen);

    let staged = worktree(&inspection, "staged");
    assert_eq!(staged.staged_changes, Evidence::Known(true));
    assert_eq!(staged.verdict, WorktreeVerdict::HasWork);

    let dirty = worktree(&inspection, "dirty");
    assert_eq!(dirty.staged_changes, Evidence::Known(false));
    assert_eq!(dirty.changed_files, Evidence::Known(1));
    assert_eq!(dirty.verdict, WorktreeVerdict::HasWork);
    assert!(dirty.owner_workflow.contains("git worktree remove"));

    let untracked = worktree(&inspection, "untracked");
    assert_eq!(
        untracked.untracked_files,
        Evidence::Known(UntrackedFiles {
            count: 1,
            more: false
        })
    );
    assert_eq!(untracked.verdict, WorktreeVerdict::HasWork);

    let detached = worktree(&inspection, "detached");
    assert!(matches!(detached.head, WorktreeHead::Detached { .. }));
    assert_eq!(detached.unique_commits, Evidence::Known(1));
    assert_eq!(detached.verdict, WorktreeVerdict::HasWork);

    // The inspection changed nothing.
    assert_eq!(
        fs::read(home.path.join("Code/dirty/README")).unwrap(),
        b"a change that no commit has\n"
    );
    assert!(home.path.join("Code/untracked/notes.txt").exists());
}

#[test]
fn a_worktree_whose_directory_is_absent_keeps_its_commits_in_the_report() {
    let home = Home::new();
    home.repository();
    home.git(
        "Code/repo",
        &["worktree", "add", "-q", "--detach", "../gone"],
    );
    home.write("Code/gone/new.txt", b"new\n");
    home.git("Code/gone", &["add", "new.txt"]);
    home.git("Code/gone", &["commit", "-q", "-m", "only here"]);
    fs::remove_dir_all(home.path.join("Code/gone")).unwrap();
    let inspection: WorktreeInspection = home.inspect();
    let gone = worktree(&inspection, "gone");
    assert_eq!(gone.presence, WorktreePresence::Missing);
    assert_eq!(gone.unique_commits, Evidence::Known(1));
    assert!(matches!(gone.changed_files, Evidence::Unknown(_)));
    assert_eq!(gone.verdict, WorktreeVerdict::HasWork);
    assert!(gone.owner_workflow.contains("git worktree prune"));
}

#[test]
fn with_no_trusted_git_no_worktree_shows_the_absence_of_work() {
    let home = Home::new();
    home.repository();
    home.worktree("clean");
    let inspection: WorktreeInspection = home.inspect_with(Err(GitToolProblem::NotInstalled));
    let clean = worktree(&inspection, "clean");
    assert_eq!(clean.staged_changes, Evidence::Unknown("git_not_available"));
    assert_eq!(clean.unique_commits, Evidence::Unknown("git_not_available"));
    assert_eq!(clean.verdict, WorktreeVerdict::NotKnown);
}

#[test]
fn a_repository_with_no_linked_worktree_and_a_symbolic_link_are_not_reported() {
    let home = Home::new();
    home.repository();
    // A repository outside the search root with a worktree, behind a
    // symbolic link of the search root.
    home.write("Other/repo/README", b"x\n");
    home.git("Other/repo", &["init", "-q"]);
    home.git("Other/repo", &["add", "-A"]);
    home.git("Other/repo", &["commit", "-q", "-m", "x"]);
    home.git(
        "Other/repo",
        &["worktree", "add", "-q", "-b", "feature", "../feature"],
    );
    symlink(home.path.join("Other"), home.path.join("Code/other")).unwrap();
    let inspection: WorktreeInspection = home.inspect();
    assert_eq!(inspection.repositories, []);
}

#[test]
fn the_index_reader_reads_each_version_and_refuses_another_form() {
    let home = Home::new();
    home.repository();
    home.write("Code/repo/a/b/c.txt", b"c\n");
    home.write("Code/repo/a/d.txt", b"d\n");
    home.git("Code/repo", &["add", "-A"]);
    home.git("Code/repo", &["commit", "-q", "-m", "more"]);
    for version in ["2", "3", "4"] {
        home.git("Code/repo", &["update-index", "--index-version", version]);
        let bytes: Vec<u8> = fs::read(home.path.join("Code/repo/.git/index")).unwrap();
        let entries = parse(&bytes).unwrap();
        let paths: Vec<&[u8]> = entries.iter().map(|entry| entry.path.as_slice()).collect();
        assert_eq!(
            paths,
            [
                b".gitignore".as_slice(),
                b"README",
                b"a/b/c.txt",
                b"a/d.txt"
            ],
            "version {version}"
        );
    }
    let bytes: Vec<u8> = fs::read(home.path.join("Code/repo/.git/index")).unwrap();
    assert!(parse(&bytes[..bytes.len() - 1]).is_err());
    assert!(parse(b"DIRC\0\0\0\x05\0\0\0\0").is_err());
    assert!(parse(b"not an index").is_err());
    // An entry whose file is absent is a change; an entry whose path
    // leaves the work tree is refused.
    let mut entries = parse(&bytes).unwrap();
    fs::remove_file(home.path.join("Code/repo/a/d.txt")).unwrap();
    let changed = compare(
        &entries,
        &home.path.join("Code/repo"),
        i64::MAX,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    assert!(changed.changed >= 1);
    entries[0].path = b"../outside".to_vec();
    assert_eq!(
        compare(
            &entries,
            &home.path.join("Code/repo"),
            i64::MAX,
            std::time::Instant::now() + Duration::from_secs(10),
        ),
        Err("index_path_not_plain")
    );
}

#[test]
fn a_local_edit_that_skip_worktree_hides_is_a_change() {
    let home = Home::new();
    home.repository();
    home.worktree("hidden");
    home.git(
        "Code/hidden",
        &["update-index", "--skip-worktree", "README"],
    );
    home.settle(&["hidden"]);
    home.write(
        "Code/hidden/README",
        b"a local edit that Git does not show\n",
    );
    let inspection: WorktreeInspection = home.inspect();
    let hidden = worktree(&inspection, "hidden");
    assert_eq!(hidden.staged_changes, Evidence::Known(false));
    assert_eq!(hidden.changed_files, Evidence::Known(1));
    assert_eq!(hidden.verdict, WorktreeVerdict::HasWork);
}

#[test]
fn a_worktree_in_a_user_exclusion_is_not_read() {
    let home = Home::new();
    home.repository();
    home.git(
        "Code/repo",
        &["worktree", "add", "-q", "-b", "private", "../../Private/wt"],
    );
    let exclusions: Vec<PathBuf> = vec![home.path.join("Private")];
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let inspection: WorktreeInspection = registry.worktrees().inspect(
        WorktreeHost {
            principal: home.principal,
            locations: &home.locations,
            user_exclusions: &exclusions,
            git: Ok(&home.git),
        },
        &SearchRoots::new(vec![PathBuf::from("Code")]).unwrap(),
        WorktreeLimits::default(),
        &CancellationToken::new(),
    );
    let private = worktree(&inspection, "wt");
    assert_eq!(private.presence, WorktreePresence::Excluded);
    assert!(matches!(private.changed_files, Evidence::Unknown(_)));
    assert!(matches!(private.untracked_files, Evidence::Unknown(_)));
    assert_eq!(private.verdict, WorktreeVerdict::NotKnown);
}

#[test]
fn an_index_with_paths_longer_than_the_bound_is_refused() {
    // A version 2 index with one entry whose path is 5000 bytes.
    let path: Vec<u8> = vec![b'a'; 5000];
    let mut bytes: Vec<u8> = b"DIRC".to_vec();
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 40]);
    bytes.extend_from_slice(&[0; 20]);
    bytes.extend_from_slice(&0x0fff_u16.to_be_bytes());
    bytes.extend_from_slice(&path);
    let size: usize = 62 + path.len();
    bytes.extend(std::iter::repeat_n(0, ((size + 8) & !7) - size));
    bytes.extend_from_slice(&[0; 20]);
    assert_eq!(parse(&bytes), Err("index_paths_too_large"));
}

#[test]
fn the_entries_that_git_ignores_are_reported_apart_from_the_verdict() {
    let home = Home::new();
    home.repository();
    home.worktree("ignored");
    home.settle(&["ignored"]);
    home.write("Code/ignored/debug.log", b"log\n");
    let inspection: WorktreeInspection = home.inspect();
    // A file that Git ignores is reported apart and is not in the
    // verdict; the workflow says that a removal deletes it.
    let ignored = worktree(&inspection, "ignored");
    assert_eq!(ignored.verdict, WorktreeVerdict::NoWorkSeen);
    assert_eq!(
        ignored.ignored_entries,
        Evidence::Known(UntrackedFiles {
            count: 1,
            more: false
        })
    );
    assert!(ignored.owner_workflow.contains("status --ignored"));
}
