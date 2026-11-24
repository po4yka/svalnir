//! Fixture tests of the layouts of game engines, `CLion`, Storybook, Gatsby,
//! and setuptools, of the evidence of an own ignore file, and of the units
//! of nested project directories of `project.dependency-directory`. Each
//! test makes a home directory and disposable Git repositories in a
//! temporary directory.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use svalnir_core::config::{UserLayout, parse_and_validate};

use super::inspect::{has_own_ignore_file, paseo_root, recheck_unit_in};
use super::tests::{Home, no_recency, quiet, refusal, unit};
use super::{
    AgentListing, AgentsRead, BuildProcesses, DirectoryName, IgnoreBasis, LazyAgents, MarkerKind,
    PROJECT_LAYOUTS, PackageCheckouts, ProjectInspection, ProjectLayout, ProjectLimits,
    ProjectMarker, ProjectUnitOutcome, RecheckInput, UnitRecheck, Unmarked, VersionControl,
};
use crate::rules::caches::ReclaimBasis;
use crate::rules::fixture::FixtureEnvironment;
use crate::scan::{ScanClock as _, WallScanClock};

fn is_listed(inspection: &ProjectInspection, path: &Path) -> bool {
    inspection.units.iter().any(|unit| unit.path == path)
}

fn assert_measured(inspection: &ProjectInspection, path: &Path, layout: &str) {
    let report = unit(inspection, path);
    assert_eq!(report.layout, layout, "{}", path.display());
    assert!(
        matches!(report.outcome, ProjectUnitOutcome::Measured(_)),
        "{}: {:?}",
        path.display(),
        report.outcome
    );
}

fn configured(text: &str) -> Vec<UserLayout> {
    let validation = parse_and_validate(text);
    validation
        .config()
        .unwrap_or_else(|| panic!("the document must validate: {:?}", validation.result))
        .cleanup()
        .projects
        .layouts
        .clone()
}

fn inspect_configured(home: &Home, layouts: &[UserLayout]) -> ProjectInspection {
    home.inspect_layouts(
        &quiet(),
        Ok(&home.git),
        ProjectLimits::default(),
        no_recency(),
        &WallScanClock,
        layouts,
    )
}

#[test]
fn the_unity_and_unreal_layouts_need_their_project_files() {
    let home = Home::new();
    let ignore = "/Library/\n/Temp/\n/Logs/\n/Intermediate/\n/DerivedDataCache/\n";
    let unity_files = [
        "ProjectSettings/ProjectVersion.txt",
        "Packages/manifest.json",
    ];
    let unity: PathBuf = home.project_files(
        "unity",
        &unity_files,
        ignore,
        &["Library/ScriptAssemblies/a.dll", "Temp/a", "Logs/a.log"],
    );
    // No package manifest beside the project settings.
    let no_manifest: PathBuf = home.project_files(
        "no-manifest",
        &["ProjectSettings/ProjectVersion.txt"],
        ignore,
        &["Library/a"],
    );
    // No project settings: `Library` is an ordinary directory.
    let plain: PathBuf =
        home.project_files("plain", &["Packages/manifest.json"], ignore, &["Library/a"]);
    let unreal: PathBuf = home.project_files(
        "unreal",
        &["Game.uproject"],
        ignore,
        &["Intermediate/Build/a", "DerivedDataCache/a.udd"],
    );
    let no_uproject: PathBuf =
        home.project_files("no-uproject", &["Game.txt"], ignore, &["Intermediate/a"]);
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_measured(&inspection, &unity.join("Library"), "unity-library");
    assert_measured(&inspection, &unity.join("Temp"), "unity-temp");
    assert_measured(&inspection, &unity.join("Logs"), "unity-logs");
    assert_eq!(
        refusal(unit(&inspection, &no_manifest.join("Library"))),
        "unsupported_layout"
    );
    assert!(!is_listed(&inspection, &plain.join("Library")));
    assert_measured(
        &inspection,
        &unreal.join("Intermediate"),
        "unreal-intermediate",
    );
    assert_measured(
        &inspection,
        &unreal.join("DerivedDataCache"),
        "unreal-derived-data-cache",
    );
    assert!(!is_listed(&inspection, &no_uproject.join("Intermediate")));
    // `UserSettings`, `Saved`, and `Binaries` stay outside the rule.
    home.write("Code/unity/UserSettings/layout.dwlt", b"x");
    home.write("Code/unreal/Saved/Autosaves/a", b"x");
    home.write("Code/unreal/Binaries/Mac/a", b"x");
    let inspection: ProjectInspection = home.inspect(&quiet());
    for path in [
        unity.join("UserSettings"),
        unreal.join("Saved"),
        unreal.join("Binaries"),
    ] {
        assert!(!is_listed(&inspection, &path), "{}", path.display());
    }
}

#[test]
fn the_pattern_layouts_of_setuptools_and_clion_need_their_inner_markers() {
    let home = Home::new();
    let ignore = "*.egg-info/\n/build/\n/cmake-build-*/\n";
    let egg: PathBuf = home.project_files(
        "egg",
        &["setup.py"],
        ignore,
        &["app.egg-info/PKG-INFO", "other.egg-info/SOURCES.txt"],
    );
    // The src layout: the project files are above `src`.
    let src: PathBuf = home.project_files(
        "src",
        &["pyproject.toml"],
        ignore,
        &["src/app.egg-info/PKG-INFO"],
    );
    let clion: PathBuf = home.project_files(
        "clion",
        &["CMakeLists.txt"],
        ignore,
        &[
            "build/CMakeCache.txt",
            "cmake-build-debug/CMakeCache.txt",
            "cmake-build-release/a.o",
        ],
    );
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_measured(&inspection, &egg.join("app.egg-info"), "python-egg-info");
    assert_eq!(
        refusal(unit(&inspection, &egg.join("other.egg-info"))),
        "unsupported_layout"
    );
    assert!(!is_listed(&inspection, &src.join("src/app.egg-info")));
    // `cmake-build-*` never takes `build`, and `build` keeps its layout.
    assert_measured(&inspection, &clion.join("build"), "cmake-build");
    assert_measured(
        &inspection,
        &clion.join("cmake-build-debug"),
        "clion-cmake-build",
    );
    assert_eq!(
        refusal(unit(&inspection, &clion.join("cmake-build-release"))),
        "unsupported_layout"
    );
}

#[test]
fn the_storybook_and_gatsby_layouts_need_their_markers() {
    let home = Home::new();
    let ignore = "/storybook-static/\n/.cache/\n/public/\n";
    let storybook: PathBuf = home.project_files(
        "storybook",
        &[".storybook/main.js", "package.json"],
        ignore,
        &[
            "storybook-static/index.json",
            "storybook-static/iframe.html",
        ],
    );
    let no_index: PathBuf = home.project_files(
        "no-index",
        &[".storybook/main.js"],
        ignore,
        &["storybook-static/iframe.html"],
    );
    let no_config: PathBuf = home.project_files(
        "no-config",
        &["package.json"],
        ignore,
        &["storybook-static/index.json"],
    );
    let gatsby: PathBuf = home.project_files(
        "gatsby",
        &["gatsby-config.ts", "package.json"],
        ignore,
        &[".cache/default-html.js", "public/page-data/app-data.json"],
    );
    let develop_only: PathBuf = home.project_files(
        "develop-only",
        &["gatsby-config.js"],
        ignore,
        &[".cache/api-runner-ssr.js", "public/index.html"],
    );
    // A `.cache` of another tool beside `package.json` is not a unit.
    let node: PathBuf = home.project_files(
        "node",
        &["package.json"],
        ignore,
        &[".cache/default-html.js", "public/page-data/app-data.json"],
    );
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_measured(
        &inspection,
        &storybook.join("storybook-static"),
        "storybook-static",
    );
    assert_eq!(
        refusal(unit(&inspection, &no_index.join("storybook-static"))),
        "unsupported_layout"
    );
    assert_eq!(
        refusal(unit(&inspection, &no_config.join("storybook-static"))),
        "project_marker_missing"
    );
    assert_measured(&inspection, &gatsby.join(".cache"), "gatsby-cache");
    assert_measured(&inspection, &gatsby.join("public"), "gatsby-public");
    for path in [develop_only.join(".cache"), develop_only.join("public")] {
        assert_eq!(
            refusal(unit(&inspection, &path)),
            "unsupported_layout",
            "{}",
            path.display()
        );
    }
    assert!(!is_listed(&inspection, &node.join(".cache")));
    assert!(!is_listed(&inspection, &node.join("public")));
}

#[test]
fn a_user_layout_of_a_new_table_name_comes_after_the_table_layout() {
    let home = Home::new();
    let ignore = "/storybook-static/\n";
    let storybook: PathBuf = home.project_files(
        "storybook",
        &[".storybook/main.js"],
        ignore,
        &["storybook-static/index.json"],
    );
    // The table layout has its marker and refuses the unit: the user
    // layout does not give it a second chance.
    let refused: PathBuf = home.project_files(
        "refused",
        &[".storybook/main.js"],
        ignore,
        &["storybook-static/a"],
    );
    let other: PathBuf = home.project_files("other", &["sb.toml"], ignore, &["storybook-static/a"]);
    let layouts: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"storybook-static\"\nmarkers = [\".storybook/\", \"sb.toml\"]\n",
    );
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);
    assert_measured(
        &inspection,
        &storybook.join("storybook-static"),
        "storybook-static",
    );
    let report = unit(&inspection, &refused.join("storybook-static"));
    assert_eq!(report.layout, "storybook-static");
    assert_eq!(refusal(report), "unsupported_layout");
    assert_measured(
        &inspection,
        &other.join("storybook-static"),
        "user-configured",
    );
    // `public` is a protected name of the home directory, so no layout of
    // the configuration names it; only `gatsby-public` has it.
    assert!(
        parse_and_validate(
            "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"public\"\nmarkers = [\"site.toml\"]\n"
        )
        .config()
        .is_none()
    );
}

#[test]
fn a_profile_of_nix_direnv_is_a_protected_path() {
    let home = Home::new();
    for profile in ["flake-profile-a1b2", "nix-profile-2.4-abcd"] {
        let project: PathBuf = home.project_files(
            profile,
            &[".envrc"],
            "/.direnv/\n",
            &[".direnv/CACHEDIR.TAG", ".direnv/bin/a"],
        );
        symlink(
            "/nix/store/x-profile",
            project.join(".direnv").join(profile),
        )
        .unwrap();
        let inspection: ProjectInspection = home.inspect(&quiet());
        let report = unit(&inspection, &project.join(".direnv"));
        assert_eq!(refusal(report), "protected_child", "{profile}");
        assert_eq!(report.protected_child, Some(PathBuf::from(profile)));
    }
}

// ---------------------------------------------------------------------
// The evidence of an own ignore file.
// ---------------------------------------------------------------------

/// A project at `Code/NAME` with the marker `marker`, an ignore file of
/// the project that does not name the unit `directory`, one commit, and
/// the unit with the ignore file `ignore` and one file.
fn self_ignored(home: &Home, name: &str, marker: &str, directory: &str, ignore: &[u8]) -> PathBuf {
    let project: PathBuf = home.project_files(name, &[marker], "/other/\n", &[]);
    home.write(
        &format!("Code/{name}/{directory}/data/file.bin"),
        b"generated\n",
    );
    home.write(&format!("Code/{name}/{directory}/.gitignore"), ignore);
    project.join(directory)
}

const OWN_FILE_BASIS: Option<VersionControl> = Some(VersionControl::Ignored {
    basis: IgnoreBasis::OwnIgnoreFile,
});

#[test]
fn a_unit_that_its_own_ignore_file_ignores_is_measured() {
    let home = Home::new();
    let pixi: PathBuf = self_ignored(&home, "pixi", "pixi.toml", ".pixi", b"*\n!config.toml\n");
    let elixir: PathBuf = self_ignored(&home, "elixir", "mix.exs", ".elixir_ls", b"*");
    let lexical: PathBuf = self_ignored(&home, "lexical", "mix.exs", ".lexical", b"*\n");
    let expert: PathBuf = self_ignored(&home, "expert", "mix.exs", ".expert", b"*\n");
    // Pixi with the configuration of a person: the protected path refuses
    // it before the Git queries.
    let config: PathBuf = self_ignored(&home, "config", "pixi.toml", ".pixi", b"*\n!config.toml\n");
    home.write("Code/config/.pixi/config.toml", b"[mirrors]\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    for (path, layout) in [
        (&pixi, "pixi"),
        (&elixir, "elixir-ls"),
        (&lexical, "lexical"),
        (&expert, "expert"),
    ] {
        assert_measured(&inspection, path, layout);
        assert_eq!(unit(&inspection, path).version_control, OWN_FILE_BASIS);
    }
    let report = unit(&inspection, &config);
    assert_eq!(refusal(report), "protected_child");
    assert_eq!(report.version_control, None);
}

#[test]
fn the_own_ignore_file_needs_no_tracked_and_no_untracked_entry() {
    let home = Home::new();
    // A tracked file in the unit.
    let tracked: PathBuf = self_ignored(&home, "tracked", "mix.exs", ".elixir_ls", b"*\n");
    home.git("Code/tracked", &["add", "-f", ".elixir_ls/data/file.bin"]);
    home.git("Code/tracked", &["commit", "-q", "-m", "add"]);
    // An untracked entry that Git does not ignore.
    let untracked: PathBuf = self_ignored(
        &home,
        "untracked",
        "mix.exs",
        ".elixir_ls",
        b"*\n!keep.txt\n",
    );
    home.write("Code/untracked/.elixir_ls/keep.txt", b"keep\n");
    // A first rule that is not `*`.
    let other_rule: PathBuf =
        self_ignored(&home, "other-rule", "mix.exs", ".elixir_ls", b"*.log\n*\n");
    // A layout with no permission for the evidence.
    let node: PathBuf = self_ignored(&home, "node", "package.json", "node_modules", b"*\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &tracked);
    assert_eq!(refusal(report), "tracked_files");
    assert_eq!(report.version_control, Some(VersionControl::Tracked));
    for path in [&untracked, &other_rule, &node] {
        let report = unit(&inspection, path);
        assert_eq!(refusal(report), "not_ignored", "{}", path.display());
        assert_eq!(report.version_control, Some(VersionControl::NotIgnored));
    }
    // A unit that a rule above it ignores keeps the basis of the rules.
    fs::write(home.path.join("Code/node/.gitignore"), b"/node_modules/\n").unwrap();
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_eq!(
        unit(&inspection, &node).version_control,
        Some(VersionControl::Ignored {
            basis: IgnoreBasis::IgnoreRules
        })
    );
}

/// A layout that permits the evidence of an own ignore file, with no inner
/// marker, and the same layout with no permission.
static OWN_FILE_TABLE: [ProjectLayout; 2] = [
    synthetic(".tool-state", "tool-state", true),
    synthetic(".tool-cache", "tool-cache", false),
];

const fn synthetic(directory: &'static str, layout: &'static str, own: bool) -> ProjectLayout {
    ProjectLayout {
        directory,
        layout,
        project_markers: &[ProjectMarker {
            name: "tool.cfg",
            kind: MarkerKind::File,
        }],
        inner_marker: None,
        project_file: None,
        protected: &[],
        name: DirectoryName::Distinctive,
        unmarked: Unmarked::Never,
        checkouts: PackageCheckouts::None,
        own_ignore_file: own,
        reclaim: ReclaimBasis::AllocatedBytes,
        owner_workflow: "A test layout.",
        rebuild_impact: "A test layout.",
    }
}

#[test]
fn the_own_ignore_file_is_a_regular_file_whose_first_rule_is_a_star() {
    let home = Home::new();
    let commented: PathBuf = self_ignored(
        &home,
        "commented",
        "tool.cfg",
        ".tool-state",
        b"# Made by the tool.\n\n*\n",
    );
    let not_permitted: PathBuf = self_ignored(&home, "plain", "tool.cfg", ".tool-cache", b"*\n");
    // The ignore file is a symbolic link to a file with the rule `*`.
    let linked: PathBuf = self_ignored(&home, "linked", "tool.cfg", ".tool-state", b"x\n");
    home.write("Code/elsewhere/ignore", b"*\n");
    fs::remove_file(linked.join(".gitignore")).unwrap();
    symlink(
        home.path.join("Code/elsewhere/ignore"),
        linked.join(".gitignore"),
    )
    .unwrap();
    let inspection: ProjectInspection = home.inspect_table(&OWN_FILE_TABLE, &[], false);
    assert_measured(&inspection, &commented, "tool-state");
    assert_eq!(
        unit(&inspection, &commented).version_control,
        OWN_FILE_BASIS
    );
    for path in [&not_permitted, &linked] {
        assert_eq!(
            refusal(unit(&inspection, path)),
            "not_ignored",
            "{}",
            path.display()
        );
    }
    assert!(has_own_ignore_file(&commented));
    assert!(!has_own_ignore_file(&linked));
    // A file larger than the bound is not read.
    let mut large: Vec<u8> = b"*\n".to_vec();
    large.resize(8 * 1024, b'#');
    fs::write(commented.join(".gitignore"), &large).unwrap();
    assert!(!has_own_ignore_file(&commented));
}

// ---------------------------------------------------------------------
// The checks before a step.
// ---------------------------------------------------------------------

fn complete(evidence: &FixtureEnvironment) -> BuildProcesses {
    BuildProcesses {
        processes: Vec::new(),
        incomplete: None,
        observed_at: evidence.now().monotonic_ns,
    }
}

fn recheck_with(
    home: &Home,
    table: &'static [ProjectLayout],
    layout: &str,
    unit: &Path,
    user_layouts: &[UserLayout],
) -> UnitRecheck {
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(&evidence);
    recheck_unit_in(
        table,
        &RecheckInput {
            principal: home.principal,
            layout,
            root: &home.path.join("Code"),
            unit,
            user_layouts,
            processes: &none,
            now: evidence.now().monotonic_ns,
            expiry: super::PROJECT_EVIDENCE_EXPIRY,
            git: Some(&home.git),
            admitted: &[],
            agents: &AgentListing::Off,
        },
    )
}

fn recheck(home: &Home, layout: &str, unit: &Path, user_layouts: &[UserLayout]) -> UnitRecheck {
    recheck_with(home, &PROJECT_LAYOUTS, layout, unit, user_layouts)
}

#[test]
fn the_check_before_a_step_asks_git_again_for_an_own_ignore_file() {
    let home = Home::new();
    // Basis `own_ignore_file`.
    let own: PathBuf = self_ignored(&home, "own", "mix.exs", ".elixir_ls", b"*\n");
    assert_eq!(recheck(&home, "elixir-ls", &own, &[]), UnitRecheck::Passed);
    // A negation and an entry that Git does not ignore, after the plan.
    fs::write(own.join(".gitignore"), b"*\n!keep.txt\n").unwrap();
    fs::write(own.join("keep.txt"), b"keep\n").unwrap();
    assert_eq!(
        recheck(&home, "elixir-ls", &own, &[]),
        UnitRecheck::Refused("not_ignored")
    );
    // A tracked file.
    fs::write(own.join(".gitignore"), b"*\n").unwrap();
    fs::remove_file(own.join("keep.txt")).unwrap();
    home.git("Code/own", &["add", "-f", ".elixir_ls/data/file.bin"]);
    assert_eq!(
        recheck(&home, "elixir-ls", &own, &[]),
        UnitRecheck::Refused("tracked_files")
    );
    // Basis `ignore_rules`: the rules of the project ignore the unit, so an
    // own file that does not start with `*` does not refuse it.
    let rules: PathBuf = home.project_files(
        "rules",
        &["mix.exs"],
        "/.lexical/\n",
        &[".lexical/.gitignore", ".lexical/project.log"],
    );
    let lexical: PathBuf = rules.join(".lexical");
    fs::write(lexical.join(".gitignore"), b"project.log\n").unwrap();
    assert_eq!(
        recheck(&home, "lexical", &lexical, &[]),
        UnitRecheck::Passed
    );
    // With no Git executable the evidence is not known.
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(&evidence);
    let input = RecheckInput {
        principal: home.principal,
        layout: "lexical",
        root: &home.path.join("Code"),
        unit: &lexical,
        user_layouts: &[],
        processes: &none,
        now: evidence.now().monotonic_ns,
        expiry: super::PROJECT_EVIDENCE_EXPIRY,
        git: None,
        admitted: &[],
        agents: &AgentListing::Off,
    };
    assert_eq!(
        recheck_unit_in(&PROJECT_LAYOUTS, &input),
        UnitRecheck::Unknown("version_control_unknown")
    );
    // A failed query (an index that Git cannot read) is not known.
    fs::write(home.path.join("Code/rules/.git/index"), b"not an index").unwrap();
    assert_eq!(
        recheck(&home, "lexical", &lexical, &[]),
        UnitRecheck::Unknown("version_control_unknown")
    );
    // A symbolic link is not the file of the producer; the inner marker
    // `.gitignore` of the layout refuses it first.
    fs::remove_file(own.join(".gitignore")).unwrap();
    home.write("Code/elsewhere/ignore", b"*\n");
    symlink(
        home.path.join("Code/elsewhere/ignore"),
        own.join(".gitignore"),
    )
    .unwrap();
    assert_eq!(
        recheck(&home, "elixir-ls", &own, &[]),
        UnitRecheck::Refused("unsupported_layout")
    );
    // A layout with no inner marker: the link is not an own ignore file.
    let state: PathBuf = self_ignored(&home, "tool", "tool.cfg", ".tool-state", b"*\n");
    assert_eq!(
        recheck_with(&home, &OWN_FILE_TABLE, "tool-state", &state, &[]),
        UnitRecheck::Passed
    );
    fs::remove_file(state.join(".gitignore")).unwrap();
    symlink(
        home.path.join("Code/elsewhere/ignore"),
        state.join(".gitignore"),
    )
    .unwrap();
    assert_eq!(
        recheck_with(&home, &OWN_FILE_TABLE, "tool-state", &state, &[]),
        UnitRecheck::Refused("not_ignored")
    );
}

/// The check before a step of `unit` with the Paseo listing `agents`.
fn recheck_agents(home: &Home, unit: &Path, agents: &dyn AgentsRead) -> UnitRecheck {
    let evidence = FixtureEnvironment::days_later(0);
    let none: BuildProcesses = complete(&evidence);
    recheck_unit_in(
        &PROJECT_LAYOUTS,
        &RecheckInput {
            principal: home.principal,
            layout: "elixir-ls",
            root: &home.path.join("Code"),
            unit,
            user_layouts: &[],
            processes: &none,
            now: evidence.now().monotonic_ns,
            expiry: super::PROJECT_EVIDENCE_EXPIRY,
            git: Some(&home.git),
            admitted: &[],
            agents,
        },
    )
}

fn busy(paths: &[&Path]) -> AgentListing {
    AgentListing::Listed {
        busy: paths.iter().map(|path| path.to_path_buf()).collect(),
    }
}

#[test]
fn the_check_before_a_step_asks_paseo_again() {
    let home = Home::new();
    let unit: PathBuf = self_ignored(&home, "own", "mix.exs", ".elixir_ls", b"*\n");
    let project: PathBuf = home.path.join("Code/own");
    let code: PathBuf = home.path.join("Code");
    // The source is off, or no agent runs.
    assert_eq!(
        recheck_agents(&home, &unit, &AgentListing::Off),
        UnitRecheck::Passed
    );
    assert_eq!(
        recheck_agents(&home, &unit, &busy(&[])),
        UnitRecheck::Passed
    );
    // An agent in the project root or below it refuses the unit.
    for directory in [project.clone(), project.join("src"), unit.clone()] {
        assert_eq!(
            recheck_agents(&home, &unit, &busy(&[&directory])),
            UnitRecheck::Refused("agent_running"),
            "{}",
            directory.display()
        );
    }
    // An agent in a sibling project or above the project root does not.
    let sibling: PathBuf = code.join("own-two");
    assert_eq!(
        recheck_agents(&home, &unit, &busy(&[&sibling, &code, &home.path])),
        UnitRecheck::Passed
    );
    // A failed listing is not known.
    assert_eq!(
        recheck_agents(
            &home,
            &unit,
            &AgentListing::Failed {
                reason: "paseo_timeout"
            }
        ),
        UnitRecheck::Unknown("paseo_timeout")
    );
}

#[test]
fn the_paseo_root_is_the_nearest_directory_with_a_git_entry_below_the_search_root() {
    let home = Home::new();
    let code: PathBuf = home.path.join("Code");
    // A repository with a project directory below it.
    home.repository("Code/mono");
    home.write("Code/mono/pkg/app/mix.exs", b"marker\n");
    let app: PathBuf = code.join("mono/pkg/app");
    assert_eq!(paseo_root(&app, &code).unwrap(), code.join("mono"));
    // A `.git` file, as of a linked work tree, also counts.
    home.write("Code/mono/pkg/.git", b"gitdir: ../../elsewhere\n");
    assert_eq!(paseo_root(&app, &code).unwrap(), code.join("mono/pkg"));
    // With no `.git` entry, the project directory is the root; the search
    // root itself is not searched above.
    home.write("Code/plain/mix.exs", b"marker\n");
    let plain: PathBuf = code.join("plain");
    assert_eq!(paseo_root(&plain, &code).unwrap(), plain);
    assert_eq!(paseo_root(&code, &code).unwrap(), code);
}

#[test]
fn a_failed_lookup_of_the_git_entry_is_not_a_missing_entry() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = Home::new();
    let code: PathBuf = home.path.join("Code");
    home.write("Code/locked/mix.exs", b"marker\n");
    let locked: PathBuf = code.join("locked");
    // A directory that can be read but not searched: the stat of `.git`
    // in it fails with a permission error.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
    let result = paseo_root(&locked, &code);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_err());
}

#[test]
fn the_paseo_listing_is_read_once_and_only_for_a_unit_that_is_there() {
    use std::cell::Cell;
    let home = Home::new();
    let unit: PathBuf = self_ignored(&home, "own", "mix.exs", ".elixir_ls", b"*\n");
    let calls: Cell<usize> = Cell::new(0);
    let lazy = LazyAgents::new(|| {
        calls.set(calls.get() + 1);
        AgentListing::Off
    });
    // An absent unit ends the check before the listing.
    let absent: PathBuf = home.path.join("Code/own/.missing");
    assert_eq!(recheck_agents(&home, &absent, &lazy), UnitRecheck::Absent);
    assert_eq!(calls.get(), 0);
    // A refusal by a cheaper check does not ask for it either.
    let other = home.path.join("Code/own/src");
    fs::create_dir_all(&other).unwrap();
    assert_ne!(recheck_agents(&home, &other, &lazy), UnitRecheck::Passed);
    assert_eq!(calls.get(), 0);
    // A unit that passes asks once, however often the evidence is read.
    assert_eq!(recheck_agents(&home, &unit, &lazy), UnitRecheck::Passed);
    assert_eq!(recheck_agents(&home, &unit, &lazy), UnitRecheck::Passed);
    assert_eq!(calls.get(), 1);
}

#[test]
fn a_cut_list_of_untracked_entries_is_not_an_own_ignore_file() {
    let home = Home::new();
    let cut: PathBuf = self_ignored(&home, "cut", "mix.exs", ".elixir_ls", b"*\n!*.txt\n");
    // More names than the output bound of a query holds.
    for index in 0..80 {
        fs::write(cut.join(format!("{index:03}-{}.txt", "n".repeat(60))), b"x").unwrap();
    }
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &cut);
    assert_eq!(refusal(report), "not_ignored");
    assert_eq!(
        recheck(&home, "elixir-ls", &cut, &[]),
        UnitRecheck::Refused("not_ignored")
    );
}

// ---------------------------------------------------------------------
// The units of nested project directories (independent reviews of
// `a6274a4` and of `2f00eee`).
// ---------------------------------------------------------------------

const VAR_CACHE_LAYOUTS: &str = "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"cache\"\nmarkers = [\"log/\"]\n\n[[cleanup.projects.layouts]]\ndirectory = \"cache/dev\"\nmarkers = [\"log/\"]\n";

/// A Symfony project whose cache holds sessions, with `var/log`.
fn symfony(home: &Home) -> PathBuf {
    home.project_files(
        "sf",
        &["symfony.lock", "bin/console", "var/log/dev.log"],
        "/var/cache/\n",
        &["var/cache/dev/sessions/sess_a", "var/cache/dev/a.php"],
    )
}

/// The reports of the directory `path`.
fn reports_of<'a>(
    inspection: &'a ProjectInspection,
    path: &Path,
) -> Vec<&'a super::ProjectUnitReport> {
    inspection
        .units
        .iter()
        .filter(|unit| unit.path == path)
        .collect()
}

#[test]
fn a_directory_that_two_layouts_claim_is_refused_for_both() {
    let home = Home::new();
    let project: PathBuf = symfony(&home);
    // sbt: `project/target` of the build, and `project` has a build file of
    // its own.
    let sbt: PathBuf = home.project_files(
        "sbt",
        &["build.sbt", "project/build.sbt"],
        "target/\n",
        &["project/target/a.class"],
    );
    // sbt with no build file in `project`: one unit.
    let one: PathBuf = home.project_files(
        "one",
        &["build.sbt"],
        "target/\n",
        &["project/target/a.class"],
    );
    let layouts: Vec<UserLayout> = configured(VAR_CACHE_LAYOUTS);
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);
    let cache: PathBuf = project.join("var/cache");
    let reports = reports_of(&inspection, &cache);
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].layout, "symfony-var-cache");
    assert_eq!(reports[1].layout, "user-configured");
    for report in &reports {
        assert_eq!(refusal(report), "overlaps_unit");
    }
    assert_eq!(reports[0].overlapping_layout, Some("user-configured"));
    assert_eq!(reports[1].overlapping_layout, Some("symfony-var-cache"));
    // A unit of the nested project in the earlier unit is refused.
    let inner = unit(&inspection, &project.join("var/cache/dev"));
    assert_eq!(refusal(inner), "overlaps_unit");
    assert_eq!(inner.overlapping_layout, Some("symfony-var-cache"));
    let reports = reports_of(&inspection, &sbt.join("project/target"));
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].layout, "sbt-meta-target");
    assert_eq!(reports[1].layout, "sbt-target");
    for report in &reports {
        assert_eq!(refusal(report), "overlaps_unit");
    }
    let reports = reports_of(&inspection, &one.join("project/target"));
    assert_eq!(reports.len(), 1);
    assert!(matches!(
        reports[0].outcome,
        ProjectUnitOutcome::Measured(_)
    ));
}

#[test]
fn the_check_before_a_step_refuses_a_directory_that_two_layouts_claim() {
    let home = Home::new();
    let project: PathBuf = symfony(&home);
    let layouts: Vec<UserLayout> = configured(VAR_CACHE_LAYOUTS);
    let cache: PathBuf = project.join("var/cache");
    // The table layout of the project above claims the directory.
    assert_eq!(
        recheck(&home, "user-configured", &cache, &layouts),
        UnitRecheck::Refused("overlaps_unit")
    );
    assert_eq!(
        recheck(&home, "user-configured", &cache.join("dev"), &layouts),
        UnitRecheck::Refused("overlaps_unit")
    );
    // The user layout of the nested project claims the unit of the table
    // layout.
    fs::remove_dir_all(cache.join("dev/sessions")).unwrap();
    assert_eq!(
        recheck(&home, "symfony-var-cache", &cache, &layouts),
        UnitRecheck::Refused("overlaps_unit")
    );
    assert_eq!(
        recheck(&home, "symfony-var-cache", &cache, &[]),
        UnitRecheck::Passed
    );
    // With no marker of the table layout, `cache` of the nested project
    // passes, and `cache/dev` is in the earlier unit `cache` of the same
    // project.
    fs::remove_file(project.join("symfony.lock")).unwrap();
    assert_eq!(
        recheck(&home, "user-configured", &cache, &layouts),
        UnitRecheck::Passed
    );
    assert_eq!(
        recheck(&home, "user-configured", &cache.join("dev"), &layouts),
        UnitRecheck::Refused("overlaps_unit")
    );
    // sbt: both claims of `project/target` are refused; with no build file
    // in `project`, `sbt-meta-target` passes.
    home.write("Code/sbt/build.sbt", b"x");
    home.write("Code/sbt/project/build.sbt", b"x");
    home.write("Code/sbt/project/target/a.class", b"x");
    let target: PathBuf = home.path.join("Code/sbt/project/target");
    for layout in ["sbt-target", "sbt-meta-target"] {
        assert_eq!(
            recheck(&home, layout, &target, &[]),
            UnitRecheck::Refused("overlaps_unit"),
            "{layout}"
        );
    }
    fs::remove_file(home.path.join("Code/sbt/project/build.sbt")).unwrap();
    assert_eq!(
        recheck(&home, "sbt-meta-target", &target, &[]),
        UnitRecheck::Passed
    );
}

#[test]
fn the_check_before_a_step_keeps_the_first_user_layout_with_its_marker() {
    let home = Home::new();
    home.write("Code/c/premake5.lua", b"x");
    home.write("Code/c/meson.build", b"x");
    home.write("Code/c/build/a.o", b"x");
    let layouts: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"build\"\nmarkers = [\"premake5.lua\"]\nprotected = [\"keep\"]\n\n[[cleanup.projects.layouts]]\ndirectory = \"b?ild\"\nmarkers = [\"meson.build\"]\n",
    );
    let build: PathBuf = home.path.join("Code/c/build");
    assert_eq!(
        recheck(&home, "user-configured", &build, &layouts),
        UnitRecheck::Passed
    );
    // The first layout refuses the unit now: the second one, with no
    // protected path, does not let it pass.
    home.write("Code/c/build/keep", b"x");
    assert_eq!(
        recheck(&home, "user-configured", &build, &layouts),
        UnitRecheck::Refused("protected_child")
    );
}

#[test]
fn an_inner_marker_path_is_reached_through_plain_directories_only() {
    let home = Home::new();
    let project: PathBuf = home.project_files(
        "php",
        &["composer.json", "composer.lock"],
        "/vendor/\n",
        &["vendor/acme/lib/a.php", "elsewhere/installed.json"],
    );
    symlink(project.join("elsewhere"), project.join("vendor/composer")).unwrap();
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_eq!(
        refusal(unit(&inspection, &project.join("vendor"))),
        "unsupported_layout"
    );
    assert_eq!(
        recheck(&home, "composer-vendor", &project.join("vendor"), &[]),
        UnitRecheck::Refused("unsupported_layout")
    );
    // The same file in a plain directory is the inner marker.
    fs::remove_file(project.join("vendor/composer")).unwrap();
    home.write("Code/php/vendor/composer/installed.json", b"{}");
    assert_eq!(
        recheck(&home, "composer-vendor", &project.join("vendor"), &[]),
        UnitRecheck::Passed
    );
}
