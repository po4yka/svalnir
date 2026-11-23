//! Fixture tests of the layout catalog of `project.dependency-directory`
//! and of the layouts of the configuration. Each test makes a home
//! directory and disposable Git repositories in a temporary directory.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use svalnir_core::config::{UserLayout, parse_and_validate};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{LifecycleState, RuleMode, RuleRefusal, RuleRegistry};

use super::DirectoryName::Distinctive;
use super::inspect::{ChildSearch, find_protected, glob_matches};
use super::tests::{Home, no_recency, quiet, refusal, unit};
use super::{
    DirectoryName, MarkerKind, PROJECT_LAYOUT_COUNT, PROJECT_LAYOUTS, PackageCheckouts,
    ProjectInspection, ProjectLayout, ProjectLimits, ProjectMarker, ProjectUnitOutcome, Unmarked,
};
use crate::rules::ReviewedRules;
use crate::rules::caches::ReclaimBasis;
use crate::rules::fixture::{automatic_eviction_validated, manual_action_validated};
use crate::rules::nested_git::RefusalReason;
use crate::scan::WallScanClock;

/// The entry to make for a marker of the catalog: a pattern gets a name
/// that matches it.
fn marker_name(marker: &ProjectMarker) -> String {
    marker.name.replace('*', "App")
}

/// Makes the marker `marker` in the project `project`.
fn make_marker(home: &Home, project: &str, marker: &ProjectMarker) {
    let name: String = marker_name(marker);
    match marker.kind {
        MarkerKind::File => {
            home.write(&format!("{project}/{name}"), b"marker\n");
        }
        MarkerKind::Directory => {
            home.write(
                &format!("{project}/{name}/contents.xcworkspacedata"),
                b"<x/>\n",
            );
        }
    }
}

/// A project at `Code/p-NAME` with the first marker of the layout of
/// `directory`, an ignore file for the directory, one commit, and a unit
/// with one file and the inner marker `inner`.
fn project_with(
    home: &Home,
    name: &str,
    marker: &ProjectMarker,
    directory: &str,
    inner: Option<&str>,
) -> PathBuf {
    // A prefix keeps the name of the project from being the name of a
    // layout, for example `zig-cache`.
    let project: String = format!("Code/p-{name}");
    make_marker(home, &project, marker);
    home.write(
        &format!("{project}/.gitignore"),
        format!("/{directory}/\n").as_bytes(),
    );
    home.repository(&project);
    home.write(
        &format!("{project}/{directory}/data/file.bin"),
        b"generated\n",
    );
    if let Some(inner) = inner {
        home.write(&format!("{project}/{directory}/{inner}"), b"tag\n");
    }
    if let Some(file) = project_file(directory, marker) {
        home.write(&format!("{project}/{file}"), b"{}");
    }
    home.path.join(project)
}

/// The project file of the layout of `directory` with the first marker
/// `marker`, when it has one.
fn project_file(directory: &str, marker: &ProjectMarker) -> Option<&'static str> {
    PROJECT_LAYOUTS
        .iter()
        .find(|layout| layout.directory == directory && layout.project_markers[0] == *marker)
        .and_then(|layout| layout.project_file)
}

#[test]
fn the_bin_directory_of_dotnet_needs_the_restore_output_beside_it() {
    let home = Home::new();
    for project in ["Code/a", "Code/b", "Code/c"] {
        home.write(&format!("{project}/App.csproj"), b"<Project/>\n");
        home.write(&format!("{project}/.gitignore"), b"/bin/\n/obj/\n");
        home.repository(project);
        home.write(&format!("{project}/bin/Debug/app.dll"), b"1\n");
    }
    home.write("Code/a/obj/project.assets.json", b"{}");
    // The file is a directory, or is reached through a symbolic link.
    fs::create_dir_all(home.path.join("Code/b/obj/project.assets.json")).unwrap();
    home.write("Code/elsewhere/project.assets.json", b"{}");
    symlink(
        home.path.join("Code/elsewhere"),
        home.path.join("Code/c/obj"),
    )
    .unwrap();
    let inspection: ProjectInspection = home.inspect(&quiet());
    let bin = unit(&inspection, &home.path.join("Code/a/bin"));
    assert_eq!(bin.layout, "dotnet-bin");
    assert!(matches!(bin.outcome, ProjectUnitOutcome::Measured(_)));
    for project in ["Code/b", "Code/c"] {
        assert_eq!(
            refusal(unit(&inspection, &home.path.join(project).join("bin"))),
            "unsupported_layout",
            "{project}"
        );
    }
}

#[test]
fn each_layout_of_the_catalog_keeps_the_bounds_of_the_walk() {
    use svalnir_core::config::{
        KEPT_OUT_LAYOUT_NAMES, MAX_LAYOUT_DIRECTORY_NAMES, SKIPPED_DIRECTORY_NAMES,
    };
    for layout in &PROJECT_LAYOUTS {
        let names: Vec<&str> = layout.directory.split('/').collect();
        assert!(
            (1..=MAX_LAYOUT_DIRECTORY_NAMES).contains(&names.len()),
            "{}",
            layout.layout
        );
        // Only the first name can be a pattern.
        assert!(
            names[1..].iter().all(|name| !name.contains(['*', '?'])),
            "{}",
            layout.layout
        );
        // A pattern never matches a name that the rule keeps out or a name
        // of the skip list.
        if names[0].contains(['*', '?']) {
            for refused in KEPT_OUT_LAYOUT_NAMES
                .iter()
                .chain(SKIPPED_DIRECTORY_NAMES.iter())
            {
                assert!(
                    !glob_matches(names[0].as_bytes(), refused.as_bytes(), true),
                    "{} matches {refused}",
                    layout.layout
                );
            }
        }
        // No first name is a name of the table "Names that stay outside the
        // rule" with no layout, or a name of the skip list other than
        // `.cache`.
        for refused in ["zig-out", "deps", ".git", ".hg", ".jj", ".svn"] {
            assert!(!names[0].eq_ignore_ascii_case(refused), "{}", layout.layout);
        }
        // A layout of `.cache` needs a marker; a distinctive name with no
        // marker would make each shared cache directory listed.
        if names[0].eq_ignore_ascii_case(".cache") {
            assert_eq!(layout.name, DirectoryName::Generic, "{}", layout.layout);
        }
    }
}

#[test]
fn the_unmarked_layouts_are_the_reviewed_distinctive_layouts() {
    let unmarked: Vec<(&str, &str)> = PROJECT_LAYOUTS
        .iter()
        .filter_map(|layout| match layout.unmarked {
            Unmarked::Never => None,
            Unmarked::ManualOnly { layout: name } => Some((layout.layout, name)),
        })
        .collect();
    let expected: [&str; 10] = [
        "python-venv",
        "mypy-cache",
        "pytest-cache",
        "ruff-cache",
        "tox",
        "gradle-project-cache",
        "next-build",
        "astro",
        "svelte-kit",
        "parcel-cache",
    ];
    let mut layouts: Vec<&str> = unmarked.iter().map(|(layout, _)| *layout).collect();
    layouts.sort_unstable();
    let mut sorted: Vec<&str> = expected.to_vec();
    sorted.sort_unstable();
    assert_eq!(layouts, sorted);
    for (layout, name) in unmarked {
        assert_eq!(
            name,
            format!("{layout}{}", svalnir_core::rule::UNMARKED_LAYOUT_SUFFIX)
        );
        assert!(svalnir_core::rule::is_manual_only_layout(name));
        let entry = PROJECT_LAYOUTS
            .iter()
            .find(|entry| entry.layout == layout)
            .unwrap();
        assert_eq!(entry.name, Distinctive, "{layout}");
    }
    // `.build`, `DerivedData`, and each generic name have no unmarked
    // units.
    for layout in PROJECT_LAYOUTS.iter().filter(|layout| {
        layout.name == DirectoryName::Generic
            || matches!(layout.directory, ".build" | "DerivedData")
    }) {
        assert_eq!(layout.unmarked, Unmarked::Never, "{}", layout.layout);
    }
}

/// The layouts of the configuration document `text`.
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

fn is_listed(inspection: &ProjectInspection, path: &Path) -> bool {
    inspection.units.iter().any(|unit| unit.path == path)
}

#[test]
fn each_layout_of_the_catalog_is_a_unit_with_its_marker() {
    let home = Home::new();
    let mut expected: Vec<(PathBuf, &str)> = Vec::new();
    for layout in &PROJECT_LAYOUTS {
        let project: PathBuf = project_with(
            &home,
            layout.layout,
            &layout.project_markers[0],
            layout.directory,
            layout.inner_marker,
        );
        expected.push((project.join(layout.directory), layout.layout));
    }
    let inspection: ProjectInspection = home.inspect(&quiet());
    for (path, layout) in expected {
        let report = unit(&inspection, &path);
        assert_eq!(report.layout, layout, "{}", path.display());
        assert!(
            matches!(report.outcome, ProjectUnitOutcome::Measured(_)),
            "{layout}: {:?}",
            report.outcome
        );
        assert_eq!(report.protected_child, None);
    }
    // The inspection changed nothing.
    assert!(
        home.path
            .join("Code/p-node-modules/node_modules/data/file.bin")
            .exists()
    );
}

#[test]
fn each_layout_with_an_inner_marker_needs_it() {
    let home = Home::new();
    let mut expected: Vec<PathBuf> = Vec::new();
    for layout in PROJECT_LAYOUTS
        .iter()
        .filter(|layout| layout.inner_marker.is_some())
    {
        let project: PathBuf = project_with(
            &home,
            layout.layout,
            &layout.project_markers[0],
            layout.directory,
            None,
        );
        expected.push(project.join(layout.directory));
    }
    assert!(expected.len() >= 8);
    let inspection: ProjectInspection = home.inspect(&quiet());
    for path in expected {
        assert_eq!(
            refusal(unit(&inspection, &path)),
            "unsupported_layout",
            "{}",
            path.display()
        );
    }
}

#[test]
fn a_distinctive_name_with_no_marker_is_refused_and_a_generic_name_is_entered() {
    let home = Home::new();
    home.write("Code/n1/.gitignore", b".next/\n");
    home.repository("Code/n1");
    home.write("Code/n1/.next/cache/a", b"1\n");
    // A generic name with no marker is an ordinary directory, which can
    // hold a project.
    home.write("Code/g1/.gitignore", b"node_modules/\n");
    home.repository("Code/g1");
    home.write("Code/g1/build/package.json", b"{}");
    home.write("Code/g1/build/node_modules/a/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let next = unit(&inspection, &home.path.join("Code/n1/.next"));
    assert_eq!(next.layout, "next-build");
    assert_eq!(refusal(next), "project_marker_missing");
    assert!(!is_listed(&inspection, &home.path.join("Code/g1/build")));
    assert!(matches!(
        unit(&inspection, &home.path.join("Code/g1/build/node_modules")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
}

#[test]
fn a_pattern_marker_matches_a_regular_file_of_its_kind_only() {
    let home = Home::new();
    let gitignore: &[u8] = b"/obj/\n/bin/\n";
    for project in ["Code/dn", "Code/dn2", "Code/dn3", "Code/dn4"] {
        home.write(&format!("{project}/.gitignore"), gitignore);
    }
    home.write("Code/dn/App.csproj", b"<Project/>\n");
    home.write("Code/dn/obj/project.assets.json", b"{}");
    // A directory with the name of the pattern is not a marker.
    home.write("Code/dn2/App.csproj/x", b"1\n");
    home.write("Code/dn2/obj/project.assets.json", b"{}");
    // The marker is present, and the inner marker is not.
    home.write("Code/dn3/Lib.fsproj", b"<Project/>\n");
    home.write("Code/dn3/obj/a.cache", b"1\n");
    // A name that only starts like the pattern does not match it.
    home.write("Code/dn4/App.csproj.bak", b"<Project/>\n");
    home.write("Code/dn4/bin/Debug/app.dll", b"1\n");
    for project in ["Code/dn", "Code/dn2", "Code/dn3", "Code/dn4"] {
        home.repository(project);
    }
    let inspection: ProjectInspection = home.inspect(&quiet());
    let obj = unit(&inspection, &home.path.join("Code/dn/obj"));
    assert_eq!(obj.layout, "dotnet-obj");
    assert!(matches!(obj.outcome, ProjectUnitOutcome::Measured(_)));
    assert!(!is_listed(&inspection, &home.path.join("Code/dn2/obj")));
    assert_eq!(
        refusal(unit(&inspection, &home.path.join("Code/dn3/obj"))),
        "unsupported_layout"
    );
    assert!(!is_listed(&inspection, &home.path.join("Code/dn4/bin")));
}

#[test]
fn a_committed_directory_of_a_generic_layout_is_not_a_candidate() {
    let home = Home::new();
    home.write("Code/lib/package.json", b"{}");
    home.write("Code/lib/dist/index.js", b"1;\n");
    home.repository("Code/lib");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let report = unit(&inspection, &home.path.join("Code/lib/dist"));
    assert_eq!(report.layout, "node-dist");
    assert_eq!(refusal(report), "tracked_files");
}

#[test]
fn a_protected_child_refuses_the_unit() {
    let home = Home::new();
    for project in ["Code/m1", "Code/m2", "Code/m3"] {
        home.write(&format!("{project}/mix.exs"), b"defmodule A do end\n");
        home.write(&format!("{project}/.gitignore"), b"/_build/\n");
        home.repository(project);
    }
    home.write("Code/m1/_build/prod/rel/app/bin/app", b"#!/bin/sh\n");
    home.write("Code/m2/_build/dev/lib/dep/src/a.erl", b"-module(a).\n");
    home.write("Code/m3/_build/dev/lib/app/ebin/a.beam", b"beam\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let release = unit(&inspection, &home.path.join("Code/m1/_build"));
    assert_eq!(release.layout, "mix-build");
    assert_eq!(refusal(release), "protected_child");
    assert_eq!(release.protected_child, Some(PathBuf::from("prod/rel")));
    // No evidence after the refusal: the checks stop at it.
    assert_eq!(release.version_control, None);
    let sources = unit(&inspection, &home.path.join("Code/m2/_build"));
    assert_eq!(refusal(sources), "protected_child");
    assert_eq!(
        sources.protected_child,
        Some(PathBuf::from("dev/lib/dep/src"))
    );
    assert!(matches!(
        unit(&inspection, &home.path.join("Code/m3/_build")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
}

#[test]
fn the_search_for_a_protected_child_follows_no_link_and_ignores_case() {
    let directory = tempfile::TempDir::new().unwrap();
    let base: PathBuf = fs::canonicalize(directory.path()).unwrap();
    let unit: PathBuf = base.join("unit");
    fs::create_dir_all(base.join("outside/rel")).unwrap();
    fs::create_dir_all(&unit).unwrap();
    symlink(base.join("outside"), unit.join("prod")).unwrap();
    // A symbolic link on the way is not entered.
    assert_eq!(find_protected(&unit, &["prod/rel"]), ChildSearch::Clear);
    fs::create_dir_all(unit.join("Dev/REL")).unwrap();
    assert_eq!(
        find_protected(&unit, &["*/rel"]),
        ChildSearch::Found(PathBuf::from("Dev/REL"))
    );
    // The last component matches an entry of each type, also a link.
    assert_eq!(
        find_protected(&unit, &["prod"]),
        ChildSearch::Found(PathBuf::from("prod"))
    );
    assert_eq!(find_protected(&unit, &[]), ChildSearch::Clear);
    // A directory on the way that cannot be read makes the result unknown.
    assert_eq!(
        find_protected(&unit.join("absent"), &["x"]),
        ChildSearch::Unknown
    );
}

#[test]
fn a_pattern_matches_by_byte() {
    assert!(glob_matches(b"*.csproj", b"App.csproj", false));
    assert!(glob_matches(b"*.csproj", b".csproj", false));
    assert!(!glob_matches(b"*.csproj", b"App.csproj.bak", false));
    assert!(!glob_matches(b"*.csproj", b"App.CSPROJ", false));
    assert!(glob_matches(b"*.csproj", b"App.CSPROJ", true));
    assert!(glob_matches(b"a?c", b"abc", false));
    assert!(!glob_matches(b"a?c", b"ac", false));
    assert!(glob_matches(b"*", b"", false));
    assert!(glob_matches(b"*/lib", b"*/lib", false));
    assert!(glob_matches(b"a*b*c", b"aXbYbZc", false));
    assert!(!glob_matches(b"a*b*c", b"aXbYbZ", false));
    assert!(!glob_matches(b"rel", b"release", false));
}

#[test]
fn a_directory_of_two_names_needs_plain_directories_on_the_way() {
    let home = Home::new();
    for project in ["Code/r1", "Code/r2", "Code/r3"] {
        home.write(&format!("{project}/Gemfile"), b"source 'x'\n");
        home.write(&format!("{project}/.gitignore"), b"/vendor/bundle/\n");
        home.repository(project);
    }
    home.write("Code/r1/vendor/bundle/ruby/3.3/gems/x.rb", b"1\n");
    home.write("Code/elsewhere/bundle/x.rb", b"1\n");
    symlink(
        home.path.join("Code/elsewhere"),
        home.path.join("Code/r2/vendor"),
    )
    .unwrap();
    fs::create_dir_all(home.path.join("Code/r3/vendor")).unwrap();
    let inspection: ProjectInspection = home.inspect(&quiet());
    let bundle = unit(&inspection, &home.path.join("Code/r1/vendor/bundle"));
    assert_eq!(bundle.layout, "bundler-vendor");
    assert_eq!(bundle.project, home.path.join("Code/r1"));
    assert!(matches!(bundle.outcome, ProjectUnitOutcome::Measured(_)));
    assert_eq!(
        refusal(unit(&inspection, &home.path.join("Code/r2/vendor/bundle"))),
        "unit_path_not_plain"
    );
    assert!(!is_listed(
        &inspection,
        &home.path.join("Code/r3/vendor/bundle")
    ));
    // The walk does not report the unit a second time from `vendor`.
    assert_eq!(
        inspection
            .units
            .iter()
            .filter(|unit| unit.path.ends_with("vendor/bundle"))
            .count(),
        2
    );
}

#[test]
fn the_first_layout_with_a_marker_gives_the_unit() {
    let home = Home::new();
    home.write("Code/b/build.gradle", b"plugins {}\n");
    home.write("Code/b/pyproject.toml", b"[project]\n");
    home.write("Code/b/.gitignore", b"/build/\n");
    home.repository("Code/b");
    home.write("Code/b/build/libs/app.jar", b"jar\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_eq!(
        unit(&inspection, &home.path.join("Code/b/build")).layout,
        "gradle-build"
    );
}

#[test]
fn the_walk_does_not_enter_a_directory_of_the_skip_list() {
    let home = Home::new();
    for skipped in [".cache", ".hg", ".svn", ".jj"] {
        home.write(&format!("Code/{skipped}/p/package.json"), b"{}");
        home.write(
            &format!("Code/{skipped}/p/node_modules/a/index.js"),
            b"1;\n",
        );
    }
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert_eq!(inspection.units, []);
}

#[test]
fn a_build_directory_of_swift_package_manager_has_the_exception_for_its_checkouts() {
    let home = Home::new();
    home.write("Code/sp/Package.swift", b"// swift-tools-version:5.9\n");
    home.write("Code/sp/.gitignore", b"/.build/\n");
    home.repository("Code/sp");
    home.write("Code/sp/.build/workspace-state.json", b"{}");
    home.write("Code/sp/.build/checkouts/dep/Sources/a.swift", b"//\n");
    home.repository("Code/sp/.build/checkouts/dep");
    let inspection: ProjectInspection = home.inspect(&quiet());
    // The checkout is examined with the pins, and the project has no
    // `Package.resolved`.
    let ProjectUnitOutcome::RepositoryRefused(refused) =
        &unit(&inspection, &home.path.join("Code/sp/.build")).outcome
    else {
        panic!("not refused");
    };
    assert_eq!(refused.reason, RefusalReason::PinsUnavailable);
    // A repository outside `checkouts` has no exception.
    home.write("Code/sp/.build/other/repo/a", b"1\n");
    home.repository("Code/sp/.build/other/repo");
    fs::remove_dir_all(home.path.join("Code/sp/.build/checkouts")).unwrap();
    let inspection: ProjectInspection = home.inspect(&quiet());
    let ProjectUnitOutcome::RepositoryRefused(refused) =
        &unit(&inspection, &home.path.join("Code/sp/.build")).outcome
    else {
        panic!("not refused");
    };
    assert_eq!(refused.reason, RefusalReason::NestedRepository);
}

const USER_LAYOUTS: &str = "schema_version = 1

[[cleanup.projects.layouts]]
directory = \"builddir\"
markers = [\"meson.build\"]
protected = [\"keep\"]
quiet_period = \"2h\"

[[cleanup.projects.layouts]]
directory = \"gen\"
markers = [\"meson.build\"]

[[cleanup.projects.layouts]]
directory = \"gen/cache\"
markers = [\"meson.build\"]
";

#[test]
fn a_layout_of_the_configuration_has_each_check() {
    let home = Home::new();
    let layouts: Vec<UserLayout> = configured(USER_LAYOUTS);
    for project in ["Code/u1", "Code/u2", "Code/u4", "Code/u5"] {
        home.write(&format!("{project}/meson.build"), b"project('a')\n");
        home.write(&format!("{project}/.gitignore"), b"/builddir/\n/gen/\n");
    }
    for project in ["Code/u1", "Code/u2", "Code/u4", "Code/u5"] {
        home.repository(project);
    }
    home.write("Code/u1/builddir/a.o", b"o\n");
    home.write("Code/u2/builddir/keep/notes.txt", b"mine\n");
    home.write("Code/u3/builddir/a.o", b"o\n");
    home.write("Code/u4/gen/a.o", b"o\n");
    home.write("Code/u4/gen/cache/b.o", b"o\n");
    // A directory of the layout that Git does not ignore.
    home.write("Code/u6/meson.build", b"project('a')\n");
    home.repository("Code/u6");
    home.write("Code/u6/builddir/a.o", b"o\n");
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);

    let measured = unit(&inspection, &home.path.join("Code/u1/builddir"));
    assert_eq!(measured.layout, "user-configured");
    assert!(matches!(measured.outcome, ProjectUnitOutcome::Measured(_)));
    // The quiet period of the layout replaces the period of the table.
    assert_eq!(
        measured
            .recency
            .as_ref()
            .map(|recency| recency.quiet_period),
        Some(Nanoseconds::new(2 * 3_600_000_000_000))
    );
    let protected = unit(&inspection, &home.path.join("Code/u2/builddir"));
    assert_eq!(refusal(protected), "protected_child");
    assert_eq!(protected.protected_child, Some(PathBuf::from("keep")));
    assert!(!is_listed(&inspection, &home.path.join("Code/u3/builddir")));
    // One directory is never in two units: the earlier layout measures it,
    // and the unit in it is refused.
    let outer = unit(&inspection, &home.path.join("Code/u4/gen"));
    assert!(matches!(outer.outcome, ProjectUnitOutcome::Measured(_)));
    let inner = unit(&inspection, &home.path.join("Code/u4/gen/cache"));
    assert_eq!(refusal(inner), "overlaps_unit");
    assert_eq!(inner.overlapping_layout, Some("user-configured"));
    assert_eq!(inner.version_control, None);
    assert_eq!(
        refusal(unit(&inspection, &home.path.join("Code/u6/builddir"))),
        "not_ignored"
    );
    // The layout name is in the report with its lifecycle state.
    assert!(inspection.layouts.iter().any(|layout| {
        layout.layout == "user-configured" && layout.lifecycle == LifecycleState::Proposed
    }));
    // With no layout of the configuration, the directory is ordinary.
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert!(!is_listed(&inspection, &home.path.join("Code/u1/builddir")));
}

#[test]
fn a_layout_of_the_configuration_permits_no_automatic_mode() {
    let registry: ReviewedRules = ReviewedRules::new().unwrap();
    let rule = registry.projects().rule();
    for mode in RuleMode::ALL {
        assert_eq!(
            registry
                .resolve(&rule.reference, "user-configured", &mode)
                .err(),
            Some(RuleRefusal::ModeNotValidated)
        );
    }
    // A fixture lifecycle gives the layout at most a manual state, and no
    // state of it can permit an automatic mode.
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(&state).unwrap();
        let rule = registry.projects().rule();
        let support = rule
            .layouts
            .iter()
            .find(|layout| layout.layout == "user-configured")
            .unwrap();
        assert_eq!(support.lifecycle, manual_action_validated());
        assert!(support.permits(&RuleMode::ManualEviction));
        assert!(!support.permits(&RuleMode::AutomaticEviction));
        assert_eq!(
            registry
                .resolve(
                    &rule.reference,
                    "user-configured",
                    &RuleMode::AutomaticEviction
                )
                .err(),
            Some(RuleRefusal::ModeNotValidated)
        );
    }
    let promoted = svalnir_core::rule::LayoutSupport {
        layout: "user-configured".to_owned(),
        lifecycle: manual_action_validated(),
    };
    assert!(promoted.permits(&RuleMode::ManualEviction));
    assert!(!promoted.permits(&RuleMode::AutomaticEviction));
}

#[test]
fn each_layout_name_of_the_catalog_is_unique() {
    let mut names: Vec<&str> = PROJECT_LAYOUTS.iter().map(|layout| layout.layout).collect();
    names.sort_unstable();
    let count: usize = names.len();
    names.dedup();
    assert_eq!(names.len(), count);
    assert_eq!(count, PROJECT_LAYOUT_COUNT);
}

/// The directories of the catalog, each one time, in the sequence of the
/// catalog.
fn directories() -> Vec<&'static str> {
    let mut directories: Vec<&'static str> = Vec::new();
    for layout in &PROJECT_LAYOUTS {
        if !directories.contains(&layout.directory) {
            directories.push(layout.directory);
        }
    }
    directories
}

#[test]
fn each_directory_of_the_catalog_with_no_marker_is_refused_or_ordinary() {
    let home = Home::new();
    let mut projects: Vec<(PathBuf, &str)> = Vec::new();
    for (index, directory) in directories().into_iter().enumerate() {
        let project: String = format!("Code/n{index}");
        home.write(
            &format!("{project}/.gitignore"),
            format!("/{directory}/\n").as_bytes(),
        );
        home.repository(&project);
        home.write(
            &format!("{project}/{directory}/data/file.bin"),
            b"generated\n",
        );
        projects.push((home.path.join(project).join(directory), directory));
    }
    let inspection: ProjectInspection = home.inspect(&quiet());
    for (path, directory) in projects {
        // The first distinctive layout of the directory gives the refused
        // unit; a directory of generic layouts only is not listed.
        match PROJECT_LAYOUTS
            .iter()
            .find(|layout| layout.directory == directory && layout.name == Distinctive)
        {
            Some(layout) => {
                let report = unit(&inspection, &path);
                assert_eq!(report.layout, layout.layout, "{directory}");
                assert_eq!(refusal(report), "project_marker_missing", "{directory}");
            }
            None => assert!(!is_listed(&inspection, &path), "{directory}"),
        }
    }
}

#[test]
fn each_protected_path_of_the_catalog_refuses_the_unit() {
    let home = Home::new();
    let mut expected: Vec<(PathBuf, &str, String)> = Vec::new();
    for layout in &PROJECT_LAYOUTS {
        for (index, protected) in layout.protected.iter().enumerate() {
            let project: PathBuf = project_with(
                &home,
                &format!("{}-{index}", layout.layout),
                &layout.project_markers[0],
                layout.directory,
                layout.inner_marker,
            );
            // Each pattern component gets a name that matches it.
            let child: String = protected.replace('*', "x");
            fs::create_dir_all(project.join(layout.directory)).unwrap();
            let entry: PathBuf = project.join(layout.directory).join(&child);
            fs::create_dir_all(entry.parent().unwrap()).unwrap();
            fs::write(&entry, b"keep\n").unwrap();
            expected.push((project.join(layout.directory), layout.layout, child));
        }
    }
    assert!(expected.len() >= 12);
    let inspection: ProjectInspection = home.inspect(&quiet());
    for (path, layout, child) in expected {
        let report = unit(&inspection, &path);
        assert_eq!(report.layout, layout);
        assert_eq!(refusal(report), "protected_child", "{layout}: {child}");
        assert_eq!(report.protected_child, Some(PathBuf::from(&child)));
    }
}

#[test]
fn each_layout_with_a_project_file_needs_it() {
    let home = Home::new();
    let mut expected: Vec<(PathBuf, &str)> = Vec::new();
    for layout in PROJECT_LAYOUTS
        .iter()
        .filter(|layout| layout.project_file.is_some())
    {
        let project: PathBuf = project_with(
            &home,
            layout.layout,
            &layout.project_markers[0],
            layout.directory,
            layout.inner_marker,
        );
        if let Some(file) = layout.project_file {
            fs::remove_file(project.join(file)).unwrap();
        }
        expected.push((project.join(layout.directory), layout.layout));
    }
    assert!(expected.len() >= 6);
    let inspection: ProjectInspection = home.inspect(&quiet());
    for (path, layout) in expected {
        let report = unit(&inspection, &path);
        assert_eq!(report.layout, layout);
        assert_eq!(refusal(report), "unsupported_layout", "{layout}");
    }
}

/// One case of layouts with the same directory: the markers in the
/// project, and the layout that gives the unit.
struct SharedName {
    directory: &'static str,
    markers: &'static [&'static str],
    layout: &'static str,
}

const SHARED_NAMES: &[SharedName] = &[
    SharedName {
        directory: "target",
        markers: &["Cargo.toml", "pom.xml", "build.sbt"],
        layout: "cargo-target",
    },
    SharedName {
        directory: "target",
        markers: &["pom.xml", "build.sbt"],
        layout: "maven-target",
    },
    SharedName {
        directory: "target",
        markers: &["build.sbt"],
        layout: "sbt-target",
    },
    SharedName {
        directory: "build",
        markers: &["build.gradle", "pubspec.yaml", "CMakeLists.txt", "Makefile"],
        layout: "gradle-build",
    },
    SharedName {
        directory: "build",
        markers: &["pyproject.toml", "CMakeLists.txt"],
        layout: "setuptools-build",
    },
    SharedName {
        directory: "build",
        markers: &["pubspec.yaml", "CMakeLists.txt", "Makefile"],
        layout: "flutter-build",
    },
    SharedName {
        directory: "build",
        markers: &["CMakeLists.txt", "Makefile"],
        layout: "cmake-build",
    },
    SharedName {
        directory: "build",
        markers: &["Makefile"],
        layout: "sphinx-build-separate",
    },
    SharedName {
        directory: "_build",
        markers: &["mix.exs", "dune-project", "conf.py"],
        layout: "mix-build",
    },
    SharedName {
        directory: "_build",
        markers: &["dune-project", "conf.py"],
        layout: "dune-build",
    },
    SharedName {
        directory: "_build",
        markers: &["conf.py"],
        layout: "sphinx-build",
    },
    SharedName {
        directory: ".output",
        markers: &["nuxt.config.ts", "nitro.config.ts"],
        layout: "nuxt-output",
    },
    SharedName {
        directory: ".output",
        markers: &["nitro.config.ts"],
        layout: "nitro-output",
    },
    SharedName {
        directory: ".stack-work",
        markers: &["stack.yaml", "package.yaml"],
        layout: "stack-work",
    },
    SharedName {
        directory: ".stack-work",
        markers: &["app.cabal"],
        layout: "stack-work-package",
    },
];

#[test]
fn the_first_layout_of_a_shared_name_with_a_marker_gives_the_unit() {
    let home = Home::new();
    let mut expected: Vec<(PathBuf, &str)> = Vec::new();
    for (index, case) in SHARED_NAMES.iter().enumerate() {
        let project: String = format!("Code/s{index}");
        for marker in case.markers {
            home.write(&format!("{project}/{marker}"), b"marker\n");
        }
        home.write(
            &format!("{project}/.gitignore"),
            format!("/{}/\n", case.directory).as_bytes(),
        );
        home.repository(&project);
        home.write(
            &format!("{project}/{}/data/file.bin", case.directory),
            b"generated\n",
        );
        expected.push((home.path.join(project).join(case.directory), case.layout));
    }
    let inspection: ProjectInspection = home.inspect(&quiet());
    for (path, layout) in expected {
        assert_eq!(
            unit(&inspection, &path).layout,
            layout,
            "{}",
            path.display()
        );
    }
}

#[test]
fn vendor_is_a_unit_of_composer_only() {
    let home = Home::new();
    // Composer, with a package of a path repository as a symbolic link.
    home.write("Code/php/composer.json", b"{}");
    home.write("Code/php/composer.lock", b"{}");
    home.write("Code/php/.gitignore", b"/vendor/\n");
    home.write("Code/php/packages/lib/src/A.php", b"<?php\n");
    home.repository("Code/php");
    home.write("Code/php/vendor/composer/installed.json", b"{}");
    home.write("Code/php/vendor/acme/other/src/B.php", b"<?php\n");
    symlink(
        home.path.join("Code/php/packages/lib"),
        home.path.join("Code/php/vendor/acme/lib"),
    )
    .unwrap();
    // Go: `vendor` is an ordinary directory.
    home.write("Code/go/go.mod", b"module a\n");
    home.write("Code/go/.gitignore", b"/vendor/\n");
    home.repository("Code/go");
    home.write("Code/go/vendor/modules.txt", b"# a\n");
    // Bundler and Composer: `vendor/bundle` comes first, and `vendor`
    // overlaps its unit.
    home.write("Code/both/Gemfile", b"source 'x'\n");
    home.write("Code/both/composer.json", b"{}");
    home.write("Code/both/composer.lock", b"{}");
    home.write("Code/both/.gitignore", b"/vendor/\n");
    home.repository("Code/both");
    home.write("Code/both/vendor/bundle/ruby/a.rb", b"1\n");
    home.write("Code/both/vendor/composer/installed.json", b"{}");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let composer = unit(&inspection, &home.path.join("Code/php/vendor"));
    assert_eq!(composer.layout, "composer-vendor");
    assert!(
        matches!(composer.outcome, ProjectUnitOutcome::Measured(_)),
        "{:?}",
        composer.outcome
    );
    assert!(!is_listed(&inspection, &home.path.join("Code/go/vendor")));
    assert_eq!(
        unit(&inspection, &home.path.join("Code/both/vendor/bundle")).layout,
        "bundler-vendor"
    );
    let overlap = unit(&inspection, &home.path.join("Code/both/vendor"));
    assert_eq!(overlap.layout, "composer-vendor");
    assert_eq!(refusal(overlap), "overlaps_unit");
    assert_eq!(overlap.overlapping_layout, Some("bundler-vendor"));
    // The inspection changed nothing, also not the target of the link.
    assert!(home.path.join("Code/php/packages/lib/src/A.php").exists());
}

#[test]
fn a_committed_cache_of_yarn_zero_install_is_refused() {
    let home = Home::new();
    home.write("Code/zero/.yarnrc.yml", b"enableGlobalCache: false\n");
    home.write(
        "Code/zero/.gitignore",
        b".yarn/*\n!.yarn/cache\n!.yarn/releases\n",
    );
    home.write("Code/zero/.yarn/cache/left-pad-1.0.0-abc.zip", b"zip\n");
    home.write("Code/zero/.yarn/releases/yarn-4.19.0.cjs", b"//\n");
    home.repository("Code/zero");
    home.write("Code/zero/.yarn/unplugged/fsevents/index.js", b"1;\n");
    let inspection: ProjectInspection = home.inspect(&quiet());
    let cache = unit(&inspection, &home.path.join("Code/zero/.yarn/cache"));
    assert_eq!(cache.layout, "yarn-cache");
    assert_eq!(refusal(cache), "tracked_files");
    let unplugged = unit(&inspection, &home.path.join("Code/zero/.yarn/unplugged"));
    assert_eq!(unplugged.layout, "yarn-unplugged");
    assert!(matches!(unplugged.outcome, ProjectUnitOutcome::Measured(_)));
    // `.yarn` itself and its releases are never a unit.
    assert!(!is_listed(&inspection, &home.path.join("Code/zero/.yarn")));
    assert!(!is_listed(
        &inspection,
        &home.path.join("Code/zero/.yarn/releases")
    ));
}

// ---------------------------------------------------------------------
// The capabilities of the walk, with synthetic layouts of a table that
// the test gives (no layout of `PROJECT_LAYOUTS` is needed).
// ---------------------------------------------------------------------

/// A synthetic layout of a table for a test.
const fn synthetic(
    directory: &'static str,
    layout: &'static str,
    project_markers: &'static [ProjectMarker],
    name: DirectoryName,
) -> ProjectLayout {
    ProjectLayout {
        directory,
        layout,
        project_markers,
        inner_marker: None,
        project_file: None,
        protected: &[],
        name,
        unmarked: Unmarked::Never,
        checkouts: PackageCheckouts::None,
        reclaim: ReclaimBasis::AllocatedBytes,
        owner_workflow: "A test layout.",
        rebuild_impact: "A test layout.",
    }
}

const fn file_marker(name: &'static str) -> ProjectMarker {
    ProjectMarker {
        name,
        kind: MarkerKind::File,
    }
}

const fn directory_marker(name: &'static str) -> ProjectMarker {
    ProjectMarker {
        name,
        kind: MarkerKind::Directory,
    }
}

static SUBDIRECTORY_MARKER: [ProjectLayout; 1] = [synthetic(
    "UnityTemp",
    "unity-temp",
    &[file_marker("ProjectSettings/ProjectVersion.txt")],
    Distinctive,
)];

#[test]
fn a_marker_in_a_subdirectory_needs_plain_directories_on_its_way() {
    let home = Home::new();
    let ignore = "/UnityTemp/\n";
    let generated = ["UnityTemp/a.bin"];
    let good: PathBuf = home.project_files(
        "good",
        &["ProjectSettings/ProjectVersion.txt"],
        ignore,
        &generated,
    );
    // The directory on the way is a symbolic link to a directory with the
    // file.
    home.write("Code/elsewhere/ProjectVersion.txt", b"m_EditorVersion\n");
    let linked: PathBuf = home.project_files("linked", &[], ignore, &generated);
    symlink(
        home.path.join("Code/elsewhere"),
        linked.join("ProjectSettings"),
    )
    .unwrap();
    // The last name is a directory, or a symbolic link to a file.
    let directory: PathBuf = home.project_files(
        "directory",
        &["ProjectSettings/ProjectVersion.txt/x"],
        ignore,
        &generated,
    );
    let link: PathBuf = home.project_files("link", &["ProjectSettings/other"], ignore, &generated);
    symlink(
        link.join("ProjectSettings/other"),
        link.join("ProjectSettings/ProjectVersion.txt"),
    )
    .unwrap();
    let inspection: ProjectInspection = home.inspect_table(&SUBDIRECTORY_MARKER, &[], false);
    let report = unit(&inspection, &good.join("UnityTemp"));
    assert_eq!(report.layout, "unity-temp");
    assert!(
        matches!(report.outcome, ProjectUnitOutcome::Measured(_)),
        "{:?}",
        report.outcome
    );
    for project in [&linked, &directory, &link] {
        assert_eq!(
            refusal(unit(&inspection, &project.join("UnityTemp"))),
            "project_marker_missing",
            "{}",
            project.display()
        );
    }
    // A layout of the configuration has the same check.
    let layouts: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"Obj2\"\nmarkers = [\"ProjectSettings/ProjectVersion.txt\"]\n",
    );
    for project in [&good, &linked] {
        home.write(
            &format!(
                "{}/Obj2/a.bin",
                project.strip_prefix(&home.path).unwrap().display()
            ),
            b"x",
        );
        fs::write(project.join(".gitignore"), "/UnityTemp/\n/Obj2/\n").unwrap();
    }
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);
    assert!(matches!(
        unit(&inspection, &good.join("Obj2")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
    // A generic name with no marker is not listed.
    assert!(!is_listed(&inspection, &linked.join("Obj2")));
}

static PATTERN_NAMES: [ProjectLayout; 3] = [
    synthetic(
        "out-cache",
        "out-cache",
        &[file_marker("a.cfg")],
        Distinctive,
    ),
    synthetic(
        "*-cache",
        "pattern-cache",
        &[file_marker("b.cfg")],
        DirectoryName::Generic,
    ),
    synthetic(
        "*.egg-info",
        "egg-info",
        &[file_marker("setup.py")],
        DirectoryName::Generic,
    ),
];

#[test]
fn a_pattern_name_gives_units_and_the_first_layout_with_a_marker_wins() {
    let home = Home::new();
    let ignore = "*-cache/\n*-CACHE/\n*.egg-info/\n";
    let pattern: PathBuf = home.project_files("one", &["b.cfg"], ignore, &["x-cache/a"]);
    // A literal layout of the table and the pattern both match `out-cache`.
    let both: PathBuf = home.project_files("both", &["a.cfg", "b.cfg"], ignore, &["out-cache/a"]);
    let second: PathBuf = home.project_files("second", &["b.cfg"], ignore, &["out-cache/a"]);
    let neither: PathBuf = home.project_files("neither", &[], ignore, &["out-cache/a"]);
    // The comparison keeps the case.
    let case: PathBuf = home.project_files("case", &["b.cfg"], ignore, &["Y-CACHE/a"]);
    let egg: PathBuf = home.project_files("egg", &["setup.py"], ignore, &["pkg.egg-info/PKG-INFO"]);
    // A generic pattern name with no marker is an ordinary directory: the
    // walk enters it.
    let entered: PathBuf = home.project_files(
        "entered",
        &[],
        ignore,
        &["z-cache/inner/b.cfg", "z-cache/inner/q-cache/a"],
    );
    let inspection: ProjectInspection = home.inspect_table(&PATTERN_NAMES, &[], false);
    let measured = |path: &Path, layout: &str| {
        let report = unit(&inspection, path);
        assert_eq!(report.layout, layout, "{}", path.display());
        assert!(
            matches!(report.outcome, ProjectUnitOutcome::Measured(_)),
            "{}: {:?}",
            path.display(),
            report.outcome
        );
    };
    measured(&pattern.join("x-cache"), "pattern-cache");
    measured(&both.join("out-cache"), "out-cache");
    measured(&second.join("out-cache"), "pattern-cache");
    measured(&egg.join("pkg.egg-info"), "egg-info");
    measured(&entered.join("z-cache/inner/q-cache"), "pattern-cache");
    assert_eq!(
        refusal(unit(&inspection, &neither.join("out-cache"))),
        "project_marker_missing"
    );
    assert!(!is_listed(&inspection, &case.join("Y-CACHE")));
    assert!(!is_listed(&inspection, &entered.join("z-cache")));
    // Each directory is one unit.
    let units: Vec<&Path> = inspection
        .units
        .iter()
        .map(|unit| unit.path.as_path())
        .collect();
    let mut unique: Vec<&Path> = units.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(units.len(), unique.len());
}

static SKIP_PATTERN: [ProjectLayout; 1] = [synthetic(
    ".c*",
    "dot-c",
    &[file_marker("m.cfg")],
    Distinctive,
)];

#[test]
fn a_pattern_name_never_matches_a_name_of_the_skip_list() {
    let home = Home::new();
    let project: PathBuf =
        home.project_files("app", &["m.cfg"], ".c*/\n", &[".cache/a", ".cargo-home/a"]);
    let inspection: ProjectInspection = home.inspect_table(&SKIP_PATTERN, &[], false);
    assert!(!is_listed(&inspection, &project.join(".cache")));
    assert!(matches!(
        unit(&inspection, &project.join(".cargo-home")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
}

static DIRECTORY_MARKER: [ProjectLayout; 1] = [synthetic(
    "storybook-static",
    "storybook-static",
    &[directory_marker(".storybook")],
    Distinctive,
)];

#[test]
fn a_directory_marker_is_a_directory_and_not_a_link() {
    let home = Home::new();
    let ignore = "/storybook-static/\n/sb-out/\n";
    let generated = ["storybook-static/index.html", "sb-out/index.html"];
    let good: PathBuf = home.project_files("good", &[".storybook/main.js"], ignore, &generated);
    let file: PathBuf = home.project_files("file", &[".storybook"], ignore, &generated);
    home.write("Code/elsewhere/main.js", b"x");
    let linked: PathBuf = home.project_files("linked", &[], ignore, &generated);
    symlink(home.path.join("Code/elsewhere"), linked.join(".storybook")).unwrap();
    let inspection: ProjectInspection = home.inspect_table(&DIRECTORY_MARKER, &[], false);
    assert!(matches!(
        unit(&inspection, &good.join("storybook-static")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
    for project in [&file, &linked] {
        assert_eq!(
            refusal(unit(&inspection, &project.join("storybook-static"))),
            "project_marker_missing",
            "{}",
            project.display()
        );
    }
    // A marker of the configuration that ends with `/` is a directory; one
    // with no `/` is a regular file.
    let layouts: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"sb-out\"\nmarkers = [\".storybook/\"]\n",
    );
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);
    assert!(matches!(
        unit(&inspection, &good.join("sb-out")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
    assert!(!is_listed(&inspection, &file.join("sb-out")));
    assert!(!is_listed(&inspection, &linked.join("sb-out")));
    let as_file: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"sb-out\"\nmarkers = [\".storybook\"]\n",
    );
    let inspection: ProjectInspection = inspect_configured(&home, &as_file);
    assert!(!is_listed(&inspection, &good.join("sb-out")));
    assert!(is_listed(&inspection, &file.join("sb-out")));
}

static THREE_NAMES: [ProjectLayout; 1] = [synthetic(
    "storage/framework/cache",
    "laravel-cache",
    &[file_marker("artisan")],
    DirectoryName::Generic,
)];

#[test]
fn a_directory_of_three_names_needs_plain_directories_on_the_way() {
    let home = Home::new();
    let ignore = "/storage/framework/cache/\n/out/a/b/\n";
    let good: PathBuf = home.project_files(
        "good",
        &["artisan", "storage/logs/keep"],
        ignore,
        &["storage/framework/cache/data/a", "out/a/b/c"],
    );
    // The middle name is a symbolic link to a directory of the project.
    let linked: PathBuf = home.project_files(
        "linked",
        &["artisan", "storage/real/cache/keep"],
        ignore,
        &[],
    );
    symlink(
        linked.join("storage/real"),
        linked.join("storage/framework"),
    )
    .unwrap();
    let inspection: ProjectInspection = home.inspect_table(&THREE_NAMES, &[], false);
    assert!(matches!(
        unit(&inspection, &good.join("storage/framework/cache")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
    assert_eq!(
        refusal(unit(&inspection, &linked.join("storage/framework/cache"))),
        "unit_path_not_plain"
    );
    // No leading name is a unit.
    for leading in ["storage", "storage/framework"] {
        assert!(!is_listed(&inspection, &good.join(leading)), "{leading}");
    }
    // A layout of the configuration can have three names.
    let layouts: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"out/a/b\"\nmarkers = [\"artisan\"]\n",
    );
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);
    let report = unit(&inspection, &good.join("out/a/b"));
    assert_eq!(report.layout, "user-configured");
    assert!(matches!(report.outcome, ProjectUnitOutcome::Measured(_)));
}

static CACHE_UNIT: [ProjectLayout; 1] = [synthetic(
    ".cache",
    "tool-cache",
    &[file_marker("tool.cfg")],
    Distinctive,
)];

#[test]
fn a_cache_directory_is_a_unit_only_with_the_marker_of_its_layout() {
    let home = Home::new();
    let marked: PathBuf = home.project_files("marked", &["tool.cfg"], "/.cache/\n", &[".cache/a"]);
    // With no marker, `.cache` is not listed and not entered, also for a
    // distinctive layout: a project in it is not found.
    let unmarked: PathBuf = home.project_files(
        "unmarked",
        &[],
        "/.cache/\n",
        &[".cache/inner/tool.cfg", ".cache/inner/.cache/a"],
    );
    let inspection: ProjectInspection = home.inspect_table(&CACHE_UNIT, &[], true);
    let report = unit(&inspection, &marked.join(".cache"));
    assert_eq!(report.layout, "tool-cache");
    assert!(matches!(report.outcome, ProjectUnitOutcome::Measured(_)));
    assert!(!is_listed(&inspection, &unmarked.join(".cache")));
    assert!(!is_listed(
        &inspection,
        &unmarked.join(".cache/inner/.cache")
    ));
    // The catalog of this build has no layout of `.cache`, so the walk
    // lists none.
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert!(!is_listed(&inspection, &marked.join(".cache")));
}

#[test]
fn a_user_layout_with_a_table_name_loses_to_a_table_layout_with_its_marker() {
    let home = Home::new();
    let ignore = "/build/\n/target/\n";
    let cmake: PathBuf = home.project_files("cmake", &["premake5.lua"], ignore, &["build/a.o"]);
    let gradle: PathBuf = home.project_files(
        "gradle",
        &["premake5.lua", "build.gradle"],
        ignore,
        &["build/a.o"],
    );
    let cargo: PathBuf = home.project_files(
        "cargo",
        &["Cargo.toml", "premake5.lua"],
        ignore,
        &["target/CACHEDIR.TAG", "target/native/a.o"],
    );
    let layouts: Vec<UserLayout> = configured(
        "schema_version = 1\n[[cleanup.projects.layouts]]\ndirectory = \"build\"\nmarkers = [\"premake5.lua\"]\n\n[[cleanup.projects.layouts]]\ndirectory = \"target/native\"\nmarkers = [\"premake5.lua\"]\n",
    );
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);
    let user = unit(&inspection, &cmake.join("build"));
    assert_eq!(user.layout, "user-configured");
    assert!(matches!(user.outcome, ProjectUnitOutcome::Measured(_)));
    let table = unit(&inspection, &gradle.join("build"));
    assert_eq!(table.layout, "gradle-build");
    assert!(matches!(table.outcome, ProjectUnitOutcome::Measured(_)));
    // A user unit in a unit of the table is refused, and only the unit of
    // the table is measured.
    assert!(matches!(
        unit(&inspection, &cargo.join("target")).outcome,
        ProjectUnitOutcome::Measured(_)
    ));
    let inner = unit(&inspection, &cargo.join("target/native"));
    assert_eq!(refusal(inner), "overlaps_unit");
    assert_eq!(inner.overlapping_layout, Some("cargo-target"));
}

#[test]
fn an_unmarked_directory_is_a_unit_only_with_the_option_and_each_other_check() {
    let home = Home::new();
    let ignore = "/.venv/\n/.build/\n/venv/\n";
    let venv: PathBuf = home.project_files(
        "venv",
        &[],
        ignore,
        &[".venv/pyvenv.cfg", ".venv/bin/python"],
    );
    // The inner marker is still required.
    let no_inner: PathBuf = home.project_files("no-inner", &[], ignore, &[".venv/bin/python"]);
    // Git must ignore the directory.
    let not_ignored: PathBuf = home.project_files("not-ignored", &[], "", &[]);
    home.write("Code/not-ignored/.venv/pyvenv.cfg", b"home = /usr\n");
    // `.build` and a generic name have no unmarked units.
    let swift: PathBuf = home.project_files("swift", &[], ignore, &[".build/workspace-state.json"]);
    let plain: PathBuf = home.project_files("plain", &[], ignore, &["venv/pyvenv.cfg"]);
    // Without the option, the behavior is unchanged.
    let inspection: ProjectInspection = home.inspect(&quiet());
    for project in [&venv, &no_inner, &not_ignored] {
        let report = unit(&inspection, &project.join(".venv"));
        assert_eq!(report.layout, "python-venv");
        assert_eq!(report.marker_allowance, None);
        assert_eq!(refusal(report), "project_marker_missing");
    }
    let inspection: ProjectInspection = home.inspect_table(&PROJECT_LAYOUTS, &[], true);
    let report = unit(&inspection, &venv.join(".venv"));
    assert_eq!(report.layout, "python-venv+unmarked");
    assert_eq!(
        report.marker_allowance,
        Some(super::PROJECT_MARKER_ABSENT_ALLOWED)
    );
    assert!(
        matches!(report.outcome, ProjectUnitOutcome::Measured(_)),
        "{:?}",
        report.outcome
    );
    let report = unit(&inspection, &no_inner.join(".venv"));
    assert_eq!(report.layout, "python-venv+unmarked");
    assert_eq!(refusal(report), "unsupported_layout");
    assert_eq!(
        refusal(unit(&inspection, &not_ignored.join(".venv"))),
        "not_ignored"
    );
    let report = unit(&inspection, &swift.join(".build"));
    assert_eq!(report.layout, "swiftpm-build");
    assert_eq!(refusal(report), "project_marker_missing");
    assert!(!is_listed(&inspection, &plain.join("venv")));
    // A directory with its marker keeps its layout with the option.
    let marked: PathBuf =
        home.project_files("marked", &["pyproject.toml"], ignore, &[".venv/pyvenv.cfg"]);
    let inspection: ProjectInspection = home.inspect_table(&PROJECT_LAYOUTS, &[], true);
    let report = unit(&inspection, &marked.join(".venv"));
    assert_eq!(report.layout, "python-venv");
    assert_eq!(report.marker_allowance, None);
}
