//! Fixture tests of the layout catalog of `project.dependency-directory`
//! and of the layouts of the configuration. Each test makes a home
//! directory and disposable Git repositories in a temporary directory.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use svalnir_core::config::{UserLayout, parse_and_validate};
use svalnir_core::quantity::Nanoseconds;
use svalnir_core::rule::{LifecycleState, RuleMode, RuleRefusal, RuleRegistry};

use super::inspect::{ChildSearch, find_protected, glob_matches};
use super::tests::{Home, no_recency, quiet, refusal, unit};
use super::{
    MarkerKind, PROJECT_LAYOUTS, ProjectInspection, ProjectLimits, ProjectMarker,
    ProjectUnitOutcome,
};
use crate::rules::ReviewedRules;
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
    home.path.join(project)
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
directory = \"out\"
markers = [\"meson.build\"]
protected = [\"keep\"]
quiet_period = \"2h\"

[[cleanup.projects.layouts]]
directory = \"build\"
markers = [\"meson.build\"]
";

#[test]
fn a_layout_of_the_configuration_has_each_check() {
    let home = Home::new();
    let layouts: Vec<UserLayout> = configured(USER_LAYOUTS);
    for project in ["Code/u1", "Code/u2", "Code/u4", "Code/u5"] {
        home.write(&format!("{project}/meson.build"), b"project('a')\n");
        home.write(&format!("{project}/.gitignore"), b"/out/\n/build/\n");
    }
    home.write("Code/u5/build.gradle", b"plugins {}\n");
    for project in ["Code/u1", "Code/u2", "Code/u4", "Code/u5"] {
        home.repository(project);
    }
    home.write("Code/u1/out/a.o", b"o\n");
    home.write("Code/u2/out/keep/notes.txt", b"mine\n");
    home.write("Code/u3/out/a.o", b"o\n");
    home.write("Code/u4/build/a.o", b"o\n");
    home.write("Code/u5/build/a.o", b"o\n");
    // A directory of the layout that Git does not ignore.
    home.write("Code/u6/meson.build", b"project('a')\n");
    home.repository("Code/u6");
    home.write("Code/u6/out/a.o", b"o\n");
    let inspection: ProjectInspection = inspect_configured(&home, &layouts);

    let measured = unit(&inspection, &home.path.join("Code/u1/out"));
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
    let protected = unit(&inspection, &home.path.join("Code/u2/out"));
    assert_eq!(refusal(protected), "protected_child");
    assert_eq!(protected.protected_child, Some(PathBuf::from("keep")));
    assert!(!is_listed(&inspection, &home.path.join("Code/u3/out")));
    assert_eq!(
        unit(&inspection, &home.path.join("Code/u4/build")).layout,
        "user-configured"
    );
    // A layout of the catalog comes first.
    assert_eq!(
        unit(&inspection, &home.path.join("Code/u5/build")).layout,
        "gradle-build"
    );
    assert_eq!(
        refusal(unit(&inspection, &home.path.join("Code/u6/out"))),
        "not_ignored"
    );
    // The layout name is in the report with its lifecycle state.
    assert!(inspection.layouts.iter().any(|layout| {
        layout.layout == "user-configured" && layout.lifecycle == LifecycleState::Proposed
    }));
    // With no layout of the configuration, the directory is ordinary.
    let inspection: ProjectInspection = home.inspect(&quiet());
    assert!(!is_listed(&inspection, &home.path.join("Code/u1/out")));
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
    // A fixture lifecycle does not change the layout, and no state of it
    // can permit an automatic mode.
    for state in [manual_action_validated(), automatic_eviction_validated()] {
        let registry: ReviewedRules = ReviewedRules::with_fixture_lifecycle(&state).unwrap();
        let support = registry
            .projects()
            .rule()
            .layouts
            .iter()
            .find(|layout| layout.layout == "user-configured")
            .unwrap();
        assert_eq!(support.lifecycle, LifecycleState::Proposed);
        assert!(!support.permits(&RuleMode::AutomaticEviction));
    }
    let promoted = svalnir_core::rule::LayoutSupport {
        layout: "user-configured".to_owned(),
        lifecycle: manual_action_validated(),
    };
    assert!(promoted.permits(&RuleMode::ManualEviction));
    assert!(!promoted.permits(&RuleMode::AutomaticEviction));
}
