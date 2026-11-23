//! The layout catalog of `project.dependency-directory`
//! (`docs/CLEANUP_RULES.md` section 12, "Layouts").
//!
//! Each layout is data: the generated directory, the project markers in the
//! directory that holds it, the marker in the unit, the protected children,
//! and the texts for the user. The inspection applies the same checks to
//! each layout, also to a layout of the configuration.

use super::super::caches::ReclaimBasis;

/// What a project marker must be. A symbolic link is never a marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerKind {
    /// A regular file, for example `package.json`.
    File,
    /// A directory, for example the bundle `App.xcodeproj` or the
    /// configuration directory `.storybook`.
    Directory,
}

/// One project marker, relative to the directory that holds the first name
/// of the generated directory: a name, a pattern with `*` and `?`, or a
/// path of names with `/` between them and no pattern, for example
/// `ProjectSettings/ProjectVersion.txt`. Each directory on the way of a
/// path must be a directory of the user, not a symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectMarker {
    /// The name, the pattern, or the path.
    pub name: &'static str,
    /// What the last entry must be.
    pub kind: MarkerKind,
}

const fn file(name: &'static str) -> ProjectMarker {
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

/// How the walk treats a directory with the name of a layout and no
/// marker of that layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryName {
    /// Only the producer uses the name, for example `node_modules`. The
    /// report lists the directory as `project_marker_missing`, and the walk
    /// does not enter it.
    Distinctive,
    /// Other software also uses the name, for example `build` or `bin`. The
    /// directory is an ordinary directory: the report does not list it, and
    /// the walk enters it.
    Generic,
}

/// Whether a distinctive directory of a layout with no project marker can
/// be a unit of a manual plan (`docs/CLEANUP_RULES.md` section 12,
/// "Unmarked directories", owner decision of 2026-11-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmarked {
    /// Never: the report lists the directory as `project_marker_missing`.
    Never,
    /// Only for a manual plan whose request allows it (`--allow-unmarked`).
    /// The unit has the layout name `layout`, which ends with
    /// [`svalnir_core::rule::UNMARKED_LAYOUT_SUFFIX`] and permits at most a
    /// manual mode. Each other check of the layout applies unchanged.
    ManualOnly {
        /// The layout name of an unmarked unit.
        layout: &'static str,
    },
}

/// Which clones of Swift Package Manager a unit of the layout can hold
/// (`docs/CLEANUP_RULES.md` section 6, "Repositories in a unit").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageCheckouts {
    /// None: each repository in the unit refuses it.
    None,
    /// `checkouts` and `repositories` of `.build`, with the pins of
    /// `Package.resolved` beside `Package.swift`.
    PackageBuild,
    /// `SourcePackages/checkouts` of a `DerivedData` directory of a
    /// project, with the pins of the one package, workspace, or project
    /// beside it.
    XcodeDerivedData,
}

/// One layout of the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectLayout {
    /// The generated directory, relative to the project directory: one to
    /// [`svalnir_core::config::MAX_LAYOUT_DIRECTORY_NAMES`] names with `/`
    /// between them. The first name can be a pattern with `*` and `?`,
    /// compared as a marker pattern; a pattern never matches a name of the
    /// skip list of the walk.
    pub directory: &'static str,
    /// The layout name of the declaration. It is stable.
    pub layout: &'static str,
    /// The project markers. One of them must be in the directory that
    /// holds the first name of [`ProjectLayout::directory`].
    pub project_markers: &'static [ProjectMarker],
    /// A regular file that the unit must have, when the layout has one.
    pub inner_marker: Option<&'static str>,
    /// A regular file, relative to the project directory, that the project
    /// must have beside the unit, when the layout has one: for example
    /// `obj/project.assets.json` beside `bin` of .NET. Each directory on
    /// its way must be a directory, not a symbolic link.
    pub project_file: Option<&'static str>,
    /// The protected children, relative to the unit. Each component is a
    /// name or a pattern with `*` and `?`. A unit with an entry at one of
    /// them is refused (`protected_child`).
    pub protected: &'static [&'static str],
    /// How the walk treats the name with no marker.
    pub name: DirectoryName,
    /// Whether a directory of a distinctive name with no marker can be a
    /// unit of a manual plan.
    pub unmarked: Unmarked,
    /// The clones of Swift Package Manager that the unit can hold.
    pub checkouts: PackageCheckouts,
    /// What the reclaim figure of a measured unit is.
    pub reclaim: ReclaimBasis,
    /// The owner workflow, as a text for the user. Svalnir does not run it.
    pub owner_workflow: &'static str,
    /// The consequence of a removal.
    pub rebuild_impact: &'static str,
}

const PYTHON_PROJECT: &[ProjectMarker] = &[
    file("pyproject.toml"),
    file("requirements.txt"),
    file("setup.py"),
    file("Pipfile"),
];
const GRADLE_PROJECT: &[ProjectMarker] = &[
    file("build.gradle"),
    file("build.gradle.kts"),
    file("settings.gradle"),
    file("settings.gradle.kts"),
];
const DOTNET_PROJECT: &[ProjectMarker] = &[file("*.csproj"), file("*.fsproj"), file("*.vbproj")];
const NODE_PROJECT: &[ProjectMarker] = &[file("package.json")];

const VENV_WORKFLOW: &str = "Remove the environment, then make it again with the tool of the project (for example `uv sync`, or `python3 -m venv` and an install). Svalnir does not run them.";
const VENV_IMPACT: &str = "The next sync makes the environment again and downloads each package that no cache has. Packages that a person installed by hand are not in the project files and are lost.";

/// A layout with no inner marker, no protected child, and no clone of Swift
/// Package Manager.
const fn plain(
    directory: &'static str,
    layout: &'static str,
    project_markers: &'static [ProjectMarker],
    name: DirectoryName,
    owner_workflow: &'static str,
    rebuild_impact: &'static str,
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
        owner_workflow,
        rebuild_impact,
    }
}

const fn with_inner(layout: ProjectLayout, inner_marker: &'static str) -> ProjectLayout {
    ProjectLayout {
        inner_marker: Some(inner_marker),
        ..layout
    }
}

/// The layout `layout` with the unmarked units of the layout name
/// `unmarked` for a manual plan.
const fn unmarked(layout: ProjectLayout, unmarked: &'static str) -> ProjectLayout {
    ProjectLayout {
        unmarked: Unmarked::ManualOnly { layout: unmarked },
        ..layout
    }
}

const fn linked(layout: ProjectLayout) -> ProjectLayout {
    ProjectLayout {
        reclaim: ReclaimBasis::LinkedIntoProjects,
        ..layout
    }
}

use DirectoryName::{Distinctive, Generic};

/// The number of built-in layouts.
pub const PROJECT_LAYOUT_COUNT: usize = 31;

/// The built-in layouts, in the sequence of the specification. For two
/// layouts with the same directory, the first one whose marker is present
/// gives the unit.
pub const PROJECT_LAYOUTS: [ProjectLayout; PROJECT_LAYOUT_COUNT] = [
    // pnpm and Bun link package files from a store with hard links or
    // clones, so the size of the directory is not its exclusive storage.
    linked(plain(
        "node_modules",
        "node-modules",
        NODE_PROJECT,
        Distinctive,
        "Remove the directory in the project, then run the install command of the package manager of the project (`npm install`, `pnpm install`, or `yarn install`) when you need it again. Svalnir does not run them.",
        "The next install downloads or links each package again, and can run the install scripts of the packages.",
    )),
    // uv can link files from its cache into an environment with clones or
    // hard links.
    unmarked(
        linked(with_inner(
            plain(
                ".venv",
                "python-venv",
                PYTHON_PROJECT,
                Distinctive,
                VENV_WORKFLOW,
                VENV_IMPACT,
            ),
            "pyvenv.cfg",
        )),
        "python-venv+unmarked",
    ),
    linked(with_inner(
        plain(
            "venv",
            "python-venv-plain",
            PYTHON_PROJECT,
            Generic,
            VENV_WORKFLOW,
            VENV_IMPACT,
        ),
        "pyvenv.cfg",
    )),
    with_inner(
        plain(
            "Pods",
            "cocoapods-pods",
            &[file("Podfile")],
            Distinctive,
            "Remove the directory, then run `pod install` in the project when you need it again. Svalnir does not run it.",
            "The next `pod install` downloads each pod that the cache of CocoaPods does not have, and needs sources that are still available.",
        ),
        "Manifest.lock",
    ),
    // Cargo writes `CACHEDIR.TAG` in each target directory that it makes.
    with_inner(
        plain(
            "target",
            "cargo-target",
            &[file("Cargo.toml")],
            Generic,
            "Run `cargo clean` in the workspace, or remove the directory. Svalnir does not run them.",
            "The next build compiles the workspace and its dependencies again. A program in `target/release` that a person runs from there is not available until the next release build.",
        ),
        "CACHEDIR.TAG",
    ),
    plain(
        "target",
        "maven-target",
        &[file("pom.xml")],
        Generic,
        "Run `mvn clean` in the project, or remove the directory. Svalnir does not run them.",
        "The next build compiles the project and makes its packages again, and downloads each dependency that the local Maven repository does not have.",
    ),
    unmarked(
        plain(
            ".next",
            "next-build",
            NODE_PROJECT,
            Distinctive,
            "Remove the directory, then run `next build` or the development server when you need it again. Svalnir does not run them.",
            "The next build or development server compiles the application again.",
        ),
        "next-build+unmarked",
    ),
    plain(
        ".turbo",
        "turbo-cache",
        &[file("turbo.json"), file("package.json")],
        Distinctive,
        "Remove the directory. Turborepo makes it again at the next `turbo run`. Svalnir does not run it.",
        "The next task runs have no local cache hits, so each task runs again, unless a remote cache has the results.",
    ),
    unmarked(
        plain(
            ".svelte-kit",
            "svelte-kit",
            NODE_PROJECT,
            Distinctive,
            "Remove the directory, then run `svelte-kit sync`, a build, or the development server. Svalnir does not run them.",
            "The next sync or build makes the generated types and the build output again.",
        ),
        "svelte-kit+unmarked",
    ),
    unmarked(
        plain(
            ".astro",
            "astro",
            NODE_PROJECT,
            Distinctive,
            "Remove the directory, then run `astro sync` or the development server. Svalnir does not run them.",
            "The next sync makes the generated types and the content data again.",
        ),
        "astro+unmarked",
    ),
    unmarked(
        plain(
            ".parcel-cache",
            "parcel-cache",
            NODE_PROJECT,
            Distinctive,
            "Remove the directory. Parcel makes it again at the next build. Svalnir does not run it.",
            "The next build has no cache, so it transforms each asset again.",
        ),
        "parcel-cache+unmarked",
    ),
    plain(
        "dist",
        "node-dist",
        NODE_PROJECT,
        Generic,
        "Remove the directory, then run the build script of the project (for example `npm run build`). Svalnir does not run it.",
        "The next build makes the output again. A file that a person put in the directory, or an output that the current project files cannot make again, is lost.",
    ),
    plain(
        "dist",
        "python-dist",
        &[file("pyproject.toml"), file("setup.py")],
        Generic,
        "Remove the directory, then run the build of the package (for example `python3 -m build`). Svalnir does not run it.",
        "The next build makes the archives of the current version again. The archives of earlier versions are lost.",
    ),
    // A module with source has its bytecode in `__pycache__`; Python 3 does
    // not import a file of `__pycache__` with no source file.
    plain(
        "__pycache__",
        "pycache",
        &[file("*.py")],
        Distinctive,
        "Remove the directory. Python writes the bytecode again when it imports the modules. Svalnir does not run Python.",
        "The next import of each module compiles it again.",
    ),
    // pytest, mypy, and Ruff write `CACHEDIR.TAG` in their cache.
    unmarked(
        with_inner(
            plain(
                ".pytest_cache",
                "pytest-cache",
                &[
                    file("pyproject.toml"),
                    file("pytest.ini"),
                    file("setup.cfg"),
                    file("tox.ini"),
                    file("setup.py"),
                    file("conftest.py"),
                ],
                Distinctive,
                "Remove the directory, or run `pytest --cache-clear`. Svalnir does not run it.",
                "The next run of pytest has no record of the tests that failed last, so `--last-failed` runs each test.",
            ),
            "CACHEDIR.TAG",
        ),
        "pytest-cache+unmarked",
    ),
    unmarked(
        with_inner(
            plain(
                ".mypy_cache",
                "mypy-cache",
                &[
                    file("pyproject.toml"),
                    file("mypy.ini"),
                    file(".mypy.ini"),
                    file("setup.cfg"),
                    file("setup.py"),
                ],
                Distinctive,
                "Remove the directory. mypy makes it again at the next run. Svalnir does not run it.",
                "The next run of mypy examines each module again with no cache.",
            ),
            "CACHEDIR.TAG",
        ),
        "mypy-cache+unmarked",
    ),
    unmarked(
        with_inner(
            plain(
                ".ruff_cache",
                "ruff-cache",
                &[
                    file("pyproject.toml"),
                    file("ruff.toml"),
                    file(".ruff.toml"),
                ],
                Distinctive,
                "Remove the directory, or run `ruff clean`. Svalnir does not run it.",
                "The next run of Ruff examines each file again with no cache.",
            ),
            "CACHEDIR.TAG",
        ),
        "ruff-cache+unmarked",
    ),
    unmarked(
        linked(plain(
            ".tox",
            "tox",
            &[file("tox.ini"), file("pyproject.toml"), file("setup.cfg")],
            Distinctive,
            "Remove the directory, or run `tox --recreate` when you need the environments again. Svalnir does not run it.",
            "The next run of tox makes each environment again and downloads each package that no cache has.",
        )),
        "tox+unmarked",
    ),
    linked(plain(
        ".nox",
        "nox",
        &[file("noxfile.py")],
        Distinctive,
        "Remove the directory. The next run of `nox` makes the sessions again. Svalnir does not run it.",
        "The next run of nox makes each session environment again and downloads each package that no cache has.",
    )),
    unmarked(
        plain(
            ".gradle",
            "gradle-project-cache",
            GRADLE_PROJECT,
            Distinctive,
            "Stop the Gradle daemons (`gradle --stop`), then remove the directory. Svalnir does not run them.",
            "The next build has no local task history and no configuration cache, so each task runs again.",
        ),
        "gradle-project-cache+unmarked",
    ),
    plain(
        "build",
        "gradle-build",
        GRADLE_PROJECT,
        Generic,
        "Run `gradle clean` (or `./gradlew clean`) in the project. Svalnir does not run it.",
        "The next build compiles the project and makes its outputs again. An application package that a person did not copy to another location is not available until the next build.",
    ),
    plain(
        "build",
        "setuptools-build",
        &[file("pyproject.toml"), file("setup.py")],
        Generic,
        "Remove the directory. The next build of the package makes it again (for example `python3 -m build`). Svalnir does not run it.",
        "The next build compiles the extension modules of the package again.",
    ),
    // A release of Mix is in `_build/ENV/rel`; the protected paths are those
    // of the reference of the layout coverage.
    ProjectLayout {
        protected: &["*/rel", "*/lib/*/src"],
        ..plain(
            "_build",
            "mix-build",
            &[file("mix.exs")],
            Generic,
            "Run `mix clean --deps`, or remove the directory, then run `mix compile`. Svalnir does not run them.",
            "The next `mix compile` compiles the project and its dependencies again. A release in `_build/ENV/rel` can hold a generated Erlang cookie and the earlier versions that an upgrade needs, so a unit with a release is refused.",
        )
    },
    // A restore of an SDK-style project writes `project.assets.json`.
    with_inner(
        plain(
            "obj",
            "dotnet-obj",
            DOTNET_PROJECT,
            Generic,
            "Run `dotnet clean`, or remove the directory, then run `dotnet restore`. Svalnir does not run them.",
            "The next restore and build make the intermediate files again.",
        ),
        "project.assets.json",
    ),
    // `bin` is a generic name: the restore output beside it shows that the
    // .NET SDK builds the project.
    ProjectLayout {
        project_file: Some("obj/project.assets.json"),
        ..plain(
            "bin",
            "dotnet-bin",
            DOTNET_PROJECT,
            Generic,
            "Run `dotnet clean` in the project, or remove the directory. Svalnir does not run them.",
            "The next build makes the programs and the libraries again. A file that a person put in the directory is lost.",
        )
    },
    ProjectLayout {
        checkouts: PackageCheckouts::PackageBuild,
        ..with_inner(
            plain(
                ".build",
                "swiftpm-build",
                &[file("Package.swift")],
                Distinctive,
                "Run `swift package reset`, or `swift package clean` to keep the checkouts. Svalnir does not run them.",
                "The next `swift build` resolves and downloads each dependency again and compiles the package again.",
            ),
            "workspace-state.json",
        )
    },
    ProjectLayout {
        checkouts: PackageCheckouts::XcodeDerivedData,
        ..plain(
            "DerivedData",
            "xcode-project-derived-data",
            &[
                directory_marker("*.xcworkspace"),
                directory_marker("*.xcodeproj"),
                file("Package.swift"),
            ],
            Distinctive,
            "Remove the directory, then build the project again in Xcode or with `xcodebuild -derivedDataPath DerivedData`. Svalnir does not run them.",
            "The next build compiles the project again, makes the index again, and resolves the package dependencies again.",
        )
    },
    plain(
        ".zig-cache",
        "zig-cache",
        &[file("build.zig")],
        Distinctive,
        "Remove the directory. `zig build` makes it again. Svalnir does not run it.",
        "The next build compiles the project again with no cache.",
    ),
    plain(
        "zig-cache",
        "zig-cache-legacy",
        &[file("build.zig")],
        Distinctive,
        "Remove the directory. `zig build` of Zig before 0.13 makes it again. Svalnir does not run it.",
        "The next build compiles the project again with no cache.",
    ),
    plain(
        "vendor/bundle",
        "bundler-vendor",
        &[file("Gemfile"), file("gems.rb")],
        Generic,
        "Remove the directory, then run `bundle install`. Svalnir does not run it.",
        "The next install downloads and compiles each gem again. A gem from a source that is not available now cannot be installed again.",
    ),
    plain(
        "tmp/cache",
        "rails-tmp-cache",
        &[file("config.ru")],
        Generic,
        "Run `bin/rails tmp:cache:clear`, or remove the directory. Svalnir does not run them.",
        "The application makes its cache again, and bootsnap compiles its cache again at the next start.",
    ),
];

/// The owner workflow of a layout of the configuration.
pub const USER_LAYOUT_WORKFLOW: &str = "A layout of the configuration. Svalnir has no command that makes the directory again: use the tool of the project. Svalnir does not run it.";

/// The consequence of a removal of a unit of a layout of the configuration.
pub const USER_LAYOUT_IMPACT: &str = "Not known to Svalnir: the configuration names the layout, and no review confirms that a tool makes the directory again.";
