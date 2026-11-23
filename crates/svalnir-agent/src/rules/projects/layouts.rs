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
const SBT_PROJECT: &[ProjectMarker] = &[file("build.sbt")];
const SCALA_BUILD: &[ProjectMarker] = &[file("build.sbt"), file("build.mill"), file("build.sc")];
const MIX_PROJECT: &[ProjectMarker] = &[file("mix.exs")];
const NUXT_PROJECT: &[ProjectMarker] = &[file("nuxt.config.*")];
const NX_PROJECT: &[ProjectMarker] = &[file("nx.json")];
const YARN_PROJECT: &[ProjectMarker] = &[file(".yarnrc.yml")];
const GODOT_PROJECT: &[ProjectMarker] = &[file("project.godot")];
const TERRAFORM_MODULE: &[ProjectMarker] = &[file("*.tf"), file("*.tf.json")];
const RENV_PROJECT: &[ProjectMarker] = &[file("renv.lock")];
const SPHINX_PROJECT: &[ProjectMarker] = &[file("conf.py")];

const ANDROID_NATIVE_WORKFLOW: &str = "Remove the directory. The next Gradle build or sync of the module makes it again (for example `./gradlew assembleDebug`). Svalnir does not run them.";
const ANDROID_NATIVE_IMPACT: &str = "The next build configures CMake or ndk-build again and compiles the native code of each ABI again.";
const SPHINX_WORKFLOW: &str =
    "Run `make clean`, or remove the directory, then run `make html`. Svalnir does not run them.";
const SPHINX_IMPACT: &str =
    "The next build reads each source file again and makes the documentation again.";
const NX_WORKFLOW: &str =
    "Run `nx reset`, or stop the Nx daemon and remove the directory. Svalnir does not run them.";
const STACK_WORKFLOW: &str = "Run `stack clean --full`, or remove the directory, then run `stack build`. Svalnir does not run them.";
const STACK_IMPACT: &str = "The next `stack build` builds the packages again, which can take a long time. A program that `stack install` did not copy out of `.stack-work/install` is not available until then.";
const OUTPUT_IMPACT: &str = "The next build makes the server files and the public files again. A deployment that uses this directory has no output until the next build.";

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

const fn with_protected(
    layout: ProjectLayout,
    protected: &'static [&'static str],
) -> ProjectLayout {
    ProjectLayout {
        protected,
        ..layout
    }
}

const fn with_project_file(layout: ProjectLayout, project_file: &'static str) -> ProjectLayout {
    ProjectLayout {
        project_file: Some(project_file),
        ..layout
    }
}

use DirectoryName::{Distinctive, Generic};

/// The number of built-in layouts.
pub const PROJECT_LAYOUT_COUNT: usize = 85;

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
    // sbt writes `target` in the build and in the meta-build `project`.
    plain(
        "target",
        "sbt-target",
        SBT_PROJECT,
        Generic,
        "Run `sbt clean` in the build, or remove the directory. Svalnir does not run them.",
        "The next `sbt compile` compiles the build again. A package in `target` that a person did not copy to another location is not available until the next package task.",
    ),
    plain(
        "project/target",
        "sbt-meta-target",
        SBT_PROJECT,
        Generic,
        "Remove the directory. The next start of sbt compiles the build definition again. Svalnir does not run sbt.",
        "The next start of sbt compiles the build definition and its plugins again, which can take some minutes.",
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
    // Nuxt writes the declarations `nuxt.d.ts` in its build directory.
    with_inner(
        plain(
            ".nuxt",
            "nuxt-build",
            NUXT_PROJECT,
            Distinctive,
            "Remove the directory, then run `nuxt prepare`, the development server, or `nuxt build`. Svalnir does not run them.",
            "The next `nuxt prepare`, development server, or build makes the generated types and the build files again.",
        ),
        "nuxt.d.ts",
    ),
    // A production build of Nitro, also for Nuxt, writes `nitro.json`.
    with_inner(
        plain(
            ".output",
            "nuxt-output",
            NUXT_PROJECT,
            Generic,
            "Remove the directory, then run `nuxt build` or `nuxt generate`. Svalnir does not run them.",
            OUTPUT_IMPACT,
        ),
        "nitro.json",
    ),
    with_inner(
        plain(
            ".output",
            "nitro-output",
            &[file("nitro.config.*")],
            Generic,
            "Remove the directory, then run `nitro build`. Svalnir does not run it.",
            OUTPUT_IMPACT,
        ),
        "nitro.json",
    ),
    // Only the cache of `.angular`: its other entries are working
    // directories of the development server.
    plain(
        ".angular/cache",
        "angular-cache",
        &[file("angular.json"), file(".angular.json")],
        Distinctive,
        "Run `ng cache clean`, or remove the directory. Svalnir does not run them.",
        "The next `ng build`, `ng serve`, or `ng test` has no cache, so it compiles each file again. The other entries of `.angular` stay.",
    ),
    // `.nx/installation` holds the pinned installation of Nx and stays.
    plain(
        ".nx/cache",
        "nx-cache",
        NX_PROJECT,
        Distinctive,
        NX_WORKFLOW,
        "The next task runs have no local cache hits, so each task runs again, unless a remote cache has the results. `.nx/installation` stays.",
    ),
    plain(
        ".nx/workspace-data",
        "nx-workspace-data",
        NX_PROJECT,
        Distinctive,
        NX_WORKFLOW,
        "The next `nx` command makes the project graph again. The history of the task runs is lost. `.nx/installation` stays.",
    ),
    with_inner(
        plain(
            ".docusaurus",
            "docusaurus",
            &[file("docusaurus.config.*")],
            Distinctive,
            "Run `docusaurus clear`, or remove the directory, then run `docusaurus start` or `docusaurus build`. Svalnir does not run them.",
            "The next start or build makes the generated files of the site again.",
        ),
        "globalData.json",
    ),
    // Only two entries of `.yarn`: `releases`, `plugins`, `patches`,
    // `sdks`, and `versions` are files of the project. With zero-install,
    // the repository commits the cache, and the index check refuses it.
    plain(
        ".yarn/cache",
        "yarn-cache",
        YARN_PROJECT,
        Distinctive,
        "Remove the directory, then run `yarn install`. Svalnir does not run it.",
        "The next `yarn install` downloads each package again, unless the global cache of Yarn has it. With zero-install the repository commits this directory, and a unit with a tracked file is refused. The other entries of `.yarn` stay.",
    ),
    plain(
        ".yarn/unplugged",
        "yarn-unplugged",
        YARN_PROJECT,
        Distinctive,
        "Remove the directory, then run `yarn install`. Svalnir does not run it.",
        "The next `yarn install` extracts the unplugged packages again and runs their build scripts again. With zero-install the repository can commit this directory, and a unit with a tracked file is refused. The other entries of `.yarn` stay.",
    ),
    // `vercel build` writes `config.json` in its output. The link files of
    // `.vercel` stay.
    with_inner(
        plain(
            ".vercel/output",
            "vercel-output",
            &[file("package.json"), file("vercel.json")],
            Distinctive,
            "Remove the directory, then run `vercel build`. Svalnir does not run it.",
            "The next `vercel build` makes the output again; it needs the project link and the settings of `vercel pull`, a network, and a login. `vercel deploy --prebuilt` has no output until then. The other entries of `.vercel` stay.",
        ),
        "config.json",
    ),
    // `.wrangler/state` holds the local data of the bindings and stays.
    plain(
        ".wrangler/tmp",
        "wrangler-tmp",
        &[
            file("wrangler.toml"),
            file("wrangler.json"),
            file("wrangler.jsonc"),
        ],
        Distinctive,
        "Remove the directory. Wrangler makes it again at the next `wrangler dev` or `wrangler deploy`. Svalnir does not run them.",
        "The next run bundles the worker again. The local data of the bindings in `.wrangler/state` stays.",
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
    // The default reporters of Jest and of Vitest write
    // `coverage-final.json`; `coverage` is a generic name.
    with_inner(
        plain(
            "coverage",
            "node-coverage",
            NODE_PROJECT,
            Generic,
            "Remove the directory, then run the tests with coverage (for example `jest --coverage` or `vitest run --coverage`). Svalnir does not run them.",
            "The next coverage run makes the reports again. A report of an earlier run is lost.",
        ),
        "coverage-final.json",
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
    // Pixi writes `.gitignore` in its directory, and it links the files of
    // an environment from its package cache with hard links. A person
    // writes `config.toml`.
    linked(with_protected(
        with_inner(
            plain(
                ".pixi",
                "pixi",
                &[file("pixi.toml"), file("pyproject.toml")],
                Distinctive,
                "Remove the directory, then run `pixi install`. Svalnir does not run it.",
                "The next `pixi install` makes each environment again and downloads each package that the package cache does not have. A unit with the project configuration `config.toml` is refused, because a person writes that file.",
            ),
            ".gitignore",
        ),
        &["config.toml"],
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
    // The Kotlin Gradle plugin writes `.kotlin` in the root project only.
    plain(
        ".kotlin",
        "kotlin-project-data",
        &[file("settings.gradle"), file("settings.gradle.kts")],
        Distinctive,
        "Stop the Gradle and Kotlin daemons (`gradle --stop`), then remove the directory. Svalnir does not run them.",
        "The next build makes the directory again. The error reports in `errors` are lost. A running Gradle or Kotlin daemon uses the files in `sessions`; the use check sees the daemon only while it has a file of the unit open.",
    ),
    plain(
        ".cxx",
        "android-cxx",
        GRADLE_PROJECT,
        Distinctive,
        ANDROID_NATIVE_WORKFLOW,
        ANDROID_NATIVE_IMPACT,
    ),
    plain(
        ".externalNativeBuild",
        "android-external-native-build",
        GRADLE_PROJECT,
        Distinctive,
        ANDROID_NATIVE_WORKFLOW,
        ANDROID_NATIVE_IMPACT,
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
    // `build` beside `pubspec.yaml` has no file of its own that Flutter
    // writes. `flutter pub get` writes `.flutter-plugins-dependencies`
    // beside it, which shows that Flutter, not Dart alone, builds the
    // project.
    with_project_file(
        plain(
            "build",
            "flutter-build",
            &[file("pubspec.yaml")],
            Generic,
            "Run `flutter clean`, or remove the directory, then run `flutter build` or `flutter run`. Svalnir does not run them.",
            "The next build compiles the application for each platform again. An application package in `build` that a person did not copy to another location is not available until the next build.",
        ),
        ".flutter-plugins-dependencies",
    ),
    // CMake writes `CMakeCache.txt` in each build tree.
    with_inner(
        plain(
            "build",
            "cmake-build",
            &[file("CMakeLists.txt")],
            Generic,
            "Remove the directory, then configure and build again (for example `cmake -S . -B build` and `cmake --build build`). Svalnir does not run them.",
            "The next configure and build compile the project again. The cache options that a person gave only on a command line (`-D`) or in `ccmake` are lost; a preset or a toolchain file keeps them. The downloads of `FetchContent` in `_deps` need a network again.",
        ),
        "CMakeCache.txt",
    ),
    // `sphinx-quickstart` with separate source and build directories puts
    // `conf.py` in `source`; `make html` writes the doctrees in `build`.
    with_inner(
        with_project_file(
            plain(
                "build",
                "sphinx-build-separate",
                &[file("Makefile"), file("make.bat")],
                Generic,
                SPHINX_WORKFLOW,
                SPHINX_IMPACT,
            ),
            "source/conf.py",
        ),
        "doctrees/environment.pickle",
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
    // dune writes the file `_build/log` in each build directory.
    with_inner(
        plain(
            "_build",
            "dune-build",
            &[file("dune-project")],
            Generic,
            "Run `dune clean`, or remove the directory, then run `dune build`. Svalnir does not run them.",
            "The next `dune build` compiles the project again. The development tools that dune built in `_build/.dev-tools.locks` are built again.",
        ),
        "log",
    ),
    // `make html` of `sphinx-quickstart` writes the doctrees in `_build`.
    with_inner(
        plain(
            "_build",
            "sphinx-build",
            SPHINX_PROJECT,
            Generic,
            SPHINX_WORKFLOW,
            SPHINX_IMPACT,
        ),
        "doctrees/environment.pickle",
    ),
    // The three language servers of Elixir write `.gitignore` in their
    // directory.
    with_inner(
        plain(
            ".elixir_ls",
            "elixir-ls",
            MIX_PROJECT,
            Distinctive,
            "Stop the editor, then remove the directory. ElixirLS makes it again at its next start. Svalnir does not run it.",
            "The next start of ElixirLS compiles the project again and makes the Dialyzer PLT again, which can take some minutes.",
        ),
        ".gitignore",
    ),
    with_inner(
        plain(
            ".lexical",
            "lexical",
            MIX_PROJECT,
            Distinctive,
            "Stop the editor, then remove the directory. Lexical makes it again at its next start. Svalnir does not run it.",
            "The next start of Lexical makes the index of the project again. The project log is lost.",
        ),
        ".gitignore",
    ),
    with_inner(
        plain(
            ".expert",
            "expert",
            MIX_PROJECT,
            Distinctive,
            "Stop the editor, then remove the directory. Expert makes it again at its next start. Svalnir does not run it.",
            "The next start of Expert makes the index of the project again. The project log is lost.",
        ),
        ".gitignore",
    ),
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
    // The artifacts output of the .NET SDK is beside `Directory.Build.props`.
    // `artifacts/publish` and `artifacts/package` hold the deliverables and
    // stay.
    plain(
        "artifacts/bin",
        "dotnet-artifacts-bin",
        &[file("Directory.Build.props")],
        Generic,
        "Run `dotnet clean`, or remove the directory. Svalnir does not run them.",
        "The next build makes the programs and the libraries again. A file that a person put in the directory is lost. `artifacts/publish` and `artifacts/package` stay.",
    ),
    plain(
        "artifacts/obj",
        "dotnet-artifacts-obj",
        &[file("Directory.Build.props")],
        Generic,
        "Run `dotnet clean`, or remove the directory, then run `dotnet restore`. Svalnir does not run them.",
        "The next restore and build make the intermediate files again. `artifacts/publish` and `artifacts/package` stay.",
    ),
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
    // `Carthage/Checkouts` holds the sources of the dependencies, which can
    // be submodules of the user, and stays.
    with_project_file(
        plain(
            "Carthage/Build",
            "carthage-build",
            &[file("Cartfile")],
            Distinctive,
            "Remove the directory, then run `carthage bootstrap` or `carthage build`. Svalnir does not run them.",
            "The next bootstrap downloads or builds each dependency of `Cartfile.resolved` again. A binary whose source is not available now cannot be made again. `Carthage/Checkouts` stays.",
        ),
        "Cartfile.resolved",
    ),
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
    // `vendor` is also the directory of Go and of other tools. Composer
    // writes `vendor/composer/installed.json`, and without `composer.lock`
    // an install can select other versions. `bundler-vendor` comes first,
    // so a `vendor` that holds `vendor/bundle` overlaps its unit.
    with_inner(
        with_project_file(
            plain(
                "vendor",
                "composer-vendor",
                &[file("composer.json")],
                Generic,
                "Remove the directory, then run `composer install`. Svalnir does not run it.",
                "The next `composer install` installs the versions of `composer.lock` again; it needs a network or the cache of Composer, and the credentials of each private repository. A change that a person made by hand in `vendor` is lost. A package of a path repository is a symbolic link: the removal removes the link and never follows it, so the source of the package stays.",
            ),
            "composer.lock",
        ),
        "composer/installed.json",
    ),
    plain(
        "tmp/cache",
        "rails-tmp-cache",
        &[file("config.ru")],
        Generic,
        "Run `bin/rails tmp:cache:clear`, or remove the directory. Svalnir does not run them.",
        "The application makes its cache again, and bootsnap compiles its cache again at the next start.",
    ),
    // Symfony keeps the sessions, the application cache pool, and the HTTP
    // cache in the cache directory of each environment by default. These
    // are not made again, so a unit with one of them is refused.
    with_protected(
        with_project_file(
            plain(
                "var/cache",
                "symfony-var-cache",
                &[file("symfony.lock")],
                Generic,
                "Run `php bin/console cache:clear`, or remove the directory, then run `php bin/console cache:warmup`. Svalnir does not run them.",
                "The next request or `cache:warmup` makes the cache again, and the first requests are slow. A unit with sessions, the application cache pool, or the HTTP cache is refused. `var/log` and the other entries of `var` stay.",
            ),
            "bin/console",
        ),
        &["*/sessions", "*/pools/app", "*/http_cache"],
    ),
    // Each `pub get` writes `.dart_tool/package_config.json`.
    with_inner(
        plain(
            ".dart_tool",
            "dart-tool",
            &[file("pubspec.yaml")],
            Distinctive,
            "Remove the directory, then run `dart pub get` or `flutter pub get`. Svalnir does not run them.",
            "The next `pub get` makes the package configuration again, and it needs a network or the pub cache. The next build makes the build files of Flutter and of `build_runner` again.",
        ),
        "package_config.json",
    ),
    plain(
        ".bloop",
        "bloop",
        SCALA_BUILD,
        Distinctive,
        "Remove the directory, then import the build again (in Metals, or with `sbt bloopInstall`). Svalnir does not run them.",
        "The next import writes the Bloop configuration of each project again, and the next compile compiles each project again.",
    ),
    plain(
        ".metals",
        "metals",
        SCALA_BUILD,
        Distinctive,
        "Stop the editor, then remove the directory. Metals makes it again at its next start. Svalnir does not run it.",
        "The next start of Metals asks to import the build again and shows again the notifications that a person dismissed. The logs and the reports of Metals are lost.",
    ),
    // Mill 1 writes `out/mill-out-lock`; `out` is a generic name.
    with_inner(
        plain(
            "out",
            "mill-out",
            &[file("build.mill"), file("build.sc")],
            Generic,
            "Run `./mill clean`, or stop the Mill daemon and remove the directory. Svalnir does not run them.",
            "The next `./mill` task runs each task again. The state of a running Mill daemon is in `out/mill-daemon`, so stop the daemon first.",
        ),
        "mill-out-lock",
    ),
    // The editor of Godot 4 writes `.godot/.gdignore`. The export
    // credentials are secrets. `editor` holds only the editor state of the
    // project (open scenes, layout), which the editor makes again on each
    // open, so it is not protected.
    with_protected(
        with_inner(
            plain(
                ".godot",
                "godot",
                GODOT_PROJECT,
                Distinctive,
                "Close the project in the editor, then remove the directory. The editor imports the assets again when it opens the project. Svalnir does not run it.",
                "The next open of the project imports each asset again and compiles the shaders again. The editor state of the project in `editor` (the open scenes and the layout) is lost. A unit with `export_credentials.cfg` (the passwords and the keys of the export) is refused.",
            ),
            ".gdignore",
        ),
        &["export_credentials.cfg"],
    ),
    plain(
        ".import",
        "godot3-import",
        GODOT_PROJECT,
        Distinctive,
        "Close the project in the editor of Godot 3, then remove the directory. The editor imports the assets again when it opens the project. Svalnir does not run it.",
        "The next open of the project imports each asset again. The files `*.import` beside the assets hold the import settings, and they stay.",
    ),
    // Stack writes `stack.sqlite3` in the work directory of the project, and
    // a work directory with no file at a fixed path in each package.
    with_inner(
        plain(
            ".stack-work",
            "stack-work",
            &[file("stack.yaml")],
            Distinctive,
            STACK_WORKFLOW,
            STACK_IMPACT,
        ),
        "stack.sqlite3",
    ),
    plain(
        ".stack-work",
        "stack-work-package",
        &[file("package.yaml"), file("*.cabal")],
        Distinctive,
        STACK_WORKFLOW,
        STACK_IMPACT,
    ),
    // Each planning of cabal writes `cache/plan.json`.
    with_inner(
        plain(
            "dist-newstyle",
            "cabal-dist-newstyle",
            &[file("cabal.project"), file("*.cabal")],
            Distinctive,
            "Run `cabal clean`, or remove the directory, then run `cabal build`. Svalnir does not run them.",
            "The next `cabal build` plans the project and builds its local packages again.",
        ),
        "cache/plan.json",
    ),
    // Each compile of Elm 0.19.1 takes the lock `elm-stuff/0.19.1/lock`.
    with_inner(
        plain(
            "elm-stuff",
            "elm-stuff",
            &[file("elm.json")],
            Distinctive,
            "Remove the directory, then run `elm make`. Svalnir does not run it.",
            "The next `elm make` compiles the project again from the package cache of `ELM_HOME`; it needs a network only for a package that the cache does not have.",
        ),
        "0.19.1/lock",
    ),
    // Only two entries of `.terraform`: the backend configuration in
    // `terraform.tfstate` and the selected workspace in `environment` are
    // not made again from the files of the module.
    plain(
        ".terraform/providers",
        "terraform-providers",
        TERRAFORM_MODULE,
        Distinctive,
        "Remove the directory, then run `terraform init`. Svalnir does not run it.",
        "The next `terraform init` downloads each provider of `.terraform.lock.hcl` again, or links it from the plugin cache. With a plugin cache the directory holds symbolic links: the removal removes the links and never follows them. The other entries of `.terraform` stay.",
    ),
    with_inner(
        plain(
            ".terraform/modules",
            "terraform-modules",
            TERRAFORM_MODULE,
            Distinctive,
            "Remove the directory, then run `terraform init` or `terraform get`. Svalnir does not run them.",
            "The next `terraform init` downloads each module again. A module from a source that is not available now cannot be installed again. The other entries of `.terraform` stay.",
        ),
        "modules.json",
    ),
    // The cloud assembly has `manifest.json`. A lock file shows a synthesis
    // or a reader that runs now.
    with_protected(
        with_inner(
            plain(
                "cdk.out",
                "cdk-out",
                &[file("cdk.json")],
                Distinctive,
                "Remove the directory, then run `cdk synth`. Svalnir does not run it.",
                "The next `cdk synth`, `cdk diff`, or `cdk deploy` makes the cloud assembly again. A unit with a lock file of a synthesis or of a reader is refused. `cdk.context.json` beside the directory stays.",
            ),
            "manifest.json",
        ),
        &["synth.lock", "read.*.lock"],
    ),
    // `sam build` writes `.aws-sam/build.toml`.
    with_inner(
        plain(
            ".aws-sam",
            "aws-sam",
            &[
                file("samconfig.toml"),
                file("template.yaml"),
                file("template.yml"),
            ],
            Distinctive,
            "Remove the directory, then run `sam build`. Svalnir does not run it.",
            "The next `sam build` builds each function and each layer again, and it can need a network and Docker.",
        ),
        "build.toml",
    ),
    // A package or a deployment writes `serverless-state.json`. `dev` holds
    // the records and the token of a dev mode session.
    with_protected(
        with_inner(
            plain(
                ".serverless",
                "serverless",
                &[
                    file("serverless.yml"),
                    file("serverless.ts"),
                    file("serverless.js"),
                    file("serverless.json"),
                ],
                Distinctive,
                "Remove the directory, then run `serverless package` or `serverless deploy`. Svalnir does not run them.",
                "The next package makes the deployment artifacts and the state file again. A unit with `dev` (the records and the token of a dev mode session) is refused.",
            ),
            "serverless-state.json",
        ),
        &["dev"],
    ),
    // Only three entries of `renv`: `local`, `cellar`, and `python` hold
    // packages and environments that a person supplies, and `activate.R` and
    // `settings.json` are project files.
    plain(
        "renv/library",
        "renv-library",
        RENV_PROJECT,
        Distinctive,
        "Remove the directory, then run `renv::restore()` in R. Svalnir does not run it.",
        "The next restore installs each package of `renv.lock` again from the cache of renv, or from a repository with a network. A package that no repository and no cache has cannot be installed again. The entries of the library are frequently symbolic links into the cache of renv: the removal removes the links and never follows them.",
    ),
    plain(
        "renv/staging",
        "renv-staging",
        RENV_PROJECT,
        Distinctive,
        "Remove the directory when no install runs. renv makes it again at the next install. Svalnir does not run R.",
        "The next install makes the directory again.",
    ),
    plain(
        "renv/sandbox",
        "renv-sandbox",
        RENV_PROJECT,
        Distinctive,
        "Remove the directory. renv makes the sandbox again at the next start of R in the project. Svalnir does not run R.",
        "The next start of R in the project makes the sandbox of the system library again.",
    ),
    // The `layout` functions of direnv write `CACHEDIR.TAG`. A profile of
    // `use flake` is a garbage collector root of Nix.
    with_protected(
        with_inner(
            plain(
                ".direnv",
                "direnv",
                &[file(".envrc")],
                Distinctive,
                "Remove the directory, then enter the directory again or run `direnv reload`. Svalnir does not run them.",
                "The next load of `.envrc` makes each layout again, for example the virtual environment of `layout python`, and it can need a network. A unit with a profile of `use flake` is refused, because it is a garbage collector root of Nix.",
            ),
            "CACHEDIR.TAG",
        ),
        &["flake-profile*"],
    ),
    // `state` holds the data of the services of devenv.
    with_protected(
        plain(
            ".devenv",
            "devenv",
            &[file("devenv.nix")],
            Distinctive,
            "Stop the processes of devenv, then remove the directory and run `devenv shell`. Svalnir does not run them.",
            "The next `devenv shell` evaluates the environment again, and it can need a network or the Nix store. A unit with `state` (the data of the services, for example a PostgreSQL database) is refused.",
        ),
        &["state"],
    ),
    plain(
        ".jekyll-cache",
        "jekyll-cache",
        &[
            file("_config.yml"),
            file("_config.yaml"),
            file("_config.toml"),
        ],
        Distinctive,
        "Run `jekyll clean`, or remove the directory. Svalnir does not run them.",
        "The next `jekyll build` or `jekyll serve` renders each page again with no cache.",
    ),
    // Only `_gen` of `resources`: Hugo documents no other entry of it as
    // generated.
    plain(
        "resources/_gen",
        "hugo-resources",
        &[
            file("hugo.toml"),
            file("hugo.yaml"),
            file("hugo.yml"),
            file("hugo.json"),
            file("config.toml"),
        ],
        Generic,
        "Remove the directory, then run `hugo`. Svalnir does not run it.",
        "The next build processes each image and each asset again. The other entries of `resources` stay.",
    ),
    // The search plugin of MkDocs, which is on by default, writes
    // `search/search_index.json`; `site` is a generic name.
    with_inner(
        plain(
            "site",
            "mkdocs-site",
            &[file("mkdocs.yml"), file("mkdocs.yaml")],
            Generic,
            "Remove the directory, then run `mkdocs build`. Svalnir does not run it.",
            "The next `mkdocs build` makes the site again. A hidden entry that a person put in the directory, which `mkdocs build` keeps, is lost; a Git repository in it refuses the unit.",
        ),
        "search/search_index.json",
    ),
];

/// The owner workflow of a layout of the configuration.
pub const USER_LAYOUT_WORKFLOW: &str = "A layout of the configuration. Svalnir has no command that makes the directory again: use the tool of the project. Svalnir does not run it.";

/// The consequence of a removal of a unit of a layout of the configuration.
pub const USER_LAYOUT_IMPACT: &str = "Not known to Svalnir: the configuration names the layout, and no review confirms that a tool makes the directory again.";
