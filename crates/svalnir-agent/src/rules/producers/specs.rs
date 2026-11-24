//! The reviewed facts of each rule with an owner operation
//! (`docs/CLEANUP_RULES.md` section 9, "Rules with an owner operation").
//!
//! Each command acts on the scope root that the rule measured: the
//! argument vector or the fixed environment names that root to the
//! producer. No rule runs a query of the producer (as `uv cache dir` or
//! `go env GOCACHE`) to find the root: the root comes from the
//! configuration files of the producer, as for the cache rules, or is the
//! documented default.

use svalnir_core::action::{OwnerOperationBound, OwnerOperationKind};
use svalnir_core::policy::RebuildCost;

use super::{Guard, Part, ProducerBase, ProducerSpec};
use crate::rules::caches::{
    ConfigFormat, ConfigSource, ExclusionSpec, GO, HOMEBREW, Location, Marker, PNPM, RootSpec, UV,
    YARN,
};

/// The search path of each command: the system directories only.
const SYSTEM_PATH: (&str, Part) = ("PATH", Part::Literal("/usr/bin:/bin:/usr/sbin:/sbin"));

/// The home directory of each command.
const HOME: (&str, Part) = ("HOME", Part::Home);

/// The interpreters of a Node.js script. A `#!/usr/bin/env node` line
/// takes the first of them whose file name is `node`.
const NODE: [(Location, Option<&str>); 3] = [
    (Location::Absolute("/opt/homebrew/bin/node"), None),
    (Location::Absolute("/usr/local/bin/node"), None),
    (
        Location::Home(".local/share/mise/installs/node/latest/bin/node"),
        None,
    ),
];

/// The file of the configuration of Go.
const GO_ENV: &str = "Library/Application Support/go/env";

/// The fixed environment of Go: no configuration file and no download of
/// a toolchain.
const GO_FIXED: [(&str, Part); 2] = [
    ("GOENV", Part::Literal("off")),
    ("GOTOOLCHAIN", Part::Literal("local")),
];

/// The paths of Go.
const GO_EXECUTABLES: [Location; 4] = [
    Location::Absolute("/opt/homebrew/bin/go"),
    Location::Absolute("/usr/local/go/bin/go"),
    Location::Absolute("/usr/local/bin/go"),
    Location::Home(".local/share/mise/installs/go/latest/bin/go"),
];

/// The paths of mise.
const MISE_EXECUTABLES: [Location; 4] = [
    Location::Home(".local/bin/mise"),
    Location::Absolute("/opt/homebrew/bin/mise"),
    Location::Absolute("/usr/local/bin/mise"),
    Location::Home(".cargo/bin/mise"),
];

/// The text of the lookup decision of a rule whose root comes from the
/// configuration files of the producer.
const FROM_FILES: &str = "The root comes from the configuration files of the producer, or is the documented default. Svalnir runs no query of the producer.";

/// The root of the cache of mise: the default of macOS. mise has no
/// configuration key for it.
const MISE_CACHE_ROOT: RootSpec = RootSpec {
    sources: &[],
    default: "Library/Caches/mise",
    disabled_value: None,
    units: &[],
};

/// The directory of the installed tool versions of mise.
const MISE_INSTALLS_ROOT: RootSpec = RootSpec {
    sources: &[],
    default: ".local/share/mise/installs",
    disabled_value: None,
    units: &[],
};

/// The module cache of Go.
const GO_MODULE_ROOT: RootSpec = RootSpec {
    sources: &[ConfigSource {
        file: GO_ENV,
        format: ConfigFormat::Assignment,
        key: "GOMODCACHE",
        tilde: false,
        list: false,
    }],
    default: "go/pkg/mod",
    disabled_value: None,
    units: &[],
};

/// The `GOPATH` list of the `env` file of Go.
const GO_PATH_SOURCE: ConfigSource = ConfigSource {
    file: GO_ENV,
    format: ConfigFormat::Assignment,
    key: "GOPATH",
    tilde: false,
    list: true,
};

/// The source code and the installed commands of `GOPATH`, which the
/// module cache never contains.
const GO_PATH_EXCLUSION: ExclusionSpec = ExclusionSpec {
    sources: &[GO_PATH_SOURCE],
    default: Location::Home("go"),
    children: &["src", "bin"],
};

/// The cache of npm.
const NPM_ROOT: RootSpec = RootSpec {
    sources: &[ConfigSource {
        file: ".npmrc",
        format: ConfigFormat::Ini,
        key: "cache",
        tilde: true,
        list: false,
    }],
    default: ".npm",
    disabled_value: None,
    units: &[],
};

/// The cache of pip: the default of macOS. The keys of `pip.conf` are in
/// sections, which the configuration reader does not read, and the
/// command gives `--isolated`, so pip reads no configuration file.
const PIP_ROOT: RootSpec = RootSpec {
    sources: &[],
    default: "Library/Caches/pip",
    disabled_value: None,
    units: &[],
};

/// The rule `mise.cache`.
pub const MISE_CACHE: ProducerSpec = ProducerSpec {
    id: "mise.cache",
    producer: "mise",
    base: ProducerBase::Own {
        rebuild_cost: RebuildCost::Low,
    },
    layout: "mise-cache-root",
    kind: OwnerOperationKind::Prune,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "mise can load the configuration files of the working directory and write its state directory, which is outside the cache.",
    root: &MISE_CACHE_ROOT,
    exclusions: &[],
    executables: &MISE_EXECUTABLES,
    interpreters: &[],
    arguments: &[Part::Literal("cache"), Part::Literal("prune")],
    environment: &[HOME, SYSTEM_PATH, ("MISE_CACHE_DIR", Part::ScopeRoot)],
    deadline_seconds: 120,
    effect: "mise removes the files of its cache that it has not used for its age limit. The environment names the measured root as the cache directory.",
    regeneration: "mise downloads or makes a removed file again when a later command needs it.",
    whole_cache: true,
    default_below: None,
    guard: Guard::None,
    processes: &["mise"],
    // The file or directory `.auto_prune` that mise writes in its cache root
    // for its pruning interval. One host has an empty
    // directory of this name; the file form is accepted too.
    markers: &[Marker::ChildDirectory(".auto_prune"), Marker::File(".auto_prune")],
    lookup: "The root is the default of macOS. Plonge runs `mise cache path`; Svalnir runs no query and gives the root to mise in `MISE_CACHE_DIR`.",
};

/// The rule `mise.installs`.
pub const MISE_INSTALLS: ProducerSpec = ProducerSpec {
    id: "mise.installs",
    producer: "mise",
    base: ProducerBase::Own {
        rebuild_cost: RebuildCost::Medium,
    },
    layout: "mise-installs-root",
    kind: OwnerOperationKind::Prune,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "mise selects the versions from each tracked configuration file and can write its state directory, which is outside the installs directory.",
    root: &MISE_INSTALLS_ROOT,
    exclusions: &[],
    executables: &MISE_EXECUTABLES,
    interpreters: &[],
    arguments: &[
        Part::Literal("prune"),
        Part::Literal("--tools"),
        Part::Literal("--yes"),
    ],
    environment: &[HOME, SYSTEM_PATH],
    deadline_seconds: 300,
    effect: "mise removes each installed tool version that no tracked configuration file names.",
    regeneration: "`mise install` downloads and installs a removed version again. A project that needs the version fails until then.",
    whole_cache: true,
    default_below: None,
    guard: Guard::MiseTrackedConfigs,
    processes: &["mise"],
    markers: &[Marker::File(".mise-installs.toml")],
    lookup: "The root is the default of the data directory of mise, which mise uses with the fixed environment of the command. Plonge reads `mise doctor --json`; Svalnir runs no query.",
};

/// The rule `uv.cache`, revision 2.
pub const UV_CACHE: ProducerSpec = ProducerSpec {
    id: "uv.cache",
    producer: "uv",
    base: ProducerBase::Cache,
    layout: "uv-cache-root",
    kind: OwnerOperationKind::Prune,
    bound: OwnerOperationBound::WithinScope,
    bound_reason: "The command names the measured root as the cache directory (`--cache-dir`), reads no configuration file (`--no-config`), and `uv cache prune` removes only entries of that directory.",
    root: &UV.roots[0],
    exclusions: UV.exclusions,
    executables: &[
        Location::Home(".local/bin/uv"),
        Location::Absolute("/opt/homebrew/bin/uv"),
        Location::Absolute("/usr/local/bin/uv"),
        Location::Home(".cargo/bin/uv"),
        // The `latest` install of mise unpacks the archive of uv into a
        // directory named for the platform.
        Location::Home(".local/share/mise/installs/uv/latest/uv-aarch64-apple-darwin/uv"),
        Location::Home(".local/share/mise/installs/uv/latest/uv-x86_64-apple-darwin/uv"),
    ],
    interpreters: &[],
    arguments: &[
        Part::Literal("cache"),
        Part::Literal("prune"),
        Part::Literal("--no-config"),
        Part::Literal("--cache-dir"),
        Part::ScopeRoot,
    ],
    environment: &[HOME, SYSTEM_PATH, ("UV_NO_PROGRESS", Part::Literal("1"))],
    deadline_seconds: 300,
    effect: "uv removes the entries of its cache that no environment can use, also the cached environments of uv (for example of `uvx` and `uv run --with`) that a `.venv` link of a project can refer to.",
    regeneration: "A later install downloads and builds each removed package again and needs an index that is still available.",
    whole_cache: true,
    default_below: None,
    guard: Guard::None,
    processes: &["uv", "uvx"],
    markers: &[Marker::FilePrefix {
        file: "CACHEDIR.TAG",
        prefix: b"Signature: 8a477f597d28d172789f06886806bc55",
    }],
    lookup: FROM_FILES,
};

/// The rule `pnpm.content-store`, revision 2.
pub const PNPM_STORE: ProducerSpec = ProducerSpec {
    id: "pnpm.content-store",
    producer: "pnpm",
    base: ProducerBase::Cache,
    layout: "pnpm-store-root",
    kind: OwnerOperationKind::Prune,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "pnpm can write its state and metadata caches outside the store, and a Corepack shim can start another pnpm.",
    root: &PNPM.roots[0],
    exclusions: PNPM.exclusions,
    executables: &[
        Location::Home("Library/pnpm/pnpm"),
        Location::Absolute("/opt/homebrew/bin/pnpm"),
        Location::Absolute("/usr/local/bin/pnpm"),
        Location::Home(".local/share/mise/installs/pnpm/latest/bin/pnpm"),
    ],
    interpreters: &NODE,
    arguments: &[
        Part::Literal("store"),
        Part::Literal("prune"),
        Part::Literal("--store-dir"),
        Part::ScopeRoot,
    ],
    environment: &[
        HOME,
        SYSTEM_PATH,
        ("CI", Part::Literal("true")),
        ("COREPACK_ENABLE_NETWORK", Part::Literal("0")),
    ],
    deadline_seconds: 300,
    effect: "pnpm removes the packages of the store that no project refers to.",
    regeneration: "A later install downloads each removed package again and needs a registry that is still available.",
    whole_cache: true,
    default_below: None,
    guard: Guard::None,
    processes: &["pnpm", "node"],
    markers: &[
        Marker::ChildDirectory("v10/files"),
        Marker::ChildDirectory("v3/files"),
    ],
    lookup: FROM_FILES,
};

/// The rule `go.build-cache`, revision 2.
pub const GO_BUILD: ProducerSpec = ProducerSpec {
    id: "go.build-cache",
    producer: "go",
    base: ProducerBase::Cache,
    layout: "go-build-cache-root",
    kind: OwnerOperationKind::Clear,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "Go can write its telemetry data and its configuration directory, which are outside the cache.",
    root: &GO.roots[0],
    exclusions: GO.exclusions,
    executables: &GO_EXECUTABLES,
    interpreters: &[],
    arguments: &[Part::Literal("clean"), Part::Literal("-cache")],
    environment: &[
        HOME,
        SYSTEM_PATH,
        ("GOCACHE", Part::ScopeRoot),
        GO_FIXED[0],
        GO_FIXED[1],
    ],
    deadline_seconds: 300,
    effect: "Go removes the whole build cache. The environment names the measured root as `GOCACHE`.",
    regeneration: "The next build compiles each package again, and the next test run runs each test again.",
    whole_cache: false,
    default_below: None,
    guard: Guard::None,
    processes: &["go"],
    markers: &[Marker::FilePrefix {
        file: "README",
        prefix: b"This directory holds cached build artifacts from the Go build system.",
    }],
    lookup: FROM_FILES,
};

/// The rule `go.module-cache`.
pub const GO_MODULES: ProducerSpec = ProducerSpec {
    id: "go.module-cache",
    producer: "go",
    base: ProducerBase::Own {
        rebuild_cost: RebuildCost::Medium,
    },
    layout: "go-module-cache-root",
    kind: OwnerOperationKind::Clear,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "Go can write its telemetry data and its configuration directory, which are outside the cache.",
    root: &GO_MODULE_ROOT,
    exclusions: &[GO_PATH_EXCLUSION],
    executables: &GO_EXECUTABLES,
    interpreters: &[],
    arguments: &[Part::Literal("clean"), Part::Literal("-modcache")],
    environment: &[
        HOME,
        SYSTEM_PATH,
        ("GOMODCACHE", Part::ScopeRoot),
        GO_FIXED[0],
        GO_FIXED[1],
    ],
    deadline_seconds: 300,
    effect: "Go removes the whole module cache, with the downloaded modules and their sources. The environment names the measured root as `GOMODCACHE`.",
    regeneration: "The next build downloads each module again and needs a module proxy or a source that is still available.",
    whole_cache: false,
    guard: Guard::None,
    default_below: Some((GO_PATH_SOURCE, "pkg/mod")),
    processes: &["go"],
    markers: &[Marker::ChildDirectory("cache/download")],
    lookup: FROM_FILES,
};

/// The rule `homebrew.cleanup`, revision 2.
pub const HOMEBREW_CLEANUP: ProducerSpec = ProducerSpec {
    id: "homebrew.cleanup",
    producer: "homebrew",
    base: ProducerBase::OwnerTool,
    layout: "homebrew-cache-root",
    kind: OwnerOperationKind::Clear,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "`brew cleanup --prune=all` also removes old kegs in the Cellar and files of the Caskroom and of the logs, outside the cache. The bound interpreter `/bin/bash` starts a Ruby interpreter and Ruby code that the binding does not have.",
    root: &HOMEBREW.roots[0],
    exclusions: HOMEBREW.exclusions,
    executables: &[
        Location::Absolute("/opt/homebrew/bin/brew"),
        Location::Absolute("/usr/local/bin/brew"),
    ],
    interpreters: &[(Location::Absolute("/bin/bash"), Some("-pu"))],
    arguments: &[Part::Literal("cleanup"), Part::Literal("--prune=all")],
    environment: &[
        HOME,
        SYSTEM_PATH,
        ("HOMEBREW_CACHE", Part::ScopeRoot),
        ("HOMEBREW_NO_AUTO_UPDATE", Part::Literal("1")),
        ("HOMEBREW_NO_INSTALL_CLEANUP", Part::Literal("1")),
        ("HOMEBREW_NO_AUTOREMOVE", Part::Literal("1")),
        ("HOMEBREW_NO_ANALYTICS", Part::Literal("1")),
        ("HOMEBREW_NO_ENV_HINTS", Part::Literal("1")),
    ],
    deadline_seconds: 300,
    effect: "Homebrew removes each file of its cache. Outside the measured cache it also removes the old versions of each formula of the Cellar and of each cask that is not pinned, old versions of its portable Ruby, the compiled Python files of the prefix, old logs and lock files, and the broken symbolic links and empty directories of the prefix. The environment names the measured root as `HOMEBREW_CACHE` and stops the removal of unused dependencies.",
    regeneration: "A later install or reinstall downloads the bottle or the source again, and an old version is not available again unless the user installs it.",
    whole_cache: true,
    default_below: None,
    guard: Guard::HomebrewSystemEnv,
    processes: &["brew", "ruby"],
    markers: &[Marker::ChildDirectory("downloads")],
    lookup: FROM_FILES,
};

/// The rule `npm.content-cache`.
pub const NPM_CACHE: ProducerSpec = ProducerSpec {
    id: "npm.content-cache",
    producer: "npm",
    base: ProducerBase::Own {
        rebuild_cost: RebuildCost::Medium,
    },
    layout: "npm-cache-root",
    kind: OwnerOperationKind::Clear,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "npm loads the configuration files of the user, and the bound interpreter loads the modules of npm, which the binding does not have.",
    root: &NPM_ROOT,
    exclusions: &[],
    executables: &[
        Location::Absolute("/opt/homebrew/bin/npm"),
        Location::Absolute("/usr/local/bin/npm"),
        // The real npm of the `latest` install of mise. The `bin/npm` of
        // that install is a Bash wrapper that finds `mise` and `npm` through
        // `PATH`, so it is not a location.
        Location::Home(".local/share/mise/installs/node/latest/lib/node_modules/npm/bin/npm-cli.js"),
    ],
    interpreters: &NODE,
    arguments: &[
        Part::Literal("cache"),
        Part::Literal("clean"),
        Part::Literal("--force"),
        Part::Literal("--cache"),
        Part::ScopeRoot,
    ],
    environment: &[
        HOME,
        SYSTEM_PATH,
        ("CI", Part::Literal("true")),
        ("NPM_CONFIG_UPDATE_NOTIFIER", Part::Literal("false")),
    ],
    deadline_seconds: 300,
    effect: "npm removes its content cache (`_cacache`) below the measured root. The logs and the `npx` directory stay.",
    regeneration: "A later install downloads each removed package again and needs a registry that is still available.",
    whole_cache: true,
    default_below: None,
    guard: Guard::None,
    processes: &["npm", "npx", "node"],
    markers: &[Marker::ChildDirectory("_cacache")],
    lookup: FROM_FILES,
};

/// The rule `yarn.cache`, revision 2: the global cache of Yarn 1.
pub const YARN_CACHE: ProducerSpec = ProducerSpec {
    id: "yarn.cache",
    producer: "yarn",
    base: ProducerBase::Cache,
    layout: "yarn-classic-cache-root",
    kind: OwnerOperationKind::Clear,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "Yarn loads the configuration files of the user, the bound interpreter loads the modules of Yarn, and a Corepack shim can start another Yarn.",
    root: &YARN.roots[0],
    exclusions: YARN.exclusions,
    executables: &[
        Location::Absolute("/opt/homebrew/bin/yarn"),
        Location::Absolute("/usr/local/bin/yarn"),
        Location::Home(".local/share/mise/installs/yarn/latest/bin/yarn"),
    ],
    interpreters: &NODE,
    arguments: &[
        Part::Literal("cache"),
        Part::Literal("clean"),
        Part::Literal("--cache-folder"),
        Part::ScopeRoot,
    ],
    environment: &[
        HOME,
        SYSTEM_PATH,
        ("CI", Part::Literal("true")),
        ("COREPACK_ENABLE_NETWORK", Part::Literal("0")),
    ],
    deadline_seconds: 300,
    effect: "Yarn 1 removes the content of the measured cache folder. Yarn 2 and later refuse the option `--cache-folder`, so the command then ends with an error and removes nothing.",
    regeneration: "A later install downloads each removed package again and needs a registry that is still available.",
    whole_cache: false,
    default_below: None,
    guard: Guard::None,
    processes: &["yarn", "node"],
    markers: &[Marker::ChildDirectory("v6")],
    lookup: FROM_FILES,
};

/// The rule `pip.cache`.
pub const PIP_CACHE: ProducerSpec = ProducerSpec {
    id: "pip.cache",
    producer: "pip",
    base: ProducerBase::Own {
        rebuild_cost: RebuildCost::Medium,
    },
    layout: "pip-cache-root",
    kind: OwnerOperationKind::Clear,
    bound: OwnerOperationBound::Unbounded,
    bound_reason: "The bound interpreter loads the modules of pip, which the binding does not have, and Python can write compiled files outside the cache.",
    root: &PIP_ROOT,
    exclusions: &[],
    executables: &[
        Location::Absolute("/opt/homebrew/bin/pip3"),
        Location::Absolute("/usr/local/bin/pip3"),
    ],
    interpreters: &[
        (Location::Absolute("/opt/homebrew/bin/python3"), None),
        (Location::Absolute("/usr/local/bin/python3"), None),
    ],
    arguments: &[
        Part::Literal("cache"),
        Part::Literal("purge"),
        Part::Literal("--isolated"),
        Part::Literal("--no-input"),
        Part::Literal("--disable-pip-version-check"),
        Part::Literal("--cache-dir"),
        Part::ScopeRoot,
    ],
    environment: &[HOME, SYSTEM_PATH],
    deadline_seconds: 120,
    effect: "pip removes the wheels and the HTTP responses of its cache. With `--isolated`, pip reads no configuration file and no `PIP_` variable.",
    regeneration: "A later install downloads each removed package again and needs an index that is still available.",
    whole_cache: true,
    default_below: None,
    guard: Guard::None,
    processes: &["pip*", "python*", "Python"],
    markers: &[
        Marker::ChildDirectory("http-v2"),
        Marker::ChildDirectory("http"),
        Marker::ChildDirectory("wheels"),
    ],
    lookup: "The root is the default of macOS: the keys of `pip.conf` are in sections, which Svalnir does not read, and the command gives `--isolated`. Plonge runs `pip cache dir`; Svalnir runs no query.",
};

/// The rules of this module, in the sequence of the report.
pub const PRODUCER_SPECS: [ProducerSpec; 10] = [
    MISE_CACHE,
    MISE_INSTALLS,
    UV_CACHE,
    PNPM_STORE,
    GO_BUILD,
    GO_MODULES,
    HOMEBREW_CLEANUP,
    NPM_CACHE,
    YARN_CACHE,
    PIP_CACHE,
];
