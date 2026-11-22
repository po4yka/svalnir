//! The project roots that mise records (`docs/CLEANUP_RULES.md` section 4).
//!
//! mise makes a symbolic link in its tracked-configs directory for each
//! configuration file that it loads. This module reads the targets of these
//! links. It runs no mise command, reads no configuration file, and follows
//! no link: the target of a link is a path text, and the project root is the
//! directory of the configuration file, as mise defines it. A project root is
//! a project directory, not a search root: the inspection examines the units
//! of that directory only.
//!
//! The read is bounded: at most [`MAX_TRACKED_CONFIGS`] entries of the
//! directory, each link target at most [`MAX_LINK_BYTES`] long.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use svalnir_core::process::Uid;

use super::inspect::{RootKind, RootSource, SearchRootEntry};

/// The largest number of entries of the tracked-configs directory that one
/// read examines.
pub const MAX_TRACKED_CONFIGS: usize = 1_024;

/// The longest link target that the read accepts, in bytes.
pub const MAX_LINK_BYTES: usize = 4_096;

/// The locations of the files of mise for one user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseLocations {
    /// The tracked-configs directory.
    pub tracked_configs: PathBuf,
    /// The directory of the global configuration of mise. A file below it
    /// applies to each project.
    pub config_directory: PathBuf,
}

impl MiseLocations {
    /// The locations below the home directory `home`:
    /// `$XDG_STATE_HOME/mise/tracked-configs`, else
    /// `~/.local/state/mise/tracked-configs`, and `$XDG_CONFIG_HOME/mise`,
    /// else `~/.config/mise`. A value that is not an absolute path is not
    /// used.
    #[must_use]
    pub fn resolve(home: &Path, state_home: Option<&OsStr>, config_home: Option<&OsStr>) -> Self {
        let absolute = |value: Option<&OsStr>| {
            value
                .map(Path::new)
                .filter(|path| path.is_absolute())
                .map(Path::to_path_buf)
        };
        let state: PathBuf = absolute(state_home).unwrap_or_else(|| home.join(".local/state"));
        let config: PathBuf = absolute(config_home).unwrap_or_else(|| home.join(".config"));
        Self {
            tracked_configs: state.join("mise/tracked-configs"),
            config_directory: config.join("mise"),
        }
    }
}

/// Why the read of the tracked-configs directory gave no project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum MiseState {
    /// The caller turned the source off (`--no-mise`).
    Off,
    /// The directory was read.
    Read,
    /// The directory does not exist: mise loaded no configuration, or it is
    /// not installed.
    Absent,
    /// The directory failed a check. The reason is a stable name.
    Refused(&'static str),
}

/// One link of the tracked-configs directory that gives no project root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IgnoredLink {
    /// The name of the entry in the tracked-configs directory.
    pub name: PathBuf,
    /// Why: a stable name.
    pub reason: &'static str,
}

/// One project root that mise records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MiseRoot {
    /// The project directory, relative to the home directory.
    pub relative: PathBuf,
    /// The configuration file, the target of the link.
    pub config: PathBuf,
}

/// The result of one read of the tracked-configs directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MiseDiscovery {
    /// The tracked-configs directory.
    pub directory: PathBuf,
    /// The state of the read.
    pub state: MiseState,
    /// The project roots, sorted, each one time.
    pub roots: Vec<MiseRoot>,
    /// The links that give no project root.
    pub ignored: Vec<IgnoredLink>,
    /// True when the directory has more entries than the read examines.
    pub truncated: bool,
}

impl MiseDiscovery {
    /// The result when the caller turned the source off.
    #[must_use]
    pub fn off(locations: &MiseLocations) -> Self {
        Self {
            directory: locations.tracked_configs.clone(),
            state: MiseState::Off,
            roots: Vec::new(),
            ignored: Vec::new(),
            truncated: false,
        }
    }

    /// The project roots as roots of a request of the rule.
    #[must_use]
    pub fn entries(&self) -> Vec<SearchRootEntry> {
        self.roots
            .iter()
            .map(|root| SearchRootEntry {
                relative: root.relative.clone(),
                kind: RootKind::Project,
                source: RootSource::Mise {
                    config: root.config.clone(),
                },
            })
            .collect()
    }
}

/// Whether `path` is an absolute path with no `.`, no `..`, and no empty
/// component.
fn is_plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// The project root of the configuration file `file`, as mise defines it:
/// a file in `.config`, `.config/mise`, `.config/mise/conf.d`, `mise`, or
/// `.mise` belongs to the directory above those directories.
#[must_use]
pub fn project_root(file: &Path) -> PathBuf {
    let name = |path: &Path| -> String {
        path.file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
    };
    let mut directory: PathBuf = file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    let mut base: String = name(file);
    if name(&directory) == "conf.d"
        && directory
            .parent()
            .is_some_and(|parent| name(parent) == "mise")
    {
        directory.pop();
        "config.toml".clone_into(&mut base);
    }
    match name(&directory).as_str() {
        "mise" | ".mise" if base.starts_with("config") => {
            directory.pop();
            if name(&directory) == ".config" {
                directory.pop();
            }
        }
        ".config" if base.starts_with("mise") => {
            directory.pop();
        }
        _ => {}
    }
    directory
}

/// Reads the tracked-configs directory of `locations` for the user
/// `principal` with the home directory `home`.
///
/// The directory must be a directory with the user as owner, not a
/// symbolic link. Each entry must be a symbolic link whose target is a
/// plain absolute path below the home directory to a regular file. A
/// target that is absent, is a global configuration of mise (below its
/// configuration directory, or with the home directory as its project
/// root), or is outside the home directory gives no project root, and the
/// result names it.
#[must_use]
pub fn tracked_projects(home: &Path, locations: &MiseLocations, principal: Uid) -> MiseDiscovery {
    let directory: &Path = &locations.tracked_configs;
    let mut result: MiseDiscovery = MiseDiscovery {
        directory: directory.to_path_buf(),
        state: MiseState::Read,
        roots: Vec::new(),
        ignored: Vec::new(),
        truncated: false,
    };
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && metadata.uid() == principal.get() => {}
        Ok(metadata) if metadata.is_dir() => {
            result.state = MiseState::Refused("tracked_configs_owner");
            return result;
        }
        Ok(_) => {
            result.state = MiseState::Refused("tracked_configs_not_directory");
            return result;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            result.state = MiseState::Absent;
            return result;
        }
        Err(_) => {
            result.state = MiseState::Refused("tracked_configs_not_readable");
            return result;
        }
    }
    let Ok(entries) = fs::read_dir(directory) else {
        result.state = MiseState::Refused("tracked_configs_not_readable");
        return result;
    };
    let mut names: Vec<PathBuf> = Vec::new();
    for entry in entries {
        if names.len() >= MAX_TRACKED_CONFIGS {
            result.truncated = true;
            break;
        }
        let Ok(entry) = entry else {
            result.state = MiseState::Refused("tracked_configs_not_readable");
            return result;
        };
        names.push(PathBuf::from(entry.file_name()));
    }
    names.sort();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for name in names {
        match root_of_link(home, locations, &directory.join(&name)) {
            Ok((relative, config)) => {
                if seen.insert(relative.clone()) {
                    result.roots.push(MiseRoot { relative, config });
                }
            }
            Err(reason) => result.ignored.push(IgnoredLink { name, reason }),
        }
    }
    result
        .roots
        .sort_by(|left, right| left.relative.cmp(&right.relative));
    result
}

/// The project root of one link, relative to the home directory, and its
/// configuration file; or why the link gives none.
fn root_of_link(
    home: &Path,
    locations: &MiseLocations,
    link: &Path,
) -> Result<(PathBuf, PathBuf), &'static str> {
    let metadata = fs::symlink_metadata(link).map_err(|_| "link_not_readable")?;
    if !metadata.file_type().is_symlink() {
        return Err("not_a_link");
    }
    let target: PathBuf = fs::read_link(link).map_err(|_| "link_not_readable")?;
    if target.as_os_str().len() > MAX_LINK_BYTES {
        return Err("target_too_long");
    }
    let target: PathBuf = if target.is_absolute() {
        target
    } else {
        link.parent().unwrap_or(link).join(target)
    };
    if !is_plain_absolute(&target) {
        return Err("target_not_plain");
    }
    if !target.starts_with(home) {
        return Err("target_outside_home");
    }
    match fs::symlink_metadata(&target) {
        Ok(found) if found.is_file() => {}
        Ok(_) => return Err("target_not_file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err("target_absent"),
        Err(_) => return Err("target_not_readable"),
    }
    if target.starts_with(&locations.config_directory) {
        return Err("global_config");
    }
    let root: PathBuf = project_root(&target);
    if root == home {
        return Err("global_config");
    }
    let relative: PathBuf = root
        .strip_prefix(home)
        .map_err(|_| "target_outside_home")?
        .to_path_buf();
    if relative.as_os_str().is_empty() {
        return Err("global_config");
    }
    Ok((relative, target))
}
