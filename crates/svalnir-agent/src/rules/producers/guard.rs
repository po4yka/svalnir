//! The guard of `mise.installs`: each tracked configuration file of mise
//! loads.
//!
//! `mise prune --tools` removes each installed tool version that no
//! tracked configuration file names. A tracked file that mise cannot load
//! protects no version, so the prune can remove a version that a project
//! needs. Plonge checks this with `mise prune --tools --dry-run`; this
//! build runs no producer query (`docs/CLEANUP_RULES.md` section 9), so the
//! guard reads the files. It is weaker than the load of mise: it does not
//! know the trust state of a file or the schema of mise.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Serialize;
use svalnir_core::process::Uid;

use crate::rules::projects::{MAX_TRACKED_CONFIGS, MiseLocations};

/// The largest tracked configuration file that the guard reads, in bytes.
pub const MAX_TRACKED_CONFIG_BYTES: u64 = 1024 * 1024;

/// The result of the guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuardOutcome {
    /// The rule has no guard.
    None,
    /// Each tracked file loads: a link to a file that is absent, which mise
    /// leaves out, or a readable regular file, with a TOML file that parses.
    Passed {
        /// The number of tracked files that the guard read.
        files: usize,
    },
    /// The guard refused the operation. The reason is a stable name.
    Refused {
        /// The reason.
        reason: &'static str,
        /// The tracked file or the directory of the reason.
        path: PathBuf,
    },
}

impl GuardOutcome {
    /// Whether the operation can have a plan.
    #[must_use]
    pub const fn permits(&self) -> bool {
        matches!(self, Self::None | Self::Passed { .. })
    }
}

/// Whether the absent target `target` is the file of a removed project,
/// which mise leaves out: its directory exists, and it is not below a
/// directory of `/Volumes` that is not a mount point. A project on a
/// volume that is not mounted is not removed, and mise cannot load its
/// file.
fn absent_is_removed(target: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let parent_exists: bool = target
        .parent()
        .is_some_and(|parent| fs::metadata(parent).is_ok_and(|metadata| metadata.is_dir()));
    if !parent_exists {
        return false;
    }
    let mut components = target.components();
    let volume: Option<PathBuf> = match (components.next(), components.next(), components.next()) {
        (
            Some(std::path::Component::RootDir),
            Some(std::path::Component::Normal(first)),
            Some(std::path::Component::Normal(name)),
        ) if first == "Volumes" => Some(Path::new("/Volumes").join(name)),
        _ => None,
    };
    let Some(volume) = volume else {
        return true;
    };
    // A mount point has another device than the directory above it.
    match (fs::metadata(&volume), fs::metadata("/Volumes")) {
        (Ok(mounted), Ok(above)) => mounted.dev() != above.dev(),
        _ => false,
    }
}

/// Reads one tracked file. `Ok(false)` when the target of the link is
/// absent and is the file of a removed project ([`absent_is_removed`]).
fn read_tracked(target: &Path) -> Result<bool, &'static str> {
    let metadata = match fs::metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return if absent_is_removed(target) {
                Ok(false)
            } else {
                Err("tracked_config_volume_absent")
            };
        }
        Err(_) => return Err("tracked_config_not_readable"),
    };
    if !metadata.is_file() {
        return Err("tracked_config_not_file");
    }
    if metadata.len() > MAX_TRACKED_CONFIG_BYTES {
        return Err("tracked_config_too_large");
    }
    let mut text: String = String::new();
    fs::File::open(target)
        .and_then(|file| {
            file.take(MAX_TRACKED_CONFIG_BYTES)
                .read_to_string(&mut text)
        })
        .map_err(|_| "tracked_config_not_readable")?;
    let is_toml: bool = target
        .extension()
        .is_some_and(|extension| extension == "toml");
    if is_toml && text.parse::<toml::Table>().is_err() {
        return Err("tracked_config_not_loadable");
    }
    Ok(true)
}

/// Checks each tracked configuration file of mise for the user
/// `principal` with the home directory `home`.
///
/// The tracked-configs directory is below the home directory, as mise
/// finds it with the fixed environment of the command, which has no
/// `XDG_STATE_HOME`. An absent directory passes: mise tracks no file. The
/// directory must be a directory of the user with at most
/// [`MAX_TRACKED_CONFIGS`] entries, and each entry must be a symbolic link.
#[must_use]
pub fn mise_tracked_configs(home: &Path, principal: Uid) -> GuardOutcome {
    use std::os::unix::fs::MetadataExt;

    let directory: PathBuf = MiseLocations::resolve(home, None, None).tracked_configs;
    let refused = |reason: &'static str, path: &Path| GuardOutcome::Refused {
        reason,
        path: path.to_path_buf(),
    };
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && metadata.uid() == principal.get() => {}
        Ok(_) => return refused("tracked_configs_not_private_directory", &directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return GuardOutcome::Passed { files: 0 };
        }
        Err(_) => return refused("tracked_configs_not_readable", &directory),
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return refused("tracked_configs_not_readable", &directory);
    };
    let mut links: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return refused("tracked_configs_not_readable", &directory);
        };
        if links.len() >= MAX_TRACKED_CONFIGS {
            return refused("tracked_configs_truncated", &directory);
        }
        links.push(entry.path());
    }
    links.sort();
    let mut files: usize = 0;
    for link in links {
        let is_link: bool =
            fs::symlink_metadata(&link).is_ok_and(|metadata| metadata.file_type().is_symlink());
        if !is_link {
            return refused("tracked_config_not_link", &link);
        }
        let Ok(target) = fs::read_link(&link) else {
            return refused("tracked_config_not_readable", &link);
        };
        let target: PathBuf = if target.is_absolute() {
            target
        } else {
            directory.join(target)
        };
        match read_tracked(&target) {
            Ok(true) => files += 1,
            Ok(false) => {}
            Err(reason) => return refused(reason, &target),
        }
    }
    GuardOutcome::Passed { files }
}

/// The system `brew.env` files of Homebrew: the file of the system and the
/// file of each documented prefix.
pub const HOMEBREW_SYSTEM_ENV_FILES: [&str; 3] = [
    "/etc/homebrew/brew.env",
    "/opt/homebrew/etc/homebrew/brew.env",
    "/usr/local/etc/homebrew/brew.env",
];

/// The keys of a system `brew.env` file that change the effect of
/// `brew cleanup --prune=all` with the fixed environment of the command.
pub const HOMEBREW_OVERRIDING_KEYS: [&str; 7] = [
    "HOMEBREW_CACHE",
    "HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY",
    "HOMEBREW_NO_INSTALL_CLEANUP",
    "HOMEBREW_NO_AUTOREMOVE",
    "HOMEBREW_AUTOREMOVE",
    "HOMEBREW_NO_AUTO_UPDATE",
    "HOMEBREW_CLEANUP_MAX_AGE_DAYS",
];

/// The largest system `brew.env` file that the guard reads, in bytes.
const MAX_BREW_ENV_BYTES: u64 = 64 * 1024;

/// The guard of `homebrew.cleanup`: no file of `files` sets a key of
/// [`HOMEBREW_OVERRIDING_KEYS`]. Homebrew reads these files, and a value
/// there can take priority over the fixed environment of the command. A
/// file that exists and cannot be read, or that is larger than 64 KiB,
/// also refuses: its keys are not known.
#[must_use]
pub fn homebrew_system_env<P: AsRef<Path>>(files: &[P]) -> GuardOutcome {
    use crate::rules::caches::ConfigFormat;
    use crate::rules::caches::config::find_values;

    let refused = |path: &Path| GuardOutcome::Refused {
        reason: super::HOMEBREW_ENV_OVERRIDES,
        path: path.to_path_buf(),
    };
    let mut read: usize = 0;
    for file in files {
        let path: &Path = file.as_ref();
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return refused(path),
        };
        if !metadata.is_file() || metadata.len() > MAX_BREW_ENV_BYTES {
            return refused(path);
        }
        let mut text: String = String::new();
        let opened = fs::File::open(path)
            .and_then(|file| file.take(MAX_BREW_ENV_BYTES).read_to_string(&mut text));
        if opened.is_err() {
            return refused(path);
        }
        read += 1;
        let sets_key: bool = HOMEBREW_OVERRIDING_KEYS
            .iter()
            .any(|key| !find_values(&text, ConfigFormat::Assignment, key).is_empty());
        if sets_key {
            return refused(path);
        }
    }
    GuardOutcome::Passed { files: read }
}

/// The user `brew.env` file of Homebrew below the home directory. The fixed
/// environment of the command has `HOME` and no `XDG_CONFIG_HOME`, so this is
/// the one user file that Homebrew reads for it.
const HOMEBREW_USER_ENV_FILE: &str = ".homebrew/brew.env";

/// The guard of `homebrew.cleanup` for the user file of the home directory
/// `home`. The user file takes precedence over the system files, so a key of
/// [`HOMEBREW_OVERRIDING_KEYS`] in it can change the effect of the command
/// as a key of a system file can. `HOMEBREW_CACHE` is the exception: the root
/// of the rule is read from this same file and the command names that root
/// in its own `HOMEBREW_CACHE`, so the value cannot differ from the root.
/// The file is read with no symbolic link followed and at most 64 KiB; a
/// file that is a link, is not a regular file, is too large, or cannot be
/// read refuses, because its keys are not known.
#[must_use]
pub fn homebrew_user_env(home: &Path) -> GuardOutcome {
    use crate::rules::caches::ConfigFormat;
    use crate::rules::caches::config::find_values;
    use std::os::unix::fs::OpenOptionsExt;

    let path: PathBuf = home.join(HOMEBREW_USER_ENV_FILE);
    let refused = || GuardOutcome::Refused {
        reason: super::HOMEBREW_ENV_OVERRIDES,
        path: path.clone(),
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return GuardOutcome::Passed { files: 0 };
        }
        Err(_) => return refused(),
    };
    if !metadata.is_file() || metadata.len() > MAX_BREW_ENV_BYTES {
        return refused();
    }
    let mut text: String = String::new();
    let opened = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .and_then(|file| file.take(MAX_BREW_ENV_BYTES).read_to_string(&mut text));
    if opened.is_err() {
        return refused();
    }
    let sets_key: bool = HOMEBREW_OVERRIDING_KEYS
        .iter()
        .filter(|key| **key != "HOMEBREW_CACHE")
        .any(|key| !find_values(&text, ConfigFormat::Assignment, key).is_empty());
    if sets_key {
        return refused();
    }
    GuardOutcome::Passed { files: 1 }
}
