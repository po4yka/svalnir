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

/// Reads one tracked file. `Ok(false)` when the target of the link is
/// absent.
fn read_tracked(target: &Path) -> Result<bool, &'static str> {
    let metadata = match fs::metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
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
