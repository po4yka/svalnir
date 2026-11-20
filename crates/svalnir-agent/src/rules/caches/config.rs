//! The read of one fixed key from the configuration file of a producer.
//!
//! `docs/CLEANUP_RULES.md` section 4: discover the configured location of
//! the producer when that is supported; the default is a hint only. Do not
//! evaluate substitutions, scripts, or environment expressions.
//!
//! This module reads text only. It runs no producer tool, reads no
//! environment variable, and evaluates nothing: a value with a variable
//! reference, a command substitution, or a relative path is a value that
//! this build does not support. A configuration file must be a plain file
//! with one name and the owner of the inspection ([`read_record`]), with
//! no symbolic link in its path and on local filesystems only
//! ([`read_source`]).

use std::path::{Path, PathBuf};

use svalnir_core::process::Uid;

use super::super::unit::{RecordRead, WalkStop, is_plain_absolute, read_record, walk_local};
use crate::platform::volume::MountTable;

/// The largest configuration file that the inspection reads, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// The syntax of a configuration file. Each parser reads one key at the
/// top level only. A key in a section, a table, or a nested map is not
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// `key=value` lines, with `#` and `;` comments, as `.npmrc` and the
    /// `rc` file of pnpm. The first `[section]` line ends the top level.
    Ini,
    /// `key value` lines, with `#` comments, as `.yarnrc` of Yarn 1.
    SpaceSeparated,
    /// `key: value` lines with no indentation, as `.yarnrc.yml` of Yarn 2
    /// and later and `config.yaml` of `CocoaPods`.
    YamlTopLevel,
    /// `key = "value"` lines, as `uv.toml`. The first `[table]` line ends
    /// the top level.
    TomlTopLevel,
    /// `KEY=VALUE` lines, as the `env` file of Go and `brew.env` of
    /// Homebrew.
    Assignment,
}

/// One configuration file of a producer and the key that names a
/// location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSource {
    /// The file, relative to the home directory.
    pub file: &'static str,
    /// The syntax of the file.
    pub format: ConfigFormat,
    /// The key.
    pub key: &'static str,
    /// Whether the producer expands a value that starts with `~/` to the
    /// home directory. For a producer that does not, such a value is not
    /// supported.
    pub tilde: bool,
    /// Whether the value is a list of paths separated by `:`, as `GOPATH`.
    pub list: bool,
}

/// The reason a configuration file gives no location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigProblem {
    /// The file exists and is not a plain file with one name and the
    /// owner of the inspection, is too large, or cannot be read.
    FileNotReadable,
    /// The value is a relative path, has a variable reference or a
    /// command substitution, or is not valid UTF-8.
    ValueNotSupported,
    /// Two configuration files name different locations, and this build
    /// does not know which one the producer uses.
    Conflicting,
}

impl ConfigProblem {
    /// The stable name of the problem.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileNotReadable => "configuration_not_readable",
            Self::ValueNotSupported => "configuration_value_not_supported",
            Self::Conflicting => "configuration_conflicting",
        }
    }
}

/// What one configuration file says about the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    /// The file is absent, or it does not have the key.
    NotSet,
    /// The raw text of the value, with its quotes removed.
    Set(String),
    /// The file gives no value that this build can read.
    Problem(ConfigProblem),
}

/// Reads the key of `source` below `home`.
///
/// Before the first call on the path of the file, [`walk_local`] examines
/// each component from `/` on local filesystems only, and a directory
/// above the file must not be a symbolic link. A file below a link (for
/// example a `~/.config` of a dotfile manager) or on a filesystem that is
/// not local is thus not read, and the read starts no automount.
pub fn read_source(
    source: &ConfigSource,
    home: &Path,
    principal: Uid,
    mounts: &MountTable,
) -> ConfigValue {
    let path: PathBuf = home.join(source.file);
    match walk_local(&path, mounts) {
        Ok(_) => {}
        Err(WalkStop::Absent) => return ConfigValue::NotSet,
        Err(_) => return ConfigValue::Problem(ConfigProblem::FileNotReadable),
    }
    match read_record(&path, MAX_CONFIG_BYTES, principal) {
        RecordRead::Absent => ConfigValue::NotSet,
        RecordRead::Denied | RecordRead::Invalid => {
            ConfigValue::Problem(ConfigProblem::FileNotReadable)
        }
        RecordRead::Read { bytes, .. } => match std::str::from_utf8(&bytes) {
            Ok(text) => match find_values(text, source.format, source.key).as_slice() {
                [] => ConfigValue::NotSet,
                [first, rest @ ..] if rest.iter().all(|other| other == first) => {
                    // An empty list value, as `GOPATH=`, is the default.
                    if source.list && first.is_empty() {
                        ConfigValue::NotSet
                    } else {
                        ConfigValue::Set(first.clone())
                    }
                }
                // A producer can use the first or the last line of a key;
                // this build does not decide which.
                _ => ConfigValue::Problem(ConfigProblem::Conflicting),
            },
            Err(_) => ConfigValue::Problem(ConfigProblem::FileNotReadable),
        },
    }
}

/// The value of each top-level line of `key` in `text`, with its quotes
/// and its trailing comment removed.
pub fn find_values(text: &str, format: ConfigFormat, key: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // A byte order mark is not a part of the first key.
    let text: &str = text.strip_prefix('\u{feff}').unwrap_or(text);
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let value: Option<&str> = match format {
            ConfigFormat::Ini | ConfigFormat::TomlTopLevel => {
                if trimmed.starts_with('[') {
                    break;
                }
                if format == ConfigFormat::Ini && trimmed.starts_with(';') {
                    continue;
                }
                trimmed
                    .split_once('=')
                    .filter(|(name, _)| unquote(name.trim()) == key)
                    .map(|(_, value)| value)
            }
            ConfigFormat::SpaceSeparated => trimmed
                .split_once(char::is_whitespace)
                .filter(|(name, _)| unquote(name) == key)
                .map(|(_, value)| value),
            ConfigFormat::YamlTopLevel => {
                // A line with indentation is in a nested map.
                if line.starts_with(char::is_whitespace) {
                    continue;
                }
                trimmed
                    .split_once(':')
                    .filter(|(name, _)| unquote(name.trim()) == key)
                    .map(|(_, value)| value)
            }
            ConfigFormat::Assignment => trimmed
                .split_once('=')
                .filter(|(name, _)| name.trim() == key)
                .map(|(_, value)| value),
        };
        if let Some(value) = value {
            found.push(unquote(strip_comment(value.trim(), format)).to_owned());
        }
    }
    found
}

/// `value` with a trailing comment removed. A value in quotes ends at its
/// closing quote. In an unquoted value, a comment of the `ini` syntax of
/// npm starts at the first `;` or `#`; in the other syntaxes, a comment
/// starts at a `#` after a space or a tab.
fn strip_comment(value: &str, format: ConfigFormat) -> &str {
    if value.starts_with('"') || value.starts_with('\'') {
        let quote: char = value.chars().next().unwrap_or('"');
        return value[1..]
            .find(quote)
            .map_or(value, |end| &value[..end + 2]);
    }
    let start: Option<usize> = match format {
        ConfigFormat::Ini => value.find([';', '#']),
        ConfigFormat::YamlTopLevel | ConfigFormat::TomlTopLevel | ConfigFormat::SpaceSeparated => {
            value
                .char_indices()
                .zip(value.chars().skip(1))
                .find(|((_, before), after)| before.is_whitespace() && *after == '#')
                .map(|((index, _), _)| index)
        }
        ConfigFormat::Assignment => None,
    };
    start.map_or(value, |start| value[..start].trim_end())
}

/// `text` with one pair of matching quotes removed.
fn unquote(text: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = text
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    text
}

/// The paths of a raw value: an absolute path, or `~/` and a path when
/// the producer expands it. A list value gives each of its paths.
///
/// # Errors
///
/// Returns [`ConfigProblem::ValueNotSupported`] for an empty value, a
/// relative path, a path with a `.` or `..` component, and a value with
/// `$`, `` ` ``, `%`, or a control character: this build evaluates no
/// substitution.
pub fn paths_of(
    raw: &str,
    source: &ConfigSource,
    home: &Path,
) -> Result<Vec<PathBuf>, ConfigProblem> {
    let parts: Vec<&str> = if source.list {
        raw.split(':').filter(|part| !part.is_empty()).collect()
    } else {
        vec![raw]
    };
    if parts.is_empty() {
        return Err(ConfigProblem::ValueNotSupported);
    }
    parts
        .into_iter()
        .map(|part| path_of(part, source.tilde, home))
        .collect()
}

fn path_of(raw: &str, tilde: bool, home: &Path) -> Result<PathBuf, ConfigProblem> {
    let has_expression: bool = raw
        .chars()
        .any(|character| matches!(character, '$' | '`' | '%') || character.is_control());
    if raw.is_empty() || has_expression {
        return Err(ConfigProblem::ValueNotSupported);
    }
    let path: PathBuf = match raw.strip_prefix("~/") {
        Some(rest) if tilde => home.join(rest),
        _ => PathBuf::from(raw),
    };
    // A trailing `/` is not a component; the plain form has none.
    let plain: PathBuf = path.components().collect();
    if is_plain_absolute(&plain) {
        Ok(plain)
    } else {
        Err(ConfigProblem::ValueNotSupported)
    }
}
