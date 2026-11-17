//! Paths in a configuration document and their `~/` expansion.
//!
//! `docs/POLICY_SPEC.md` section 3 permits an explicit leading `~/` and
//! forbids shell evaluation, command substitution, and globs. The validation
//! keeps the path as text. [`ConfigPath::expand`] is the only expansion: a
//! pure function of the path and the home directory that the caller supplies.
//! It does not read the environment or the file system.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// The largest accepted length of a path, in bytes. This is `PATH_MAX` of
/// macOS.
pub const MAX_PATH_BYTES: usize = 1024;

/// Characters that a shell or a glob matcher gives a meaning to. A path with
/// one of them is rejected, because the document has no evaluation and the
/// literal path would protect less than the writer intended.
const EVALUATION_CHARACTERS: [char; 8] = ['*', '?', '[', ']', '{', '}', '$', '`'];

/// The reason a path text was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigPathError {
    /// The text is empty.
    #[error("the path is empty")]
    Empty,
    /// The text is longer than [`MAX_PATH_BYTES`].
    #[error("the path is longer than 1024 bytes")]
    TooLong,
    /// The text has a control character.
    #[error("the path has a control character")]
    ControlCharacter,
    /// The text does not start with `/` or `~/`.
    #[error("the path must start with `/` or `~/`; `~user` and relative paths are not supported")]
    NotAnchored,
    /// The text has a character that a shell or a glob matcher evaluates.
    #[error(
        "the path has one of the characters `*`, `?`, `[`, `]`, `{{`, `}}`, `$`, or a backquote; \
         the configuration has no shell evaluation, command substitution, or globs"
    )]
    EvaluationSyntax,
    /// The text has a `.` or `..` component.
    #[error("the path has a `.` or `..` component")]
    RelativeComponent,
}

/// The reason an expansion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ExpandPathError {
    /// The supplied home directory is not an absolute path.
    #[error("the home directory is not an absolute path")]
    HomeNotAbsolute,
}

/// The directory that a configuration path starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathBase {
    /// The path started with `~/`.
    Home,
    /// The path started with `/`.
    Root,
}

/// A validated path of a configuration document.
///
/// A TOML string is UTF-8, thus a path with other bytes cannot be written in
/// the document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfigPath {
    base: PathBase,
    components: Vec<String>,
}

impl ConfigPath {
    /// Validates a path text.
    ///
    /// Repeated and trailing `/` characters are ignored.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigPathError`] when the text is not an accepted path.
    pub fn parse(text: &str) -> Result<Self, ConfigPathError> {
        if text.is_empty() {
            return Err(ConfigPathError::Empty);
        }
        if text.len() > MAX_PATH_BYTES {
            return Err(ConfigPathError::TooLong);
        }
        if text.chars().any(char::is_control) {
            return Err(ConfigPathError::ControlCharacter);
        }
        let (base, rest): (PathBase, &str) = if let Some(rest) = text.strip_prefix("~/") {
            (PathBase::Home, rest)
        } else if let Some(rest) = text.strip_prefix('/') {
            (PathBase::Root, rest)
        } else {
            return Err(ConfigPathError::NotAnchored);
        };
        if rest.contains(EVALUATION_CHARACTERS) {
            return Err(ConfigPathError::EvaluationSyntax);
        }
        let mut components: Vec<String> = Vec::new();
        for component in rest.split('/').filter(|component| !component.is_empty()) {
            if component == "." || component == ".." {
                return Err(ConfigPathError::RelativeComponent);
            }
            components.push(component.to_owned());
        }
        Ok(Self { base, components })
    }

    /// The directory that the path starts from.
    pub const fn base(&self) -> PathBase {
        self.base
    }

    /// The components after the base.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.components.iter().map(String::as_str)
    }

    /// Gives the absolute path. `home` is the home directory of the relevant
    /// user; a path that starts from the root does not use it.
    ///
    /// This function is pure. It does not read the environment, resolve a
    /// symbolic link, or touch the file system.
    ///
    /// # Errors
    ///
    /// Returns [`ExpandPathError::HomeNotAbsolute`] when the path starts from
    /// the home directory and `home` is not absolute.
    pub fn expand(&self, home: &Path) -> Result<PathBuf, ExpandPathError> {
        let mut expanded: PathBuf = match self.base {
            PathBase::Home => {
                if !home.is_absolute() {
                    return Err(ExpandPathError::HomeNotAbsolute);
                }
                home.to_path_buf()
            }
            PathBase::Root => PathBuf::from("/"),
        };
        for component in &self.components {
            expanded.push(component);
        }
        Ok(expanded)
    }
}

impl std::fmt::Display for ConfigPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.base {
            PathBase::Home if self.components.is_empty() => formatter.write_str("~/")?,
            PathBase::Home => formatter.write_str("~")?,
            PathBase::Root if self.components.is_empty() => formatter.write_str("/")?,
            PathBase::Root => {}
        }
        for component in &self.components {
            write!(formatter, "/{component}")?;
        }
        Ok(())
    }
}
