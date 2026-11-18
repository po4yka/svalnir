//! The account record of the effective user and the check of `HOME`.
//!
//! The home directory decides the home protections of the filesystem
//! executor, the Trash, and the default state directory of the client. The
//! value of `HOME` comes from the environment of the process, which a
//! wrapper script, an edited service definition, or `sudo -E` can change.
//! [`verify_home`] compares it with the home directory of the account
//! record of the effective user and refuses a difference. The agent and
//! each command of the client that changes state call it before they act
//! (`docs/THREAT_MODEL.md`, the trust in the environment).
//!
//! The comparison is of the canonical paths: each path has its symbolic
//! links resolved, and the two results must be equal. Two different paths
//! to the same directory, for example through a firmlink of the system
//! volume, are a difference, because the protections use the path.
//!
//! [`PasswordDatabase`] reads the record with `getpwuid_r`, which is
//! thread safe. A debug build with the feature `test-support` can take the
//! home directory of the record from [`TEST_ACCOUNT_HOME_VARIABLE`]
//! instead, so that a test starts the binary with a temporary home
//! directory; a build without the feature, and a build with no debug
//! assertions (a release build), has no code that reads that variable.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The environment variable that replaces the home directory of the
/// account record. Only a debug build with the feature `test-support`
/// reads it.
pub const TEST_ACCOUNT_HOME_VARIABLE: &str = "SVALNIR_TEST_ACCOUNT_HOME";

/// The largest buffer for one account record, in bytes.
const MAX_RECORD_BUFFER: usize = 64 * 1024;

/// The first buffer for one account record, in bytes.
const INITIAL_RECORD_BUFFER: usize = 1024;

/// A source of the home directory of the account record of the effective
/// user.
pub trait AccountSource: std::fmt::Debug + Send + Sync {
    /// The home directory of the account record.
    ///
    /// # Errors
    ///
    /// Returns the error of the lookup. `Ok(None)`: the effective user has
    /// no account record, or the record has no home directory.
    fn home_directory(&self) -> std::io::Result<Option<PathBuf>>;
}

/// Why `HOME` is not the home directory of the effective user.
#[derive(Debug, thiserror::Error)]
pub enum HomeError {
    /// `HOME` is not set, or it is empty.
    #[error("`HOME` is not set")]
    NotSet,
    /// The effective user has no account record with a home directory.
    #[error("the effective user has no account record with a home directory")]
    NoAccountRecord,
    /// The lookup of the account record failed.
    #[error("the account record of the effective user cannot be read")]
    AccountLookup(#[source] std::io::Error),
    /// The path of `HOME`, or the home directory of the account record,
    /// cannot be made canonical: it does not exist or is not accessible.
    #[error("the home directory cannot be resolved")]
    NotResolvable(#[source] std::io::Error),
    /// `HOME` and the home directory of the account record are different
    /// directories.
    #[error("`HOME` is not the home directory of the account record of the effective user")]
    Mismatch,
}

impl HomeError {
    /// The stable code of the error. The message of the error has no path.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotSet => "home_not_set",
            Self::NoAccountRecord | Self::AccountLookup(_) => "home_account_unknown",
            Self::NotResolvable(_) => "home_not_resolvable",
            Self::Mismatch => "home_mismatch",
        }
    }
}

/// Compares `home`, the value of `HOME`, with the home directory of the
/// account record of `account`, and returns the canonical home directory.
///
/// # Errors
///
/// Returns a [`HomeError`] when `home` is absent or empty, when the account
/// has no record, when a path cannot be made canonical, or when the two
/// canonical paths are different.
pub fn verify_home(home: Option<&Path>, account: &dyn AccountSource) -> Result<PathBuf, HomeError> {
    let home: &Path = home
        .filter(|home| !home.as_os_str().is_empty())
        .ok_or(HomeError::NotSet)?;
    let recorded: PathBuf = account
        .home_directory()
        .map_err(HomeError::AccountLookup)?
        .ok_or(HomeError::NoAccountRecord)?;
    let home: PathBuf = std::fs::canonicalize(home).map_err(HomeError::NotResolvable)?;
    let recorded: PathBuf = std::fs::canonicalize(recorded).map_err(HomeError::NotResolvable)?;
    if home == recorded {
        Ok(home)
    } else {
        Err(HomeError::Mismatch)
    }
}

/// The account source of this process: [`PasswordDatabase`], or, in a
/// debug build with the feature `test-support`, the path of
/// [`TEST_ACCOUNT_HOME_VARIABLE`] when it is set.
#[must_use]
pub fn process_account_source() -> Box<dyn AccountSource> {
    #[cfg(all(feature = "test-support", debug_assertions))]
    {
        if let Some(home) = std::env::var_os(TEST_ACCOUNT_HOME_VARIABLE) {
            return Box::new(FixedAccount(Some(PathBuf::from(home))));
        }
    }
    Box::new(PasswordDatabase)
}

/// Compares the `HOME` of the environment of this process with the account
/// record of [`process_account_source`].
///
/// # Errors
///
/// Returns the [`HomeError`] of [`verify_home`].
pub fn verify_process_home() -> Result<PathBuf, HomeError> {
    let home: Option<std::ffi::OsString> = std::env::var_os("HOME");
    verify_home(
        home.as_deref().map(Path::new),
        process_account_source().as_ref(),
    )
}

/// An account record with a fixed home directory. `None`: no record.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct FixedAccount(pub Option<PathBuf>);

#[cfg(any(test, feature = "test-support"))]
impl AccountSource for FixedAccount {
    fn home_directory(&self) -> std::io::Result<Option<PathBuf>> {
        Ok(self.0.clone())
    }
}

/// The account record of the effective user in the user database of the
/// system, from `getpwuid_r(geteuid())`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PasswordDatabase;

impl AccountSource for PasswordDatabase {
    fn home_directory(&self) -> std::io::Result<Option<PathBuf>> {
        lookup_home(INITIAL_RECORD_BUFFER)
    }
}

/// Reads the home directory of the effective user with a first buffer of
/// `initial` bytes. The buffer doubles after each `ERANGE` up to
/// [`MAX_RECORD_BUFFER`].
#[cfg(unix)]
fn lookup_home(initial: usize) -> std::io::Result<Option<PathBuf>> {
    use std::os::unix::ffi::OsStrExt as _;

    // SAFETY: `geteuid` has no argument, changes nothing, and does not
    // fail.
    let user: libc::uid_t = unsafe { libc::geteuid() };
    let mut size: usize = initial.clamp(1, MAX_RECORD_BUFFER);
    loop {
        let mut buffer: Vec<libc::c_char> = vec![0; size];
        let mut record: std::mem::MaybeUninit<libc::passwd> = std::mem::MaybeUninit::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `record` is writable storage for one `passwd`, `buffer`
        // is writable for `buffer.len()` bytes, and `result` is a writable
        // pointer. Each of them lives until the end of this iteration. The
        // call writes the strings of the record into `buffer` only.
        let status: libc::c_int = unsafe {
            libc::getpwuid_r(
                user,
                record.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut result,
            )
        };
        match status {
            0 => {}
            libc::EINTR => continue,
            libc::ERANGE if size < MAX_RECORD_BUFFER => {
                size = size.saturating_mul(2).min(MAX_RECORD_BUFFER);
                continue;
            }
            error => return Err(std::io::Error::from_raw_os_error(error)),
        }
        if result.is_null() {
            return Ok(None);
        }
        // SAFETY: the call returned 0 and a pointer that is not null, so
        // `result` points to `record`, which the call initialized.
        let directory: *const libc::c_char = unsafe { (*result).pw_dir };
        if directory.is_null() {
            return Ok(None);
        }
        // SAFETY: `pw_dir` points to a string with a terminating zero in
        // `buffer`, which lives until the end of this iteration. The bytes
        // are copied before `buffer` is dropped.
        let bytes: &[u8] = unsafe { std::ffi::CStr::from_ptr(directory) }.to_bytes();
        if bytes.is_empty() {
            return Ok(None);
        }
        return Ok(Some(PathBuf::from(OsStr::from_bytes(bytes))));
    }
}

#[cfg(not(unix))]
fn lookup_home(_initial: usize) -> std::io::Result<Option<PathBuf>> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{FixedAccount, HomeError, verify_home};

    fn directory() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let base: PathBuf = std::fs::canonicalize(temp.path()).unwrap();
        let home: PathBuf = base.join("home");
        std::fs::create_dir(&home).unwrap();
        (temp, home)
    }

    #[test]
    fn an_equal_home_gives_the_canonical_path() {
        let (_temp, home) = directory();
        let verified: PathBuf =
            verify_home(Some(&home), &FixedAccount(Some(home.clone()))).unwrap();
        assert_eq!(verified, home);
    }

    #[test]
    fn a_home_through_a_symbolic_link_is_the_same_directory() {
        let (_temp, home) = directory();
        let link: PathBuf = home.with_file_name("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        let verified: PathBuf =
            verify_home(Some(&link), &FixedAccount(Some(home.clone()))).unwrap();
        assert_eq!(verified, home);
        // The account record can also name the link.
        let verified: PathBuf = verify_home(Some(&home), &FixedAccount(Some(link))).unwrap();
        assert_eq!(verified, home);
    }

    #[test]
    fn a_different_home_is_a_mismatch() {
        let (_temp, home) = directory();
        let other: PathBuf = home.with_file_name("other");
        std::fs::create_dir(&other).unwrap();
        let error: HomeError = verify_home(Some(&other), &FixedAccount(Some(home))).unwrap_err();
        assert!(matches!(error, HomeError::Mismatch), "{error:?}");
        assert_eq!(error.code(), "home_mismatch");
    }

    #[test]
    fn no_home_and_an_empty_home_are_not_set() {
        let (_temp, home) = directory();
        let account = FixedAccount(Some(home));
        for value in [None, Some(Path::new(""))] {
            let error: HomeError = verify_home(value, &account).unwrap_err();
            assert!(matches!(error, HomeError::NotSet), "{error:?}");
            assert_eq!(error.code(), "home_not_set");
        }
    }

    #[test]
    fn no_account_record_is_refused() {
        let (_temp, home) = directory();
        let error: HomeError = verify_home(Some(&home), &FixedAccount(None)).unwrap_err();
        assert!(matches!(error, HomeError::NoAccountRecord), "{error:?}");
        assert_eq!(error.code(), "home_account_unknown");
    }

    #[test]
    fn a_home_that_does_not_exist_is_not_resolvable() {
        let (_temp, home) = directory();
        let absent: PathBuf = home.join("absent");
        let error: HomeError =
            verify_home(Some(&absent), &FixedAccount(Some(absent.clone()))).unwrap_err();
        assert!(matches!(error, HomeError::NotResolvable(_)), "{error:?}");
        assert_eq!(error.code(), "home_not_resolvable");
    }

    /// The real adapter. The test reads only the path of the record: it
    /// does not list, open, or write the directory.
    #[cfg(unix)]
    #[test]
    fn the_account_record_of_the_effective_user_has_an_absolute_home() {
        let home: PathBuf = super::lookup_home(super::INITIAL_RECORD_BUFFER)
            .unwrap()
            .unwrap();
        assert!(home.is_absolute(), "the home directory is not absolute");
        // A buffer of one byte is too small: the lookup grows it after
        // each `ERANGE` and gets the same record.
        assert_eq!(super::lookup_home(1).unwrap(), Some(home));
    }
}
