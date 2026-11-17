//! The host effects of the mutating commands that a test replaces.
//!
//! A command reaches the terminal of the user, the Trash of the user, and
//! the service manager only through this module. A test gives scripted
//! answers, a Trash directory in a temporary directory, and a service host
//! that records its calls, so no test moves a file to the Trash of the
//! user, registers a service, or waits for a terminal.

use std::fmt::Debug;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use svalnir_agent::executor::fs::{SystemTrash, TrashBackend};

/// The answer of the user to a confirmation question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confirmation {
    /// The user approved.
    Approved,
    /// The user did not approve.
    Declined,
    /// The session has no terminal, so no question was asked.
    NotInteractive,
}

/// The reason a host effect of the service commands did not occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceFailure {
    /// A stable name of the step that failed.
    pub(crate) step: &'static str,
    /// A description with no path.
    pub(crate) detail: String,
}

/// Each host effect of `agent install` and `agent uninstall`.
///
/// The commands decide what to do and call these functions; they do no
/// other write outside the state directory and start no other process.
pub(crate) trait ServiceHost: Debug + Send + Sync {
    /// The path of the `svalnir-agent` executable, when it exists.
    fn agent_program(&self) -> Option<PathBuf>;
    /// Whether a definition file exists at `path`.
    fn definition_exists(&self, path: &Path) -> bool;
    /// Writes the definition file. Its directory is made when it does not
    /// exist.
    fn write_definition(&self, path: &Path, text: &str) -> Result<(), ServiceFailure>;
    /// Removes the definition file. A file that does not exist is not an
    /// error.
    fn remove_definition(&self, path: &Path) -> Result<(), ServiceFailure>;
    /// Asks the service manager to load the definition in the session of
    /// the user.
    fn load(&self, uid: u32, path: &Path) -> Result<(), ServiceFailure>;
    /// Asks the service manager to stop and unload the service `label` of
    /// the session of the user. A service that is not loaded is not an
    /// error.
    fn unload(&self, uid: u32, label: &str) -> Result<(), ServiceFailure>;
}

/// The service host of the running system: the file system and
/// `launchctl`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemServiceHost;

/// The absolute path of the service-manager tool. No search path is used.
const LAUNCHCTL: &str = "/bin/launchctl";

/// The file name of the agent executable, beside the `svalnir` executable.
const AGENT_PROGRAM_NAME: &str = "svalnir-agent";

impl SystemServiceHost {
    fn launchctl(arguments: &[&std::ffi::OsStr]) -> Result<std::process::ExitStatus, String> {
        std::process::Command::new(LAUNCHCTL)
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|error| format!("the service manager did not start: {}", error.kind()))
    }
}

impl ServiceHost for SystemServiceHost {
    fn agent_program(&self) -> Option<PathBuf> {
        let own: PathBuf = std::env::current_exe().ok()?.canonicalize().ok()?;
        let program: PathBuf = own.parent()?.join(AGENT_PROGRAM_NAME);
        program.is_file().then_some(program)
    }

    fn definition_exists(&self, path: &Path) -> bool {
        path.symlink_metadata().is_ok()
    }

    fn write_definition(&self, path: &Path, text: &str) -> Result<(), ServiceFailure> {
        let failure = |error: &std::io::Error| ServiceFailure {
            step: "write_definition",
            detail: format!("the definition file was not written: {}", error.kind()),
        };
        if let Some(directory) = path.parent() {
            std::fs::create_dir_all(directory).map_err(|error| failure(&error))?;
        }
        // The file is written beside its final name and then renamed, so a
        // reader never sees a part of it.
        let mut temporary: std::ffi::OsString = path.as_os_str().to_owned();
        temporary.push(".svalnir-new");
        let temporary: PathBuf = PathBuf::from(temporary);
        // A file that has the temporary name is of an earlier failure.
        drop(std::fs::remove_file(&temporary));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
        }
        let written: std::io::Result<()> = options.open(&temporary).and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        });
        if let Err(error) = written {
            drop(std::fs::remove_file(&temporary));
            return Err(failure(&error));
        }
        std::fs::rename(&temporary, path).map_err(|error| {
            drop(std::fs::remove_file(&temporary));
            failure(&error)
        })
    }

    fn remove_definition(&self, path: &Path) -> Result<(), ServiceFailure> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ServiceFailure {
                step: "remove_definition",
                detail: format!("the definition file was not removed: {}", error.kind()),
            }),
        }
    }

    fn load(&self, uid: u32, path: &Path) -> Result<(), ServiceFailure> {
        let domain: String = format!("gui/{uid}");
        let status = Self::launchctl(&["bootstrap".as_ref(), domain.as_ref(), path.as_os_str()])
            .map_err(|detail| ServiceFailure {
                step: "load",
                detail,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(ServiceFailure {
                step: "load",
                detail: format!(
                    "the service manager refused the definition (status {})",
                    status.code().unwrap_or(-1)
                ),
            })
        }
    }

    fn unload(&self, uid: u32, label: &str) -> Result<(), ServiceFailure> {
        let target: String = format!("gui/{uid}/{label}");
        let status = Self::launchctl(&["bootout".as_ref(), target.as_ref()]).map_err(|detail| {
            ServiceFailure {
                step: "unload",
                detail,
            }
        })?;
        // Status 3 ("no such process") and status 113 ("could not find
        // the service") report a service that is not loaded, which is
        // the condition that the caller wants. These values are from the
        // documentation of the tool; no run on a host confirmed them.
        if status.success() || matches!(status.code(), Some(3 | 113)) {
            Ok(())
        } else {
            Err(ServiceFailure {
                step: "unload",
                detail: format!(
                    "the service manager did not unload the service (status {})",
                    status.code().unwrap_or(-1)
                ),
            })
        }
    }
}

/// The values that a test sets in place of the host.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct TestSeams {
    /// A directory that takes the place of the Trash of the user.
    pub(crate) trash_directory: Option<PathBuf>,
    /// The answers of an interactive user, in sequence. `None` is a
    /// session with no terminal.
    pub(crate) answers: Option<Arc<std::sync::Mutex<std::collections::VecDeque<String>>>>,
    /// The service host.
    pub(crate) service_host: Option<Arc<dyn ServiceHost>>,
    /// Gives a target process with no verified membership the membership
    /// of a synthetic application instance. The process inventory of a
    /// test runner does not attribute a child process of the test.
    pub(crate) attribute_target: bool,
}

/// The host effects of one invocation.
#[derive(Debug, Clone, Default)]
pub(crate) struct Seams {
    #[cfg(test)]
    pub(crate) test: TestSeams,
}

impl Seams {
    /// The Trash operation of the filesystem executor.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "a test build reads the values of the test"
        )
    )]
    pub(crate) fn trash_backend(&self) -> Box<dyn TrashBackend> {
        #[cfg(test)]
        if let Some(directory) = &self.test.trash_directory {
            return Box::new(crate::test_support::DirectoryTrash::new(directory.clone()));
        }
        Box::new(SystemTrash)
    }

    /// The service host.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "a test build reads the values of the test"
        )
    )]
    pub(crate) fn service_host(&self) -> Arc<dyn ServiceHost> {
        #[cfg(test)]
        if let Some(host) = &self.test.service_host {
            return Arc::clone(host);
        }
        Arc::new(SystemServiceHost)
    }

    /// Whether a target process with no verified membership gets a
    /// synthetic one. Always false outside a test.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "a test build reads the values of the test"
        )
    )]
    pub(crate) fn attributes_target(&self) -> bool {
        #[cfg(test)]
        {
            self.test.attribute_target
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Asks the user to approve an action. The question goes to `stderr`,
    /// so machine output on stdout stays clean. Only the answers `y` and
    /// `yes` approve.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "a test build reads the values of the test"
        )
    )]
    pub(crate) fn confirm(&self, stderr: &mut dyn Write, question: &str) -> Confirmation {
        #[cfg(test)]
        {
            let Some(answers) = &self.test.answers else {
                return Confirmation::NotInteractive;
            };
            drop(write!(stderr, "{question} [y/N] "));
            let answer: Option<String> = answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front();
            interpret(answer.as_deref())
        }
        #[cfg(not(test))]
        {
            if !terminal_is_interactive() {
                return Confirmation::NotInteractive;
            }
            if write!(stderr, "{question} [y/N] ")
                .and_then(|()| stderr.flush())
                .is_err()
            {
                return Confirmation::NotInteractive;
            }
            let mut line: String = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(_) => interpret(Some(&line)),
                Err(_) => Confirmation::Declined,
            }
        }
    }
}

/// Reads an answer. Text other than `y` or `yes` does not approve.
fn interpret(answer: Option<&str>) -> Confirmation {
    match answer.map(|text| text.trim().to_ascii_lowercase()) {
        Some(text) if text == "y" || text == "yes" => Confirmation::Approved,
        _ => Confirmation::Declined,
    }
}

/// Whether the standard input and the standard error stream are terminals.
#[cfg(not(test))]
fn terminal_is_interactive() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::{Confirmation, interpret};

    #[test]
    fn only_an_explicit_yes_approves() {
        assert_eq!(interpret(Some("y\n")), Confirmation::Approved);
        assert_eq!(interpret(Some(" YES ")), Confirmation::Approved);
        for answer in [Some(""), Some("n"), Some("yep"), Some("\n"), None] {
            assert_eq!(interpret(answer), Confirmation::Declined, "{answer:?}");
        }
    }
}
