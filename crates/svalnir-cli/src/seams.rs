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

#[cfg(not(test))]
use svalnir_agent::executor::fs::SystemTrash;
use svalnir_agent::executor::fs::TrashBackend;

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

/// The reason the `svalnir-agent` executable is not usable for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramProblem {
    /// No executable file is beside the `svalnir` executable.
    NotFound,
    /// The executable or its directory has an owner other than this user
    /// and the superuser, or the group or each user can write it. A
    /// service that starts at each login must not start a file that a
    /// different user can replace.
    NotTrusted,
}

/// Finds the `svalnir-agent` executable beside `own`, the executable of
/// this process, and examines its owner and its permissions.
///
/// The result has no symbolic link, so the service definition names the
/// file that was examined and not a link that can get a new destination.
///
/// # Errors
///
/// Returns a [`ProgramProblem`].
pub(crate) fn examined_agent_program(own: &Path, uid: u32) -> Result<PathBuf, ProgramProblem> {
    use std::os::unix::fs::MetadataExt as _;

    /// The write permission of the group and of each user.
    const WRITE_BY_OTHERS: u32 = 0o022;
    /// The write permission of each user.
    const WRITE_BY_EACH_USER: u32 = 0o002;
    /// The sticky bit: only the owner of an entry can rename or remove it.
    const STICKY: u32 = 0o1000;
    /// The execute permission of the owner.
    const EXECUTE_BY_OWNER: u32 = 0o100;

    let own: PathBuf = own.canonicalize().map_err(|_| ProgramProblem::NotFound)?;
    let beside: PathBuf = own
        .parent()
        .ok_or(ProgramProblem::NotFound)?
        .join(AGENT_PROGRAM_NAME);
    let program: PathBuf = beside
        .canonicalize()
        .map_err(|_| ProgramProblem::NotFound)?;
    let file = program
        .symlink_metadata()
        .map_err(|_| ProgramProblem::NotFound)?;
    if !file.is_file() || file.mode() & EXECUTE_BY_OWNER == 0 {
        return Err(ProgramProblem::NotFound);
    }
    let directory = program
        .parent()
        .ok_or(ProgramProblem::NotFound)?
        .symlink_metadata()
        .map_err(|_| ProgramProblem::NotFound)?;
    let trusted = |metadata: &std::fs::Metadata| {
        (metadata.uid() == uid || metadata.uid() == 0) && metadata.mode() & WRITE_BY_OTHERS == 0
    };
    // A directory above can be renamed by a user who can write its
    // parent. Each one must have this user or the superuser as owner, and
    // each user can write it only when it has the sticky bit. The write
    // permission of a group is accepted there: the system gives it to
    // directories such as `/Applications`.
    let ancestors_trusted = || {
        program.ancestors().skip(2).all(|ancestor| {
            ancestor.symlink_metadata().is_ok_and(|metadata| {
                (metadata.uid() == uid || metadata.uid() == 0)
                    && (metadata.mode() & WRITE_BY_EACH_USER == 0 || metadata.mode() & STICKY != 0)
            })
        })
    };
    if trusted(&file) && trusted(&directory) && ancestors_trusted() {
        Ok(program)
    } else {
        Err(ProgramProblem::NotTrusted)
    }
}

/// Each host effect of `agent install` and `agent uninstall`.
///
/// The commands decide what to do and call these functions; they do no
/// other write outside the state directory and start no other process.
pub(crate) trait ServiceHost: Debug + Send + Sync {
    /// The path of the `svalnir-agent` executable, with no symbolic link.
    ///
    /// # Errors
    ///
    /// Returns a [`ProgramProblem`] when the executable does not exist, or
    /// when a different user can change it.
    fn agent_program(&self) -> Result<PathBuf, ProgramProblem>;
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
///
/// A test build does not have this type, so no test can register a
/// service or write a service definition of the developer.
#[cfg(not(test))]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemServiceHost;

/// The absolute path of the service-manager tool. No search path is used.
#[cfg(not(test))]
const LAUNCHCTL: &str = "/bin/launchctl";

/// The file name of the agent executable, beside the `svalnir` executable.
const AGENT_PROGRAM_NAME: &str = "svalnir-agent";

#[cfg(not(test))]
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

#[cfg(not(test))]
impl ServiceHost for SystemServiceHost {
    fn agent_program(&self) -> Result<PathBuf, ProgramProblem> {
        let own: PathBuf = std::env::current_exe().map_err(|_| ProgramProblem::NotFound)?;
        examined_agent_program(&own, crate::commands::session::current_uid().get())
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

/// An action of a test that runs while a question waits.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct WhileAsked(pub(crate) Arc<dyn Fn() + Send + Sync>);

#[cfg(test)]
impl Debug for WhileAsked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WhileAsked")
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
    /// An action that runs while the question waits for its answer, in
    /// the place of what a different client does in that time.
    pub(crate) while_asked: Option<WhileAsked>,
    /// The service host.
    pub(crate) service_host: Option<Arc<dyn ServiceHost>>,
}

/// The service host of a test that set none: it has no agent executable
/// and refuses each change, so a test cannot reach the service manager or
/// the service definitions of the developer.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RefusingServiceHost;

#[cfg(test)]
impl RefusingServiceHost {
    fn refusal(step: &'static str) -> ServiceFailure {
        ServiceFailure {
            step,
            detail: "the test set no service host".to_owned(),
        }
    }
}

#[cfg(test)]
impl ServiceHost for RefusingServiceHost {
    fn agent_program(&self) -> Result<PathBuf, ProgramProblem> {
        Err(ProgramProblem::NotFound)
    }

    fn definition_exists(&self, _path: &Path) -> bool {
        false
    }

    fn write_definition(&self, _path: &Path, _text: &str) -> Result<(), ServiceFailure> {
        Err(Self::refusal("write_definition"))
    }

    fn remove_definition(&self, _path: &Path) -> Result<(), ServiceFailure> {
        Err(Self::refusal("remove_definition"))
    }

    fn load(&self, _uid: u32, _path: &Path) -> Result<(), ServiceFailure> {
        Err(Self::refusal("load"))
    }

    fn unload(&self, _uid: u32, _label: &str) -> Result<(), ServiceFailure> {
        Err(Self::refusal("unload"))
    }
}

/// The Trash of a test that set no Trash directory: it moves nothing, so
/// a test cannot move a file to the Trash of the developer.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RefusingTrash;

#[cfg(test)]
impl TrashBackend for RefusingTrash {
    fn move_to_trash(
        &self,
        _request: &svalnir_agent::executor::fs::TrashRequest<'_>,
    ) -> svalnir_agent::executor::fs::TrashReply {
        svalnir_agent::executor::fs::TrashReply::Failed(
            svalnir_agent::executor::fs::TrashFailure::Unsupported,
        )
    }
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
        // A test build never has the Trash of the system.
        #[cfg(test)]
        {
            match &self.test.trash_directory {
                Some(directory) => {
                    Box::new(crate::test_support::DirectoryTrash::new(directory.clone()))
                }
                None => Box::new(RefusingTrash),
            }
        }
        #[cfg(not(test))]
        {
            Box::new(SystemTrash)
        }
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
        // A test build never has the service host of the system.
        #[cfg(test)]
        {
            match &self.test.service_host {
                Some(host) => Arc::clone(host),
                None => Arc::new(RefusingServiceHost),
            }
        }
        #[cfg(not(test))]
        {
            Arc::new(SystemServiceHost)
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
            if let Some(action) = &self.test.while_asked {
                (action.0)();
            }
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
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{
        Confirmation, ProgramProblem, RefusingServiceHost, Seams, ServiceHost as _,
        examined_agent_program, interpret,
    };

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
    }

    /// A directory with a `svalnir` file and a `svalnir-agent` file.
    fn programs(directory: &Path) -> (PathBuf, PathBuf) {
        std::fs::create_dir_all(directory).expect("directory");
        set_mode(directory, 0o755);
        let own: PathBuf = directory.join("svalnir");
        let agent: PathBuf = directory.join("svalnir-agent");
        for path in [&own, &agent] {
            std::fs::write(path, b"#!/bin/sh\n").expect("file");
            set_mode(path, 0o755);
        }
        (own, agent)
    }

    fn uid_of(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        path.metadata().expect("metadata").uid()
    }

    #[test]
    fn the_agent_program_is_the_examined_file_beside_this_executable() {
        let directory = crate::test_support::TempDirectory::new();
        let (own, agent) = programs(&directory.path().join("bin"));
        let uid: u32 = uid_of(&own);
        assert_eq!(
            examined_agent_program(&own, uid),
            Ok(agent.canonicalize().expect("canonical"))
        );
        std::fs::remove_file(&agent).expect("remove");
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotFound)
        );
    }

    #[test]
    fn an_agent_program_that_a_different_user_can_change_is_refused() {
        let directory = crate::test_support::TempDirectory::new();
        let bin: PathBuf = directory.path().join("bin");
        let (own, agent) = programs(&bin);
        let uid: u32 = uid_of(&own);

        // Each user can write the file.
        set_mode(&agent, 0o757);
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotTrusted)
        );
        // The group can write the file.
        set_mode(&agent, 0o775);
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotTrusted)
        );
        set_mode(&agent, 0o755);

        // Each user can write the directory, so each user can replace the
        // file.
        set_mode(&bin, 0o777);
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotTrusted)
        );
        set_mode(&bin, 0o755);

        // Each user can write a directory above, so each user can put a
        // different directory in the place of the examined one.
        set_mode(directory.path(), 0o777);
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotTrusted)
        );
        // With the sticky bit, only the owner can rename the entry.
        set_mode(directory.path(), 0o1777);
        assert!(examined_agent_program(&own, uid).is_ok());
        set_mode(directory.path(), 0o755);

        // The owner is a different user.
        assert_eq!(
            examined_agent_program(&own, uid.wrapping_add(1).max(1)),
            Err(ProgramProblem::NotTrusted)
        );

        // A file that the owner cannot execute is not a program.
        set_mode(&agent, 0o644);
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotFound)
        );
    }

    #[test]
    fn a_link_to_an_agent_program_is_examined_at_its_destination() {
        let directory = crate::test_support::TempDirectory::new();
        let (_, real_agent) = programs(&directory.path().join("real"));
        let (own, agent) = programs(&directory.path().join("bin"));
        let uid: u32 = uid_of(&own);
        std::fs::remove_file(&agent).expect("remove");
        std::os::unix::fs::symlink(&real_agent, &agent).expect("link");

        // The result names the destination, not the link.
        assert_eq!(
            examined_agent_program(&own, uid),
            Ok(real_agent.canonicalize().expect("canonical"))
        );
        // The directory of the destination decides, not that of the link.
        set_mode(&directory.path().join("real"), 0o777);
        assert_eq!(
            examined_agent_program(&own, uid),
            Err(ProgramProblem::NotTrusted)
        );
        set_mode(&directory.path().join("real"), 0o755);
    }

    #[test]
    fn a_test_with_no_seam_has_no_host_effect() {
        let seams = Seams::default();
        let host = seams.service_host();
        assert_eq!(host.agent_program(), Err(ProgramProblem::NotFound));
        assert!(host.load(501, Path::new("/nonexistent")).is_err());
        assert!(host.unload(501, "dev.svalnir.agent").is_err());
        assert!(
            host.write_definition(Path::new("/nonexistent"), "")
                .is_err()
        );
        assert!(host.remove_definition(Path::new("/nonexistent")).is_err());
        assert!(!RefusingServiceHost.definition_exists(Path::new("/")));
        assert_eq!(format!("{:?}", seams.trash_backend()), "RefusingTrash");
    }

    #[test]
    fn only_an_explicit_yes_approves() {
        assert_eq!(interpret(Some("y\n")), Confirmation::Approved);
        assert_eq!(interpret(Some(" YES ")), Confirmation::Approved);
        for answer in [Some(""), Some("n"), Some("yep"), Some("\n"), None] {
            assert_eq!(interpret(answer), Confirmation::Declined, "{answer:?}");
        }
    }
}
