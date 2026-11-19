//! Svalnir user agent.
//!
//! The process observes the host, evaluates the two guards, serves the
//! request queue of the journal, and carries out the automatic plans that
//! the authority record of the journal permits. With no authority record
//! it only observes: no argument and no configuration file makes a guard
//! active.
//!
//! ```text
//! svalnir-agent --foreground --state-dir DIRECTORY [--config FILE]
//! ```
//!
//! The process runs in the foreground until `SIGINT` or `SIGTERM`. It
//! registers no service: a `LaunchAgent` definition starts it with the
//! same arguments. A permanent start error writes the start-failure record
//! of `svalnir_agent::runtime::start_failure` and exits with status 0,
//! which that definition does not restart; a transient one exits with
//! status 1. The log is structured text on the standard error
//! stream; it has no secret, no path of user data, and no process
//! argument.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

/// The exit status of a usage error.
const EXIT_USAGE: u8 = 2;

const USAGE: &str = "usage: svalnir-agent --foreground --state-dir DIRECTORY [--config FILE]

  --foreground           Run in the foreground until SIGINT or SIGTERM. Required:
                         the agent does not detach from its terminal.
  --state-dir DIRECTORY  The state directory with the operation journal. Required.
  --config FILE          The configuration that the agent evaluates when the
                         journal has no policy revision in effect. It gives no
                         authority.
  --help                 Print this text.
  --version              Print the version.
";

/// The arguments of the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    state_directory: PathBuf,
    config: Option<PathBuf>,
}

/// What the arguments request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Invocation {
    Run(Options),
    Help,
    Version,
}

/// Reads the arguments. The first argument, the program name, is not in
/// `arguments`.
fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut foreground: bool = false;
    let mut state_directory: Option<PathBuf> = None;
    let mut config: Option<PathBuf> = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let mut value = |name: &str| {
            arguments
                .next()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| format!("`{name}` needs a value"))
        };
        match argument.to_str() {
            Some("--help") => return Ok(Invocation::Help),
            Some("--version") => return Ok(Invocation::Version),
            Some("--foreground") => foreground = true,
            Some("--state-dir") if state_directory.is_none() => {
                state_directory = Some(value("--state-dir")?);
            }
            Some("--config") if config.is_none() => config = Some(value("--config")?),
            Some(name @ ("--state-dir" | "--config")) => {
                return Err(format!("`{name}` is given two times"));
            }
            // The text of an argument that is not known is not printed:
            // it can be a path.
            _ => return Err("an argument is not known".to_owned()),
        }
    }
    let state_directory: PathBuf =
        state_directory.ok_or_else(|| "`--state-dir` is required".to_owned())?;
    if !state_directory.is_absolute() || config.as_ref().is_some_and(|path| !path.is_absolute()) {
        return Err("each path must be absolute".to_owned());
    }
    if !foreground {
        return Err("`--foreground` is required".to_owned());
    }
    Ok(Invocation::Run(Options {
        state_directory,
        config,
    }))
}

fn main() -> ExitCode {
    let options: Options = match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Run(options)) => options,
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Invocation::Version) => {
            println!("svalnir-agent {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprint!("svalnir-agent: {message}\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    agent::run(&options)
}

#[cfg(not(target_os = "macos"))]
mod agent {
    use std::process::ExitCode;

    use super::Options;

    /// The collectors and the executors of the agent exist for macOS
    /// only.
    pub(super) fn run(_options: &Options) -> ExitCode {
        tracing::error!("the agent has collectors and executors for macOS only");
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "macos")]
mod agent {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::time::Duration;

    use svalnir_agent::coordinator::CoordinatorConfig;
    use svalnir_agent::journal::{CoordinatorRole, JournalOptions};
    use svalnir_agent::platform::account::verify_process_home;
    use svalnir_agent::platform::memory::{PressureEvent, PressureSubscription};
    use svalnir_agent::platform::run_loop::{
        StopSignal, request_main_run_loop_stop, run_main_run_loop_until_stop,
    };
    use svalnir_agent::runtime::host::{SystemParts, system_parts};
    use svalnir_agent::runtime::start_failure::{
        PERMANENT_START_ERROR_STATUS, StartFailure, StartFailureReason, remove_start_failure,
        write_start_failure,
    };
    use svalnir_agent::runtime::{
        AgentClock, Driver, DriverError, DriverSettings, DriverStart, ServiceSettings,
        ShutdownReport, StopHandle, run as run_service,
    };
    use svalnir_agent::store::{Store, StoreOptions};
    use svalnir_core::config::{MAX_DOCUMENT_BYTES, ValidatedConfig, parse_and_validate};
    use svalnir_core::file::LosslessPath;
    use svalnir_core::id::{AdapterId, ExecutorEpochId};
    use svalnir_core::process::Uid;
    use svalnir_core::quantity::{Bytes, Nanoseconds};
    use svalnir_core::time::WallTime;

    use super::Options;

    /// The file name of the catalog store in the state directory.
    const CATALOG_FILE_NAME: &str = "catalog.sqlite";

    /// The capacity of the channel of memory-pressure events.
    const PRESSURE_EVENT_CAPACITY: usize = 64;

    /// The budget of the physical footprint of the agent.
    const SELF_BUDGET: Bytes = Bytes::new(128 * 1024 * 1024);

    /// The longest time between two ticks of the driver.
    const IDLE_INTERVAL: Duration = Duration::from_secs(1);

    /// The configuration that the agent evaluates with no policy revision
    /// in effect: the file of `--config`, or the template values.
    pub(super) fn proposal(path: Option<&Path>) -> Result<ValidatedConfig, StartFailureReason> {
        let text: String = match path {
            None => "schema_version = 1\n".to_owned(),
            Some(path) => {
                use std::io::Read as _;
                // The read has a bound also for a file that grows and for
                // a file that is not a regular file.
                let limit: u64 = u64::try_from(MAX_DOCUMENT_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                let mut text: String = String::new();
                // The open does not wait for the writer of a named pipe,
                // and only a regular file is read.
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path)
                    .and_then(|file| {
                        if file.metadata()?.is_file() {
                            file.take(limit).read_to_string(&mut text)
                        } else {
                            Err(std::io::ErrorKind::InvalidInput.into())
                        }
                    })
                    .map_err(|_| StartFailureReason::ConfigurationNotReadable)?;
                if text.len() > MAX_DOCUMENT_BYTES {
                    return Err(StartFailureReason::ConfigurationNotReadable);
                }
                text
            }
        };
        parse_and_validate(&text)
            .config()
            .cloned()
            .ok_or(StartFailureReason::ConfigurationInvalid)
    }

    /// Makes the state directory when it does not exist, for this user
    /// only. A path that exists must be a directory of this user that no
    /// other user can read or write, and not a symbolic link: the journal
    /// has the targets of the plans and the history.
    pub(super) fn state_directory(path: &Path) -> std::io::Result<()> {
        let refused = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                // SAFETY: `geteuid` has no argument, changes nothing, and
                // does not fail.
                let user: u32 = unsafe { libc::geteuid() };
                // The permission bits of the group and of each other user.
                let shared: u32 = u32::from(libc::S_IRWXG | libc::S_IRWXO);
                let private: bool = metadata.file_type().is_dir()
                    && metadata.uid() == user
                    && metadata.mode() & shared == 0;
                if private { Ok(()) } else { Err(refused()) }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(path)
            }
            Err(error) => Err(error),
        }
    }

    /// The home directory of the user as a canonical path: `HOME`, when
    /// it is the home directory of the account record of the effective
    /// user.
    fn home_directory() -> Result<LosslessPath, StartFailed> {
        let home = verify_process_home().map_err(|error| {
            StartFailureReason::of_home(&error).map_or(
                StartFailed::Transient("the account record of the effective user cannot be read"),
                StartFailed::Permanent,
            )
        })?;
        home_path(&home).map_err(StartFailed::Permanent)
    }

    /// The canonical home directory as a path of the journal. A path that
    /// it refuses is refused again at each start with the same `HOME`.
    pub(super) fn home_path(home: &Path) -> Result<LosslessPath, StartFailureReason> {
        LosslessPath::from_path(home).map_err(|_| StartFailureReason::HomeNotResolvable)
    }

    fn settings(
        principal: Uid,
        home: LosslessPath,
        config: ValidatedConfig,
    ) -> Option<DriverSettings> {
        let agent = config.agent();
        let sample: Nanoseconds = Nanoseconds::try_from(agent.sample_interval).ok()?;
        let pressure: Nanoseconds = Nanoseconds::try_from(agent.pressure_sample_interval).ok()?;
        Some(DriverSettings {
            principal,
            home_directory: Some(home),
            coordinator: CoordinatorConfig {
                filesystem_adapter: AdapterId::new("svalnir.filesystem").ok()?,
                process_adapter: AdapterId::new("macos.process").ok()?,
                batch_targets: 8,
                poll_interval: Nanoseconds::new(500_000_000),
                volatile_capacity: 16,
                role: CoordinatorRole::Agent,
            },
            journal: JournalOptions::default(),
            status_interval: Nanoseconds::new(30_000_000_000),
            maintenance_interval: Nanoseconds::new(3_600_000_000_000),
            self_budget: SELF_BUDGET,
            shutdown_bound: Nanoseconds::new(10_000_000_000),
            coordinator_units: 8,
            sample_stale_after: Nanoseconds::new(
                sample.get().max(pressure.get()).saturating_mul(3),
            ),
            proposal: config,
        })
    }

    /// The memory-pressure events of the host. With no subscription the
    /// agent has the periodic collection only.
    fn pressure_events(
        parts: &SystemParts,
    ) -> (Option<PressureSubscription>, Receiver<PressureEvent>) {
        match PressureSubscription::start(&parts.context, PRESSURE_EVENT_CAPACITY) {
            Ok((subscription, events)) => (Some(subscription), events),
            Err(error) => {
                tracing::warn!(%error, "no memory-pressure event source; periodic sampling only");
                // The sender is dropped, so the channel is disconnected.
                let (_sender, events) = sync_channel::<PressureEvent>(1);
                (None, events)
            }
        }
    }

    /// What a start needs before the journal is opened.
    struct Prepared {
        epoch: ExecutorEpochId,
        parts: SystemParts,
        service: ServiceSettings,
        settings: DriverSettings,
    }

    /// Why the agent did not start.
    enum StartFailed {
        /// A new start with the same inputs fails again.
        Permanent(StartFailureReason),
        /// A start can pass later. The message has no path.
        Transient(&'static str),
    }

    /// Reads the configuration and makes the parts of the running system,
    /// in the state directory that [`state_directory`] accepted.
    fn prepare(options: &Options) -> Result<Prepared, StartFailed> {
        let config: ValidatedConfig =
            proposal(options.config.as_deref()).map_err(StartFailed::Permanent)?;
        let home: LosslessPath = home_directory()?;
        // SAFETY: `geteuid` has no argument, changes nothing, and does
        // not fail.
        let principal: Uid = Uid::new(unsafe { libc::geteuid() });
        let started: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let epoch: ExecutorEpochId =
            ExecutorEpochId::new(format!("agent-{}-{started:x}", std::process::id())).map_err(
                |_| StartFailed::Transient("the identity of the executor lifetime is not valid"),
            )?;
        // Retained samples are optional: with no store the agent keeps
        // none.
        let store: Option<Store> = Store::open(
            &options.state_directory.join(CATALOG_FILE_NAME),
            &StoreOptions::default(),
        )
        // The text of the error can have the path of the store.
        .map_err(|_| tracing::warn!("the catalog store is not usable"))
        .ok();
        let parts: SystemParts =
            // The text of the error can have a path of the user.
            system_parts(&epoch, principal, &home, &options.state_directory, store)
                .map_err(|error| StartFailed::Transient(error.cause()))?;
        let service: ServiceSettings = ServiceSettings {
            sample_interval: config.agent().sample_interval,
            pressure_sample_interval: config.agent().pressure_sample_interval,
            idle_interval: IDLE_INTERVAL,
        };
        // The settings come from the intervals of the configuration.
        let settings: DriverSettings = settings(principal, home, config).ok_or(
            StartFailed::Permanent(StartFailureReason::ConfigurationInvalid),
        )?;
        Ok(Prepared {
            epoch,
            parts,
            service,
            settings,
        })
    }

    /// Ends the main run loop when the driver thread ends with no stop
    /// request: the service failed, or a thread of it had a panic.
    struct EndRunLoop(StopHandle);

    impl Drop for EndRunLoop {
        fn drop(&mut self) {
            if !self.0.was_requested() {
                // The request is not a signal: when the service ends
                // before the main thread made its signal sources, a
                // signal would have its default action and end the
                // process before the report of the stop.
                request_main_run_loop_stop();
            }
        }
    }

    /// Ends a start with a permanent error: writes the start-failure
    /// record and one line on the standard error stream, and gives the
    /// status that the service manager does not restart.
    fn end_permanently(state: &Path, reason: StartFailureReason) -> ExitCode {
        let failed_at: Option<WallTime> = WallTime::try_from(std::time::SystemTime::now()).ok();
        let recorded: bool = reason != StartFailureReason::StateDirectoryRefused
            && write_start_failure(state, &StartFailure::new(reason, failed_at)).is_ok();
        tracing::error!(
            reason = reason.code(),
            recorded,
            "the agent did not start: {}; the cause is permanent, so the agent ends with status {PERMANENT_START_ERROR_STATUS} and the service manager does not start it again",
            reason.message()
        );
        ExitCode::from(PERMANENT_START_ERROR_STATUS)
    }

    /// Checks the state directory and prepares the start. `Err`: the
    /// exit status of a start that failed.
    fn checked_prepare(options: &Options) -> Result<Prepared, ExitCode> {
        let state: &Path = &options.state_directory;
        if let Err(error) = state_directory(state) {
            // A refused directory stays refused. The record cannot go to
            // it, so the line on the standard error stream is the report.
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(end_permanently(
                    state,
                    StartFailureReason::StateDirectoryRefused,
                ));
            }
            tracing::error!(
                cause = %error.kind(),
                "the agent did not start: the state directory is not usable"
            );
            return Err(ExitCode::FAILURE);
        }
        prepare(options).map_err(|failure| match failure {
            StartFailed::Permanent(reason) => end_permanently(state, reason),
            StartFailed::Transient(message) => {
                tracing::error!(message, "the agent did not start");
                ExitCode::FAILURE
            }
        })
    }

    /// The exit status of a start error of the driver.
    fn driver_failure(state: &Path, error: &DriverError) -> ExitCode {
        if let Some(reason) = StartFailureReason::of_driver(error) {
            return end_permanently(state, reason);
        }
        // The text of a journal error can have a path.
        let cause: &str = match error {
            DriverError::Journal(_) => "journal",
            DriverError::Coordinator(_) => "coordinator",
            DriverError::Clock => "clock",
            DriverError::Reconciliation => "reconciliation",
        };
        tracing::error!(cause, "the agent did not start");
        ExitCode::FAILURE
    }

    pub(super) fn run(options: &Options) -> ExitCode {
        let state: &Path = &options.state_directory;
        let Prepared {
            epoch,
            parts,
            service,
            settings,
        } = match checked_prepare(options) {
            Ok(prepared) => prepared,
            Err(status) => return status,
        };
        let (subscription, events) = pressure_events(&parts);
        let SystemParts {
            driver: driver_parts,
            collector,
            clock,
            context: _context,
        } = parts;
        let driver: Box<Driver> = match Driver::start(state, epoch.clone(), settings, driver_parts)
        {
            Ok(DriverStart::Running(driver)) => {
                // The start succeeded: the record of an earlier permanent
                // start error is not current.
                if remove_start_failure(state).is_err() {
                    tracing::warn!("the start-failure record of an earlier start was not removed");
                }
                driver
            }
            Ok(DriverStart::Busy {
                holder: CoordinatorRole::Agent,
            }) => {
                // An agent has the lock. This is not a failure: `launchd`
                // does not start a second agent again.
                tracing::info!("an agent runs already; this process changed nothing");
                return ExitCode::SUCCESS;
            }
            Ok(DriverStart::Busy {
                holder: CoordinatorRole::Client,
            }) => {
                // A client executes a request and releases the lock after
                // it, or the kind of the holder is not known. The failure
                // status makes `launchd` start the agent again after its
                // throttle interval, so the guards do not stay stopped.
                tracing::warn!(
                    "a client holds the coordinator lock; this process changed nothing and ends with a failure so that it is started again"
                );
                return ExitCode::FAILURE;
            }
            Err(error) => return driver_failure(state, &error),
        };
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            executor_epoch = %epoch,
            "svalnir-agent started"
        );

        let stop: StopHandle = StopHandle::new();
        let service_stop: StopHandle = stop.clone();
        let service_clock: Arc<dyn AgentClock> = clock;
        let thread = std::thread::Builder::new()
            .name("svalnir-driver".to_owned())
            .spawn(move || {
                // Also when the service ends with a panic, the main run
                // loop must end.
                let _end_run_loop = EndRunLoop(service_stop.clone());
                let report: ShutdownReport = run_service(
                    driver,
                    collector,
                    events,
                    service,
                    &service_stop,
                    service_clock,
                );
                report
            });
        let Ok(thread) = thread else {
            tracing::error!("the driver thread did not start");
            return ExitCode::FAILURE;
        };

        let signal = run_main_run_loop_until_stop();
        stop.request_stop();
        // The end of the subscription ends the delivery of events.
        drop(subscription);
        let report: Option<ShutdownReport> = thread.join().ok();
        match (signal, report) {
            (Ok(signal @ (StopSignal::Interrupt | StopSignal::Terminate)), Some(report))
                if report.clean =>
            {
                tracing::info!(?signal, "svalnir-agent stopped");
                ExitCode::SUCCESS
            }
            (signal, report) => {
                // The service ended with no stop signal, or the stop was
                // not clean. The failure status makes `launchd` start the
                // agent again, and the next start reconciles what this
                // lifetime left.
                tracing::error!(
                    run_loop_error = signal.is_err(),
                    service_ended_first = matches!(signal, Ok(StopSignal::Requested)),
                    clean = report.is_some_and(|report| report.clean),
                    "svalnir-agent stopped, and the stop was not clean"
                );
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod host_tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::agent::{home_path, proposal, state_directory};
    use svalnir_agent::runtime::start_failure::StartFailureReason;

    #[test]
    fn a_home_directory_that_is_not_a_journal_path_is_a_permanent_error() {
        assert_eq!(
            home_path(std::path::Path::new("")),
            Err(StartFailureReason::HomeNotResolvable)
        );
        assert!(home_path(std::path::Path::new("/Users/someone")).is_ok());
    }

    #[test]
    fn a_new_state_directory_is_for_this_user_only() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested").join("state");
        state_directory(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        // The directory that the agent made is accepted again.
        state_directory(&path).unwrap();
    }

    #[test]
    fn a_state_directory_that_other_users_can_read_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(state_directory(&path).is_err());
        // The agent does not change a directory that it did not make.
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn a_state_directory_that_is_a_symbolic_link_or_a_file_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(state_directory(&link).is_err());
        let file = temp.path().join("file");
        std::fs::write(&file, b"").unwrap();
        assert!(state_directory(&file).is_err());
    }

    #[test]
    fn a_configuration_path_that_is_a_named_pipe_is_refused_and_does_not_block() {
        let temp = tempfile::tempdir().unwrap();
        let pipe = temp.path().join("pipe");
        let name = std::ffi::CString::new(pipe.to_str().unwrap()).unwrap();
        // SAFETY: `name` is a valid C string for the time of the call, and
        // the call makes one named pipe in the temporary directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // No process writes to the pipe. A blocking open would not return.
        assert!(proposal(Some(&pipe)).is_err());
        assert!(proposal(Some(temp.path())).is_err());
        let file = temp.path().join("config.toml");
        std::fs::write(&file, "schema_version = 1\n").unwrap();
        assert!(proposal(Some(&file)).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{Invocation, Options, parse};

    fn arguments(text: &[&str]) -> Vec<OsString> {
        text.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_foreground_flag_and_the_state_directory_are_required() {
        assert_eq!(
            parse(arguments(&["--foreground", "--state-dir", "/tmp/state"])),
            Ok(Invocation::Run(Options {
                state_directory: PathBuf::from("/tmp/state"),
                config: None,
            }))
        );
        assert!(parse(arguments(&["--state-dir", "/tmp/state"])).is_err());
        assert!(parse(arguments(&["--foreground"])).is_err());
        assert!(parse(arguments(&[])).is_err());
    }

    #[test]
    fn the_configuration_path_is_optional_and_each_path_is_absolute() {
        assert_eq!(
            parse(arguments(&[
                "--config",
                "/tmp/config.toml",
                "--state-dir",
                "/tmp/state",
                "--foreground",
            ])),
            Ok(Invocation::Run(Options {
                state_directory: PathBuf::from("/tmp/state"),
                config: Some(PathBuf::from("/tmp/config.toml")),
            }))
        );
        assert!(parse(arguments(&["--foreground", "--state-dir", "state"])).is_err());
        assert!(
            parse(arguments(&[
                "--foreground",
                "--state-dir",
                "/tmp/state",
                "--config",
                "config.toml",
            ]))
            .is_err()
        );
    }

    #[test]
    fn an_argument_that_is_not_known_is_refused_and_not_printed() {
        let error: String = parse(arguments(&[
            "--foreground",
            "--enable-guards",
            "/secret/path",
        ]))
        .unwrap_err();
        assert!(!error.contains("secret"));
        assert!(!error.contains("enable"));
        assert!(parse(arguments(&["--state-dir"])).is_err());
        assert!(
            parse(arguments(&[
                "--foreground",
                "--state-dir",
                "/a",
                "--state-dir",
                "/b",
            ]))
            .is_err()
        );
    }

    #[test]
    fn help_and_version_need_no_other_argument() {
        assert_eq!(parse(arguments(&["--help"])), Ok(Invocation::Help));
        assert_eq!(parse(arguments(&["--version"])), Ok(Invocation::Version));
    }
}
