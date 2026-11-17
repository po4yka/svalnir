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
//! same arguments. The log is structured text on the standard error
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
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::Path;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::time::Duration;

    use svalnir_agent::coordinator::CoordinatorConfig;
    use svalnir_agent::journal::JournalOptions;
    use svalnir_agent::platform::memory::{PressureEvent, PressureSubscription};
    use svalnir_agent::platform::run_loop::run_main_run_loop_until_stop;
    use svalnir_agent::runtime::host::{SystemParts, system_parts};
    use svalnir_agent::runtime::{
        AgentClock, Driver, DriverSettings, DriverStart, ServiceSettings, ShutdownReport,
        StopHandle, run as run_service,
    };
    use svalnir_agent::store::{Store, StoreOptions};
    use svalnir_core::config::{MAX_DOCUMENT_BYTES, ValidatedConfig, parse_and_validate};
    use svalnir_core::file::LosslessPath;
    use svalnir_core::id::{AdapterId, ExecutorEpochId};
    use svalnir_core::process::Uid;
    use svalnir_core::quantity::{Bytes, Nanoseconds};

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
    fn proposal(path: Option<&Path>) -> Result<ValidatedConfig, String> {
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
                std::fs::File::open(path)
                    .and_then(|file| file.take(limit).read_to_string(&mut text))
                    .map_err(|_| "the configuration file is not readable")?;
                if text.len() > MAX_DOCUMENT_BYTES {
                    return Err("the configuration file is too large".to_owned());
                }
                text
            }
        };
        parse_and_validate(&text).config().cloned().ok_or_else(|| {
            "the configuration is not valid; `svalnir config validate` shows the findings"
                .to_owned()
        })
    }

    /// Makes the state directory when it does not exist, for this user
    /// only.
    fn state_directory(path: &Path) -> std::io::Result<()> {
        if path.is_dir() {
            return Ok(());
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }

    /// The home directory of the user, from the environment of the
    /// process, as a canonical path.
    fn home_directory() -> Option<LosslessPath> {
        let home = std::env::var_os("HOME")?;
        let canonical = std::fs::canonicalize(home).ok()?;
        LosslessPath::from_path(&canonical).ok()
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

    /// Reads the configuration and makes the parts of the running system.
    /// The message of an error has no path.
    fn prepare(options: &Options) -> Result<Prepared, String> {
        let config: ValidatedConfig = proposal(options.config.as_deref())?;
        state_directory(&options.state_directory)
            .map_err(|_| "the state directory is not usable")?;
        let home: LosslessPath =
            home_directory().ok_or("the home directory of the user is not known")?;
        // SAFETY: `geteuid` has no argument, changes nothing, and does
        // not fail.
        let principal: Uid = Uid::new(unsafe { libc::geteuid() });
        let started: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let epoch: ExecutorEpochId =
            ExecutorEpochId::new(format!("agent-{}-{started:x}", std::process::id()))
                .map_err(|_| "the identity of the executor lifetime is not valid")?;
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
            system_parts(&epoch, principal, &home, store).map_err(|error| error.to_string())?;
        let service: ServiceSettings = ServiceSettings {
            sample_interval: config.agent().sample_interval,
            pressure_sample_interval: config.agent().pressure_sample_interval,
            idle_interval: IDLE_INTERVAL,
        };
        let settings: DriverSettings =
            settings(principal, home, config).ok_or("a setting of the agent is not valid")?;
        Ok(Prepared {
            epoch,
            parts,
            service,
            settings,
        })
    }

    pub(super) fn run(options: &Options) -> ExitCode {
        let Prepared {
            epoch,
            parts,
            service,
            settings,
        } = match prepare(options) {
            Ok(prepared) => prepared,
            Err(message) => {
                tracing::error!(message, "the agent did not start");
                return ExitCode::FAILURE;
            }
        };
        let (subscription, events) = pressure_events(&parts);
        let SystemParts {
            driver: driver_parts,
            collector,
            clock,
            context: _context,
        } = parts;
        let driver: Box<Driver> = match Driver::start(
            &options.state_directory,
            epoch.clone(),
            settings,
            driver_parts,
        ) {
            Ok(DriverStart::Running(driver)) => driver,
            Ok(DriverStart::Busy) => {
                // A different coordinator has the lock. This is not a
                // failure: `launchd` does not start the agent again.
                tracing::info!("a different coordinator runs; this process changed nothing");
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                // The text of a journal error can have a path.
                let cause: &str = match error {
                    svalnir_agent::runtime::DriverError::Journal(_) => "journal",
                    svalnir_agent::runtime::DriverError::Coordinator(_) => "coordinator",
                    svalnir_agent::runtime::DriverError::Clock => "clock",
                    svalnir_agent::runtime::DriverError::Reconciliation => "reconciliation",
                };
                tracing::error!(cause, "the agent did not start");
                return ExitCode::FAILURE;
            }
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
                let report: ShutdownReport = run_service(
                    driver,
                    collector,
                    events,
                    service,
                    &service_stop,
                    service_clock,
                );
                if !service_stop.was_requested() {
                    // The service ended with no stop request. The main
                    // run loop ends at a stop signal of this process.
                    // SAFETY: `raise` sends one signal to the calling
                    // process, which has a signal source for it.
                    unsafe { libc::raise(libc::SIGTERM) };
                }
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
            (Ok(signal), Some(report)) if report.clean => {
                tracing::info!(?signal, "svalnir-agent stopped");
                ExitCode::SUCCESS
            }
            (signal, report) => {
                // The next start reconciles what this lifetime left.
                tracing::error!(
                    run_loop_error = signal.is_err(),
                    clean = report.is_some_and(|report| report.clean),
                    "svalnir-agent stopped, and the stop was not clean"
                );
                ExitCode::FAILURE
            }
        }
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
