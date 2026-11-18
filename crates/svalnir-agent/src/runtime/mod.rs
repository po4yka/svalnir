//! The runtime of the agent process.
//!
//! The runtime carries out what the controller decides. It opens the
//! journal and takes the coordinator lock, reconciles the operations that
//! an earlier lifetime left unsettled before anything else, and then runs
//! bounded periodic sampling with the memory-pressure events, the
//! controller step, the queue service of the coordinator for client
//! requests, and the retention of the journal and of the catalog store.
//!
//! Owning specifications: `docs/ARCHITECTURE.md` sections 3, 5, 12, 14,
//! and 15, and `README.md`, "Background service lifecycle" and "Operate
//! within resource limits".
//!
//! # Interface
//!
//! | Item | Use |
//! | --- | --- |
//! | [`Driver::start`] | Opens the journal in a state directory, takes the coordinator lock, reconciles, and restores the state of the controller. [`DriverStart::Busy`]: a different coordinator runs. |
//! | [`Driver::tick`] | One bounded unit of work with the newest sample. It never sleeps. |
//! | [`Driver::shutdown`] | Stops new dispatch, waits for the operation in progress within a bound, and checkpoints. |
//! | [`run`] | The threads of the agent: the driver on the calling thread and one collector thread. |
//! | [`AgentStatus`], [`LifecycleRecord`] | The records that the agent writes to the journal. A client reads [`AgentStatus`] with [`OperationJournal::agent_record`](crate::journal::OperationJournal::agent_record) and [`AgentRecord::Status`](crate::journal::AgentRecord). |
//! | [`launch_agent::render`] | The property list of a conventional per-user `LaunchAgent`, as text. Nothing here installs it. |
//! | [`start_failure`] | The classes of start errors, and the record of the latest permanent start error in the state directory. |
//! | [`Collector`], [`CandidateSource`], [`AgentClock`], [`Notifier`], [`SelfFootprint`] | The interfaces that a test replaces. `host` has the implementations for the running system. |
//!
//! # Concurrency design
//!
//! The crate has no asynchronous runtime. The agent process has three
//! threads, and the number is fixed:
//!
//! 1. The **main thread** runs the main run loop until a stop signal, so
//!    that the application list of `AppKit` is current
//!    ([`crate::platform::run_loop`]). It does no other work.
//! 2. The **collector thread** reads the resource signals. It makes one
//!    collection, puts the sample in a slot of one sample, and waits for
//!    a memory-pressure event or for the sample interval. A collection
//!    can take the time of a process inventory; it holds no lock while it
//!    runs, and it never waits for the driver.
//! 3. The **driver thread** owns the [`Driver`]: the coordinator with its
//!    journal connection and its executors, the state of the controller,
//!    and a second journal connection for the agent records. It calls
//!    [`Driver::tick`] with each new sample and at most each idle
//!    interval.
//!
//! Dispatch delivers a memory-pressure event on a queue of the system and
//! puts it in a bounded channel; that queue is not a thread of this crate.
//!
//! Collection is not blocked by an action. The process executor issues a
//! request and returns; a grace period is a wake time of the coordinator
//! and not a wait. A filesystem call of an executor runs on the driver
//! thread, and the collector thread continues during it: the newest
//! sample replaces the one that the driver did not take.
//!
//! The two threads share one mutex with a condition variable. A critical
//! section moves one sample or reads one flag. No collection, no tick, no
//! journal call, and no executor call runs with the lock held. The
//! authority records have a second mutex, which only the driver thread
//! takes; it is a mutex because the coordinator owns its authority source
//! as a separate value.
//!
//! One intervention action runs at a time: the coordinator dispatches one
//! step, and the controller keeps one automatic plan in progress. A
//! client request arrives through the request queue of the journal; the
//! coordinator claims it in a tick, so a client waits at most the idle
//! interval for its claim.
//!
//! # Bounds
//!
//! - Retained samples: one sample in the slot and one in the driver. The
//!   catalog store has the samples that a retention policy bounds.
//! - Candidates: [`MAX_PREPARED_CANDIDATES`](crate::controller::MAX_PREPARED_CANDIDATES)
//!   in one set, and one set.
//! - Reports of plans: one for each apply and one for each finished plan,
//!   and at most one plan is in progress.
//! - Coordinator work in one tick: [`DriverSettings::coordinator_units`].
//! - The agent measures its own physical footprint at each tick. Above
//!   [`DriverSettings::self_budget`] it reduces its optional work:
//!   retained samples, candidate discovery, and maintenance.
//!
//! # Lifecycle
//!
//! - **Start error.** A permanent start error, for example an invalid
//!   configuration, writes one record and exits with a status that the
//!   `LaunchAgent` definition does not restart ([`start_failure`]). A
//!   transient one exits with failure, and `launchd` starts the agent
//!   again after its throttle interval.
//! - **Start.** A capability check, the coordinator lock, the
//!   reconciliation, the lifecycle record, the state of the controller,
//!   the authority record, and then the first sample. Each qualification
//!   window starts idle.
//! - **Authority.** The policy in effect and each grant come only from
//!   the authority record of the journal. With no record the agent only
//!   observes. No argument and no configuration file makes a guard active.
//! - **Wake.** A collector reads the cumulative sleep time of the host. A
//!   change between two collections is a clock discontinuity: the clock
//!   gets a new continuity generation, so each window starts again and
//!   each earlier sample is not usable, and the candidate set is
//!   discarded. Each collection reads the volume identity and the process
//!   inventory again, so no baseline of before the sleep stays. The
//!   driver also asks the clock at each tick
//!   ([`AgentClock::observe_continuity`]), so a sleep is known before the
//!   next collection, and the collector measures its wait with the clock
//!   of the agent, which counts the time of a sleep. The evaluation of a
//!   tick that found a wake uses a clock reading from after it.
//! - **Pause.** A pause is in the authority record, so it survives a
//!   restart. The agent reads the record again at the start of each tick,
//!   before the coordinator dispatches a step.
//! - **Stop.** `SIGTERM` or `SIGINT` ends the main run loop. The driver
//!   ends its tick, makes no new automatic plan, gives the operation in
//!   progress a stop request so that its current step ends at its safe
//!   boundary, waits for it within [`DriverSettings::shutdown_bound`], and
//!   writes the state of the controller. A stop is clean when each
//!   operation is settled and the coordinator released its registration.
//! - **Restart backoff.** A lifetime that wrote no clean stop is counted
//!   in the lifecycle record. After such a stop, automatic work waits for
//!   [`restart_backoff`], which doubles to a maximum. Observation and
//!   client requests do not wait. A lifecycle record that is not readable
//!   gives the longest backoff.
//! - **Thread failure.** A panic of the collector thread or of the driver
//!   thread stops the other one. The stop is then not clean, and the main
//!   run loop ends.
//! - **Power.** The agent takes no power assertion and has no timer that
//!   wakes the host.

mod driver;
#[cfg(target_os = "macos")]
pub mod host;
pub mod launch_agent;
mod ports;
mod record;
mod service;
pub mod start_failure;
#[cfg(test)]
mod tests;

pub use self::driver::{
    CODE_STATE_NOT_RECORDED, Driver, DriverError, DriverParts, DriverSettings, DriverStart,
    JOURNAL_FILE_NAME, ShutdownReport, TickReport, journal_path,
};
pub use self::ports::{
    AgentClock, CandidateSource, ClockHandle, Collector, Notifier, Sample, SelfFootprint,
};
pub use self::record::{
    AGENT_STATUS_VERSION, AgentStatus, CapabilitySummary, LIFECYCLE_VERSION, LifecycleRecord,
    MAX_DEGRADED_REASONS, PolicySource, RESTART_BACKOFF_BASE, RESTART_BACKOFF_MAX, RunState,
    SelfLimits, restart_backoff,
};
pub use self::service::{ServiceSettings, StopHandle, ThreadIdle, run};
