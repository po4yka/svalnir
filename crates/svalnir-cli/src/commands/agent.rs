//! `agent status`, `agent install`, and `agent uninstall`.
//!
//! `agent status` reads the records that the agent writes to the journal
//! and the coordinator lock. A record is not evidence that a process runs:
//! only the lock is.
//!
//! `agent install` and `agent uninstall` change the registered services of
//! the host. Each host effect goes through [`ServiceHost`]. The service is
//! a conventional per-user `LaunchAgent` that starts `svalnir-agent` in
//! observation mode: the definition has no option that enables a guard,
//! and a guard is enabled only by `svalnir policy enable`.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use svalnir_agent::journal::{AgentRecord, CoordinatorRecord};
use svalnir_agent::runtime::launch_agent::{
    LAUNCH_AGENT_FILE_NAME, LAUNCH_AGENT_LABEL, LaunchAgentDefinition, render,
};
use svalnir_agent::runtime::{AgentStatus, LifecycleRecord};
use svalnir_core::file::LosslessPath;
use svalnir_core::time::WallTime;

use super::authority::AuthorityView;
use super::session::{self, CoordinatorPresence, Now, coordinator_presence, journal_error};
use super::start_failure::StartFailureView;
use super::{CommandFailure, Invocation};
use crate::cli::AgentServiceArgs;
use crate::environment::Environment;
use crate::host::Host;
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};
use crate::seams::{Confirmation, ProgramProblem, ServiceFailure, ServiceHost};
use crate::text::{escape, json_tree, put_line};

/// The directory of the per-user service definitions, below the home
/// directory.
const LAUNCH_AGENTS_DIRECTORY: &str = "Library/LaunchAgents";

const STATUS_RECORD_NOTE: &str = "The status record is what the agent wrote at `written_at`. It is not evidence that the agent runs now: only the coordinator lock is.";

/// The registration of the coordinator in the journal.
#[derive(Debug, Clone, Serialize)]
struct RegistrationView {
    executor_epoch: String,
    process_id: u32,
    started_unix_seconds: i64,
    /// False when the coordinator did not release its registration: it
    /// runs, or it stopped with no clean stop.
    released: bool,
    reconciliation_pending: bool,
}

impl From<CoordinatorRecord> for RegistrationView {
    fn from(record: CoordinatorRecord) -> Self {
        Self {
            executor_epoch: record.executor_epoch.to_string(),
            process_id: record.process_id,
            started_unix_seconds: record.started_unix_seconds,
            released: record.released,
            reconciliation_pending: record.reconciliation_pending,
        }
    }
}

/// What the journal and the lock show about the agent.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentSummary {
    /// `present` or `absent`.
    pub(crate) journal: &'static str,
    /// Whether a process holds the coordinator lock.
    pub(crate) coordinator: CoordinatorPresence,
    /// `agent` when the process that holds the lock is the agent of the
    /// status record, `client` when it is a client that executes a
    /// request, and `none`.
    pub(crate) lock_holder: &'static str,
    /// One sentence about the lock.
    pub(crate) statement: String,
    registration: Option<RegistrationView>,
    /// The latest status record of the agent.
    status: Option<AgentStatus>,
    status_written_at: Option<WallTime>,
    lifecycle: Option<LifecycleRecord>,
    /// The standing authority.
    pub(crate) authority: Option<AuthorityView>,
    /// A problem that prevented a part of the view.
    pub(crate) problem: Option<String>,
}

impl AgentSummary {
    fn absent() -> Self {
        Self {
            journal: "absent",
            coordinator: CoordinatorPresence::NotRunning,
            lock_holder: "none",
            statement: "No operation journal exists in the state directory: no agent and no client wrote one. No agent process runs on this state directory.".to_owned(),
            registration: None,
            status: None,
            status_written_at: None,
            lifecycle: None,
            authority: None,
            problem: None,
        }
    }

    /// Reads the journal and the lock. The function makes no state
    /// directory and no journal.
    pub(crate) fn collect(environment: &Environment) -> Result<Self, ErrorBody> {
        let Some(journal) = session::open_existing_journal(environment)? else {
            return Ok(Self::absent());
        };
        let coordinator: CoordinatorPresence = coordinator_presence(&environment.journal_path()?);
        let registration: Option<CoordinatorRecord> = journal
            .coordination()
            .map_err(|error| journal_error(&error))?;
        let (status, status_problem) =
            match journal.agent_record::<AgentStatus>(AgentRecord::Status) {
                Ok(status) => (status, None),
                Err(_) => (
                    None,
                    Some("the status record of the agent is not readable by this build".to_owned()),
                ),
            };
        // A record that cannot be read is not an absent record: the view
        // names each one.
        let mut problems: Vec<String> = status_problem.into_iter().collect();
        let lifecycle = if let Ok(stored) =
            journal.agent_record::<LifecycleRecord>(AgentRecord::Lifecycle)
        {
            stored.map(|stored| stored.record)
        } else {
            problems
                .push("the lifecycle record of the agent is not readable by this build".to_owned());
            None
        };
        // The lock holder is the agent when the registration of the
        // journal is that of the status record.
        let holder_is_agent: bool = match (&registration, &status) {
            (Some(registration), Some(status)) => {
                registration.executor_epoch == status.record.executor_epoch
            }
            _ => false,
        };
        let (lock_holder, statement): (&'static str, String) = match coordinator {
            CoordinatorPresence::Running if holder_is_agent => (
                "agent",
                "An agent process holds the coordinator lock.".to_owned(),
            ),
            CoordinatorPresence::Running => (
                "client",
                "A process holds the coordinator lock, and it is not the agent of the status record: a client executes a request, or an agent starts.".to_owned(),
            ),
            CoordinatorPresence::NotRunning => (
                "none",
                "No agent process holds the coordinator lock: no agent runs on this state directory.".to_owned(),
            ),
            CoordinatorPresence::Unknown => (
                "none",
                "The coordinator lock cannot be read, so it is not known whether an agent runs.".to_owned(),
            ),
        };
        let now: Option<Now> = Host::open().ok().and_then(|host| Now::read(&host).ok());
        let authority = match session::read_authority(&journal) {
            Ok(stored) => Some(AuthorityView::new(&stored.state, now.as_ref())),
            Err(error) => {
                problems.push(error.message);
                None
            }
        };
        let problem: Option<String> = (!problems.is_empty()).then(|| problems.join("; "));
        Ok(Self {
            journal: "present",
            coordinator,
            lock_holder,
            statement,
            registration: registration.map(RegistrationView::from),
            status_written_at: status.as_ref().map(|stored| stored.record.written_at),
            status: status.map(|stored| stored.record),
            lifecycle,
            authority,
            problem,
        })
    }

    /// The state for the summary of `status`.
    pub(crate) fn state(&self) -> &'static str {
        match (self.coordinator, self.lock_holder) {
            (CoordinatorPresence::Running, "agent") => "running",
            (CoordinatorPresence::Running, _) => "client_coordinator",
            (CoordinatorPresence::NotRunning, _) => "not_running",
            (CoordinatorPresence::Unknown, _) => "unknown",
        }
    }
}

/// The result of `agent status`.
#[derive(Debug, Clone, Serialize)]
struct StatusView {
    #[serde(flatten)]
    summary: AgentSummary,
    /// The latest permanent start error of the agent.
    agent_start_failure: StartFailureView,
    service: ServiceView,
    note: &'static str,
}

/// The service definition of the agent.
#[derive(Debug, Clone, Serialize)]
struct ServiceView {
    label: &'static str,
    definition_path: Option<LosslessPath>,
    /// Whether the definition file exists. A file is not evidence that
    /// the service manager loaded it.
    definition_present: Option<bool>,
    /// The log file of the agent that `agent install` names in the
    /// definition. `None` when the home directory is not known.
    log: Option<LosslessPath>,
}

impl StatusView {
    fn render(&self) -> String {
        let mut out = String::new();
        put_line!(out, "Agent: {}", self.summary.statement);
        if let Some(status) = &self.summary.status {
            put_line!(
                out,
                "  Latest status record: written {}, process {}, state {}",
                status.written_at,
                status.process_id,
                super::plan_view::wire(&status.state)
            );
            if let Some(problem) = &status.policy.problem {
                put_line!(out, "  Policy problem of the agent: {}", escape(problem));
            }
            if !status.degraded.is_empty() {
                let reasons: Vec<String> = status
                    .degraded
                    .iter()
                    .map(|reason| escape(reason))
                    .collect();
                put_line!(out, "  Degraded: {}", reasons.join(", "));
            }
            if let Some(controller) = &status.controller
                && let Ok(value) = serde_json::to_value(controller)
            {
                out.push_str("  Controller:\n");
                for line in json_tree(&value).lines() {
                    put_line!(out, "    {line}");
                }
            }
        } else {
            out.push_str("  Latest status record: none\n");
        }
        if let Some(lifecycle) = &self.summary.lifecycle {
            put_line!(
                out,
                "  Stops with no clean stop: {}",
                lifecycle.unclean_stops
            );
        }
        self.agent_start_failure.render(&mut out);
        out.push_str("Standing authority\n");
        match &self.summary.authority {
            Some(authority) => authority.render(&mut out),
            None => out.push_str("  none recorded\n"),
        }
        if let Some(problem) = &self.summary.problem {
            put_line!(out, "  Problem: {}", escape(problem));
        }
        put_line!(
            out,
            "Service definition: {}",
            match (
                &self.service.definition_path,
                self.service.definition_present
            ) {
                (Some(path), Some(true)) => format!("present at {}", path.display_label()),
                (Some(path), _) => format!("none at {}", path.display_label()),
                (None, _) => "the home directory is not known".to_owned(),
            }
        );
        if let Some(log) = &self.service.log {
            put_line!(out, "Agent log: {}", log.display_label());
        }
        put_line!(out, "\n{}", self.note);
        out
    }
}

fn definition_path(environment: &Environment) -> Option<PathBuf> {
    environment
        .home
        .as_ref()
        .filter(|home| home.is_absolute())
        .map(|home| {
            home.join(LAUNCH_AGENTS_DIRECTORY)
                .join(LAUNCH_AGENT_FILE_NAME)
        })
}

pub(crate) fn status(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let environment: &Environment = invocation.environment;
    let summary: AgentSummary = AgentSummary::collect(environment)?;
    let path: Option<PathBuf> = definition_path(environment);
    let host: Arc<dyn ServiceHost> = environment.seams.service_host();
    let view = StatusView {
        summary,
        agent_start_failure: StartFailureView::read(environment),
        service: ServiceView {
            label: LAUNCH_AGENT_LABEL,
            definition_present: path.as_ref().map(|path| host.definition_exists(path)),
            definition_path: path
                .as_ref()
                .and_then(|path| LosslessPath::from_path(path).ok()),
            log: environment.agent_log_path().as_deref().and_then(lossless),
        },
        note: STATUS_RECORD_NOTE,
    };
    invocation.emit(Kind::Snapshot, &view, StatusView::render)?;
    Ok(ExitStatus::Success)
}

fn service_error(code: &'static str, message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(code, ErrorFamily::Native, ErrorStage::Dispatch, message)
        .with_next_action(NextAction::None)
}

/// A per-user service is of the user of the session. The superuser has no
/// such session, and a definition that the superuser owns is not usable
/// for the user.
fn refuse_superuser() -> Result<(), ErrorBody> {
    if session::current_uid().get() == 0 {
        return Err(service_error(
            "superuser_not_supported",
            "the command registers a service of the user session; run it as the user, not as the superuser; the command made no change",
        ));
    }
    Ok(())
}

/// Asks for the approval of a change of the registered services.
fn approve(invocation: &mut Invocation<'_>, yes: bool, question: &str) -> Result<(), ErrorBody> {
    if yes {
        return Ok(());
    }
    match invocation
        .environment
        .seams
        .confirm(invocation.stderr, question)
    {
        Confirmation::Approved => Ok(()),
        Confirmation::Declined => Err(ErrorBody::new(
            "approval_declined",
            ErrorFamily::Authority,
            ErrorStage::Admission,
            "the change of the registered services was not approved; the command made no change",
        )
        .with_next_action(NextAction::None)),
        Confirmation::NotInteractive => Err(ErrorBody::new(
            "approval_required",
            ErrorFamily::Authority,
            ErrorStage::Admission,
            "the command changes the registered services of this host, and the session has no terminal for the approval question; give `--yes`; the command made no change",
        )
        .with_fields(&["yes"])),
    }
}

fn failure(failure: &ServiceFailure, effect: &str) -> ErrorBody {
    service_error(
        "service_change_failed",
        format!("{} ({}); {effect}", failure.detail, failure.step),
    )
}

/// The time between two queries of the service manager after an unload.
const UNLOAD_QUERY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// The largest number of queries after an unload. With the interval, the
/// command waits for no more than 5 s.
const UNLOAD_QUERY_LIMIT: u32 = 50;

/// Waits until the service manager no longer has the service.
///
/// The unload request returns before the service manager has removed the
/// service, and a load in that time is refused. The wait has a bound: the
/// command does not wait for a service that the service manager keeps.
fn wait_until_unloaded(host: &dyn ServiceHost, uid: u32) -> Result<(), ErrorBody> {
    for query in 0..UNLOAD_QUERY_LIMIT {
        if query > 0 {
            host.pause(UNLOAD_QUERY_INTERVAL);
        }
        let loaded: bool = host.is_loaded(uid, LAUNCH_AGENT_LABEL).map_err(|error| {
            failure(
                &error,
                "the definition file is written, and the service manager got the request to unload an earlier registration; the command did not load the new definition; it loads at the next login, or run `svalnir agent install` again",
            )
        })?;
        if !loaded {
            return Ok(());
        }
    }
    Err(service_error(
        "service_unload_timeout",
        format!(
            "the service manager got the request to unload the earlier registration and did not remove it in {} s; the definition file is written, and the command did not load it; the earlier agent possibly runs until the service manager removes it; the new definition loads at the next login, or run `svalnir agent install` again",
            (UNLOAD_QUERY_INTERVAL * UNLOAD_QUERY_LIMIT).as_secs()
        ),
    ))
}

/// The result of `agent install` and `agent uninstall`.
#[derive(Debug, Clone, Serialize)]
struct ServiceChangeView {
    command: &'static str,
    label: &'static str,
    definition_path: LosslessPath,
    /// The executable that the service starts.
    program: Option<LosslessPath>,
    state_directory: Option<LosslessPath>,
    log: Option<LosslessPath>,
    /// `observation` when the authority record has no enabled guard,
    /// `standing_guards` when it has one, and `unknown` when the record
    /// cannot be read. The definition has no option that enables a guard.
    mode: Option<&'static str>,
    /// The guards that this command enabled: none.
    guards_enabled: Vec<&'static str>,
    /// The guards that the authority record of the state directory has
    /// enabled, on which the agent acts. `None` when the record cannot be
    /// read, and for `agent uninstall`.
    standing_guards: Option<Vec<&'static str>>,
    /// Whether the service manager took the request.
    service_manager: &'static str,
    note: &'static str,
}

const INSTALL_NOTE: &str = "The agent starts in observation mode: it measures, serves requests of this client, and makes no automatic intervention. This command enabled no guard and made no grant. Enable a guard with `svalnir config apply` and `svalnir policy enable`.";

const INSTALL_NOTE_STANDING: &str = "This command enabled no guard and made no grant. The authority record of this state directory has an enabled guard from an earlier `svalnir policy enable`: the agent acts on it when its conditions occur. Disable it with `svalnir policy disable`, or stop all automatic work with `svalnir agent pause`.";

const INSTALL_NOTE_UNKNOWN: &str = "This command enabled no guard and made no grant. The authority record of this state directory cannot be read, so it is not known whether an earlier request enabled a guard; an enabled guard is one on which the agent acts. Read the record with `svalnir agent status`.";

/// The guards that the authority record has enabled. `None` when the
/// record cannot be read: a guard is then possibly enabled.
fn standing_guards(environment: &Environment) -> Option<Vec<&'static str>> {
    let summary: AgentSummary = AgentSummary::collect(environment).ok()?;
    match (&summary.authority, &summary.problem) {
        (Some(authority), _) => Some(
            authority
                .guards
                .iter()
                .filter(|guard| guard.grant.is_some())
                .map(|guard| guard.policy)
                .collect(),
        ),
        // A journal with no authority record has no enabled guard.
        (None, None) => Some(Vec::new()),
        (None, Some(_)) => None,
    }
}

const UNINSTALL_NOTE: &str = "The service is not registered. The state directory, the journal, and the authority record stay; a guard that is enabled stays enabled in the record, and no agent acts on it. The log of the agent stays in its log directory; remove it yourself when you do not need it.";

impl ServiceChangeView {
    fn render(&self) -> String {
        let mut out = String::new();
        put_line!(out, "svalnir {}: {}", self.command, self.service_manager);
        put_line!(out, "  Service: {}", self.label);
        put_line!(
            out,
            "  Definition: {}",
            self.definition_path.display_label()
        );
        if let Some(program) = &self.program {
            put_line!(out, "  Program: {}", program.display_label());
        }
        if let Some(log) = &self.log {
            put_line!(out, "  Log: {}", log.display_label());
        }
        if let Some(mode) = self.mode {
            put_line!(out, "  Mode: {mode}; guards enabled by this command: none");
        }
        if let Some(guards) = self
            .standing_guards
            .as_ref()
            .filter(|guards| !guards.is_empty())
        {
            put_line!(
                out,
                "  Guards enabled in the authority record: {}",
                guards.join(", ")
            );
        }
        put_line!(out, "\n{}", self.note);
        out
    }
}

fn lossless(path: &std::path::Path) -> Option<LosslessPath> {
    LosslessPath::from_path(path).ok()
}

/// The log file of the agent and its directory, for `agent install`.
///
/// The home directory has passed the `HOME` check of a command that changes
/// state, so the log path is that of this user.
fn agent_log(environment: &Environment) -> Result<(PathBuf, PathBuf), ErrorBody> {
    let unavailable = || {
        service_error(
            "home_directory_unavailable",
            "the home directory of the user is not known, so the log of the agent has no path; the command made no change",
        )
    };
    let log: PathBuf = environment.agent_log_path().ok_or_else(unavailable)?;
    let directory: PathBuf = log
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(unavailable)?;
    Ok((log, directory))
}

pub(crate) fn install(
    arguments: &AgentServiceArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    refuse_superuser()?;
    let environment: &Environment = invocation.environment;
    let host: Arc<dyn ServiceHost> = environment.seams.service_host();
    let definition: PathBuf = definition_path(environment).ok_or_else(|| {
        service_error(
            "home_directory_unavailable",
            "the home directory of the user is not known, so the service definition has no path; the command made no change",
        )
    })?;
    // The location of the agent executable has no packaging contract yet:
    // this build accepts only an executable beside this one.
    let program: PathBuf = host.agent_program().map_err(|problem| match problem {
        ProgramProblem::NotFound => service_error(
            "agent_program_not_found",
            "the `svalnir-agent` executable is not beside the `svalnir` executable; this build has no other install location for it; the command made no change",
        ),
        ProgramProblem::NotTrusted => service_error(
            "agent_program_not_trusted",
            "a different user can change the `svalnir-agent` executable or its directory: the owner is not this user or the superuser, or the group or each user has write permission; a service must not start such a file at each login; the command made no change",
        ),
    })?;
    let state_directory: PathBuf = environment.state_directory()?;
    let (log, log_directory): (PathBuf, PathBuf) = agent_log(environment)?;
    let text: String = render(&LaunchAgentDefinition {
        program: program.clone(),
        state_directory: state_directory.clone(),
        config: None,
        log: log.clone(),
    })
    .map_err(|_| {
        service_error(
            "service_definition_not_renderable",
            "a path of the service definition is not absolute or is not text that a property list can hold; the command made no change",
        )
    })?;
    let standing: Option<Vec<&'static str>> = standing_guards(environment);
    let (mode, note, consequence): (&'static str, &'static str, String) = match &standing {
        Some(guards) if guards.is_empty() => (
            "observation",
            INSTALL_NOTE,
            "It starts the Svalnir agent at login, in observation mode. It enables no guard.".to_owned(),
        ),
        Some(guards) => (
            "standing_guards",
            INSTALL_NOTE_STANDING,
            format!(
                "It starts the Svalnir agent at login. It enables no guard, but the authority record has an enabled guard ({}), and the agent acts on it.",
                guards.join(", ")
            ),
        ),
        None => (
            "unknown",
            INSTALL_NOTE_UNKNOWN,
            "It starts the Svalnir agent at login. It enables no guard. The authority record cannot be read, so it is not known whether a guard is enabled.".to_owned(),
        ),
    };
    approve(
        invocation,
        arguments.yes,
        &format!(
            "Register the per-user service {LAUNCH_AGENT_LABEL}?\n{consequence}\nAn agent of this service that runs now is stopped and started again; an operation that it executes is left for reconciliation."
        ),
    )?;
    // The service manager does not make the directory of the log file. A
    // directory that this user cannot write is refused before the
    // definition changes.
    host.prepare_log_directory(&log_directory).map_err(|error| {
        failure(
            &error,
            "the command changed no registration; make sure that this user owns the log directory and can write to it, and that no other user can write to it",
        )
    })?;
    environment.create_state_directory()?;
    let uid: u32 = session::current_uid().get();
    // The new definition is in place before an earlier registration is
    // unloaded, so a failed write leaves the earlier service as it was.
    host.write_definition(&definition, &text)
        .map_err(|error| failure(&error, "the command changed no registration"))?;
    host.unload(uid, LAUNCH_AGENT_LABEL).map_err(|error| {
        failure(
            &error,
            "the definition file is written, and an earlier registration was possibly not unloaded; the new definition loads at the next login",
        )
    })?;
    wait_until_unloaded(host.as_ref(), uid)?;
    host.load(uid, &definition).map_err(|error| {
        failure(
            &error,
            "the definition file is written, and the service manager did not load it; it loads at the next login, or remove it with `svalnir agent uninstall`",
        )
    })?;
    let view = ServiceChangeView {
        command: "agent install",
        label: LAUNCH_AGENT_LABEL,
        definition_path: lossless(&definition).ok_or_else(session::identity_error)?,
        program: lossless(&program),
        state_directory: lossless(&state_directory),
        log: lossless(&log),
        mode: Some(mode),
        guards_enabled: Vec::new(),
        standing_guards: standing,
        service_manager: "loaded",
        note,
    };
    invocation.emit(Kind::Report, &view, ServiceChangeView::render)?;
    Ok(ExitStatus::Success)
}

pub(crate) fn uninstall(
    arguments: &AgentServiceArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    refuse_superuser()?;
    let environment: &Environment = invocation.environment;
    let host: Arc<dyn ServiceHost> = environment.seams.service_host();
    let definition: PathBuf = definition_path(environment).ok_or_else(|| {
        service_error(
            "home_directory_unavailable",
            "the home directory of the user is not known, so the service definition has no path; the command made no change",
        )
    })?;
    approve(
        invocation,
        arguments.yes,
        &format!(
            "Remove the per-user service {LAUNCH_AGENT_LABEL}?\nThe agent stops. The state directory and its records stay."
        ),
    )?;
    host.unload(session::current_uid().get(), LAUNCH_AGENT_LABEL)
        .map_err(|error| {
            failure(
                &error,
                "the service is possibly loaded, and the definition file was not removed",
            )
        })?;
    host.remove_definition(&definition).map_err(|error| {
        failure(
            &error,
            "the service manager unloaded the service, and the definition file stays: the service loads again at the next login",
        )
    })?;
    let view = ServiceChangeView {
        command: "agent uninstall",
        label: LAUNCH_AGENT_LABEL,
        definition_path: lossless(&definition).ok_or_else(session::identity_error)?,
        program: None,
        state_directory: None,
        log: environment.agent_log_path().as_deref().and_then(lossless),
        mode: None,
        guards_enabled: Vec::new(),
        standing_guards: None,
        service_manager: "unloaded",
        note: UNINSTALL_NOTE,
    };
    invocation.emit(Kind::Report, &view, ServiceChangeView::render)?;
    Ok(ExitStatus::Success)
}

/// Opens the journal for the summary of `status`. A failure is a text in
/// the summary, not a failure of the command.
pub(crate) fn summary_or_problem(environment: &Environment) -> AgentSummary {
    AgentSummary::collect(environment).unwrap_or_else(|error| {
        let mut summary = AgentSummary::absent();
        summary.journal = "unreadable";
        summary.coordinator = CoordinatorPresence::Unknown;
        "The operation journal cannot be read, so the state of the agent is not known."
            .clone_into(&mut summary.statement);
        summary.problem = Some(error.message);
        summary
    })
}
