//! The live reads of the Memory, Applications, Automation, History, and
//! Diagnostics screens. Each function only reads: it makes no file, sends no
//! request, and does not read the coordinator lock.

use super::{
    model::{GuardRow, Measured, OperationPhase},
    records::{
        AgentStatusRow, ApplicationRow, AutomationSnapshot, CapabilityLevel, CapabilityRow,
        DiagnosticsSnapshot, EffectRow, Foreground, GrantRow, GroupKind, GuardDetail,
        HISTORY_ROWS_MAX, HistorySnapshot, IncidentRow, JournalRow, MemorySnapshot, Need,
        OperationDetail, PauseRow, ProcessRow, ProcessesSnapshot, Protection, RevisionRow,
        StartFailureRow, Verdict, rank_applications, rank_processes, refine_phase,
    },
};
use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use svalnir_agent::{
    capability::{self, Requirement, WorkerRole},
    journal::{AgentRecord, OperationJournal},
    observe::{self, Host},
    platform::{
        memory::collect_memory_snapshot,
        process::{
            CollectionContext as ProcessContext, DarwinProcessSource, ForegroundState,
            ProcessCollector, ProcessRecord, ProcessSnapshot, control_plane_of_this_process,
        },
    },
    runtime::{AgentStatus, RunState, journal_path, start_failure::read_start_failure},
};
use svalnir_core::{
    action::{Operation, ResourceEffect},
    grant::AuthorityState,
    observation::{Observation, Reading},
    policy::{PolicyId, ProtectionContext, ProtectionFact, hard_protection},
    process::{ProcessIdentity, VerifiedMembership},
    quantity::Bytes,
    state::{CapabilityState, PressureState},
    time::WallTime,
};

/// The label of the live source.
const SOURCE: &str = "in-process collection";

pub(crate) fn system_time(time: WallTime) -> SystemTime {
    let seconds: i64 = time.unix_seconds();
    let nanos: Duration = Duration::from_nanos(u64::from(time.subsecond_nanoseconds()));
    if seconds >= 0 {
        UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs()) + nanos
    } else {
        UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs()) + nanos
    }
}

fn observed_bytes(observation: &Observation<Bytes>) -> Measured<u64> {
    match observation.value() {
        Some(value) => Measured::Value(value.get()),
        None => Measured::Unavailable(
            observation
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

fn read_bytes(reading: &Reading<Bytes>) -> Measured<u64> {
    match reading.value() {
        Some(value) => Measured::Value(value.get()),
        None => Measured::Unavailable(
            reading
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

/// Reads the memory quantities of the host.
pub(super) fn memory(host: &Host) -> Result<MemorySnapshot, String> {
    let snapshot = collect_memory_snapshot(host.context()).map_err(|error| error.to_string())?;
    let vm = &snapshot.vm;
    Ok(MemorySnapshot {
        captured_at: SystemTime::now(),
        wired: read_bytes(&vm.page_bytes(&vm.wired)),
        compressor: read_bytes(&vm.page_bytes(&vm.compressor_physical)),
        compressed_data: read_bytes(&vm.page_bytes(&vm.compressor_uncompressed)),
        free: read_bytes(&vm.page_bytes(&vm.free)),
        source: SOURCE,
    })
}

/// The verified members of one application or job instance.
struct Group<'a> {
    instance: String,
    name: String,
    kind: GroupKind,
    members: Vec<&'a ProcessRecord>,
}

fn group_row(group: &Group<'_>, context: &ProtectionContext<'_>) -> ApplicationRow {
    let mut sum: u64 = 0;
    let mut measured: usize = 0;
    for member in &group.members {
        if let Some(bytes) = member.metrics.footprint.value() {
            sum = sum.saturating_add(bytes.get());
            measured += 1;
        }
    }
    let foreground: Foreground = if group
        .members
        .iter()
        .any(|member| member.foreground == ForegroundState::Foreground)
    {
        Foreground::Foreground
    } else if group
        .members
        .iter()
        .all(|member| member.foreground == ForegroundState::Background)
    {
        Foreground::Background
    } else {
        Foreground::Unknown
    };
    let identities: Vec<ProcessIdentity> = group
        .members
        .iter()
        .map(|member| member.identity.clone())
        .collect();
    ApplicationRow {
        instance: group.instance.clone(),
        name: group.name.clone(),
        kind: group.kind,
        members: group.members.len(),
        footprint: if measured == 0 {
            Measured::Unavailable("no member has a footprint value".to_owned())
        } else {
            Measured::Value(sum)
        },
        unmeasured_members: group.members.len() - measured,
        foreground,
        protection: match hard_protection(&identities, context) {
            ProtectionFact::Protected => Protection::Protected,
            ProtectionFact::NotProtected => Protection::NotProtected,
            ProtectionFact::Unknown => Protection::Unknown,
        },
    }
}

/// Makes the rows of a process snapshot. Only a verified membership makes a
/// process a member of a group.
fn process_rows(snapshot: &ProcessSnapshot) -> ProcessesSnapshot {
    let mut groups: Vec<Group<'_>> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut unattributed: usize = 0;
    let mut processes: Vec<ProcessRow> = Vec::with_capacity(snapshot.records.len());
    for record in &snapshot.records {
        let membership = record.identity.association.verified_membership();
        let (instance, name, kind) = match membership {
            Some(VerifiedMembership::Application {
                instance_id,
                bundle_identifier,
            }) => (
                Some(instance_id.as_str()),
                Some(bundle_identifier),
                GroupKind::Application,
            ),
            Some(VerifiedMembership::ManagedJob { instance_id, label }) => (
                Some(instance_id.as_str()),
                Some(label),
                GroupKind::ManagedJob,
            ),
            None => (None, None, GroupKind::Application),
        };
        if let (Some(instance), Some(name)) = (instance, name) {
            let position: usize = *index.entry(instance.to_owned()).or_insert_with(|| {
                groups.push(Group {
                    instance: instance.to_owned(),
                    name: name.to_owned(),
                    kind,
                    members: Vec::new(),
                });
                groups.len() - 1
            });
            if let Some(group) = groups.get_mut(position) {
                group.members.push(record);
            }
        } else {
            unattributed += 1;
        }
        processes.push(ProcessRow {
            pid: record.identity.pid.get(),
            name: record.display_label(),
            group: name.map(str::to_owned),
            footprint: observed_bytes(&record.metrics.footprint),
            resident: observed_bytes(&record.metrics.resident),
        });
    }
    let control_plane = control_plane_of_this_process(snapshot);
    let context = ProtectionContext {
        principal: observe::current_uid(),
        control_plane: control_plane.as_deref(),
    };
    let applications: Vec<ApplicationRow> = groups
        .iter()
        .map(|group| group_row(group, &context))
        .collect();
    let mut notes: Vec<String> = Vec::new();
    if let Some(reason) = &snapshot.launch_services_unavailable {
        notes.push(format!(
            "The running applications were not read ({reason}), so no process has an application."
        ));
    }
    if snapshot.application_list_may_be_stale {
        notes.push(
            "The application list is not known to be current. A process with no group can belong to a new application, and no foreground state is known."
                .to_owned(),
        );
    }
    if let Some(reason) = &snapshot.responsible_process_unavailable {
        notes.push(format!(
            "The responsible process was not read for one or more processes ({reason}); a helper can be without its group."
        ));
    }
    if control_plane.is_none() {
        notes.push(
            "The processes of this window were not found in the reading, so a group that the catalog does not protect shows \"Unknown\"."
                .to_owned(),
        );
    }
    let omissions = snapshot.omissions;
    ProcessesSnapshot {
        captured_at: system_time(snapshot.captured_at),
        process_count: processes.len(),
        processes: rank_processes(processes),
        application_count: applications.len(),
        applications: rank_applications(applications),
        unattributed,
        other_user: omissions.other_user,
        not_readable: omissions
            .permission_denied
            .saturating_add(omissions.failed)
            .saturating_add(omissions.identity_changed),
        notes,
        source: SOURCE,
    }
}

/// Reads the processes of the current user.
pub(super) fn processes(host: &Host) -> Result<ProcessesSnapshot, String> {
    collect_processes(host).map(|snapshot| process_rows(&snapshot))
}

/// Reads the process snapshot of the current user, for the rows of a
/// screen and for the plan of a stop.
pub(crate) fn collect_processes(host: &Host) -> Result<ProcessSnapshot, String> {
    let identity = host.context().identity();
    let collector = ProcessCollector::new(
        DarwinProcessSource::new(),
        ProcessContext {
            worker_id: identity.worker_id.clone(),
            boot_id: identity.boot_id.clone(),
            collector_epoch: identity.collector_epoch.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    collector.collect().map_err(|error| error.to_string())
}

/// Opens the journal of `state_directory` for reading. `Ok(None)`: no
/// journal exists. A directory that is not known is an error: it does not
/// show that no journal exists.
fn open_journal(state_directory: Option<&Path>) -> Result<Option<OperationJournal>, String> {
    match state_directory {
        None => Err("The state directory is not known, so the journal was not read.".to_owned()),
        Some(directory) => observe::open_existing_journal_read_only(&journal_path(directory))
            .map_err(|error| format!("The journal cannot be read: {error}.")),
    }
}

/// The open incidents of each guard in the status record of the agent. A
/// record that cannot be read gives none: a rearm then has no incident to
/// name.
fn open_incidents(journal: &OperationJournal) -> Vec<(PolicyId, IncidentRow)> {
    let Ok(Some(stored)) = journal.agent_record::<AgentStatus>(AgentRecord::Status) else {
        return Vec::new();
    };
    stored
        .record
        .controller
        .iter()
        .flat_map(|controller| controller.guards.iter())
        .flat_map(|guard| {
            guard.incidents.iter().map(|incident| {
                (
                    guard.guard.policy(),
                    IncidentRow {
                        id: incident.incident_id.to_string(),
                        generation: incident.generation,
                    },
                )
            })
        })
        .collect()
}

fn guard_details(
    state: &AuthorityState,
    now: WallTime,
    incidents: &[(PolicyId, IncidentRow)],
) -> Vec<GuardDetail> {
    observe::guard_standings(state, now)
        .into_iter()
        .map(|(policy, standing)| {
            let row: GuardRow = GuardRow::new(policy.as_str(), standing);
            let authority = state.guard(policy);
            let scope = state.active.as_ref().map(|active| &active.scope);
            let (requested, thresholds) = match (scope, policy) {
                (Some(scope), PolicyId::DiskGuard) => {
                    (Some(scope.disk.requested), scope.disk.thresholds.as_slice())
                }
                (Some(scope), PolicyId::MemoryGuard) => (
                    Some(scope.memory.requested),
                    scope.memory.thresholds.as_slice(),
                ),
                _ => (None, [].as_slice()),
            };
            GuardDetail {
                policy,
                name: row.name,
                scope_classes: scope.map_or_else(Vec::new, |scope| scope.action_classes(policy)),
                incidents: incidents
                    .iter()
                    .filter(|(owner, _)| *owner == policy)
                    .map(|(_, incident)| incident.clone())
                    .collect(),
                standing: row.standing,
                detail: row.detail,
                enabled: authority.is_some_and(|guard| guard.enabled),
                requested,
                grant: authority
                    .and_then(|guard| guard.grant.as_ref())
                    .map(|grant| GrantRow {
                        id: grant.grant_id.to_string(),
                        action_classes: grant
                            .action_classes
                            .iter()
                            .map(|class| class.as_str().to_owned())
                            .collect(),
                        rules: grant
                            .rules
                            .iter()
                            .map(|rule| format!("{}@{}", rule.id, rule.revision))
                            .collect(),
                        granted_at: system_time(grant.granted_at),
                        expires_at: grant.expires_at.map(system_time),
                        revoked: grant.revoked,
                        in_effect: grant.is_in_effect(now),
                    }),
                thresholds: thresholds
                    .iter()
                    .map(|threshold| (threshold.key.clone(), threshold.value))
                    .collect(),
            }
        })
        .collect()
}

/// Reads the authority record.
pub(super) fn automation(state_directory: Option<&Path>) -> AutomationSnapshot {
    let captured_at: SystemTime = SystemTime::now();
    let mut snapshot = AutomationSnapshot {
        captured_at,
        journal_present: false,
        revision: None,
        guards: Vec::new(),
        pause: None,
        problems: Vec::new(),
    };
    let uid = observe::current_uid();
    let Ok(now) = WallTime::try_from(captured_at) else {
        snapshot
            .problems
            .push("The system clock has no usable value, so the guards are not shown.".to_owned());
        return snapshot;
    };
    let journal = match open_journal(state_directory) {
        Ok(Some(journal)) => journal,
        Ok(None) => {
            snapshot.guards = guard_details(&AuthorityState::new(uid), now, &[]);
            snapshot.pause = Some(PauseRow::NotPaused);
            return snapshot;
        }
        Err(problem) => {
            snapshot.journal_present = state_directory.is_some();
            snapshot.problems.push(problem);
            return snapshot;
        }
    };
    snapshot.journal_present = true;
    match observe::read_authority(&journal, uid) {
        Ok(stored) => {
            let state: &AuthorityState = &stored.state;
            snapshot.revision = state.active.as_ref().map(|active| RevisionRow {
                id: active.revision.revision_id.to_string(),
                activated_at: system_time(active.revision.activated_at),
                profile: active.scope.profile.clone(),
            });
            snapshot.guards = guard_details(state, now, &open_incidents(&journal));
            snapshot.pause = Some(state.pause.as_ref().map_or(PauseRow::NotPaused, |pause| {
                PauseRow::Paused {
                    since: system_time(pause.started_wall),
                    until: pause
                        .deadline
                        .as_ref()
                        .map(|deadline| system_time(deadline.wall)),
                }
            }));
        }
        Err(error) => snapshot
            .problems
            .push(format!("The authority record cannot be read: {error}.")),
    }
    snapshot
}

fn pressure_text(observation: &Observation<PressureState>) -> Measured<String> {
    match observation.value() {
        Some(state) => Measured::Value(state.as_str().to_owned()),
        None => Measured::Unavailable(
            observation
                .reason()
                .map_or_else(|| "unrecognized".to_owned(), ToString::to_string),
        ),
    }
}

fn effect_row(effect: &ResourceEffect) -> EffectRow {
    match effect {
        ResourceEffect::Capacity(capacity) => EffectRow::Capacity {
            before: observed_bytes(capacity.before()),
            after: observed_bytes(capacity.after()),
        },
        ResourceEffect::MemoryPressure { before, after } => EffectRow::Pressure {
            before: pressure_text(before),
            after: pressure_text(after),
        },
        ResourceEffect::Unrecognized => EffectRow::Unrecognized,
    }
}

fn operation_detail(operation: &Operation, resources: Vec<EffectRow>) -> OperationDetail {
    let (phase, state_text) = OperationPhase::of(operation.state());
    let steps: Vec<String> = operation
        .steps()
        .iter()
        .map(|step| step.progress().state().as_str().to_owned())
        .collect();
    let mut action_classes: Vec<String> = Vec::new();
    for step in operation.steps() {
        let name: &str = step.action_class().as_str();
        if !action_classes.iter().any(|known| known == name) {
            action_classes.push(name.to_owned());
        }
    }
    let mut effects: Vec<(String, usize)> = Vec::new();
    for result in operation.target_results() {
        let name: &str = result.effect.as_str();
        match effects.iter_mut().find(|(known, _)| known == name) {
            Some((_, count)) => *count += 1,
            None => effects.push((name.to_owned(), 1)),
        }
    }
    OperationDetail {
        operation_id: operation.operation_id().to_string(),
        phase: refine_phase(phase, &steps),
        state_text,
        admitted_at: system_time(operation.admitted_at()),
        trigger: operation.trigger_class().as_str().to_owned(),
        automatic: operation.trigger_class().is_automatic(),
        action_classes,
        steps,
        effects,
        resources,
    }
}

/// Reads the latest operations.
pub(super) fn history(state_directory: Option<&Path>) -> HistorySnapshot {
    let mut snapshot = HistorySnapshot {
        captured_at: SystemTime::now(),
        journal_present: false,
        operations: Vec::new(),
        problems: Vec::new(),
    };
    let journal = match open_journal(state_directory) {
        Ok(Some(journal)) => journal,
        Ok(None) => return snapshot,
        Err(problem) => {
            snapshot.journal_present = state_directory.is_some();
            snapshot.problems.push(problem);
            return snapshot;
        }
    };
    snapshot.journal_present = true;
    let operations: Vec<Operation> = match journal.recent_operations(HISTORY_ROWS_MAX) {
        Ok(operations) => operations,
        Err(error) => {
            snapshot
                .problems
                .push(format!("The operations cannot be read: {error}."));
            return snapshot;
        }
    };
    let mut effects_failed: bool = false;
    for operation in &operations {
        let resources: Vec<EffectRow> = match journal.resource_effects(operation.operation_id()) {
            Ok(effects) => effects.iter().map(effect_row).collect(),
            Err(error) => {
                if !effects_failed {
                    effects_failed = true;
                    snapshot.problems.push(format!(
                        "The resource observations of one or more operations cannot be read: {error}."
                    ));
                }
                Vec::new()
            }
        };
        snapshot
            .operations
            .push(operation_detail(operation, resources));
    }
    snapshot
}

fn agent_row(status: &AgentStatus) -> AgentStatusRow {
    AgentStatusRow {
        process_id: status.process_id,
        started_at: system_time(status.started_at),
        written_at: system_time(status.written_at),
        run_state: match status.state {
            RunState::Starting => "starting",
            RunState::Running => "running",
            RunState::Stopping => "stopping",
            RunState::Stopped => "stopped",
        },
        revision: status.policy.revision.as_ref().map(ToString::to_string),
        policy_problem: status.policy.problem.clone(),
        capability_verdict: status
            .capabilities
            .as_ref()
            .map(|summary| summary.verdict.clone()),
        required_not_available: status
            .capabilities
            .as_ref()
            .map_or_else(Vec::new, |summary| summary.required_not_available.clone()),
        footprint: status.limits.footprint_bytes.map_or_else(
            || Measured::Unavailable("the agent did not measure its footprint".to_owned()),
            Measured::Value,
        ),
        budget: status.limits.budget_bytes,
        degraded: status.degraded.clone(),
        unclean_stops: status.unclean_stops,
        restart_backoff: status.restart_backoff,
    }
}

/// Runs the capability probes and reads the records of the service.
pub(super) fn diagnostics(state_directory: Option<&Path>) -> DiagnosticsSnapshot {
    // The report has no role for a window. A window is a client process, as
    // the CLI is, so the probes run with the role of the CLI.
    let report = capability::diagnose(WorkerRole::Cli);
    let capabilities: Vec<CapabilityRow> = report
        .capabilities
        .iter()
        .map(|entry| CapabilityRow {
            id: entry.id.as_str().to_owned(),
            title: entry.title.clone(),
            need: match entry.requirement {
                Requirement::Required => Need::Required,
                Requirement::Optional => Need::Optional,
                Requirement::Informational => Need::Informational,
            },
            level: match &entry.state {
                CapabilityState::Available => CapabilityLevel::Available,
                CapabilityState::Denied => CapabilityLevel::Denied,
                CapabilityState::Unsupported => CapabilityLevel::Unsupported,
                CapabilityState::Unknown | CapabilityState::Unrecognized(_) => {
                    CapabilityLevel::Unknown
                }
            },
            detail: entry.reason.clone().unwrap_or_else(|| entry.detail.clone()),
            enables: entry.enables.clone(),
            remediation: entry.remediation.clone(),
        })
        .collect();
    let mut snapshot = DiagnosticsSnapshot {
        captured_at: SystemTime::now(),
        subject: "This window, probed as a client process".to_owned(),
        verdict: match report.summary.verdict {
            capability::Verdict::Ready => Verdict::Ready,
            capability::Verdict::Unverified => Verdict::Unverified,
            capability::Verdict::Blocked => Verdict::Blocked,
        },
        capabilities,
        agent: Measured::Unavailable("No journal exists in the state directory.".to_owned()),
        start_failure: None,
        journal: JournalRow {
            path: state_directory.map(journal_path),
            present: false,
            size: Measured::Unavailable("no journal exists".to_owned()),
            limit: Measured::Unavailable("no journal exists".to_owned()),
        },
        client_version: env!("CARGO_PKG_VERSION"),
        problems: Vec::new(),
    };
    if let Some(directory) = state_directory {
        match read_start_failure(directory) {
            Ok(record) => {
                snapshot.start_failure = record.map(|record| StartFailureRow {
                    code: record.reason.code().to_owned(),
                    message: record.message,
                    failed_at: record.failed_at.map(system_time),
                    agent_version: record.agent_version,
                });
            }
            Err(error) => snapshot.problems.push(format!("{error}.")),
        }
    } else {
        snapshot
            .problems
            .push("The state directory is not known.".to_owned());
    }
    match open_journal(state_directory) {
        Ok(None) => {}
        Err(problem) => {
            snapshot.journal.present = state_directory.is_some();
            snapshot.agent = Measured::Unavailable("The journal was not read.".to_owned());
            if state_directory.is_some() {
                snapshot.problems.push(problem);
            }
        }
        Ok(Some(journal)) => {
            snapshot.journal.present = true;
            match journal.size() {
                Ok(size) => {
                    snapshot.journal.size = Measured::Value(size.database.get());
                    snapshot.journal.limit = Measured::Value(size.limit.get());
                }
                Err(error) => {
                    snapshot.journal.size = Measured::Unavailable(error.to_string());
                    snapshot.journal.limit = Measured::Unavailable(error.to_string());
                }
            }
            snapshot.agent = match journal.agent_record::<AgentStatus>(AgentRecord::Status) {
                Ok(Some(stored)) => Measured::Value(agent_row(&stored.record)),
                Ok(None) => Measured::Unavailable(
                    "The journal has no status record of an agent.".to_owned(),
                ),
                Err(error) => {
                    Measured::Unavailable(format!("The status record cannot be read: {error}."))
                }
            };
        }
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_state_directory_is_not_an_absent_journal() {
        let automation: AutomationSnapshot = automation(None);
        // The pause was not read: it is not "not paused".
        assert_eq!(automation.pause, None);
        assert_eq!(automation.guards, Vec::new());
        assert!(!automation.journal_present);
        assert_eq!(automation.problems.len(), 1);
        let history: HistorySnapshot = history(None);
        assert_eq!(history.operations, Vec::new());
        assert_eq!(history.problems.len(), 1);
    }

    #[test]
    fn a_state_directory_with_no_journal_has_no_problem() {
        let directory = std::env::temp_dir().join("svalnir-gui-test-no-such-state-directory");
        let automation: AutomationSnapshot = automation(Some(&directory));
        assert_eq!(automation.pause, Some(PauseRow::NotPaused));
        assert!(!automation.journal_present);
        assert_eq!(automation.problems, Vec::<String>::new());
        assert_eq!(automation.guards.len(), PolicyId::ALL.len());
        let history: HistorySnapshot = history(Some(&directory));
        assert_eq!(history.problems, Vec::<String>::new());
        assert!(!directory.exists(), "a read makes no directory");
    }
}
