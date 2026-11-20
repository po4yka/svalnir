//! The live reads of the Memory, Applications, Automation, History, and
//! Diagnostics screens. Each function only reads: it makes no file, sends no
//! request, and does not read the coordinator lock.

use super::{
    model::{GuardRow, Measured, OperationPhase},
    records::{
        AgentStatusRow, ApplicationRow, AutomationSnapshot, BudgetRow, CapabilityLevel,
        CapabilityRow, ControllerRows, ControllerSnapshot, CooldownRow, CooldownState,
        CooldownSubject, DiagnosticsSnapshot, EffectRow, Foreground, FreshMeasurement,
        GenerationRow, GrantRow, GroupKind, Growth, GuardDetail, HISTORY_ROWS_MAX, HistorySnapshot,
        IncidentRow, IncidentUsage, JournalRow, JournalUsageRow, MemorySnapshot, Need,
        OperationDetail, PauseKind, PauseRow, ProcessRow, ProcessesSnapshot, Protection,
        ProtectionReason, RevisionRow, StartFailureRow, StatusAge, StepDetail, TargetDetail,
        ThresholdQuantity, ThresholdRow, TriggerRow, UnknownCause, UsageRow, Verdict,
        rank_applications, rank_processes, refine_phase,
    },
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, PoisonError},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use svalnir_agent::{
    capability::{self, Requirement, WorkerRole},
    journal::{AgentRecord, OperationJournal},
    observe::{
        self, AgentRecordsReading, ClientClock, ControllerReading, CooldownReading, Freshness,
        GenerationReading, Host, IncidentReading, JournalReading, JournalUsage, PauseReading,
        PauseUnknown, RecordReading, StatusReading,
    },
    platform::{
        memory::collect_memory_snapshot,
        process::{
            CollectionContext as ProcessContext, DarwinProcessSource, DerivedMetrics,
            ForegroundState, ProcessCollector, ProcessRecord, ProcessSnapshot,
            control_plane_of_this_process, derive_between,
        },
    },
    runtime::{AgentStatus, RunState, journal_path, start_failure::read_start_failure},
};
use svalnir_core::{
    action::{Operation, ResourceEffect},
    grant::{AuthorityState, GenerationBasis, PauseBasis, PauseStatus, Threshold, ThresholdValue},
    observation::{Observation, Reading},
    policy::{
        CooldownCause, CooldownStatus, HardProtectionEntry, HardProtectionExplanation, PolicyId,
        ProtectionContext, ProtectionUnknownCause, TriggerState, explain_hard_protection,
    },
    process::{ProcessIdentity, VerifiedMembership},
    quantity::{Bytes, Nanoseconds},
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

/// The row of a hard protection with the entry or the cause that decided it.
fn protection_row(identities: &[ProcessIdentity], context: &ProtectionContext<'_>) -> Protection {
    match explain_hard_protection(identities, context) {
        HardProtectionExplanation::NotProtected => Protection::NotProtected,
        HardProtectionExplanation::Protected { entry, .. } => Protection::Protected {
            reason: match entry {
                HardProtectionEntry::DifferentOwner => ProtectionReason::DifferentOwner,
                HardProtectionEntry::RootOwner => ProtectionReason::RootOwner,
                HardProtectionEntry::Launchd => ProtectionReason::Launchd,
                HardProtectionEntry::SessionApplication => ProtectionReason::SessionApplication,
                HardProtectionEntry::ControlPlaneBundle => ProtectionReason::ControlPlaneBundle,
                HardProtectionEntry::ControlPlaneProcess => ProtectionReason::ControlPlaneProcess,
                HardProtectionEntry::SystemLocation => ProtectionReason::SystemLocation,
                HardProtectionEntry::ControlPlaneExecutable => {
                    ProtectionReason::ControlPlaneExecutable
                }
            },
        },
        HardProtectionExplanation::Unknown { cause, .. } => Protection::Unknown {
            cause: match cause {
                ProtectionUnknownCause::NoMember => UnknownCause::NoMember,
                ProtectionUnknownCause::NoExecutableEvidence => UnknownCause::NoExecutableEvidence,
                ProtectionUnknownCause::PathNotClassified => UnknownCause::PathNotClassified,
                ProtectionUnknownCause::ControlPlaneNotKnown => UnknownCause::ControlPlaneNotKnown,
            },
        },
    }
}

/// The footprint change of `record` between the previous snapshot of this
/// window and the current one.
fn record_growth(record: &ProcessRecord, derived: Option<&DerivedMetrics>) -> Measured<Growth> {
    let Some(derived) = derived else {
        return Measured::Unavailable(
            "the first reading of this window has no earlier sample".to_owned(),
        );
    };
    match derived.growth.get(&record.identity.generation_id) {
        Some(Ok(growth)) => Measured::Value(Growth {
            delta: growth.delta.get(),
            elapsed: Duration::from_nanos(growth.elapsed.get()),
        }),
        Some(Err(reason)) => Measured::Unavailable(reason.to_string()),
        None => Measured::Unavailable("the process is new since the previous reading".to_owned()),
    }
}

/// The sum of the footprint changes of the members, and the number of
/// members with no change value. The elapsed time is the longest of the
/// members.
fn group_growth(
    members: &[&ProcessRecord],
    derived: Option<&DerivedMetrics>,
) -> (Measured<Growth>, usize) {
    let mut sum: i128 = 0;
    let mut elapsed: Duration = Duration::ZERO;
    let mut measured: usize = 0;
    let mut first_reason: Option<String> = None;
    for member in members {
        match record_growth(member, derived) {
            Measured::Value(growth) => {
                sum = sum.saturating_add(growth.delta);
                elapsed = elapsed.max(growth.elapsed);
                measured += 1;
            }
            Measured::Unavailable(reason) => {
                first_reason.get_or_insert(reason);
            }
        }
    }
    let growth: Measured<Growth> = if measured == 0 {
        Measured::Unavailable(first_reason.unwrap_or_else(|| "the group has no member".to_owned()))
    } else {
        Measured::Value(Growth {
            delta: sum,
            elapsed,
        })
    };
    (growth, members.len() - measured)
}

fn group_row(
    group: &Group<'_>,
    context: &ProtectionContext<'_>,
    derived: Option<&DerivedMetrics>,
) -> ApplicationRow {
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
    let (growth, growth_missing) = group_growth(&group.members, derived);
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
        protection: protection_row(&identities, context),
        growth,
        growth_missing,
    }
}

/// Makes the rows of a process snapshot. Only a verified membership makes a
/// process a member of a group. `previous` is the earlier snapshot of this
/// window, for the footprint growth.
fn process_rows(
    snapshot: &ProcessSnapshot,
    previous: Option<&ProcessSnapshot>,
) -> ProcessesSnapshot {
    let derived: Option<DerivedMetrics> =
        previous.map(|previous| derive_between(previous, snapshot));
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
            growth: record_growth(record, derived.as_ref()),
        });
    }
    let control_plane = control_plane_of_this_process(snapshot);
    let context = ProtectionContext {
        principal: observe::current_uid(),
        control_plane: control_plane.as_deref(),
    };
    let applications: Vec<ApplicationRow> = groups
        .iter()
        .map(|group| group_row(group, &context, derived.as_ref()))
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

/// Reads the processes of the current user. `previous` holds the snapshot
/// of the previous read of this window: the growth is the change since
/// that read, and the new snapshot replaces it. Only one snapshot is kept.
pub(super) fn processes(
    host: &Host,
    previous: &Mutex<Option<ProcessSnapshot>>,
) -> Result<ProcessesSnapshot, String> {
    let snapshot: ProcessSnapshot = collect_processes(host)?;
    let mut kept = previous.lock().unwrap_or_else(PoisonError::into_inner);
    let rows: ProcessesSnapshot = process_rows(&snapshot, kept.as_ref());
    *kept = Some(snapshot);
    Ok(rows)
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
                thresholds: thresholds.iter().map(threshold_row).collect(),
            }
        })
        .collect()
}

/// The row of a threshold with its typed value.
fn threshold_row(threshold: &Threshold) -> ThresholdRow {
    ThresholdRow {
        key: threshold.key.clone(),
        value: match threshold.typed_value() {
            Some(ThresholdValue::Bytes(bytes)) => ThresholdQuantity::Bytes(bytes.get()),
            Some(ThresholdValue::Nanoseconds(time)) => ThresholdQuantity::Nanoseconds(time.get()),
            Some(ThresholdValue::Count(count)) => ThresholdQuantity::Count(count),
            None => ThresholdQuantity::NoUnit(threshold.value),
        },
    }
}

fn duration(value: Nanoseconds) -> Duration {
    Duration::from_nanos(value.get())
}

/// The pause row of `reading`, with the start time of the record.
fn pause_row(reading: &PauseReading, since: Option<WallTime>) -> PauseRow {
    let since: SystemTime = since.map_or(UNIX_EPOCH, system_time);
    match reading.status {
        PauseStatus::NotPaused => PauseRow::NotPaused,
        PauseStatus::Paused {
            remaining,
            until,
            basis,
        } => PauseRow::Paused {
            since,
            remaining: remaining.map(duration),
            until: until.map(system_time),
            kind: match basis {
                PauseBasis::Indefinite => PauseKind::Indefinite,
                PauseBasis::Monotonic => PauseKind::Timed,
                PauseBasis::Retained => PauseKind::Retained,
            },
        },
        PauseStatus::Expired { .. } => PauseRow::Expired { since },
    }
}

/// Whether automatic work waits for a fresh measurement. Only a current
/// status of the agent shows that it waits.
fn fresh_measurement(reading: &PauseReading) -> FreshMeasurement {
    if !reading.unknown.contains(&PauseUnknown::FreshMeasurement) {
        return FreshMeasurement::NotNeeded;
    }
    match &reading.agent_step {
        Some(step)
            if step.awaiting_fresh_measurement
                && matches!(step.freshness, Freshness::Current { .. }) =>
        {
            FreshMeasurement::Awaiting
        }
        _ => FreshMeasurement::NotKnown,
    }
}

/// Reads the authority record. `clock` is the clock of this window, read
/// as the agent reads it; the pause is decided on it.
pub(super) fn automation(
    state_directory: Option<&Path>,
    clock: Result<ClientClock, String>,
) -> AutomationSnapshot {
    let captured_at: SystemTime = SystemTime::now();
    let mut snapshot = AutomationSnapshot {
        captured_at,
        journal_present: false,
        revision: None,
        guards: Vec::new(),
        pause: None,
        measurement: FreshMeasurement::NotNeeded,
        problems: Vec::new(),
    };
    let uid = observe::current_uid();
    // The guards need the wall clock only; the pause needs the clocks of
    // the agent.
    let clock: Option<ClientClock> = match clock {
        Ok(clock) => Some(clock),
        Err(reason) => {
            snapshot.problems.push(format!(
                "The clocks of this window have no usable value ({reason}), so the pause is not shown."
            ));
            None
        }
    };
    let now: WallTime = match (&clock, WallTime::try_from(captured_at)) {
        (Some(clock), _) => clock.wall,
        (None, Ok(now)) => now,
        (None, Err(_)) => {
            snapshot.problems.push(
                "The system clock has no usable value, so the guards are not shown.".to_owned(),
            );
            return snapshot;
        }
    };
    let journal = match open_journal(state_directory) {
        Ok(Some(journal)) => journal,
        Ok(None) => {
            snapshot.guards = guard_details(&AuthorityState::new(uid), now, &[]);
            if clock.is_some() {
                snapshot.pause = Some(PauseRow::NotPaused);
            }
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
            if let Some(clock) = &clock {
                let status: RecordReading<StatusReading> = observe::read_status(&journal, now);
                let reading: PauseReading = observe::pause_reading(state, status.recorded(), clock);
                snapshot.pause = Some(pause_row(
                    &reading,
                    state.pause.as_ref().map(|pause| pause.started_wall),
                ));
                snapshot.measurement = fresh_measurement(&reading);
            }
        }
        Err(error) => snapshot
            .problems
            .push(format!("The authority record cannot be read: {error}.")),
    }
    snapshot
}

fn status_age(status: &RecordReading<StatusReading>) -> StatusAge {
    match status.recorded().map(|reading| reading.freshness) {
        Some(Freshness::Current { .. }) => StatusAge::Current,
        Some(Freshness::Stale { age }) => StatusAge::Stale { age: duration(age) },
        Some(Freshness::Stopped) => StatusAge::Stopped,
        Some(Freshness::Unknown) | None => StatusAge::Unknown,
    }
}

fn trigger_row(trigger: TriggerState) -> TriggerRow {
    match trigger {
        TriggerState::Normal => TriggerRow::Normal,
        TriggerState::Advisory => TriggerRow::Advisory,
        TriggerState::Qualifying => TriggerRow::Qualifying,
        TriggerState::Ready => TriggerRow::Ready,
        TriggerState::Acting => TriggerRow::Acting,
        TriggerState::Recovering => TriggerRow::Recovering,
        TriggerState::Held => TriggerRow::Held,
        TriggerState::Cooldown => TriggerRow::Cooldown,
        TriggerState::Exhausted => TriggerRow::Exhausted,
        TriggerState::Blocked => TriggerRow::Blocked,
        _ => TriggerRow::Other,
    }
}

const fn cause_label(cause: CooldownCause) -> &'static str {
    match cause {
        CooldownCause::PassPacing => "Pass pacing",
        CooldownCause::NoEffectBackoff => "Back-off after no effect",
        CooldownCause::ApplicationRelaunch => "Relaunch cooldown",
    }
}

fn cooldown_row(reading: &CooldownReading) -> CooldownRow {
    CooldownRow {
        subject: match &reading.subject {
            observe::CooldownSubject::Application { application } => CooldownSubject::Relaunch {
                application: application.clone(),
            },
            observe::CooldownSubject::DiskIncident { incident_id } => CooldownSubject::DiskPass {
                incident: incident_id.as_ref().map(ToString::to_string),
            },
            observe::CooldownSubject::ObserveAfterAction { incident_id } => {
                CooldownSubject::ObserveAfterAction {
                    incident: incident_id.to_string(),
                }
            }
            observe::CooldownSubject::MemoryBackoff { incident_id } => {
                CooldownSubject::MemoryBackoff {
                    incident: incident_id.to_string(),
                }
            }
        },
        cause: cause_label(reading.cause),
        state: match reading.status {
            CooldownStatus::Active { remaining } => CooldownState::Active {
                remaining: duration(remaining),
            },
            CooldownStatus::Elapsed => CooldownState::Elapsed,
            CooldownStatus::Unknown => CooldownState::EarlierBoot,
        },
    }
}

fn usage_row(usage: &svalnir_core::grant::IncidentUsage) -> UsageRow {
    match usage {
        svalnir_core::grant::IncidentUsage::Disk {
            usage,
            passes_started,
        } => UsageRow::Disk {
            consumed_bytes: usage.consumed_bytes.get(),
            reserved_bytes: usage.reserved_bytes.get(),
            consumed_items: usage.consumed_items.get(),
            reserved_items: usage.reserved_items.get(),
            passes: *passes_started,
        },
        svalnir_core::grant::IncidentUsage::Memory {
            consumed_slots,
            reserved_slots,
        } => UsageRow::Memory {
            consumed_slots: *consumed_slots,
            reserved_slots: *reserved_slots,
        },
    }
}

fn generation_row(reading: &GenerationReading) -> GenerationRow {
    GenerationRow {
        generation: reading.generation.get(),
        rearmed: reading.basis == GenerationBasis::Rearmed,
        started_at: system_time(reading.started_at),
        final_usage: reading.final_usage.as_ref().map(usage_row),
        journal: match &reading.journal {
            JournalUsage::Recorded(usage) => JournalUsageRow::Recorded {
                slots: usage.slots,
                work_bytes: usage.work.work_bytes.get(),
                items: usage.work.items.get(),
            },
            JournalUsage::NoConsumedDispatch => JournalUsageRow::NoConsumedDispatch,
            JournalUsage::Unreadable { reason } => JournalUsageRow::Unreadable(reason.clone()),
        },
    }
}

fn incident_usage(reading: &IncidentReading) -> IncidentUsage {
    IncidentUsage {
        id: reading.incident_id.to_string(),
        policy: reading.guard.policy(),
        generation: reading.generation.get(),
        established: reading.established,
        unknown_outcome: reading.unknown_outcome,
        current: reading.current_usage.as_ref().map(usage_row),
        generations: reading.generations.iter().map(generation_row).collect(),
    }
}

fn controller_rows(reading: &ControllerReading) -> ControllerRows {
    ControllerRows {
        written_at: reading.written_at.map(system_time),
        budgets: reading
            .budgets
            .iter()
            .map(|budget| BudgetRow {
                id: budget.budget_id.clone(),
                latched: budget.latched,
                trigger: budget.trigger.map(trigger_row),
            })
            .collect(),
        cooldowns: reading.cooldowns.iter().map(cooldown_row).collect(),
        incidents: reading.incidents.iter().map(incident_usage).collect(),
        truncated: reading.truncated,
    }
}

/// The controller snapshot of the agent records of one journal.
fn controller_snapshot(
    captured_at: SystemTime,
    records: &AgentRecordsReading,
) -> ControllerSnapshot {
    ControllerSnapshot {
        captured_at,
        status_age: status_age(&records.status),
        rows: match &records.controller {
            RecordReading::Recorded(reading) => Measured::Value(controller_rows(reading)),
            RecordReading::Absent => Measured::Unavailable(
                "The journal has no controller record: no agent recorded its state.".to_owned(),
            ),
            RecordReading::Unreadable { reason } => {
                Measured::Unavailable(format!("The controller record cannot be read: {reason}."))
            }
        },
    }
}

/// Reads the controller record and the status record of the agent at the
/// clock of this window.
pub(super) fn controller(
    state_directory: Option<&Path>,
    clock: Result<ClientClock, String>,
) -> ControllerSnapshot {
    let captured_at: SystemTime = SystemTime::now();
    let unavailable = |reason: String| ControllerSnapshot {
        captured_at,
        status_age: StatusAge::Unknown,
        rows: Measured::Unavailable(reason),
    };
    let Some(directory) = state_directory else {
        return unavailable(
            "The state directory is not known, so the journal was not read.".to_owned(),
        );
    };
    let clock: ClientClock = match clock {
        Ok(clock) => clock,
        Err(reason) => {
            return unavailable(format!(
                "The clocks of this window have no usable value: {reason}."
            ));
        }
    };
    match observe::read_agent_records_at(&journal_path(directory), observe::current_uid(), &clock) {
        JournalReading::Absent => {
            unavailable("No journal exists in the state directory.".to_owned())
        }
        JournalReading::Unreadable { reason } => {
            unavailable(format!("The journal cannot be read: {reason}."))
        }
        JournalReading::Read(records) => controller_snapshot(captured_at, &records),
    }
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
    let step_details: Vec<StepDetail> = operation
        .steps()
        .iter()
        .map(|step| StepDetail {
            step_id: step.step_id().to_string(),
            action_class: step.action_class().as_str().to_owned(),
            target_id: step.target_id().to_string(),
            state: step.progress().state().as_str().to_owned(),
            dispatch: step.progress().dispatch().as_str().to_owned(),
        })
        .collect();
    let targets: Vec<TargetDetail> = operation
        .target_results()
        .iter()
        .map(|result| TargetDetail {
            target_id: result.target_id.to_string(),
            member: result.member.as_ref().map(ToString::to_string),
            effect: result.effect.as_str().to_owned(),
            dispatch: result.dispatch.as_str().to_owned(),
            stop_reason: result.stop_reason.as_str().to_owned(),
            attribution: result.attribution.as_str().to_owned(),
            error: result
                .failure
                .as_ref()
                .map(|failure| format!("{} at {}", failure.code.as_str(), failure.stage.as_str())),
        })
        .collect();
    OperationDetail {
        plan_id: operation.plan_id().to_string(),
        step_details,
        targets,
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
        notifications: status
            .capabilities
            .as_ref()
            .and_then(|summary| summary.notifications.as_ref())
            .map(|notifications| notifications.detail.clone()),
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
    // The probes run with the role of a window, so that the scope note and
    // the Full Disk Access remediation name the application and not the
    // terminal. With a known state directory, the probes examine that
    // directory and not the default one.
    let report = match state_directory {
        Some(directory) => capability::diagnose_in(WorkerRole::Window, directory),
        None => capability::diagnose(WorkerRole::Window),
    };
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
    use crate::test_support::{Child, stop_plan};
    use svalnir_agent::{
        client,
        controller::{
            CONTROLLER_STATUS_VERSION, ControllerState, ControllerStatus, Guard, GuardPhase,
            GuardStatus, IncidentStatus, MemoryIncidentRecord, Summary,
        },
        journal::{CoordinatorLock, CoordinatorRole, JournalOptions},
        runtime::{AGENT_STATUS_VERSION, PolicySource, SelfLimits},
    };
    use svalnir_core::{
        action::{ClientRole, Durability, PlanApproval},
        authority::Generation,
        config::parse_and_validate,
        digest::ContentDigest,
        grant::{
            Acceptance, ActivationRequest, BudgetGenerationRecord, EnableRequest, IncidentBudget,
            InstanceInhibition, Pause, PauseDeadline, Persistence, activate, enable,
        },
        id::{
            ActionGrantId, BootId, ClockDomainId, ExecutorEpochId, IncidentId, OperationId,
            PolicyRevisionId,
        },
        policy::{
            ApplicationCooldown, BudgetState, ContinuityGeneration, Cooldown, EvaluationClock,
            MemoryIncident, QualificationWindow,
        },
        rule::{Rule, RuleRegistry},
        time::MonotonicNanos,
    };

    const SECOND: u64 = 1_000_000_000;
    const DOMAIN: &str = "macos.clock_monotonic_raw";
    const BOOT: &str = "boot-test";

    /// The configuration of the test: the memory guard is requested with
    /// force quit, and the disk guard is not requested.
    const CONFIG: &str = r#"
schema_version = 1

[agent]
profile = "balanced"

[memory_guard]
enabled = true
global_trigger = "critical"
sustain_for = "15s"
grace_period = "10s"
recovery_stable_for = "60s"
max_applications_per_incident = 3
protect_foreground = true
allow_force_quit = true
eligible_groups = ["background-user-applications", "managed-jobs"]
"#;

    fn wall(seconds: i64) -> WallTime {
        WallTime::from_unix(1_800_000_000 + seconds, 0).unwrap_or_else(|error| panic!("{error}"))
    }

    /// The clock of the window: `monotonic` seconds in the boot of the
    /// records, at the wall-clock time `wall_seconds`.
    fn clock(monotonic: u64, wall_seconds: i64) -> ClientClock {
        ClientClock {
            clock: EvaluationClock {
                now: MonotonicNanos::new(monotonic * SECOND),
                clock_domain: ClockDomainId::new(DOMAIN).unwrap_or_else(|error| panic!("{error}")),
                boot_id: BootId::new(BOOT).unwrap_or_else(|error| panic!("{error}")),
                continuity: ContinuityGeneration::new(0),
                last_discontinuity: None,
            },
            wall: wall(wall_seconds),
        }
    }

    fn cooldown(boot: &str, until_seconds: u64) -> Cooldown {
        Cooldown {
            cause: CooldownCause::ApplicationRelaunch,
            until: MonotonicNanos::new(until_seconds * SECOND),
            clock_domain: ClockDomainId::new(DOMAIN).unwrap_or_else(|error| panic!("{error}")),
            boot_id: BootId::new(boot).unwrap_or_else(|error| panic!("{error}")),
        }
    }

    #[derive(Debug)]
    struct NoRules;

    impl RuleRegistry for NoRules {
        fn rules(&self) -> Vec<&Rule> {
            Vec::new()
        }
    }

    /// The authority record: the test configuration in effect as `rev-1`,
    /// the memory guard enabled with force quit accepted, and a pause that
    /// ends at 400 s on the monotonic clock of the boot of the test.
    fn authority() -> AuthorityState {
        let uid = observe::current_uid();
        let config = parse_and_validate(CONFIG)
            .config()
            .cloned()
            .unwrap_or_else(|| panic!("the test configuration is not valid"));
        let none = InstanceInhibition::default();
        let request = ActivationRequest {
            principal: uid,
            config: &config,
            content: ContentDigest::of_bytes(CONFIG.as_bytes()),
            expected_revision: None,
            revision_id: PolicyRevisionId::new("rev-1").unwrap_or_else(|error| panic!("{error}")),
            now: wall(0),
        };
        let state: AuthorityState = activate(&AuthorityState::new(uid), &request, &NoRules)
            .unwrap_or_else(|error| panic!("{error}"))
            .acknowledge(&none, Persistence::Durable)
            .state;
        let request = EnableRequest {
            principal: uid,
            policy: PolicyId::MemoryGuard,
            accepted: Acceptance::classes_of(&[Acceptance::ForceQuit]),
            reviewed_revision: Some(
                PolicyRevisionId::new("rev-1").unwrap_or_else(|error| panic!("{error}")),
            ),
            grant_id: ActionGrantId::new("grant-memory").unwrap_or_else(|error| panic!("{error}")),
            now: wall(0),
        };
        let mut state: AuthorityState = enable(&state, &none, &request)
            .unwrap_or_else(|error| panic!("{error}"))
            .acknowledge(&none, Persistence::Durable)
            .state;
        state.pause = Some(Pause {
            started_wall: wall(10),
            deadline: Some(PauseDeadline {
                monotonic: MonotonicNanos::new(400 * SECOND),
                clock_domain: ClockDomainId::new(DOMAIN).unwrap_or_else(|error| panic!("{error}")),
                boot_id: BootId::new(BOOT).unwrap_or_else(|error| panic!("{error}")),
                wall: wall(400),
            }),
        });
        state
    }

    fn incident_id() -> IncidentId {
        IncidentId::new("incident-m").unwrap_or_else(|error| panic!("{error}"))
    }

    /// The status record of a running agent, written at `written_at`, with
    /// the open memory incident and the trigger of one budget.
    fn status(written_at: i64) -> AgentStatus {
        AgentStatus {
            schema_version: AGENT_STATUS_VERSION,
            executor_epoch: ExecutorEpochId::new("epoch-test")
                .unwrap_or_else(|error| panic!("{error}")),
            process_id: 4242,
            started_at: wall(0),
            written_at: wall(written_at),
            state: RunState::Running,
            controller: Some(ControllerStatus {
                schema_version: CONTROLLER_STATUS_VERSION,
                evaluated_at: wall(written_at),
                summary: Summary::Normal,
                paused: true,
                paused_until: Some(wall(400)),
                observation_only: false,
                guards: vec![GuardStatus {
                    guard: Guard::Memory,
                    standing: "active".to_owned(),
                    phase: GuardPhase::Normal,
                    triggers: vec!["budget.build-worker:qualifying".to_owned()],
                    blocked: Vec::new(),
                    incidents: vec![IncidentStatus {
                        incident_id: incident_id(),
                        generation: 2,
                        established: true,
                        work_bytes: None,
                        passes_started: None,
                        slots_used: Some(2),
                        slots_remaining: Some(1),
                    }],
                }],
                outstanding_plan: None,
                outstanding_operation: None,
                degraded: Vec::new(),
                optional_work_reduced: false,
            }),
            policy: PolicySource {
                revision: None,
                problem: None,
            },
            capabilities: None,
            limits: SelfLimits {
                footprint_bytes: Some(80_000_000),
                budget_bytes: 64 * 1024 * 1024,
                over_budget: false,
                optional_work_reduced: false,
            },
            degraded: Vec::new(),
            unclean_stops: 0,
            restart_backoff: false,
        }
    }

    /// The controller record: one latched budget, three relaunch cooldowns
    /// (active, ended, and of an earlier boot), and the memory incident with
    /// two budget generations.
    fn controller_state() -> ControllerState {
        let mut state = ControllerState::default();
        state.policy.memory.budgets = vec![BudgetState {
            budget_id: "build-worker".to_owned(),
            stop_window: QualificationWindow::Idle,
            recovery_window: QualificationWindow::Idle,
            latched: true,
        }];
        state.policy.memory.cooldowns = vec![
            ApplicationCooldown {
                application: "com.example.Active".to_owned(),
                cooldown: cooldown(BOOT, 400),
            },
            ApplicationCooldown {
                application: "com.example.Ended".to_owned(),
                cooldown: cooldown(BOOT, 50),
            },
            ApplicationCooldown {
                application: "com.example.EarlierBoot".to_owned(),
                cooldown: cooldown("boot-earlier", 50),
            },
        ];
        state.policy.memory.incident = Some(MemoryIncident {
            consumed_slots: 1,
            reserved_slots: 1,
            outstanding_operation: false,
        });
        state.memory_incident = Some(MemoryIncidentRecord {
            incident_id: incident_id(),
            budget: IncidentBudget {
                incident_id: incident_id(),
                policy: PolicyId::MemoryGuard,
                generation: Generation::new(2),
                history: vec![
                    BudgetGenerationRecord {
                        generation: Generation::new(1),
                        basis: GenerationBasis::IncidentOpened,
                        authorized_by: None,
                        started_at: wall(0),
                        final_usage: Some(svalnir_core::grant::IncidentUsage::Memory {
                            consumed_slots: 3,
                            reserved_slots: 0,
                        }),
                    },
                    BudgetGenerationRecord {
                        generation: Generation::new(2),
                        basis: GenerationBasis::Rearmed,
                        authorized_by: Some(observe::current_uid()),
                        started_at: wall(50),
                        final_usage: None,
                    },
                ],
                volatile_exception_at_open: false,
            },
            opened_in: ExecutorEpochId::new("epoch-test").unwrap_or_else(|error| panic!("{error}")),
            established: false,
            unknown_outcome: true,
            observe_until: None,
            backoff: Some(Cooldown {
                cause: CooldownCause::NoEffectBackoff,
                ..cooldown(BOOT, 130)
            }),
            last_refusal: None,
            refusals: 0,
        });
        state
    }

    /// A state directory with a journal that has the authority, status,
    /// and controller records and one admitted stop operation of a child of
    /// the test.
    struct World {
        directory: tempfile::TempDir,
        operation: String,
        _child: Child,
    }

    fn world() -> World {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = journal_path(directory.path());
        let options = JournalOptions {
            full_fsync: false,
            ..JournalOptions::default()
        };
        let mut journal =
            OperationJournal::open(&path, &options).unwrap_or_else(|error| panic!("{error}"));
        journal
            .put_agent_record(AgentRecord::Authority, &authority(), None, wall(20))
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .put_agent_record(AgentRecord::Status, &status(90), None, wall(90))
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .put_agent_record(AgentRecord::Controller, &controller_state(), None, wall(60))
            .unwrap_or_else(|error| panic!("{error}"));
        // One admitted stop operation, with a resource observation of a kind
        // that this build does not know.
        let mut child = Child::start();
        let plan = stop_plan(&mut child, "plan-live-1", Duration::from_secs(1));
        let lock = CoordinatorLock::try_acquire(&path, CoordinatorRole::Agent)
            .unwrap_or_else(|error| panic!("{error}"));
        let epoch = ExecutorEpochId::new("epoch-test").unwrap_or_else(|error| panic!("{error}"));
        journal
            .begin_coordination(&lock, &epoch, wall(1))
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .complete_reconciliation(&epoch)
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .try_record_plan(&plan)
            .unwrap_or_else(|error| panic!("{error}"));
        let operation = Operation::admit(
            &plan,
            OperationId::new("op-live-1").unwrap_or_else(|error| panic!("{error}")),
            epoch,
            Durability::Durable,
            wall(30),
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        let approval = PlanApproval {
            plan_id: plan.plan_id.clone(),
            digest: plan.digest().clone(),
        };
        journal
            .try_admit(&approval, &client::principal(ClientRole::Gui), &operation)
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .record_resource_effects(operation.operation_id(), &[ResourceEffect::Unrecognized])
            .unwrap_or_else(|error| panic!("{error}"));
        drop(journal);
        drop(lock);
        World {
            operation: operation.operation_id().to_string(),
            directory,
            _child: child,
        }
    }

    #[test]
    fn the_authority_record_maps_to_the_automation_view() {
        let world: World = world();
        let directory: &Path = world.directory.path();

        // Automation: the revision, the guard with its grant and its open
        // incident, the typed thresholds, and the pause on the monotonic
        // clock: 300 s remain at 100 s, although the wall clock is later.
        let paused: AutomationSnapshot = automation(Some(directory), Ok(clock(100, 95)));
        assert_eq!(paused.problems, Vec::<String>::new());
        assert!(paused.journal_present);
        assert_eq!(
            paused
                .revision
                .as_ref()
                .map(|revision| revision.id.as_str()),
            Some("rev-1")
        );
        assert_eq!(
            paused.pause,
            Some(PauseRow::Paused {
                since: system_time(wall(10)),
                remaining: Some(Duration::from_secs(300)),
                until: Some(system_time(wall(400))),
                kind: PauseKind::Timed,
            })
        );
        assert_eq!(paused.measurement, FreshMeasurement::NotNeeded);
        let memory: &GuardDetail = paused
            .guards
            .iter()
            .find(|guard| guard.policy == PolicyId::MemoryGuard)
            .unwrap_or_else(|| panic!("no memory guard"));
        assert!(memory.enabled);
        assert_eq!(memory.requested, Some(true));
        assert_eq!(
            memory.incidents,
            vec![IncidentRow {
                id: "incident-m".to_owned(),
                generation: 2,
            }]
        );
        let grant: &GrantRow = memory.grant.as_ref().unwrap_or_else(|| panic!("no grant"));
        assert_eq!(grant.id, "grant-memory");
        assert!(grant.in_effect && !grant.revoked);
        assert!(
            grant
                .action_classes
                .iter()
                .any(|class| class == "ForceApplicationExit"),
            "{:?}",
            grant.action_classes
        );
        let sustain = memory
            .thresholds
            .iter()
            .find(|threshold| threshold.key == "memory_guard.sustain_for")
            .unwrap_or_else(|| panic!("no sustain threshold: {:?}", memory.thresholds));
        assert_eq!(sustain.value, ThresholdQuantity::Nanoseconds(15 * SECOND));
        let slots = memory
            .thresholds
            .iter()
            .find(|threshold| threshold.key == "memory_guard.max_applications_per_incident")
            .unwrap_or_else(|| panic!("no slot threshold"));
        assert_eq!(slots.value, ThresholdQuantity::Count(3));

        // At 500 s the pause is expired, and the window does not know
        // whether the agent has a newer measurement.
        let later: AutomationSnapshot = automation(Some(directory), Ok(clock(500, 95)));
        assert_eq!(
            later.pause,
            Some(PauseRow::Expired {
                since: system_time(wall(10)),
            })
        );
        assert_eq!(later.measurement, FreshMeasurement::NotKnown);
    }

    #[test]
    fn the_controller_record_maps_to_the_controller_view() {
        let world: World = world();
        let directory: &Path = world.directory.path();
        // Controller: budgets with the trigger of the status, cooldowns at
        // the clock of the window, and the usage of each generation.
        let records: ControllerSnapshot = controller(Some(directory), Ok(clock(100, 95)));
        assert_eq!(records.status_age, StatusAge::Current);
        let rows: &ControllerRows = records
            .rows
            .value()
            .unwrap_or_else(|| panic!("no rows: {:?}", records.rows));
        assert_eq!(rows.written_at, Some(system_time(wall(60))));
        assert_eq!(
            rows.budgets,
            vec![BudgetRow {
                id: "build-worker".to_owned(),
                latched: true,
                trigger: Some(TriggerRow::Qualifying),
            }]
        );
        let relaunch = |application: &str| CooldownSubject::Relaunch {
            application: application.to_owned(),
        };
        assert_eq!(
            rows.cooldowns,
            vec![
                CooldownRow {
                    subject: relaunch("com.example.Active"),
                    cause: "Relaunch cooldown",
                    state: CooldownState::Active {
                        remaining: Duration::from_secs(300),
                    },
                },
                CooldownRow {
                    subject: relaunch("com.example.Ended"),
                    cause: "Relaunch cooldown",
                    state: CooldownState::Elapsed,
                },
                CooldownRow {
                    subject: relaunch("com.example.EarlierBoot"),
                    cause: "Relaunch cooldown",
                    state: CooldownState::EarlierBoot,
                },
                CooldownRow {
                    subject: CooldownSubject::MemoryBackoff {
                        incident: "incident-m".to_owned(),
                    },
                    cause: "Back-off after no effect",
                    state: CooldownState::Active {
                        remaining: Duration::from_secs(30),
                    },
                },
            ]
        );
        assert_eq!(
            rows.incidents,
            vec![IncidentUsage {
                id: "incident-m".to_owned(),
                policy: PolicyId::MemoryGuard,
                generation: 2,
                established: false,
                unknown_outcome: true,
                current: Some(UsageRow::Memory {
                    consumed_slots: 1,
                    reserved_slots: 1,
                }),
                generations: vec![
                    GenerationRow {
                        generation: 1,
                        rearmed: false,
                        started_at: system_time(wall(0)),
                        final_usage: Some(UsageRow::Memory {
                            consumed_slots: 3,
                            reserved_slots: 0,
                        }),
                        journal: JournalUsageRow::NoConsumedDispatch,
                    },
                    GenerationRow {
                        generation: 2,
                        rearmed: true,
                        started_at: system_time(wall(50)),
                        final_usage: None,
                        journal: JournalUsageRow::NoConsumedDispatch,
                    },
                ],
            }]
        );
        assert!(!rows.truncated);
        // A status that is older than 90 s is stale; the rows stay.
        let stale: ControllerSnapshot = controller(Some(directory), Ok(clock(100, 290)));
        assert_eq!(
            stale.status_age,
            StatusAge::Stale {
                age: Duration::from_secs(200),
            }
        );
        assert!(stale.rows.value().is_some());
    }

    #[test]
    fn the_operations_and_the_status_map_to_the_history_and_diagnostics_views() {
        let world: World = world();
        let directory: &Path = world.directory.path();
        // History: the admitted operation with its step states and its
        // observation of an unknown kind.
        let operations: HistorySnapshot = history(Some(directory));
        assert_eq!(operations.problems, Vec::<String>::new());
        let operation: &OperationDetail = operations
            .operations
            .iter()
            .find(|operation| operation.operation_id == world.operation)
            .unwrap_or_else(|| panic!("no operation: {:?}", operations.operations));
        assert_eq!(operation.phase, OperationPhase::Pending);
        assert_eq!(operation.admitted_at, system_time(wall(30)));
        assert!(!operation.automatic);
        assert!(
            operation.steps.iter().all(|step| step == "Admitted"),
            "{:?}",
            operation.steps
        );
        assert_eq!(operation.resources, vec![EffectRow::Unrecognized]);
        assert_eq!(operation.effects, Vec::new());
        // The detail view has each step of the plan with its state and its
        // dispatch, and the plan of the operation.
        assert_ne!(operation.plan_id, String::new());
        assert_eq!(operation.step_details.len(), operation.steps.len());
        assert!(
            operation
                .step_details
                .iter()
                .all(|step| step.state == "Admitted" && step.dispatch == "not_submitted"),
            "{:?}",
            operation.step_details
        );
        assert_eq!(operation.targets, Vec::new());
        assert_eq!(operation.errors(), Vec::<&str>::new());

        // Diagnostics: the status record of the agent.
        let service: DiagnosticsSnapshot = diagnostics(Some(directory));
        let agent: &AgentStatusRow = service
            .agent
            .value()
            .unwrap_or_else(|| panic!("no status: {:?}", service.agent));
        assert_eq!(agent.process_id, 4242);
        assert_eq!(agent.run_state, "running");
        assert_eq!(agent.footprint, Measured::Value(80_000_000));
        assert!(service.journal.present);
        assert!(service.start_failure.is_none());
    }

    #[test]
    fn a_journal_with_no_controller_record_has_no_rows_and_no_zero() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        drop(
            OperationJournal::open(&journal_path(directory.path()), &JournalOptions::default())
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let snapshot: ControllerSnapshot = controller(Some(directory.path()), Ok(clock(100, 95)));
        assert_eq!(snapshot.status_age, StatusAge::Unknown);
        assert!(
            matches!(&snapshot.rows, Measured::Unavailable(reason) if reason.contains("no controller record")),
            "{:?}",
            snapshot.rows
        );
        // No journal is a different reason, and the read makes no file.
        let empty = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let snapshot: ControllerSnapshot = controller(Some(empty.path()), Ok(clock(100, 95)));
        assert!(
            matches!(&snapshot.rows, Measured::Unavailable(reason) if reason.contains("No journal")),
            "{:?}",
            snapshot.rows
        );
        assert!(!journal_path(empty.path()).exists());
        // A clock with no value shows no pause, not "not paused", and the
        // guards stay.
        let unread: AutomationSnapshot =
            automation(Some(directory.path()), Err("no clock".to_owned()));
        assert_eq!(unread.pause, None);
        assert_eq!(unread.problems.len(), 1);
        assert_eq!(unread.guards.len(), PolicyId::ALL.len());
    }

    #[test]
    fn each_trigger_state_of_this_build_has_its_own_row() {
        assert_eq!(trigger_row(TriggerState::Held), TriggerRow::Held);
        assert_eq!(trigger_row(TriggerState::Cooldown), TriggerRow::Cooldown);
        assert_eq!(trigger_row(TriggerState::Exhausted), TriggerRow::Exhausted);
        assert_eq!(trigger_row(TriggerState::Blocked), TriggerRow::Blocked);
        assert_eq!(TriggerRow::Blocked.label(), "Blocked");
    }

    #[test]
    fn an_unknown_state_directory_is_not_an_absent_journal() {
        let unread: AutomationSnapshot = automation(None, Ok(clock(1, 1)));
        // The pause was not read: it is not "not paused".
        assert_eq!(unread.pause, None);
        assert_eq!(unread.guards, Vec::new());
        assert!(!unread.journal_present);
        assert_eq!(unread.problems.len(), 1);
        let operations: HistorySnapshot = history(None);
        assert_eq!(operations.operations, Vec::new());
        assert_eq!(operations.problems.len(), 1);
        let records: ControllerSnapshot = controller(None, Ok(clock(1, 1)));
        assert!(records.rows.value().is_none());
    }

    #[test]
    fn a_state_directory_with_no_journal_has_no_problem() {
        let directory = std::env::temp_dir().join("svalnir-gui-test-no-such-state-directory");
        let empty: AutomationSnapshot = automation(Some(&directory), Ok(clock(1, 1)));
        assert_eq!(empty.pause, Some(PauseRow::NotPaused));
        assert!(!empty.journal_present);
        assert_eq!(empty.problems, Vec::<String>::new());
        assert_eq!(empty.guards.len(), PolicyId::ALL.len());
        let operations: HistorySnapshot = history(Some(&directory));
        assert_eq!(operations.problems, Vec::<String>::new());
        assert!(!directory.exists(), "a read makes no directory");
    }
}
