//! `policy list`, `policy show`, and `policy simulate`.
//!
//! Each command reads a configuration proposal. No command makes a policy
//! active, records a grant, or changes the host. `policy simulate` evaluates
//! the proposal against one new snapshot from the collectors of this process
//! with the pure functions of `svalnir_core::policy`.

use serde::Serialize;
use svalnir_agent::capability::{ProbeSubject, WorkerRole};
use svalnir_agent::platform::memory;
use svalnir_agent::platform::process::{
    ProcessSnapshot, application_candidates, control_plane_of_this_process, instance_count,
};
use svalnir_agent::platform::volume;
use svalnir_core::config::ValidatedConfig;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{CollectorEpochId, SampleId};
use svalnir_core::observation::{Coverage, Sample};
use svalnir_core::policy::{
    self, AssumedGrants, ContinuityGeneration, CorroboratingEvidence, DiskSnapshot,
    EvaluationClock, EvaluationContext, GrantBasis, InventoryEvidence, MemorySnapshot,
    PolicyDescription, PolicyId, PolicyListEntry, PolicyState, ProtectionContext, RevisionLabel,
    RevisionSource, SimulationInput, SimulationReport, VolumeEvidence,
};
use svalnir_core::process::Uid;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::config::{self as proposal, Proposal, SourceView, proposal_text};
use super::{CommandFailure, Invocation};
use crate::cli::{PolicyName, PolicyRef, PolicySimulateArgs, ProposalOption};
use crate::environment::Environment;
use crate::host::{Host, collector_unavailable};
use crate::output::{ErrorBody, ErrorFamily, ErrorStage, ExitStatus, Kind, NextAction};

/// The logical volume selector that this build resolves.
const STARTUP_DATA_SELECTOR: &str = "startup-data";

/// The statement of `policy list` and `policy show`.
const NOT_ACTIVE_NOTE: &str = "These policies are a proposal. No policy is active in this build, and this command recorded no grant.";

/// The statement of `policy simulate` about its inputs.
const SIMULATION_NOTE: &str = "This is a simulation of a proposal that is not active. The grants are the recorded state of this build: none. The snapshot has no cleanup candidate, because this build has no rule registry. The product protection of each application comes from the catalog of hard protections; this process and its ancestors are protected. One snapshot starts a qualification window and cannot complete it.";

const fn policy_id(name: PolicyName) -> PolicyId {
    match name {
        PolicyName::DiskGuard => PolicyId::DiskGuard,
        PolicyName::MemoryGuard => PolicyId::MemoryGuard,
    }
}

/// The result of `policy list`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ListView {
    source: SourceView,
    active: bool,
    policies: Vec<PolicyListEntry>,
    note: &'static str,
}

impl ListView {
    pub(crate) fn new(source: SourceView, config: &ValidatedConfig) -> Self {
        Self {
            source,
            active: false,
            policies: policy::list_policies(config),
            note: NOT_ACTIVE_NOTE,
        }
    }

    pub(crate) fn render(&self) -> String {
        proposal_text(
            "Standing policies (proposal, not active)",
            &self.source,
            self,
        )
    }
}

/// The result of `policy show`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ShowView {
    source: SourceView,
    active: bool,
    description: PolicyDescription,
    note: &'static str,
}

impl ShowView {
    pub(crate) fn new(source: SourceView, config: &ValidatedConfig, policy: PolicyId) -> Self {
        Self {
            source,
            active: false,
            description: policy::show_policy(config, policy),
            note: NOT_ACTIVE_NOTE,
        }
    }

    pub(crate) fn render(&self) -> String {
        proposal_text("Policy (proposal, not active)", &self.source, self)
    }
}

/// What the snapshot of a simulation has.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct InputSummary {
    /// The volume selectors that this build resolved to a volume.
    volumes_resolved: Vec<String>,
    /// The volume selectors that this build did not resolve, with the
    /// reason.
    volumes_unresolved: Vec<String>,
    /// Always 0: this build has no rule registry.
    cleanup_candidates: usize,
    /// The application and job instances of the process inventory that are
    /// candidates of the simulation.
    applications: usize,
    /// The instances for which no candidate was made, because an identity
    /// of the candidate is not valid. The inventory is then not complete.
    applications_not_evaluated: usize,
    /// The reason the snapshot has no process inventory.
    process_inventory_unavailable: Option<String>,
}

/// The result of `policy simulate`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SimulateView {
    source: SourceView,
    active: bool,
    simulation: SimulationReport,
    inputs: InputSummary,
    note: &'static str,
}

impl SimulateView {
    pub(crate) fn render(&self) -> String {
        proposal_text(
            "Simulation of a proposal against one snapshot (not active)",
            &self.source,
            self,
        )
    }
}

/// The snapshot and the time of one simulation.
#[derive(Debug, Clone)]
pub(crate) struct SimulationInputs {
    pub(crate) clock: EvaluationClock,
    pub(crate) snapshot_time: WallTime,
    pub(crate) principal: Uid,
    pub(crate) home: Option<LosslessPath>,
    pub(crate) disk: DiskSnapshot,
    pub(crate) memory: MemorySnapshot,
    pub(crate) summary: InputSummary,
}

fn input_error(error: &policy::PolicyInputError) -> ErrorBody {
    ErrorBody {
        code: "simulation_input_too_large",
        family: ErrorFamily::Native,
        stage: ErrorStage::Collection,
        message: format!("the snapshot is not usable for a simulation: {error}"),
        fields: Vec::new(),
        operation_id: None,
        plan_id: None,
        next_action: NextAction::RefreshObservation,
    }
}

/// Evaluates `policy` of `config` against `inputs`. The function is pure.
pub(crate) fn simulate_with(
    source: SourceView,
    config: &ValidatedConfig,
    policy: PolicyId,
    inputs: SimulationInputs,
) -> Result<SimulateView, ErrorBody> {
    let revision: RevisionLabel =
        RevisionLabel::new(RevisionSource::Proposed, source.revision_label())
            .map_err(|error| input_error(&error))?;
    let report: SimulationReport = policy::simulate(&SimulationInput {
        policy,
        revision: &revision,
        context: EvaluationContext {
            config,
            clock: &inputs.clock,
            // This build has no grant store, so the recorded state is that
            // no action class has a grant.
            grants: AssumedGrants::none(GrantBasis::Recorded),
            principal: inputs.principal,
            home_directory: inputs.home.as_ref(),
        },
        snapshot_time: inputs.snapshot_time,
        state: &PolicyState::default(),
        disk: &inputs.disk,
        memory: &inputs.memory,
    })
    .map_err(|error| input_error(&error))?;
    Ok(SimulateView {
        source,
        active: false,
        simulation: report,
        inputs: inputs.summary,
        note: SIMULATION_NOTE,
    })
}

/// The evidence that the process inventory is complete.
pub(crate) fn inventory_evidence(
    snapshot: &ProcessSnapshot,
    collector_epoch: &CollectorEpochId,
) -> Option<InventoryEvidence> {
    let omissions = snapshot.omissions;
    // A denied identity query is a process of a different user: the system
    // answers the query for each process of the current user. Such a process
    // is out of the scope of the inventory, as `other_user` is. A query that
    // failed for a different cause can be a process of the current user.
    let complete: bool = omissions.failed == 0
        && snapshot.launch_services_unavailable.is_none()
        && snapshot.responsible_process_unavailable.is_none();
    Some(InventoryEvidence {
        coverage: if complete {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        sample: Sample {
            sample_id: SampleId::new(format!("inv-{}", snapshot.started_monotonic_ns.get()))
                .ok()?,
            clock_domain: snapshot.clock_domain.clone(),
            boot_id: snapshot.boot_id.clone(),
            collector_epoch: collector_epoch.clone(),
            started_monotonic_ns: snapshot.started_monotonic_ns,
            finished_monotonic_ns: snapshot
                .finished_monotonic_ns
                .max(snapshot.started_monotonic_ns),
            captured_at: snapshot.captured_at,
        },
    })
}

/// Reads the process inventory for a memory-guard simulation.
#[cfg(target_os = "macos")]
fn collect_processes(host: &Host) -> Result<ProcessSnapshot, String> {
    host.process_collector()
        .map_err(|error| error.message)?
        .collect()
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "macos"))]
fn collect_processes(_host: &Host) -> Result<ProcessSnapshot, String> {
    Err("the process inventory has a collector for macOS only".to_owned())
}

/// Adds the application candidates and the inventory evidence of a process
/// snapshot to the inputs of a memory-guard simulation.
fn add_applications(
    processes: &ProcessSnapshot,
    principal: Uid,
    collector_epoch: &CollectorEpochId,
    memory_snapshot: &mut MemorySnapshot,
    summary: &mut InputSummary,
) {
    // This process and its ancestors are the control plane of the
    // simulation.
    let control_plane = control_plane_of_this_process(processes);
    memory_snapshot.applications = application_candidates(
        processes,
        &ProtectionContext {
            principal,
            control_plane: control_plane.as_deref(),
        },
    );
    memory_snapshot.inventory = inventory_evidence(processes, collector_epoch);
    memory_snapshot.application_list_may_be_stale = processes.application_list_may_be_stale;
    summary.applications = memory_snapshot.applications.len();
    summary.applications_not_evaluated =
        instance_count(processes).saturating_sub(memory_snapshot.applications.len());
    // An instance with no candidate is not absent.
    if summary.applications_not_evaluated > 0
        && let Some(inventory) = &mut memory_snapshot.inventory
    {
        inventory.coverage = Coverage::Partial;
    }
}

/// Reads one snapshot of the host for a simulation of `policy`.
fn collect_inputs(
    host: &Host,
    config: &ValidatedConfig,
    policy: PolicyId,
    environment: &Environment,
) -> Result<SimulationInputs, ErrorBody> {
    let context = host.context();
    let principal: Uid = ProbeSubject::current(WorkerRole::Cli).effective_uid;
    let mut disk = DiskSnapshot {
        rule_allowances: Vec::new(),
        volumes: Vec::new(),
        candidates: Vec::new(),
    };
    let mut memory_snapshot = MemorySnapshot::default();
    let mut summary = InputSummary::default();
    match policy {
        PolicyId::DiskGuard => {
            for selector in &config.disk_guard().volumes {
                if selector.as_str() != STARTUP_DATA_SELECTOR {
                    summary.volumes_unresolved.push(format!(
                        "{}: this build resolves only `{STARTUP_DATA_SELECTOR}`",
                        selector.as_str()
                    ));
                    continue;
                }
                match Host::startup_data_volume() {
                    Ok(mounted) => {
                        let capacity = volume::collect_capacity(context, &mounted.identity)?;
                        summary.volumes_resolved.push(selector.as_str().to_owned());
                        disk.volumes.push(VolumeEvidence {
                            selector: selector.clone(),
                            identity: mounted.identity,
                            available: capacity.available,
                        });
                    }
                    Err(error) => summary
                        .volumes_unresolved
                        .push(format!("{}: {error}", selector.as_str())),
                }
            }
        }
        PolicyId::MemoryGuard => {
            let host_memory = memory::collect_memory_snapshot(context)?;
            let vm = &host_memory.vm;
            memory_snapshot.corroborating = vec![
                CorroboratingEvidence::from_observation(&vm.free),
                CorroboratingEvidence::from_observation(&vm.active),
                CorroboratingEvidence::from_observation(&vm.inactive),
                CorroboratingEvidence::from_observation(&vm.wired),
                CorroboratingEvidence::from_observation(&vm.compressor_physical),
                CorroboratingEvidence::from_observation(&host_memory.swap.used),
            ];
            memory_snapshot.pressure = Some(host_memory.pressure);
            match collect_processes(host) {
                Ok(processes) => add_applications(
                    &processes,
                    principal,
                    &context.identity().collector_epoch,
                    &mut memory_snapshot,
                    &mut summary,
                ),
                Err(reason) => summary.process_inventory_unavailable = Some(reason),
            }
        }
        // `PolicyId` can get a policy that this build does not know. Such a
        // policy has no snapshot here.
        _ => {}
    }
    // The evaluation time is after each acquisition.
    let clock = context.clock();
    let now: MonotonicNanos = clock
        .monotonic_now()
        .map_err(|error| collector_unavailable(&error.to_string()))?;
    let snapshot_time: WallTime = clock
        .wall_now()
        .map_err(|error| collector_unavailable(&error.to_string()))?;
    let identity = context.identity();
    Ok(SimulationInputs {
        clock: EvaluationClock {
            now,
            clock_domain: identity.clock_domain.clone(),
            boot_id: identity.boot_id.clone(),
            // One invocation has one continuous clock reading and knows no
            // earlier sleep or wake.
            continuity: ContinuityGeneration::new(0),
            last_discontinuity: None,
        },
        snapshot_time,
        principal,
        home: environment
            .home
            .as_deref()
            .and_then(|home| LosslessPath::from_path(home).ok()),
        disk,
        memory: memory_snapshot,
        summary,
    })
}

/// Loads the proposal and its validated values.
fn load_validated(
    environment: &Environment,
    option: &ProposalOption,
) -> Result<(Proposal, ValidatedConfig), ErrorBody> {
    let loaded: Proposal = proposal::load(environment, option, true)?;
    let config: ValidatedConfig = proposal::validated(&loaded)?;
    Ok((loaded, config))
}

pub(crate) fn list(invocation: &mut Invocation<'_>) -> Result<ExitStatus, CommandFailure> {
    let (loaded, config) =
        load_validated(invocation.environment, &ProposalOption { config: None })?;
    let view = ListView::new(loaded.source, &config);
    invocation.emit(Kind::Report, &view, ListView::render)?;
    Ok(ExitStatus::Success)
}

pub(crate) fn show(
    arguments: &PolicyRef,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let (loaded, config) =
        load_validated(invocation.environment, &ProposalOption { config: None })?;
    let view = ShowView::new(loaded.source, &config, policy_id(arguments.policy));
    invocation.emit(Kind::Report, &view, ShowView::render)?;
    Ok(ExitStatus::Success)
}

pub(crate) fn simulate(
    arguments: &PolicySimulateArgs,
    invocation: &mut Invocation<'_>,
) -> Result<ExitStatus, CommandFailure> {
    let (loaded, config) = load_validated(invocation.environment, &arguments.proposal)?;
    let policy: PolicyId = policy_id(arguments.policy.policy);
    let host: Host = Host::open()?;
    let inputs: SimulationInputs = collect_inputs(&host, &config, policy, invocation.environment)?;
    let view: SimulateView = simulate_with(loaded.source, &config, policy, inputs)?;
    invocation.emit(Kind::Report, &view, SimulateView::render)?;
    // A simulation in which each candidate is skipped is a successful result.
    Ok(ExitStatus::Success)
}

#[cfg(test)]
mod tests {
    use svalnir_core::config::parse_and_validate;
    use svalnir_core::id::CollectorEpochId;
    use svalnir_core::observation::{Coverage, Reading, UnavailableReason};
    use svalnir_core::policy::{
        ContinuityGeneration, ControlPlaneProcess, DiskSnapshot, EvaluationClock, MemorySnapshot,
        PolicyId, ProtectionContext, VolumeEvidence,
    };
    use svalnir_core::process::Uid;
    use svalnir_core::quantity::Bytes;
    use svalnir_core::time::MonotonicNanos;

    use super::{
        InputSummary, ListView, ShowView, SimulationInputs, application_candidates,
        inventory_evidence, simulate_with,
    };
    use crate::commands::config::SourceView;
    use crate::test_support::{
        BOOT, CLOCK_DOMAIN, memory_snapshot, process_snapshot, volume_capacity, wall_time,
    };

    fn source() -> SourceView {
        SourceView {
            kind: "built_in_template",
            path: None,
            selected_by: "default",
        }
    }

    fn clock() -> EvaluationClock {
        EvaluationClock {
            now: MonotonicNanos::new(1_000_500_000_000),
            clock_domain: svalnir_core::id::ClockDomainId::new(CLOCK_DOMAIN).unwrap(),
            boot_id: svalnir_core::id::BootId::new(BOOT).unwrap(),
            continuity: ContinuityGeneration::new(0),
            last_discontinuity: None,
        }
    }

    fn inputs(disk: DiskSnapshot, memory: MemorySnapshot) -> SimulationInputs {
        SimulationInputs {
            clock: clock(),
            snapshot_time: wall_time(),
            principal: Uid::new(501),
            home: None,
            disk,
            memory,
            summary: InputSummary::default(),
        }
    }

    #[test]
    fn list_and_show_label_the_proposal_as_not_active() {
        let validation = parse_and_validate("schema_version = 1\n");
        let config = validation.config().unwrap();
        let list = ListView::new(source(), config);
        let text = list.render();
        assert!(
            text.starts_with("Standing policies (proposal, not active)\n"),
            "{text}"
        );
        assert!(text.contains("Source: built-in template"), "{text}");
        assert!(text.contains("policy: disk-guard"), "{text}");
        assert!(text.contains("policy: memory-guard"), "{text}");
        assert!(text.contains("No policy is active in this build"), "{text}");
        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(json["active"], false);
        assert_eq!(json["policies"][1]["policy"], "memory-guard");
        assert_eq!(json["policies"][1]["enabled"], false);

        let show = ShowView::new(source(), config, PolicyId::MemoryGuard);
        let json = serde_json::to_value(&show).unwrap();
        assert_eq!(json["active"], false);
        assert_eq!(json["description"]["policy"], "memory-guard");
        assert!(show.render().starts_with("Policy (proposal, not active)\n"));
    }

    #[test]
    fn a_disk_simulation_reports_the_volume_below_its_threshold() {
        let validation = parse_and_validate(
            "schema_version = 1\n[agent]\nprofile = \"balanced\"\n[disk_guard]\nenabled = true\nvolumes = [\"startup-data\"]\n",
        );
        let config = validation.config().unwrap();
        let (identity, mut capacity, _) = volume_capacity();
        // One GiB is below each threshold of the template.
        capacity.available.reading = Reading::Available(Bytes::new(1024 * 1024 * 1024));
        let disk = DiskSnapshot {
            rule_allowances: Vec::new(),
            volumes: vec![VolumeEvidence {
                selector: config.disk_guard().volumes[0].clone(),
                identity,
                available: capacity.available,
            }],
            candidates: Vec::new(),
        };
        let view = simulate_with(
            source(),
            config,
            PolicyId::DiskGuard,
            inputs(disk, MemorySnapshot::default()),
        )
        .unwrap();
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["active"], false);
        assert_eq!(json["simulation"]["policy"], "disk-guard");
        assert_eq!(json["simulation"]["enabled"], true);
        assert_eq!(json["simulation"]["revision"]["source"], "proposed");
        assert_eq!(json["simulation"]["assumed_grants"]["basis"], "recorded");
        assert_eq!(
            json["simulation"]["assumed_grants"]["evict_regenerable_data"],
            false
        );
        assert_eq!(json["simulation"]["triggers"].as_array().unwrap().len(), 1);
        assert_eq!(json["simulation"]["triggers"][0]["kind"], "disk_capacity");
        assert_eq!(json["simulation"]["candidates"], serde_json::json!([]));
        let text = view.render();
        assert!(
            text.starts_with("Simulation of a proposal against one snapshot (not active)\n"),
            "{text}"
        );
        assert!(
            text.contains("This is a simulation of a proposal that is not active."),
            "{text}"
        );
        assert!(text.contains("It reserves no budget"), "{text}");
    }

    #[test]
    fn an_unavailable_capacity_is_a_problem_and_not_a_zero() {
        let validation = parse_and_validate(
            "schema_version = 1\n[disk_guard]\nenabled = true\nvolumes = [\"startup-data\"]\n",
        );
        let config = validation.config().unwrap();
        let (identity, mut capacity, _) = volume_capacity();
        capacity.available.reading = Reading::Unavailable(UnavailableReason::TransientFailure);
        capacity.available.coverage = Coverage::Unknown;
        let disk = DiskSnapshot {
            rule_allowances: Vec::new(),
            volumes: vec![VolumeEvidence {
                selector: config.disk_guard().volumes[0].clone(),
                identity,
                available: capacity.available,
            }],
            candidates: Vec::new(),
        };
        let view = simulate_with(
            source(),
            config,
            PolicyId::DiskGuard,
            inputs(disk, MemorySnapshot::default()),
        )
        .unwrap();
        let text = serde_json::to_value(&view).unwrap().to_string();
        assert!(text.contains("\"problem\":\"unavailable\""), "{text}");
        assert!(text.contains("transient_failure"), "{text}");
    }

    #[test]
    fn a_memory_simulation_gets_the_protection_of_each_application_from_the_catalog() {
        let validation = parse_and_validate(
            "schema_version = 1\n[agent]\nprofile = \"balanced\"\n[memory_guard]\nenabled = true\neligible_groups = [\"background-user-applications\"]\n",
        );
        let config = validation.config().unwrap();
        let snapshot = process_snapshot();
        let host_memory = memory_snapshot();
        let epoch = CollectorEpochId::new("epoch_test").unwrap();
        let memory_with = |control_plane: Option<&[ControlPlaneProcess]>| MemorySnapshot {
            pressure: Some(host_memory.pressure.clone()),
            corroborating: vec![
                svalnir_core::policy::CorroboratingEvidence::from_observation(&host_memory.vm.free),
            ],
            applications: application_candidates(
                &snapshot,
                &ProtectionContext {
                    principal: Uid::new(501),
                    control_plane,
                },
            ),
            inventory: inventory_evidence(&snapshot, &epoch),
            application_list_may_be_stale: snapshot.application_list_may_be_stale,
        };
        let no_disk = || DiskSnapshot {
            rule_allowances: Vec::new(),
            volumes: Vec::new(),
            candidates: Vec::new(),
        };

        // With no known control plane, the protection is unknown and the
        // application is skipped.
        let unknown = simulate_with(
            source(),
            config,
            PolicyId::MemoryGuard,
            inputs(no_disk(), memory_with(None)),
        )
        .unwrap();
        let unknown = serde_json::to_value(&unknown).unwrap();
        let skipped = unknown["simulation"]["candidates"][0].to_string();
        assert!(skipped.contains("protection_unknown"), "{skipped}");

        let memory = memory_with(Some(&[]));
        assert_eq!(
            memory.inventory.as_ref().unwrap().coverage,
            Coverage::Complete
        );
        // An identity query that failed can hide a process of this user.
        let mut failed = snapshot.clone();
        failed.omissions.failed = 1;
        assert_eq!(
            inventory_evidence(&failed, &epoch).unwrap().coverage,
            Coverage::Partial
        );
        let view = simulate_with(
            source(),
            config,
            PolicyId::MemoryGuard,
            inputs(no_disk(), memory),
        )
        .unwrap();
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["simulation"]["triggers"][0]["kind"], "global_pressure");
        let candidates = json["simulation"]["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0]["kind"], "application");
        // The catalog gives a protection, so the application is evaluated.
        // It is the foreground application, which the default protects.
        let evaluated = candidates[0].to_string();
        assert!(!evaluated.contains("protection_unknown"), "{evaluated}");
        assert!(!evaluated.contains("product_protection"), "{evaluated}");
        assert_ne!(candidates[0]["decision"], "eligible");
        assert_eq!(
            json["simulation"]["first_actions"][0]["admissible_now"],
            false
        );
    }
}
