//! The authority records behind the authority source of the coordinator.
//!
//! The coordinator reads the authority at admission, before each intent,
//! and immediately before each call. The runtime owns the records and
//! replaces them after each controller step and after each read of the
//! authority record of the journal. One mutex guards them; each critical
//! section copies or compares a few values and makes no file, journal, or
//! executor call.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use svalnir_core::action::Plan;
use svalnir_core::authority::ActionGrant;
use svalnir_core::config::UserLayout;
use svalnir_core::grant::{
    ActionRequest, AuthorityState, Authorization, AuthorizationContext, ControlClock,
    IncidentBudget, InstanceInhibition, Refusal, authorize,
};
use svalnir_core::id::{IncidentId, PlanId};
use svalnir_core::plan::{CleanupMode, PlanMode};
use svalnir_core::policy::{
    ControlPlaneProcess, ProtectionContext, ProtectionFact, hard_protection,
};
use svalnir_core::process::{ProcessIdentity, Uid};
use svalnir_core::rule::{RuleMode, RuleRef, RuleRegistry};

use super::model::{TriggerKey, TriggerRecord};
use crate::coordinator::{AuthoritySource, RevisionSnapshot, TimeReading, TriggerStanding};
use crate::executor::fs::ApprovedRoots;
use crate::protection::ProtectedLocations;
use crate::rules::projects::UnitRecheck;
use crate::rules::{ProducerActivity, SharedEnvironment};

/// The largest number of automatic plans whose trigger the records keep.
/// The oldest plan is removed first; a plan with no entry has a trigger
/// that is not known, which permits no dispatch.
pub const MAX_PLAN_TRIGGERS: usize = 64;

/// The records that the authority source reads.
pub struct AuthorityRecords {
    /// The user of the agent.
    pub principal: Uid,
    /// The authority record of the journal. `None` when the journal has no
    /// record that this build can use: each automatic step is then
    /// refused, and so is each manual step, which needs a policy revision.
    pub state: Option<AuthorityState>,
    /// The inhibitions of this instance.
    pub inhibition: InstanceInhibition,
    /// The rule registry.
    pub registry: Box<dyn RuleRegistry + Send>,
    /// The budget record of each open incident.
    pub incidents: Vec<IncidentBudget>,
    /// The standing of each trigger at the latest controller step.
    pub triggers: Vec<TriggerRecord>,
    /// The trigger of each automatic plan, in the sequence of the plans.
    pub plans: Vec<(PlanId, TriggerKey)>,
    /// The processes of the control plane, for the hard-protection
    /// catalog.
    pub control_plane: Option<Vec<ControlPlaneProcess>>,
    /// The home directory of the user and the state directory of Svalnir,
    /// for the catalog of protected file locations. The default has no
    /// location, which gives each file target an unknown protection: the
    /// owner of the records sets the locations before a plan with a file
    /// target is applied.
    pub locations: ProtectedLocations,
    /// The approved roots of this process for an automatic operation. The
    /// owner of the records resolves them from the rule declarations and
    /// the configuration in effect before it applies an automatic plan.
    pub automatic_roots: ApprovedRoots,
    /// The environment of the fresh activity check before a step of an
    /// eviction: the process table and the clock. `None` gives an unknown
    /// activity, which permits no eviction step.
    pub environment: Option<SharedEnvironment>,
    /// The layouts of `[[cleanup.projects.layouts]]` of the configuration
    /// in effect, for the check of a unit of `project.dependency-directory`
    /// with the layout `user-configured` before its step. With none, such a
    /// unit has an unknown layout, which permits no step.
    pub project_layouts: Vec<UserLayout>,
}

impl fmt::Debug for AuthorityRecords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRecords")
            .field("principal", &self.principal)
            .field("has_state", &self.state.is_some())
            .field("incidents", &self.incidents.len())
            .field("plans", &self.plans.len())
            .finish_non_exhaustive()
    }
}

impl AuthorityRecords {
    /// Records with no authority, no incident, and no trigger.
    pub fn new(principal: Uid, registry: Box<dyn RuleRegistry + Send>) -> Self {
        Self {
            principal,
            state: None,
            inhibition: InstanceInhibition::default(),
            registry,
            incidents: Vec::new(),
            triggers: Vec::new(),
            plans: Vec::new(),
            control_plane: None,
            locations: ProtectedLocations::default(),
            automatic_roots: ApprovedRoots::default(),
            environment: None,
            project_layouts: Vec::new(),
        }
    }

    /// Records the trigger of an automatic plan before the plan is given
    /// to the coordinator.
    pub fn bind_plan(&mut self, plan_id: PlanId, trigger: TriggerKey) {
        self.plans.retain(|(known, _)| known != &plan_id);
        if self.plans.len() >= MAX_PLAN_TRIGGERS {
            self.plans.remove(0);
        }
        self.plans.push((plan_id, trigger));
    }
}

/// The shared authority records. Each copy reads the same records.
#[derive(Debug, Clone)]
pub struct SharedAuthority(Arc<Mutex<AuthorityRecords>>);

impl SharedAuthority {
    /// Makes the shared records.
    pub fn new(records: AuthorityRecords) -> Self {
        Self(Arc::new(Mutex::new(records)))
    }

    /// The records. A poisoned lock still has complete records, because
    /// each update is an assignment of a complete value.
    pub fn records(&self) -> MutexGuard<'_, AuthorityRecords> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AuthoritySource for SharedAuthority {
    fn authorize(
        &self,
        request: &ActionRequest<'_>,
        time: &TimeReading,
    ) -> Result<Authorization, Refusal> {
        let records = self.records();
        // With no record, the state of a user with no policy revision
        // refuses each step with a specific reason.
        let empty: AuthorityState = AuthorityState::new(records.principal);
        let context: AuthorizationContext<'_> = AuthorizationContext {
            state: records.state.as_ref().unwrap_or(&empty),
            inhibition: &records.inhibition,
            registry: records.registry.as_ref(),
            clock: ControlClock {
                clock: &time.clock,
                wall: time.wall,
            },
        };
        authorize(&context, request)
    }

    fn revisions(&self, mode: PlanMode, time: &TimeReading) -> RevisionSnapshot {
        let records = self.records();
        let Some(state) = &records.state else {
            return RevisionSnapshot::default();
        };
        // The rule revisions that can do the mode now. Only the eviction
        // mode and an owner operation, which uses the eviction mode of its
        // rule, bind a rule.
        let rules = if matches!(
            mode,
            PlanMode::Cleanup(CleanupMode::Evict) | PlanMode::Owner(_)
        ) {
            records
                .registry
                .rules()
                .into_iter()
                .filter(|rule| {
                    rule.layouts
                        .iter()
                        .any(|layout| layout.permits(&RuleMode::ManualEviction))
                })
                .map(|rule| rule.reference.clone())
                .collect()
        } else {
            Vec::new()
        };
        RevisionSnapshot {
            policy_revision: state
                .active
                .as_ref()
                .map(|active| active.revision.revision_id.clone()),
            action_grants: state
                .guards
                .iter()
                .filter_map(|guard| guard.grant.as_ref())
                .filter(|grant| grant.is_in_effect(time.wall))
                .map(ActionGrant::reference)
                .collect(),
            rules,
        }
    }

    fn incident(&self, incident_id: &IncidentId) -> Option<IncidentBudget> {
        self.records()
            .incidents
            .iter()
            .find(|budget| &budget.incident_id == incident_id)
            .cloned()
    }

    fn trigger(&self, plan: &Plan, _time: &TimeReading) -> TriggerStanding {
        let records = self.records();
        let Some((_, key)) = records
            .plans
            .iter()
            .find(|(plan_id, _)| plan_id == &plan.plan_id)
        else {
            return TriggerStanding::Unknown;
        };
        // The trigger class of a plan does not change: a plan of the
        // budget trigger is not supported by the global trigger.
        if key.class() != plan.trigger.class {
            return TriggerStanding::Unknown;
        }
        let standings: BTreeMap<&TriggerKey, &TriggerStanding> = records
            .triggers
            .iter()
            .map(|record| (&record.key, &record.standing))
            .collect();
        standings
            .get(key)
            .map_or(TriggerStanding::Unknown, |standing| (*standing).clone())
    }

    fn protection(&self, processes: &[ProcessIdentity]) -> ProtectionFact {
        let records = self.records();
        hard_protection(
            processes,
            &ProtectionContext {
                principal: records.principal,
                control_plane: records.control_plane.as_deref(),
            },
        )
    }

    fn protected_locations(&self) -> ProtectedLocations {
        self.records().locations.clone()
    }

    fn automatic_roots(&self) -> ApprovedRoots {
        self.records().automatic_roots.clone()
    }

    fn producer_activity(&self, rule: &RuleRef) -> ProducerActivity {
        // The reading of the process table is outside the critical
        // section.
        let (environment, principal) = {
            let records = self.records();
            (records.environment.clone(), records.principal)
        };
        environment.map_or(ProducerActivity::Unknown, |environment| {
            environment.producer_activity(&rule.id, principal)
        })
    }

    fn owner_operation(&self, rule: &RuleRef) -> Option<svalnir_core::rule::owner::OwnerOperation> {
        self.records().registry.owner_operation(rule).cloned()
    }

    fn unit_use(&self, path: &std::path::Path) -> crate::rules::in_use::UnitUse {
        // The reading of the process table is outside the critical
        // section.
        let (environment, principal) = {
            let records = self.records();
            (records.environment.clone(), records.principal)
        };
        environment.map_or(
            crate::rules::in_use::UnitUse::Unknown {
                reason: "no_process_evidence",
                processes: Vec::new(),
                omitted: 0,
            },
            |environment| environment.unit_use(principal, path),
        )
    }

    fn unit_recheck(
        &self,
        rule: &RuleRef,
        layout: Option<&str>,
        root: &std::path::Path,
        path: &std::path::Path,
    ) -> UnitRecheck {
        // The reading of the filesystem and of the process table is
        // outside the critical section.
        let (environment, principal, layouts) = {
            let records = self.records();
            (
                records.environment.clone(),
                records.principal,
                records.project_layouts.clone(),
            )
        };
        environment.map_or(UnitRecheck::Unknown("no_process_evidence"), |environment| {
            environment.unit_recheck(principal, rule, layout, root, path, &layouts)
        })
    }
}

#[cfg(test)]
mod tests {
    use svalnir_core::file::LosslessPath;
    use svalnir_core::id::{BootId, ProcessGenerationId};
    use svalnir_core::policy::{ControlPlaneProcess, ProtectionFact};
    use svalnir_core::process::{
        ExecutableIdentity, Pid, ProcessAssociation, ProcessIdentity, ProcessStartTime, Uid,
    };
    use svalnir_core::rule::{Rule, RuleRegistry};

    use super::{AuthorityRecords, SharedAuthority};
    use crate::coordinator::AuthoritySource as _;

    #[derive(Debug)]
    struct NoRules;

    impl RuleRegistry for NoRules {
        fn rules(&self) -> Vec<&Rule> {
            Vec::new()
        }
    }

    const USER: Uid = Uid::new(501);

    fn process(pid: i32, path: &str) -> ProcessIdentity {
        ProcessIdentity {
            generation_id: ProcessGenerationId::new(format!("pg-{pid}")).unwrap(),
            pid: Pid::new(pid).unwrap(),
            start_time: ProcessStartTime::new(1_000),
            uid: USER,
            boot_id: BootId::new("boot_1").unwrap(),
            executable: Some(ExecutableIdentity {
                path: LosslessPath::from_bytes(path).unwrap(),
                file: None,
                code_signature: None,
            }),
            association: ProcessAssociation::Unattributed,
        }
    }

    /// The protection port gives the fact of the catalog for the list of
    /// processes that it gets, also for the one process of a process
    /// target: the control plane of the records, the owner, and the
    /// executable are those of that one process.
    #[test]
    fn the_protection_of_one_process_is_the_fact_of_the_catalog_for_that_process() {
        let authority = SharedAuthority::new(AuthorityRecords::new(USER, Box::new(NoRules)));
        let tool: ProcessIdentity = process(4_242, "/opt/tools/bin/tool");
        // With no control plane in the records, the fact is not known.
        assert_eq!(
            authority.protection(std::slice::from_ref(&tool)),
            ProtectionFact::Unknown
        );
        authority.records().control_plane = Some(vec![ControlPlaneProcess {
            pid: Pid::new(900).unwrap(),
            start_time: ProcessStartTime::new(1_000),
        }]);
        assert_eq!(
            authority.protection(std::slice::from_ref(&tool)),
            ProtectionFact::NotProtected
        );
        // An ancestor of the agent, a process of a different user, and a
        // system executable are protected, each as the only process.
        let ancestor: ProcessIdentity = process(900, "/opt/tools/bin/shell");
        let mut other_user: ProcessIdentity = tool.clone();
        other_user.uid = Uid::new(502);
        let system: ProcessIdentity = process(4_243, "/bin/sleep");
        for protected in [&ancestor, &other_user, &system] {
            assert_eq!(
                authority.protection(std::slice::from_ref(protected)),
                ProtectionFact::Protected,
                "{protected:?}"
            );
        }
        // No list is not "not protected".
        assert_ne!(authority.protection(&[]), ProtectionFact::NotProtected);
    }
}
