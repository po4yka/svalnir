//! The immutable plan and its target bindings.
//!
//! `docs/ACTION_CONTRACTS.md` sections 2 and 3 own the plan and its
//! bindings, and `docs/INTERFACES.md` section 5 owns the approval. A plan
//! is observational: it reserves nothing and authorizes nothing. It can
//! produce a maximum of one admitted operation.
//!
//! [`Plan`] has no mutable access and no public constructor other than
//! [`Plan::seal`]. The digest of a plan covers its full content, so an
//! approval that names the plan identity and the digest is bound to the
//! mode, the target set, the expiry, and the policy, grant, and rule
//! revisions.
//!
//! The builder of a plan is in [`crate::plan`].

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::budget::WorkCharge;
use super::checked::{Check, Checked};
use super::class::{ActionClass, TriggerClass};
use super::state::PlanState;
use crate::authority::{AuthorityBinding, Generation, required_option};
use crate::digest::ContentDigest;
use crate::encoding::wire_enum;
use crate::file::{FileObjectEvidence, LosslessPath};
use crate::id::{
    ApplicationInstanceId, BootId, ClockDomainId, DecisionId, IncidentId, MembershipSnapshotId,
    MountId, PlanId, RootId, SessionId, StepId, TargetId, VolumeId,
};
use crate::policy::{
    ApplicationCandidate, EvaluationClock, ProtectionContext, ProtectionFact, hard_protection,
};
use crate::process::{ProcessAssociation, ProcessIdentity, Uid, VerifiedMembership};
use crate::quantity::{EntryCount, Nanoseconds};
use crate::rule::RuleRef;
use crate::time::{MonotonicNanos, WallTime};

/// The schema version of a plan and of a request envelope.
///
/// Version 2 added the root path, the root object, and the rule layout to
/// [`FileBinding`]. A plan or an envelope of version 1 is refused: it does
/// not have these values, and this build does not make them from a
/// default. A plan is valid for a short time in one boot, so there is no
/// migration.
pub const PLAN_SCHEMA_VERSION: u32 = 2;

/// The largest number of targets and of steps in one plan.
pub const MAX_PLAN_TARGETS: usize = 4096;

/// The largest number of members in one application binding.
pub const MAX_APPLICATION_MEMBERS: usize = 1024;

wire_enum! {
    /// The force strategy that a plan permits.
    Escalation {
        /// A graceful request only.
        None => "none",
        /// A force step after the grace period, if the target is running.
        ForceAfterGrace => "force_after_grace",
        /// An immediate force step with no graceful step. The target and
        /// the consequence need separate authorization.
        ImmediateForce => "immediate_force",
    }
}

wire_enum! {
    /// The role of the client that made a request.
    ClientRole {
        /// The command-line client.
        Cli => "cli",
        /// The GPUI client.
        Gui => "gui",
        /// The agent, for automatic work.
        Agent => "agent",
    }
}

wire_enum! {
    /// The executor that does the steps of a plan.
    ExecutorRole {
        /// The executor of the owning user.
        User => "user",
        /// The privileged helper, under its own grant.
        Helper => "helper",
    }
}

wire_enum! {
    /// The type of a file object.
    FileObjectType {
        /// A regular file.
        RegularFile => "regular_file",
        /// A directory.
        Directory => "directory",
        /// A symbolic link. The link is the object; it is not followed.
        SymbolicLink => "symbolic_link",
    }
}

/// The authenticated user and client of a request.
///
/// The transport gives these values. A value that a payload supplies does
/// not replace them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// The authenticated user.
    pub uid: Uid,
    /// The authenticated session, when the transport has one.
    pub session: Option<SessionId>,
    /// The role of the client.
    pub role: ClientRole,
}

/// The trigger of a plan: a manual approval or an automatic incident.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// The original trigger class. It does not change during execution.
    pub class: TriggerClass,
    /// The incident of an automatic trigger. A manual trigger has none.
    pub incident_id: Option<IncidentId>,
    /// The policy decision of an automatic trigger.
    pub decision_id: Option<DecisionId>,
    /// The budget generation of the incident that the plan uses. An
    /// automatic trigger has it; a manual trigger has none. The journal
    /// charges the consumption of a step to this generation.
    pub budget_generation: Option<Generation>,
}

impl Trigger {
    /// The trigger of a plan that a person approves.
    pub const fn manual() -> Self {
        Self {
            class: TriggerClass::Manual,
            incident_id: None,
            decision_id: None,
            budget_generation: None,
        }
    }
}

/// The time for which a plan is valid, on the monotonic timeline of one
/// clock domain and one boot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validity {
    /// The clock domain of the two monotonic times.
    pub clock_domain: ClockDomainId,
    /// The boot of the two monotonic times.
    pub boot_id: BootId,
    /// The monotonic time at which the plan was built.
    pub created_at: MonotonicNanos,
    /// The monotonic time at which the plan expires.
    pub expires_at: MonotonicNanos,
    /// The wall-clock time at which the plan was built, for history only.
    pub created_wall: WallTime,
}

impl Validity {
    /// Whether the plan is expired at `clock`.
    ///
    /// The plan is expired at its expiry time and after it. It is also
    /// expired when `clock` is in a different clock domain or boot, or is
    /// before the time at which the plan was built: the two times are then
    /// not comparable, and a plan that cannot be shown to be current is not
    /// current. A wait for a graceful exit does not extend the expiry.
    pub fn is_expired(&self, clock: &EvaluationClock) -> bool {
        clock.clock_domain != self.clock_domain
            || clock.boot_id != self.boot_id
            || clock.now < self.created_at
            || clock.now >= self.expires_at
    }
}

/// The binding of a file target.
///
/// A display path of the entry is not in the binding: the entry is
/// relative to an approved root. The binding has the path and the native
/// identifiers of that root, so the digest of the plan covers the place
/// that the approval is for. The root record that an executor acts under
/// must have the same path and the same object.
///
/// JSON has each field. A field with no value is `null`: a binding with
/// a key that is absent is not decoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileBinding {
    /// The approved root.
    pub root_id: RootId,
    /// The absolute path of the approved root, with no `.` and no `..`
    /// component. Each target of one root has the same root path.
    pub root_path: LosslessPath,
    /// The native identifiers of the root directory. Each target of one
    /// root has the same root object.
    pub root_object: FileObjectEvidence,
    /// The entry, relative to the root.
    pub relative_entry: LosslessPath,
    /// The volume of the entry.
    pub volume_id: VolumeId,
    /// The mount generation of the volume.
    pub mount_id: MountId,
    /// The type of the object.
    pub object_type: FileObjectType,
    /// The owner of the object.
    pub owner: Uid,
    /// The native identifiers of the object. `None` means that the
    /// evidence is absent; the adapter decides whether it can act.
    #[serde(deserialize_with = "required_option::deserialize")]
    pub object: Option<FileObjectEvidence>,
    /// The rule revision that selected the entry. `EvictRegenerableData`
    /// needs it.
    #[serde(deserialize_with = "required_option::deserialize")]
    pub rule: Option<RuleRef>,
    /// The producer layout that the rule found for the entry. A target
    /// with a rule has it, and a target with no rule has none. The
    /// lifecycle state of a rule is for one layout, so the authorization
    /// reads the layout from here and not from its caller.
    #[serde(deserialize_with = "required_option::deserialize")]
    pub layout: Option<String>,
    /// The known conservative charge of the entry.
    pub charge: WorkCharge,
}

impl FileBinding {
    /// Whether `other` names the same approved root with the same
    /// evidence: the path and the object. The volume and the mount
    /// generation are those of the entry, and an entry can be on a
    /// different volume than a second entry of its root.
    fn has_same_root(&self, other: &Self) -> bool {
        self.root_path == other.root_path && self.root_object == other.root_object
    }
}

/// True when `path` is absolute, has at least one component, and has no
/// empty, `.`, or `..` component. This is the rule of the plan builder for a
/// root path. It is also the rule of the filesystem executor, so a sealed
/// plan never has a root path that an executor refuses. The path `/` has no
/// component, and a trailing or repeated `/` gives an empty component.
fn is_absolute_root(path: &LosslessPath) -> bool {
    let Some(relative) = path.as_bytes().strip_prefix(b"/") else {
        return false;
    };
    !relative.is_empty()
        && relative
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

/// The binding of an application target: one verified application
/// instance and the members that the plan applies to.
///
/// Descendants, executables with a similar name, shared services, and
/// process groups are not members.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationBinding {
    /// The running application or managed-job instance.
    pub instance_id: ApplicationInstanceId,
    /// The member list that the plan froze.
    pub membership: MembershipSnapshotId,
    /// The members. Each one has positive membership evidence for the
    /// instance.
    pub members: Vec<ProcessIdentity>,
}

/// The reason an application candidate cannot be the target of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CandidateBindingError {
    /// The candidate has a hard protection. No profile, policy, grant, or
    /// manual request removes it.
    #[error("the application has a hard protection")]
    Protected,
    /// The hard protection of the candidate is not known.
    #[error("the hard protection of the application is not known")]
    ProtectionUnknown,
    /// The candidate has no process, or a process has no positive
    /// membership evidence for one instance.
    #[error("the processes are not the verified members of one instance")]
    Membership,
}

impl ApplicationBinding {
    /// Makes the binding of the membership snapshot that the memory policy
    /// evaluated. The policy candidate and the plan target are then the
    /// same processes and the same membership identity.
    ///
    /// The hard protection is the one of the catalog
    /// ([`hard_protection`]), as the candidate recorded it. Evaluate it
    /// again with [`ApplicationBinding::hard_protection`] at each later
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns a [`CandidateBindingError`] when the hard protection of the
    /// candidate is not `NotProtected`, when the candidate has no process,
    /// or when a process has no verified membership of the same instance.
    pub fn from_candidate(candidate: &ApplicationCandidate) -> Result<Self, CandidateBindingError> {
        match candidate.hard_protection {
            ProtectionFact::NotProtected => {}
            ProtectionFact::Protected => return Err(CandidateBindingError::Protected),
            ProtectionFact::Unknown => return Err(CandidateBindingError::ProtectionUnknown),
        }
        let mut instance: Option<&ApplicationInstanceId> = None;
        for process in &candidate.processes {
            let Some(
                VerifiedMembership::Application { instance_id, .. }
                | VerifiedMembership::ManagedJob { instance_id, .. },
            ) = process.association.verified_membership()
            else {
                return Err(CandidateBindingError::Membership);
            };
            if instance.is_some_and(|first| first != instance_id) {
                return Err(CandidateBindingError::Membership);
            }
            instance = Some(instance_id);
        }
        let instance_id: ApplicationInstanceId =
            instance.ok_or(CandidateBindingError::Membership)?.clone();
        Ok(Self {
            instance_id,
            membership: candidate.membership_snapshot.clone(),
            members: candidate.processes.clone(),
        })
    }

    /// The hard protection of the members, from the catalog of the policy
    /// module. Only `NotProtected` permits a step, for a manual plan and
    /// for an automatic plan.
    pub fn hard_protection(&self, context: &ProtectionContext<'_>) -> ProtectionFact {
        hard_protection(&self.members, context)
    }
}

/// The binding of a process target: one process that has no verified
/// membership in an application or a managed job, for example a process
/// that a shell started.
///
/// The binding has the identity evidence of the process and nothing else.
/// It has no member list: a child, a process with a similar name, and a
/// process group are not targets. A process with a verified membership is
/// a target only through its instance ([`ApplicationBinding`]), so that
/// the member rules of the instance apply to it.
///
/// Only a manual plan has this binding. A guard selects an application or
/// a job instance and never one process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessBinding {
    /// The process: its generation identity, its process ID, its start
    /// time, its owner, its boot, and its executable.
    pub process: ProcessIdentity,
}

impl ProcessBinding {
    /// The hard protection of the process, from the catalog of the policy
    /// module. It is the protection of an instance with this one member:
    /// only `NotProtected` permits a step.
    pub fn hard_protection(&self, context: &ProtectionContext<'_>) -> ProtectionFact {
        hard_protection(std::slice::from_ref(&self.process), context)
    }
}

/// The verified identity that a target is bound to.
///
/// JSON encodes the binding as an object with a `kind` field. An unknown
/// `kind` is rejected: a plan with a target that this build cannot bind is
/// not executable. A build that does not know the kind `process` thus
/// refuses a plan with a process target; it does not read the target as an
/// application.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetBinding {
    /// A file object.
    File(FileBinding),
    /// An application or a managed job.
    Application(ApplicationBinding),
    /// One process with no verified membership.
    Process(ProcessBinding),
}

impl TargetBinding {
    /// The processes that a step of an application intervention applies
    /// to: the members of an application target, or the one process of a
    /// process target. `None` for a file target.
    ///
    /// The hard-protection catalog and the identity revalidation take the
    /// same list for the two kinds, so one process with no membership has
    /// the protections of an instance with one member.
    pub fn processes(&self) -> Option<&[ProcessIdentity]> {
        match self {
            Self::File(_) => None,
            Self::Application(application) => Some(&application.members),
            Self::Process(binding) => Some(std::slice::from_ref(&binding.process)),
        }
    }
}

/// One target of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTarget {
    /// The identity of the target.
    pub target_id: TargetId,
    /// The verified identity of the target.
    pub binding: TargetBinding,
}

/// One bounded executable unit of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedStep {
    /// The identity of the step.
    pub step_id: StepId,
    /// The action class of the step.
    pub action_class: ActionClass,
    /// The target of the step.
    pub target_id: TargetId,
}

/// The limits of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLimits {
    /// The total charge of a filesystem plan. An application plan has
    /// none: it uses one application slot.
    pub work: Option<WorkCharge>,
    /// The time that the execution can use after admission.
    pub execution_deadline: Nanoseconds,
    /// The grace period between the graceful request and the force step.
    pub grace: Option<Nanoseconds>,
    /// The time for which the outcome of one step is observed.
    pub verification_window: Nanoseconds,
    /// The force strategy.
    pub escalation: Escalation,
}

/// The content of a plan. [`Plan`] is the sealed form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanContent {
    /// The schema version: [`PLAN_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The identity of the plan.
    pub plan_id: PlanId,
    /// The user and client that the plan was built for.
    pub principal: Principal,
    /// The trigger.
    pub trigger: Trigger,
    /// The policy revision and the grant generations.
    pub authority: AuthorityBinding,
    /// The executor.
    pub executor: ExecutorRole,
    /// The targets. Execution adds none.
    pub targets: Vec<PlanTarget>,
    /// The steps, in execution sequence.
    pub steps: Vec<PlannedStep>,
    /// The limits.
    pub limits: PlanLimits,
    /// The validity.
    pub validity: Validity,
}

/// The reason a plan content was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PlanError {
    /// The schema version is not the version of this build.
    #[error("the schema version of the plan is not supported")]
    SchemaVersion,
    /// A value of the plan is one that this build does not recognize.
    #[error("the plan has a value that this build does not recognize")]
    Unrecognized,
    /// The plan has no target or no step, or more than the limit.
    #[error("the number of targets or steps is zero or is larger than the limit")]
    Count,
    /// Two targets or two steps have the same identity, or two targets
    /// bind the same object.
    #[error("two targets or two steps have the same identity or the same object")]
    Duplicate,
    /// A step names a target that the plan does not have, or a target has
    /// no step.
    #[error("a step and a target do not refer to each other")]
    StepTarget,
    /// The trigger cannot select an action class of the plan, the trigger
    /// identities do not agree with the trigger class, or an automatic
    /// plan has a process target.
    #[error("the trigger does not agree with the action classes")]
    Trigger,
    /// The steps mix action classes that one plan cannot have, or the
    /// steps of an application or of a process do not agree with the force
    /// strategy.
    #[error("the steps do not agree with each other or with the force strategy")]
    Steps,
    /// The binding of a target does not agree with the action class of its
    /// step, with the principal, or with its own evidence, the charge of a
    /// file target has no item, a rule target has no layout, the root path
    /// of a file target is not absolute, or one root identity has two
    /// roots.
    #[error("a target binding does not agree with its step or its evidence")]
    Binding,
    /// The limits are missing, are not finite, or are smaller than the sum
    /// of the charges.
    #[error("the limits do not bound the plan")]
    Limits,
    /// The plan expires before it is built.
    #[error("the validity of the plan is empty")]
    Validity,
    /// An automatic plan names no action grant, or the privilege grant
    /// does not agree with the executor: a helper plan needs one, and a
    /// plan of the user executor has none.
    #[error("the grants of the plan do not agree with its trigger or its executor")]
    Authority,
    /// The digest is not the digest of the content.
    #[error("the digest is not the digest of the plan content")]
    Digest,
}

/// Checks that the identities of a trigger agree with its class: a manual
/// trigger has no incident, no decision, and no budget generation, and an
/// automatic trigger has the three.
pub(super) fn check_trigger_identities(trigger: &Trigger) -> Result<(), PlanError> {
    let identities_agree: bool = match trigger.class {
        TriggerClass::Manual => {
            trigger.incident_id.is_none()
                && trigger.decision_id.is_none()
                && trigger.budget_generation.is_none()
        }
        TriggerClass::Unrecognized(_) => return Err(PlanError::Unrecognized),
        _ => {
            trigger.incident_id.is_some()
                && trigger.decision_id.is_some()
                && trigger.budget_generation.is_some()
        }
    };
    if identities_agree {
        Ok(())
    } else {
        Err(PlanError::Trigger)
    }
}

/// Checks the binding of a file target for a step of `class`.
pub(super) fn check_file_binding(
    class: &ActionClass,
    file: &FileBinding,
    principal: Uid,
    executor: &ExecutorRole,
) -> Result<(), PlanError> {
    if !file.object_type.is_recognized() {
        return Err(PlanError::Unrecognized);
    }
    let rule_agrees: bool =
        !matches!(class, ActionClass::EvictRegenerableData) || file.rule.is_some();
    // The lifecycle state of a rule is for one layout. A rule target with
    // no layout would get its layout from the caller of the authorization,
    // and a layout with no rule has no meaning.
    let layout_agrees: bool = match (&file.rule, &file.layout) {
        (Some(_), Some(layout)) => !layout.is_empty(),
        (None, None) => true,
        _ => false,
    };
    let root_agrees: bool = is_absolute_root(&file.root_path);
    // The executor of the owning user changes only the objects of that
    // user.
    let owner_agrees: bool = !matches!(executor, ExecutorRole::User) || file.owner == principal;
    // An entry is a minimum of one item. A charge of no items would use
    // no part of an item limit, and it fits in an exhausted allowance.
    let charge_agrees: bool = file.charge.items != EntryCount::ZERO;
    if class.is_filesystem()
        && rule_agrees
        && layout_agrees
        && root_agrees
        && owner_agrees
        && charge_agrees
    {
        Ok(())
    } else {
        Err(PlanError::Binding)
    }
}

/// Checks the binding of an application target: each member has positive
/// membership evidence for the instance and is a process of `principal`.
/// The process-control surface has no helper executor.
pub(super) fn check_application_binding(
    application: &ApplicationBinding,
    principal: Uid,
    executor: &ExecutorRole,
) -> Result<(), PlanError> {
    if !matches!(executor, ExecutorRole::User) {
        return Err(PlanError::Binding);
    }
    let members = &application.members;
    if members.is_empty() || members.len() > MAX_APPLICATION_MEMBERS {
        return Err(PlanError::Count);
    }
    let mut generations: BTreeSet<&str> = BTreeSet::new();
    for member in members {
        if !generations.insert(member.generation_id.as_str()) {
            return Err(PlanError::Duplicate);
        }
        let instance: &ApplicationInstanceId = match member.association.verified_membership() {
            Some(
                VerifiedMembership::Application { instance_id, .. }
                | VerifiedMembership::ManagedJob { instance_id, .. },
            ) => instance_id,
            None => return Err(PlanError::Binding),
        };
        // The process-control surface has no target of another user.
        if instance != &application.instance_id || member.uid != principal {
            return Err(PlanError::Binding);
        }
    }
    Ok(())
}

/// The process ID of `launchd`.
const LAUNCHD_PID: i32 = 1;

/// The user ID of root.
const ROOT_UID: u32 = 0;

/// Checks the binding of a process target for a plan with the trigger
/// `trigger`. These are the rules that need no observation; the catalog of
/// hard protections applies in addition, at each boundary.
///
/// - The plan is manual, and the executor is the user executor.
/// - No application or job evidence was found for the process
///   ([`ProcessAssociation::Unattributed`]). An association kind or an
///   attribution method that this build does not recognize is not that: a
///   different build can know the process as a member of an instance.
/// - The process is a process of `principal`, is not a process of root,
///   and is not `launchd`.
/// - The process has executable evidence: an executor cannot show that a
///   process with the same process ID is the planned one without it.
pub(super) fn check_process_binding(
    binding: &ProcessBinding,
    principal: Uid,
    executor: &ExecutorRole,
    trigger: &TriggerClass,
) -> Result<(), PlanError> {
    if !matches!(trigger, TriggerClass::Manual) {
        return Err(PlanError::Trigger);
    }
    let process: &ProcessIdentity = &binding.process;
    let is_single: bool = matches!(process.association, ProcessAssociation::Unattributed);
    let owner_agrees: bool = process.uid == principal && process.uid.get() != ROOT_UID;
    let is_launchd: bool = process.pid.get() == LAUNCHD_PID;
    if matches!(executor, ExecutorRole::User)
        && is_single
        && owner_agrees
        && !is_launchd
        && process.executable.is_some()
    {
        Ok(())
    } else {
        Err(PlanError::Binding)
    }
}

/// Whether a step of `class` agrees with the force strategy and the grace
/// period: a graceful step with `none` or `force_after_grace`, a force
/// step with `force_after_grace` or `immediate_force`, and a grace period
/// exactly with `force_after_grace`. A filesystem step has no force
/// strategy and no grace period.
pub(super) fn step_agrees_with_escalation(
    class: &ActionClass,
    escalation: &Escalation,
    grace: Option<Nanoseconds>,
) -> bool {
    let grace_agrees: bool = if matches!(escalation, Escalation::ForceAfterGrace) {
        grace.is_some_and(|grace| grace > Nanoseconds::ZERO)
    } else {
        grace.is_none()
    };
    let class_agrees: bool = match class {
        ActionClass::RequestApplicationExit => {
            matches!(escalation, Escalation::None | Escalation::ForceAfterGrace)
        }
        ActionClass::ForceApplicationExit => matches!(
            escalation,
            Escalation::ForceAfterGrace | Escalation::ImmediateForce
        ),
        _ => class.is_filesystem() && matches!(escalation, Escalation::None),
    };
    grace_agrees && class_agrees
}

impl PlanContent {
    /// The target with the identity `target_id`.
    pub fn target(&self, target_id: &TargetId) -> Option<&PlanTarget> {
        self.targets
            .iter()
            .find(|target| &target.target_id == target_id)
    }

    /// Checks that one root identity has one root: each file target that
    /// names it has the same root path and the same root object. With
    /// two, the identity would not say which place the approval is for.
    fn check_roots(&self) -> Result<(), PlanError> {
        let mut roots: BTreeMap<&RootId, &FileBinding> = BTreeMap::new();
        for target in &self.targets {
            if let TargetBinding::File(file) = &target.binding {
                let first: &FileBinding = roots.entry(&file.root_id).or_insert(file);
                if !first.has_same_root(file) {
                    return Err(PlanError::Binding);
                }
            }
        }
        Ok(())
    }

    /// Checks that no two targets bind the same object: the same entry of
    /// one root, the same application instance, or the same process
    /// generation. Two target identities for one object would give two
    /// steps and two charges for one irreversible action.
    fn check_distinct_objects(&self) -> Result<(), PlanError> {
        let mut entries: BTreeSet<(&RootId, &[u8])> = BTreeSet::new();
        // Two root identities can name one root. The root object then
        // shows that the two entries are one object.
        let mut placed: BTreeSet<(&FileObjectEvidence, &[u8])> = BTreeSet::new();
        let mut instances: BTreeSet<&ApplicationInstanceId> = BTreeSet::new();
        let mut generations: BTreeSet<&str> = BTreeSet::new();
        for target in &self.targets {
            let is_new: bool = match &target.binding {
                TargetBinding::File(file) => {
                    let entry: &[u8] = file.relative_entry.as_bytes();
                    // The two sets get the entry also when the first one
                    // has it.
                    let new_in_root: bool = entries.insert((&file.root_id, entry));
                    let new_in_place: bool = placed.insert((&file.root_object, entry));
                    new_in_root && new_in_place
                }
                TargetBinding::Application(application) => {
                    instances.insert(&application.instance_id)
                        && application
                            .members
                            .iter()
                            .all(|member| generations.insert(member.generation_id.as_str()))
                }
                // A process is one target, as a member or by itself.
                TargetBinding::Process(binding) => {
                    generations.insert(binding.process.generation_id.as_str())
                }
            };
            if !is_new {
                return Err(PlanError::Duplicate);
            }
        }
        Ok(())
    }

    fn check_trigger(&self) -> Result<(), PlanError> {
        check_trigger_identities(&self.trigger)?;
        if self.trigger.class.is_automatic() {
            if self.authority.action_grants.is_empty() {
                return Err(PlanError::Authority);
            }
            if !matches!(self.principal.role, ClientRole::Agent) {
                return Err(PlanError::Trigger);
            }
        }
        Ok(())
    }

    /// Checks the steps of one target and returns its charge.
    fn check_target(&self, target: &PlanTarget) -> Result<WorkCharge, PlanError> {
        let classes: Vec<&ActionClass> = self
            .steps
            .iter()
            .filter(|step| step.target_id == target.target_id)
            .map(|step| &step.action_class)
            .collect();
        for class in &classes {
            if !class.is_recognized() {
                return Err(PlanError::Unrecognized);
            }
            if !class.accepts_trigger(&self.trigger.class) {
                return Err(PlanError::Trigger);
            }
        }
        match &target.binding {
            TargetBinding::File(file) => {
                // One filesystem step for one entry.
                let [class] = classes.as_slice() else {
                    return Err(PlanError::StepTarget);
                };
                if !class.is_filesystem() {
                    return Err(PlanError::Binding);
                }
                check_file_binding(class, file, self.principal.uid, &self.executor)?;
                Ok(file.charge)
            }
            binding @ (TargetBinding::Application(_) | TargetBinding::Process(_)) => {
                use ActionClass::{ForceApplicationExit, RequestApplicationExit};
                let steps_agree: bool = match (&self.limits.escalation, classes.as_slice()) {
                    (Escalation::Unrecognized(_), _) => return Err(PlanError::Unrecognized),
                    (_, []) => return Err(PlanError::StepTarget),
                    (Escalation::None, [RequestApplicationExit])
                    | (
                        Escalation::ForceAfterGrace,
                        [RequestApplicationExit, ForceApplicationExit],
                    )
                    | (Escalation::ImmediateForce, [ForceApplicationExit]) => true,
                    _ => false,
                };
                if !steps_agree {
                    return Err(PlanError::Steps);
                }
                let uid: Uid = self.principal.uid;
                match binding {
                    TargetBinding::Application(application) => {
                        check_application_binding(application, uid, &self.executor)?;
                    }
                    TargetBinding::Process(process) => {
                        check_process_binding(process, uid, &self.executor, &self.trigger.class)?;
                    }
                    TargetBinding::File(_) => return Err(PlanError::Binding),
                }
                Ok(WorkCharge::ZERO)
            }
        }
    }

    fn check_limits(&self, is_filesystem: bool, total: WorkCharge) -> Result<(), PlanError> {
        let limits = &self.limits;
        let zero = Nanoseconds::ZERO;
        if limits.execution_deadline == zero || limits.verification_window == zero {
            return Err(PlanError::Limits);
        }
        let limits_agree: bool = if is_filesystem {
            let no_force: bool = matches!(limits.escalation, Escalation::None);
            no_force
                && limits.grace.is_none()
                && limits.work.is_some_and(|work| total.fits_in(&work))
        } else {
            // A grace period exists exactly when a force step follows a
            // graceful step.
            let grace_agrees: bool = if matches!(limits.escalation, Escalation::ForceAfterGrace) {
                limits.grace.is_some_and(|grace| grace > zero)
            } else {
                limits.grace.is_none()
            };
            limits.work.is_none() && grace_agrees
        };
        if limits_agree {
            Ok(())
        } else {
            Err(PlanError::Limits)
        }
    }
}

impl Check for PlanContent {
    type Error = PlanError;

    fn check(&self) -> Result<(), PlanError> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            return Err(PlanError::SchemaVersion);
        }
        if !self.principal.role.is_recognized() || !self.executor.is_recognized() {
            return Err(PlanError::Unrecognized);
        }
        let count_agrees = |count: usize| (1..=MAX_PLAN_TARGETS).contains(&count);
        if !count_agrees(self.targets.len()) || !count_agrees(self.steps.len()) {
            return Err(PlanError::Count);
        }
        self.check_trigger()?;
        // A helper acts only under its own grant, and a plan of the user
        // executor names no privilege grant.
        let is_helper: bool = matches!(self.executor, ExecutorRole::Helper);
        if self.authority.privilege_grant.is_some() != is_helper {
            return Err(PlanError::Authority);
        }

        let mut target_ids: BTreeSet<&TargetId> = BTreeSet::new();
        for target in &self.targets {
            if !target_ids.insert(&target.target_id) {
                return Err(PlanError::Duplicate);
            }
        }
        self.check_distinct_objects()?;
        self.check_roots()?;
        let mut step_ids: BTreeSet<&StepId> = BTreeSet::new();
        for step in &self.steps {
            if !step_ids.insert(&step.step_id) {
                return Err(PlanError::Duplicate);
            }
            if !target_ids.contains(&step.target_id) {
                return Err(PlanError::StepTarget);
            }
        }

        let mut total: WorkCharge = WorkCharge::ZERO;
        for target in &self.targets {
            let charge: WorkCharge = self.check_target(target)?;
            total = total.checked_add(charge).ok_or(PlanError::Limits)?;
        }
        // One plan has one filesystem class, or application steps only.
        let first: &ActionClass = &self.steps[0].action_class;
        let is_filesystem: bool = first.is_filesystem();
        let classes_agree: bool = self.steps.iter().all(|step| {
            if is_filesystem {
                &step.action_class == first
            } else {
                step.action_class.is_application_intervention()
            }
        });
        if !classes_agree {
            return Err(PlanError::Steps);
        }
        self.check_limits(is_filesystem, total)?;

        if self.validity.created_at >= self.validity.expires_at {
            return Err(PlanError::Validity);
        }
        Ok(())
    }
}

/// An immutable plan: checked content and the digest of that content.
///
/// The content is read through `Deref`. No method changes a plan. JSON
/// encodes the plan as an object with `content` and `digest`, and decoding
/// checks the content and the digest again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PlanWire")]
pub struct Plan {
    content: Checked<PlanContent>,
    digest: ContentDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanWire {
    content: PlanContent,
    digest: ContentDigest,
}

impl TryFrom<PlanWire> for Plan {
    type Error = PlanError;

    fn try_from(wire: PlanWire) -> Result<Self, Self::Error> {
        let plan = Self::seal(wire.content)?;
        if plan.digest == wire.digest {
            Ok(plan)
        } else {
            Err(PlanError::Digest)
        }
    }
}

impl Plan {
    /// Checks the content and seals it with its digest.
    ///
    /// # Errors
    ///
    /// Returns the [`PlanError`] of the first rule that the content does
    /// not agree with.
    pub fn seal(content: PlanContent) -> Result<Self, PlanError> {
        let content = Checked::new(content)?;
        // The content has only strings, integers, and lists, so it always
        // has a JSON encoding.
        let digest = ContentDigest::of_json(&*content).map_err(|_| PlanError::Digest)?;
        Ok(Self { content, digest })
    }

    /// The digest of the content.
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// The state of a plan: `Prepared`. Admission makes an operation; it
    /// does not change the plan.
    pub fn state(&self) -> PlanState {
        PlanState::Prepared
    }

    /// Whether the plan is expired at `clock`. See
    /// [`Validity::is_expired`].
    pub fn is_expired(&self, clock: &EvaluationClock) -> bool {
        self.content.validity.is_expired(clock)
    }

    /// Whether `approval` is bound to this plan: the same identity and the
    /// same digest.
    pub fn is_bound_by(&self, approval: &PlanApproval) -> bool {
        approval.plan_id == self.content.plan_id && approval.digest == self.digest
    }
}

impl Deref for Plan {
    type Target = PlanContent;

    fn deref(&self) -> &PlanContent {
        &self.content
    }
}

/// The reference that a client applies a plan with. It names the plan and
/// the digest that the client reviewed. It has no replacement path and no
/// target identity: the executor reads the plan content from its own
/// state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanApproval {
    /// The plan.
    pub plan_id: PlanId,
    /// The digest of the plan that the client reviewed.
    pub digest: ContentDigest,
}
