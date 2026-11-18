//! The state of the helper: its own record of each privilege grant, the
//! identity that it expects of its caller, and its limits.
//!
//! `docs/THREAT_MODEL.md` section 4.2 owns the rule that a privilege grant
//! is helper-owned and administrator-approved. Each value in this module
//! comes from root-owned storage or from the compiled policy of the
//! product. No value comes from a request, from the configuration of the
//! user, or from a catalog of the agent.

use svalnir_core::action::{ActionClass, WorkCharge};
use svalnir_core::authority::PrivilegeGrant;
use svalnir_core::file::LosslessPath;
use svalnir_core::id::{BootId, ClockDomainId, PrivilegeGrantId, RootId};
use svalnir_core::quantity::{EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::{MonotonicNanos, WallTime};
use thiserror::Error;

use super::path::{PathDefect, RootPath};
use super::record::{ConsumedRequest, ConsumedRequests, RecordError, Restored};
use crate::request::{CodeIdentity, MAX_TARGETS_PER_REQUEST, SupportedProtocols};

/// The largest number of privilege grants in the state.
pub const MAX_GRANTS: usize = 64;

/// The largest number of approved roots in one grant.
pub const MAX_ROOTS_PER_GRANT: usize = 32;

/// The largest number of rule revisions for one root.
pub const MAX_RULES_PER_ROOT: usize = 16;

/// The action class that this build can do for a grant.
pub const SUPPORTED_ACTION_CLASS: ActionClass = ActionClass::EvictRegenerableData;

/// The time of one validation. The caller reads the clocks; this crate
/// does not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelperClock {
    /// The wall-clock time. The expiry of a grant uses it.
    pub wall: WallTime,
    /// The monotonic time. The validity of a request and the rate window
    /// use it.
    pub monotonic: MonotonicNanos,
    /// The clock domain of `monotonic`.
    pub clock_domain: ClockDomainId,
    /// The boot of `monotonic`.
    pub boot_id: BootId,
}

/// One approved root of a grant, as the helper recorded it at enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedRoot {
    root_id: RootId,
    path: RootPath,
    rules: Vec<RuleRef>,
}

impl ApprovedRoot {
    /// Makes the record of a root.
    ///
    /// `rules` are the rule revisions that the helper can execute below
    /// the root.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] when the path is not an absolute path of
    /// checked names, when there is no rule or more than
    /// [`MAX_RULES_PER_ROOT`] rules, or when a rule is there two times.
    pub fn new(
        root_id: RootId,
        path: &LosslessPath,
        rules: Vec<RuleRef>,
    ) -> Result<Self, StateError> {
        let path: RootPath = RootPath::parse(path).map_err(StateError::RootPath)?;
        if rules.is_empty() || rules.len() > MAX_RULES_PER_ROOT || has_duplicate(&rules) {
            return Err(StateError::Rules);
        }
        Ok(Self {
            root_id,
            path,
            rules,
        })
    }

    /// The identity of the root.
    pub fn root_id(&self) -> &RootId {
        &self.root_id
    }

    /// The absolute path of the root, as checked names.
    pub fn path(&self) -> &RootPath {
        &self.path
    }

    /// The rule revisions that the helper can execute below the root.
    pub fn rules(&self) -> &[RuleRef] {
        &self.rules
    }
}

/// The rate ceiling of a grant: the largest number of accepted requests
/// and the largest accepted work in one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RateCeiling {
    /// The length of the window.
    pub window: Nanoseconds,
    /// The largest number of accepted requests in one window.
    pub max_requests: u32,
    /// The largest sum of accepted work in one window.
    pub work: WorkCharge,
}

/// The ceilings of a grant that `svalnir_core::authority::PrivilegeGrant`
/// does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantLimits {
    /// The largest number of entries in one request.
    pub max_targets: usize,
    /// The rate ceiling.
    pub rate: RateCeiling,
}

/// The record of one privilege grant in the helper: the grant, the paths
/// and the rules of its roots, and its ceilings.
///
/// The record is a container of
/// [`PrivilegeGrant`](svalnir_core::authority::PrivilegeGrant). It is not a
/// second grant type: the grant gives the principal, the action classes,
/// the root identities, the ceiling of one operation, the expiry, and the
/// generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperGrant {
    pub(super) grant: PrivilegeGrant,
    pub(super) roots: Vec<ApprovedRoot>,
    pub(super) limits: GrantLimits,
}

impl HelperGrant {
    /// Makes the record and checks that its parts agree.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] when:
    ///
    /// - The grant has no action class, an action class other than
    ///   [`SUPPORTED_ACTION_CLASS`], or an action class two times.
    /// - The grant permits the critical-memory exception of the journal.
    ///   The helper has no application step, and the exception never
    ///   applies to a filesystem step.
    /// - The roots of the grant and `roots` are not the same set, a root
    ///   is there two times, there is no root, or there are more than
    ///   [`MAX_ROOTS_PER_GRANT`] roots.
    /// - One root is another root or is below it.
    /// - The ceiling of one operation has no item.
    /// - A limit is zero, or `max_targets` is larger than
    ///   [`MAX_TARGETS_PER_REQUEST`].
    pub fn new(
        grant: PrivilegeGrant,
        roots: Vec<ApprovedRoot>,
        limits: GrantLimits,
    ) -> Result<Self, StateError> {
        let classes: &[ActionClass] = &grant.action_classes;
        if classes.is_empty()
            || has_duplicate(classes)
            || classes
                .iter()
                .any(|class: &ActionClass| *class != SUPPORTED_ACTION_CLASS)
        {
            return Err(StateError::ActionClasses);
        }
        if grant.allow_volatile_journal_on_critical {
            return Err(StateError::VolatileException);
        }
        if grant.roots.is_empty()
            || grant.roots.len() > MAX_ROOTS_PER_GRANT
            || has_duplicate(&grant.roots)
            || roots.len() != grant.roots.len()
            || grant.roots.iter().any(|root_id: &RootId| {
                !roots
                    .iter()
                    .any(|root: &ApprovedRoot| &root.root_id == root_id)
            })
        {
            return Err(StateError::Roots);
        }
        for (index, root) in roots.iter().enumerate() {
            let overlaps = |other: &ApprovedRoot| {
                root.path.contains(&other.path) || other.path.contains(&root.path)
            };
            if roots.iter().skip(index.saturating_add(1)).any(overlaps) {
                return Err(StateError::Roots);
            }
        }
        if grant.ceiling.items == EntryCount::ZERO
            || limits.max_targets == 0
            || limits.max_targets > MAX_TARGETS_PER_REQUEST
            || limits.rate.window == Nanoseconds::ZERO
            || limits.rate.max_requests == 0
            || limits.rate.work.items == EntryCount::ZERO
        {
            return Err(StateError::Limits);
        }
        Ok(Self {
            grant,
            roots,
            limits,
        })
    }

    /// The grant.
    pub fn grant(&self) -> &PrivilegeGrant {
        &self.grant
    }

    /// The roots, with their paths and rules.
    pub fn roots(&self) -> &[ApprovedRoot] {
        &self.roots
    }

    /// The record of the root `root_id`, when the grant has it.
    pub fn root(&self, root_id: &RootId) -> Option<&ApprovedRoot> {
        self.roots
            .iter()
            .find(|root: &&ApprovedRoot| &root.root_id == root_id)
    }

    /// The ceilings that the grant record adds.
    pub fn limits(&self) -> &GrantLimits {
        &self.limits
    }
}

/// The compiled and administrator-approved settings of the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperConfig {
    /// The protocol versions that the helper supports.
    pub protocols: SupportedProtocols,
    /// The code-signing identity of the agent: the only executable whose
    /// requests the helper accepts.
    pub agent: CodeIdentity,
    /// The longest validity of a request. A request cannot state a longer
    /// one.
    pub max_validity: Nanoseconds,
    /// The capacity of the record of consumed requests.
    pub record_capacity: usize,
    /// The largest number of records of one user. One user cannot fill
    /// the record and stop the requests of each other user.
    pub principal_quota: usize,
    /// The shortest time for which a settled request stays in the record.
    /// It is not shorter than `max_validity` or than a rate window.
    pub retention: Nanoseconds,
}

/// The reason a state of the helper was refused. A refused state is not
/// used: the helper then has no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StateError {
    /// The path of a root was refused.
    #[error("the path of a root is not permitted: {0}")]
    RootPath(#[source] PathDefect),
    /// A root has no rule, too many rules, or a rule two times.
    #[error("the rules of a root are not permitted")]
    Rules,
    /// A grant has no action class, an action class that this build cannot
    /// do, or an action class two times.
    #[error("the action classes of a grant are not permitted")]
    ActionClasses,
    /// A grant permits the critical-memory exception of the journal.
    #[error("a grant permits the critical-memory exception, which the helper does not support")]
    VolatileException,
    /// The roots of a grant and their records do not agree, or one root
    /// contains another.
    #[error("the roots of a grant are not permitted")]
    Roots,
    /// A ceiling is zero or is larger than the limit of the protocol.
    #[error("a ceiling of a grant is not permitted")]
    Limits,
    /// There are too many grants, or two grants have one identity.
    #[error("the grants are not permitted")]
    Grants,
    /// The validity or the retention is zero, or the retention is shorter
    /// than the validity or than a rate window.
    #[error("the validity and the retention do not agree")]
    Retention,
    /// The record quota of one user is zero or larger than the capacity.
    #[error("the record quota of one user is not permitted")]
    Quota,
    /// The record of consumed requests was refused.
    #[error("the record of consumed requests is not permitted: {0}")]
    Record(#[from] RecordError),
}

/// The state that the helper decides with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperState {
    pub(super) config: HelperConfig,
    pub(super) grants: Vec<HelperGrant>,
    pub(super) consumed: ConsumedRequests,
}

impl HelperState {
    /// Makes the state with an empty record of consumed requests.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] when the settings and the grants do not
    /// agree. See [`HelperState::restore`].
    pub fn new(config: HelperConfig, grants: Vec<HelperGrant>) -> Result<Self, StateError> {
        Self::restore(config, grants, Vec::new()).map(|restored| restored.state)
    }

    /// Makes the state with the consumed requests of an earlier lifetime
    /// of the helper. A step that the earlier lifetime left in work gets
    /// the state `UnknownOutcome`: the result names each such step in
    /// [`Restored::changed`], and the storage layer writes those records
    /// back. The agent gets `unknown_outcome` from a status query for such
    /// a step after a restart of the helper.
    ///
    /// # Errors
    ///
    /// Returns a [`StateError`] when there are more than [`MAX_GRANTS`]
    /// grants, when two grants have one identity, when the validity or the
    /// retention is zero, when the retention is shorter than the validity
    /// or than a rate window, when the record quota of one user is zero or
    /// larger than the capacity, or when the record refuses the requests.
    pub fn restore(
        config: HelperConfig,
        grants: Vec<HelperGrant>,
        consumed: Vec<ConsumedRequest>,
    ) -> Result<Restored<Self>, StateError> {
        if grants.len() > MAX_GRANTS {
            return Err(StateError::Grants);
        }
        let grant_ids: Vec<&PrivilegeGrantId> = grants
            .iter()
            .map(|record: &HelperGrant| &record.grant.grant_id)
            .collect();
        if has_duplicate(&grant_ids) {
            return Err(StateError::Grants);
        }
        if config.max_validity == Nanoseconds::ZERO
            || config.retention < config.max_validity
            || grants
                .iter()
                .any(|record: &HelperGrant| config.retention < record.limits.rate.window)
        {
            return Err(StateError::Retention);
        }
        let Restored {
            state: consumed,
            changed,
        } = ConsumedRequests::restore(config.record_capacity, config.retention, consumed)?;
        if config.principal_quota == 0 || config.principal_quota > config.record_capacity {
            return Err(StateError::Quota);
        }
        Ok(Restored {
            state: Self {
                config,
                grants,
                consumed,
            },
            changed,
        })
    }

    /// The settings.
    pub fn config(&self) -> &HelperConfig {
        &self.config
    }

    /// The grant records.
    pub fn grants(&self) -> &[HelperGrant] {
        &self.grants
    }

    /// The record of the grant `grant_id`, when the helper has it.
    pub fn grant(&self, grant_id: &PrivilegeGrantId) -> Option<&HelperGrant> {
        self.grants
            .iter()
            .find(|record: &&HelperGrant| &record.grant.grant_id == grant_id)
    }

    /// The record of consumed requests.
    pub fn consumed(&self) -> &ConsumedRequests {
        &self.consumed
    }
}

/// Whether `values` has one value two times. The lists of this module are
/// short, so the function compares each pair.
fn has_duplicate<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value): (usize, &T)| {
            values
                .iter()
                .skip(index.saturating_add(1))
                .any(|other: &T| other == value)
        })
}
