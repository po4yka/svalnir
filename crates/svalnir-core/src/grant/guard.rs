//! Enablement, disablement, and revocation of the standing authority of a
//! guard.
//!
//! A guard is active only when each of these is true: a policy revision is
//! in effect, its configuration requests the guard, its profile is not
//! `observe`, the user enabled the guard, and the action grant of the guard
//! is in effect, is bound to the revision in effect, and covers each action
//! class that the configuration can use. Administrative access, Full Disk
//! Access, and a profile name are not inputs of this module: they grant
//! nothing (`README.md`, "Protection profiles").

use serde::Serialize;
use thiserror::Error;

use super::scope::{PolicyScope, ScopeDifference, ScopeEffect, difference};
use super::state::{
    ActiveRevision, AuthorityState, Change, Fallback, GuardAuthority, InhibitedGuard,
    InhibitionCause, InstanceInhibition, Settled, policy_id,
};
use crate::action::ActionClass;
use crate::authority::{ActionGrant, ActionGrantRef, Generation};
use crate::id::{ActionGrantId, PolicyRevisionId};
use crate::policy::PolicyId;
use crate::process::Uid;
use crate::time::WallTime;

/// One acceptance of a consequence, as a client states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Acceptance {
    /// `--accept-permanent-eviction`: permanent eviction of approved
    /// regenerable data.
    PermanentEviction,
    /// The acceptance of automatic graceful application exit, with no force
    /// step.
    ApplicationExit,
    /// `--accept-force-quit`: automatic application termination that ends
    /// with a force quit. It includes the graceful request.
    ForceQuit,
}

impl Acceptance {
    /// The action classes that the acceptance names.
    pub fn classes(self) -> Vec<ActionClass> {
        match self {
            Self::PermanentEviction => vec![ActionClass::EvictRegenerableData],
            Self::ApplicationExit => vec![ActionClass::RequestApplicationExit],
            Self::ForceQuit => vec![
                ActionClass::RequestApplicationExit,
                ActionClass::ForceApplicationExit,
            ],
        }
    }

    /// The action classes that a list of acceptances names, each one time.
    pub fn classes_of(acceptances: &[Self]) -> Vec<ActionClass> {
        let mut classes: Vec<ActionClass> = Vec::new();
        for class in acceptances
            .iter()
            .flat_map(|acceptance| acceptance.classes())
        {
            if !classes.contains(&class) {
                classes.push(class);
            }
        }
        classes
    }
}

/// The standing of a guard: whether it has automatic authority, or the
/// first reason that it has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStanding {
    /// The guard has automatic authority for the scope of the revision in
    /// effect.
    Active,
    /// No policy revision is in effect.
    NoActiveRevision,
    /// The running instance inhibits the guard after a restriction that
    /// was not persisted.
    Inhibited,
    /// The configuration in effect does not request the guard.
    NotRequested,
    /// The profile in effect is `observe`, or is not known.
    ObserveProfile,
    /// The user did not enable the guard, or disabled it.
    Disabled,
    /// The guard has no action grant.
    NoGrant,
    /// The action grant was revoked.
    GrantRevoked,
    /// The action grant is at its expiry or after it.
    GrantExpired,
    /// The action grant does not cover the revision in effect: the scope
    /// became wider after the acceptance, or the grant does not have each
    /// action class that the configuration can use. A new acceptance is
    /// necessary.
    AcceptanceRequired,
}

/// Whether `grant` has each action class, force strategy, and rule
/// revision that `scope` can use for `policy`.
fn covers_scope(grant: &ActionGrant, scope: &PolicyScope, policy: PolicyId) -> bool {
    scope
        .action_classes(policy)
        .iter()
        .all(|class| grant.action_classes.contains(class))
        && scope
            .escalations(policy)
            .iter()
            .all(|escalation| grant.escalations.contains(escalation))
        && scope
            .rules(policy)
            .iter()
            .all(|rule| grant.rules.contains(rule))
}

/// The widening differences from the scope that the grant of `guard`
/// covers to `scope`, for the guard. `None` when the guard has no grant
/// with a reviewed scope.
pub(super) fn uncovered(
    guard: &GuardAuthority,
    scope: &PolicyScope,
) -> Option<Vec<ScopeDifference>> {
    let reviewed: &PolicyScope = guard.reviewed.as_ref()?;
    guard.grant.as_ref()?;
    Some(
        difference(reviewed, scope)
            .into_iter()
            .filter(|difference| {
                difference.guards.includes(guard.policy)
                    && difference.effect == ScopeEffect::Widening
            })
            .collect(),
    )
}

/// The standing of `policy` at `now`.
///
/// The grant covers the revision in effect only when it is bound to that
/// revision and the scope in effect is not wider than the scope that the
/// acceptance reviewed. The second condition does not depend on the
/// revision identity, so an identity that is used again gives no authority.
///
/// A pause is not part of the standing: it is an orthogonal condition
/// (`docs/POLICY_SPEC.md` section 8), and [`super::pause_status`] reports
/// it.
pub fn guard_standing(
    state: &AuthorityState,
    inhibition: &InstanceInhibition,
    policy: PolicyId,
    now: WallTime,
) -> GuardStanding {
    let Some(active) = &state.active else {
        return GuardStanding::NoActiveRevision;
    };
    if inhibition.inhibits(policy) {
        return GuardStanding::Inhibited;
    }
    if !active.scope.requests(policy) {
        return GuardStanding::NotRequested;
    }
    if !active.scope.profile_permits_intervention() {
        return GuardStanding::ObserveProfile;
    }
    let Some(guard) = state.guard(policy).filter(|guard| guard.enabled) else {
        return GuardStanding::Disabled;
    };
    let Some(grant) = &guard.grant else {
        return GuardStanding::NoGrant;
    };
    if grant.revoked {
        return GuardStanding::GrantRevoked;
    }
    if !grant.is_in_effect(now) {
        return GuardStanding::GrantExpired;
    }
    let covers: bool = grant.principal == state.principal
        && grant.policy_revision == active.revision.revision_id
        && covers_scope(grant, &active.scope, policy)
        && uncovered(guard, &active.scope).is_some_and(|widening| widening.is_empty());
    if covers {
        GuardStanding::Active
    } else {
        GuardStanding::AcceptanceRequired
    }
}

/// A request to enable a guard (`policy enable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableRequest {
    /// The authenticated user of the request.
    pub principal: Uid,
    /// The guard.
    pub policy: PolicyId,
    /// The action classes that the user accepted. Use
    /// [`Acceptance::classes_of`] for the flags of a command.
    pub accepted: Vec<ActionClass>,
    /// The policy revision that the user reviewed. A noninteractive request
    /// must name it.
    pub reviewed_revision: Option<PolicyRevisionId>,
    /// True when the client showed the scope of the revision in effect and
    /// the consequence to a person before the request. Such a request can
    /// omit `reviewed_revision`; it then binds the revision in effect.
    pub interactive: bool,
    /// The identity of a new grant. The function uses it only when the
    /// guard has no grant, or when the generation of its grant cannot
    /// become larger.
    pub grant_id: ActionGrantId,
    /// The wall-clock time of the request.
    pub now: WallTime,
}

/// The reason an enable request was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnableRefusal {
    /// The request is from a different user than the record.
    #[error("the request is from a different user than the authority record")]
    WrongPrincipal,
    /// No policy revision is in effect, so there is no scope to accept.
    #[error("no policy revision is in effect")]
    NoActiveRevision,
    /// A noninteractive request did not name the revision that was
    /// reviewed.
    #[error("a noninteractive request must name the reviewed policy revision")]
    ReviewedRevisionRequired,
    /// The reviewed revision is not the revision in effect. The user must
    /// review the revision in effect; nothing is overwritten.
    #[error("the reviewed policy revision {reviewed} is not the revision in effect {active}")]
    RevisionConflict {
        /// The revision that the request names.
        reviewed: PolicyRevisionId,
        /// The revision in effect.
        active: PolicyRevisionId,
    },
    /// The profile in effect is `observe`, which permits no automatic
    /// intervention, or is not known.
    #[error("the profile in effect permits no automatic intervention")]
    ObserveProfile,
    /// The configuration in effect does not request the guard, so it can
    /// use no action class.
    #[error("the configuration in effect does not request the guard")]
    GuardNotRequested,
    /// The accepted action classes are not exactly the classes that the
    /// configuration of the guard can use.
    #[error("the accepted action classes are not the classes that the guard can use")]
    AcceptanceMismatch {
        /// The classes that the guard can use and that the request does not
        /// accept.
        missing: Vec<ActionClass>,
        /// The classes that the request accepts and that the guard cannot
        /// use.
        excess: Vec<ActionClass>,
    },
    /// The identity of the new grant is the identity of a grant of the
    /// record.
    #[error("the identity of the new action grant is in use")]
    GrantIdInUse,
}

/// The report of an enabled guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnableReport {
    /// The guard.
    #[serde(serialize_with = "policy_id::serialize")]
    pub policy: PolicyId,
    /// The grant and its generation.
    pub grant: ActionGrantRef,
    /// The policy revision that the grant is bound to.
    pub policy_revision: PolicyRevisionId,
    /// The action classes of the grant.
    pub action_classes: Vec<ActionClass>,
    /// True when the guard was active with the same grant before the
    /// request. The grant has no new generation then.
    pub unchanged: bool,
}

/// Checks the acceptance against the classes that the guard can use.
fn check_acceptance(
    required: &[ActionClass],
    accepted: &[ActionClass],
) -> Result<(), EnableRefusal> {
    let missing: Vec<ActionClass> = required
        .iter()
        .filter(|class| !accepted.contains(class))
        .cloned()
        .collect();
    let mut excess: Vec<ActionClass> = Vec::new();
    for class in accepted {
        if !required.contains(class) && !excess.contains(class) {
            excess.push(class.clone());
        }
    }
    if missing.is_empty() && excess.is_empty() {
        Ok(())
    } else {
        Err(EnableRefusal::AcceptanceMismatch { missing, excess })
    }
}

/// The grant that an acceptance of the scope of `active` gives.
fn accepted_grant(
    state: &AuthorityState,
    active: &ActiveRevision,
    earlier: Option<&ActionGrant>,
    request: &EnableRequest,
) -> Result<ActionGrant, EnableRefusal> {
    let policy: PolicyId = request.policy;
    // The grant keeps its identity and gets a larger generation. When the
    // generation cannot become larger, a new identity starts again.
    let continued =
        earlier.and_then(|grant| Some((grant.grant_id.clone(), grant.generation.next()?)));
    let (grant_id, generation) = if let Some(continued) = continued {
        continued
    } else {
        // A new identity is not the identity of a grant of the record: a
        // plan that names an earlier generation must not match.
        let in_use: bool = state.guards.iter().any(|guard| {
            guard
                .grant
                .as_ref()
                .is_some_and(|grant| grant.grant_id == request.grant_id)
        });
        if in_use {
            return Err(EnableRefusal::GrantIdInUse);
        }
        (request.grant_id.clone(), Generation::new(1))
    };
    Ok(ActionGrant {
        grant_id,
        generation,
        principal: state.principal,
        policy_revision: active.revision.revision_id.clone(),
        action_classes: active.scope.action_classes(policy),
        rules: active.scope.rules(policy),
        escalations: active.scope.escalations(policy),
        allow_volatile_journal_on_critical: policy == PolicyId::MemoryGuard
            && active.scope.memory.allow_volatile_journal_on_critical,
        granted_at: request.now,
        expires_at: None,
        revoked: false,
    })
}

/// Enables a guard with the acceptance of exactly the action classes that
/// its configuration can use.
///
/// The acceptance makes the action grant of the guard, or a larger
/// generation of it, bound to the policy revision in effect. The grant has
/// the action classes, the rule revisions, the force strategies, and the
/// critical-memory exception of that revision, and nothing more. A request
/// that changes nothing gives no new generation.
///
/// When the running instance inhibits the guard after a disable or a
/// revocation that was not persisted, the request is a new acceptance: the
/// grant gets a larger generation, so a plan that was prepared before the
/// restriction does not become valid again.
///
/// The change adds authority: when it cannot be persisted, nothing changes.
///
/// # Errors
///
/// Returns an [`EnableRefusal`] with the first condition that is not true.
pub fn enable(
    state: &AuthorityState,
    inhibition: &InstanceInhibition,
    request: &EnableRequest,
) -> Result<Change<EnableReport>, EnableRefusal> {
    if request.principal != state.principal {
        return Err(EnableRefusal::WrongPrincipal);
    }
    let active: &ActiveRevision = state
        .active
        .as_ref()
        .ok_or(EnableRefusal::NoActiveRevision)?;
    match &request.reviewed_revision {
        None if !request.interactive => return Err(EnableRefusal::ReviewedRevisionRequired),
        Some(reviewed) if reviewed != &active.revision.revision_id => {
            return Err(EnableRefusal::RevisionConflict {
                reviewed: reviewed.clone(),
                active: active.revision.revision_id.clone(),
            });
        }
        _ => {}
    }
    let policy: PolicyId = request.policy;
    if !active.scope.profile_permits_intervention() {
        return Err(EnableRefusal::ObserveProfile);
    }
    if !active.scope.requests(policy) {
        return Err(EnableRefusal::GuardNotRequested);
    }
    check_acceptance(&active.scope.action_classes(policy), &request.accepted)?;

    // An enable is the latest request of the user for this guard, so it
    // replaces the inhibition of a disable or a revocation that was not
    // persisted. It does not replace the inhibition of an activation that
    // was not persisted: only a durable activation changes the scope.
    let on_durable: Settled = Settled {
        clear_guards: [InhibitionCause::Disable, InhibitionCause::Revoke]
            .into_iter()
            .map(|cause| InhibitedGuard { policy, cause })
            .collect(),
        ..Settled::default()
    };
    let report = |grant: &ActionGrant, unchanged: bool| EnableReport {
        policy,
        grant: grant.reference(),
        policy_revision: grant.policy_revision.clone(),
        action_classes: grant.action_classes.clone(),
        unchanged,
    };

    let standing: GuardStanding = guard_standing(state, inhibition, policy, request.now);
    let current: Option<&GuardAuthority> = state.guard(policy);
    if let (GuardStanding::Active, Some(grant)) =
        (standing, current.and_then(|guard| guard.grant.as_ref()))
    {
        let unchanged: Change<EnableReport> = Change::new(
            state,
            state.clone(),
            report(grant, true),
            Fallback::default(),
            on_durable,
        );
        return Ok(unchanged);
    }

    let grant: ActionGrant = accepted_grant(
        state,
        active,
        current.and_then(|guard| guard.grant.as_ref()),
        request,
    )?;
    let mut next: AuthorityState = state.clone();
    let reviewed: PolicyScope = active.scope.clone();
    let entry: &mut GuardAuthority = next.guard_entry(policy);
    entry.enabled = true;
    entry.reviewed = Some(reviewed);
    let enabled: EnableReport = report(&grant, false);
    entry.grant = Some(grant);
    Ok(Change::new(
        state,
        next,
        enabled,
        Fallback::default(),
        on_durable,
    ))
}

/// The reason a disable or a revoke request was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlRefusal {
    /// The request is from a different user than the record.
    #[error("the request is from a different user than the authority record")]
    WrongPrincipal,
    /// The record has no grant with the identity.
    #[error("the action grant {grant_id} is not in the authority record")]
    UnknownGrant {
        /// The identity that the request names.
        grant_id: ActionGrantId,
    },
}

/// A request to disable a guard (`policy disable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisableRequest {
    /// The authenticated user of the request.
    pub principal: Uid,
    /// The guard.
    pub policy: PolicyId,
}

/// The report of a restriction of one guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestrictionReport {
    /// The guard.
    #[serde(serialize_with = "policy_id::serialize")]
    pub policy: PolicyId,
    /// The grant of the guard after the request, with its new generation.
    /// `None` when the guard has no grant.
    pub grant: Option<ActionGrantRef>,
    /// True when the record already had the content of the request.
    pub unchanged: bool,
}

/// The larger generation of a restricted grant. A plan that names the
/// earlier generation then does not match.
fn restrict(grant: &mut ActionGrant, revoke: bool) {
    if revoke {
        grant.revoked = true;
    }
    // When the generation cannot become larger, the revocation flag is the
    // only safe change that remains: a revoked grant covers nothing.
    match grant.generation.next() {
        Some(generation) => grant.generation = generation,
        None => grant.revoked = true,
    }
}

/// Disables a guard.
///
/// The guard does no new dispatch from this moment. Its grant stays in the
/// record with a larger generation, so a plan that was prepared before the
/// request does not become valid when the guard is enabled again. A new
/// enable needs a new acceptance.
///
/// The change is a restriction: when it cannot be persisted, the running
/// instance inhibits the guard, and the acknowledgement is
/// [`super::AcknowledgementLevel::CurrentInstanceInhibition`].
///
/// # Errors
///
/// Returns [`ControlRefusal::WrongPrincipal`] when the user is not the user
/// of the record.
pub fn disable(
    state: &AuthorityState,
    request: &DisableRequest,
) -> Result<Change<RestrictionReport>, ControlRefusal> {
    if request.principal != state.principal {
        return Err(ControlRefusal::WrongPrincipal);
    }
    let policy: PolicyId = request.policy;
    let inhibited: InhibitedGuard = InhibitedGuard {
        policy,
        cause: InhibitionCause::Disable,
    };
    let on_failure: Fallback = Fallback {
        guards: vec![inhibited],
        pause: None,
    };
    let on_durable: Settled = Settled {
        clear_guards: vec![inhibited],
        ..Settled::default()
    };
    let mut next: AuthorityState = state.clone();
    let unchanged: bool = !state.guard(policy).is_some_and(|guard| guard.enabled);
    if !unchanged {
        let entry: &mut GuardAuthority = next.guard_entry(policy);
        entry.enabled = false;
        if let Some(grant) = &mut entry.grant {
            restrict(grant, false);
        }
    }
    let report: RestrictionReport = RestrictionReport {
        policy,
        grant: next
            .guard(policy)
            .and_then(|guard| guard.grant.as_ref())
            .map(ActionGrant::reference),
        unchanged,
    };
    Ok(Change::new(state, next, report, on_failure, on_durable))
}

/// A request to revoke an action grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeRequest {
    /// The authenticated user of the request.
    pub principal: Uid,
    /// The grant.
    pub grant_id: ActionGrantId,
}

/// Revokes an action grant.
///
/// The grant covers nothing from this moment, and it gets a larger
/// generation. The guard keeps its enabled flag and has the standing
/// [`GuardStanding::GrantRevoked`] until a new acceptance.
///
/// The change is a restriction: when it cannot be persisted, the running
/// instance inhibits the guard of the grant.
///
/// # Errors
///
/// Returns a [`ControlRefusal`] when the user is not the user of the
/// record, or when the record has no grant with the identity.
pub fn revoke(
    state: &AuthorityState,
    request: &RevokeRequest,
) -> Result<Change<RestrictionReport>, ControlRefusal> {
    if request.principal != state.principal {
        return Err(ControlRefusal::WrongPrincipal);
    }
    let has_grant = |guard: &&GuardAuthority| {
        guard
            .grant
            .as_ref()
            .is_some_and(|grant| grant.grant_id == request.grant_id)
    };
    let policy: PolicyId = state
        .guards
        .iter()
        .find(has_grant)
        .map(|guard| guard.policy)
        .ok_or_else(|| ControlRefusal::UnknownGrant {
            grant_id: request.grant_id.clone(),
        })?;
    // Each guard with the identity is inhibited, also when the record has
    // the identity for more than one guard.
    let inhibited: Vec<InhibitedGuard> = state
        .guards
        .iter()
        .filter(has_grant)
        .map(|guard| InhibitedGuard {
            policy: guard.policy,
            cause: InhibitionCause::Revoke,
        })
        .collect();
    let on_failure: Fallback = Fallback {
        guards: inhibited.clone(),
        pause: None,
    };
    let on_durable: Settled = Settled {
        clear_guards: inhibited,
        ..Settled::default()
    };
    let mut next: AuthorityState = state.clone();
    let mut unchanged: bool = true;
    // Each entry with the identity is revoked, also when the record has an
    // entry two times.
    for guard in &mut next.guards {
        if let Some(grant) = guard
            .grant
            .as_mut()
            .filter(|grant| grant.grant_id == request.grant_id && !grant.revoked)
        {
            restrict(grant, true);
            unchanged = false;
        }
    }
    let report: RestrictionReport = RestrictionReport {
        policy,
        grant: next
            .guards
            .iter()
            .find(has_grant)
            .and_then(|guard| guard.grant.as_ref())
            .map(ActionGrant::reference),
        unchanged,
    };
    Ok(Change::new(state, next, report, on_failure, on_durable))
}
