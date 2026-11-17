//! Activation of a validated configuration as the policy revision in
//! effect (`config apply`).
//!
//! `docs/POLICY_SPEC.md` section 5 owns the activation. An edit of the
//! configuration file activates nothing: only [`activate`] makes a
//! [`PolicyRevision`], and only when the expected revision of the request
//! is the revision in effect.

use serde::Serialize;
use thiserror::Error;

use super::guard::{GuardStanding, guard_standing, uncovered};
use super::scope::{
    PolicyScope, ScopeDifference, ScopeDifferenceKind, ScopeEffect, ScopeError, difference,
    effect_on,
};
use super::state::{
    ActiveRevision, AuthorityState, Change, Fallback, GuardAuthority, InhibitedGuard,
    InhibitionCause, InstanceInhibition, Settled, policy_id,
};
use crate::authority::PolicyRevision;
use crate::config::ValidatedConfig;
use crate::digest::ContentDigest;
use crate::id::PolicyRevisionId;
use crate::policy::PolicyId;
use crate::process::Uid;
use crate::rule::{LifecycleState, RuleRef, RuleRegistry};
use crate::time::WallTime;

/// A request to activate a validated configuration.
#[derive(Debug, Clone)]
pub struct ActivationRequest<'a> {
    /// The authenticated user of the request.
    pub principal: Uid,
    /// The validated configuration.
    pub config: &'a ValidatedConfig,
    /// The digest of the configuration document that `config` was parsed
    /// from. The caller computes it from the bytes that it validated.
    pub content: ContentDigest,
    /// The revision that the client expects to be in effect
    /// (`--expected-revision`). `None` expects that no revision is in
    /// effect.
    pub expected_revision: Option<PolicyRevisionId>,
    /// The identity of the new revision.
    pub revision_id: PolicyRevisionId,
    /// The wall-clock time of the request.
    pub now: WallTime,
}

/// The reason an activation was refused. The revision in effect does not
/// change.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ActivationRefusal {
    /// The request is from a different user than the record.
    #[error("the request is from a different user than the authority record")]
    WrongPrincipal,
    /// The expected revision is not the revision in effect. The client
    /// must evaluate the proposal against the revision in effect again;
    /// nothing is overwritten.
    #[error("the expected policy revision is not the revision in effect")]
    RevisionConflict {
        /// The revision that the request expects.
        expected: Option<PolicyRevisionId>,
        /// The revision in effect.
        active: Option<PolicyRevisionId>,
        /// True when the revision in effect has the content of the
        /// request. A client that lost the reply of an earlier apply can
        /// then see that its configuration is in effect.
        content_is_active: bool,
    },
    /// The identity of the new revision is the identity of the revision in
    /// effect.
    #[error("the identity of the new policy revision is in use")]
    RevisionIdInUse,
    /// The configuration has no scope.
    #[error(transparent)]
    Scope(#[from] ScopeError),
}

/// The result of an activation for one guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardActivation {
    /// The guard.
    #[serde(serialize_with = "policy_id::serialize")]
    pub policy: PolicyId,
    /// The effect of the differences from the earlier revision on the
    /// guard.
    pub effect: ScopeEffect,
    /// The standing of the guard with the new revision.
    pub standing: GuardStanding,
    /// The widening differences from the scope that the grant of the guard
    /// covers to the new scope. A new acceptance is necessary when the
    /// list is not empty.
    pub uncovered: Vec<ScopeDifference>,
}

/// The report of an activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivationReport {
    /// The revision in effect after the request.
    pub revision: PolicyRevision,
    /// The revision that was in effect before the request.
    pub previous: Option<PolicyRevisionId>,
    /// True when the revision in effect already had the content and the
    /// scope of the request. No new revision was made.
    pub unchanged: bool,
    /// The differences from the earlier scope to the new scope. For the
    /// first activation, the earlier scope is the empty scope, and the
    /// thresholds are not listed.
    pub differences: Vec<ScopeDifference>,
    /// The result for each guard.
    pub guards: Vec<GuardActivation>,
    /// True when the revision changed: each plan that is not consumed and
    /// that names the earlier revision is then invalid
    /// (`docs/POLICY_SPEC.md` section 5).
    pub invalidates_unconsumed_plans: bool,
    /// The approved rule revisions with no layout that is validated for
    /// automatic eviction. The authorization refuses their automatic use.
    pub rules_not_validated: Vec<RuleRef>,
}

/// The approved rule revisions with no layout that is validated for
/// automatic eviction.
fn rules_not_validated(scope: &PolicyScope, registry: &dyn RuleRegistry) -> Vec<RuleRef> {
    scope
        .rules(PolicyId::DiskGuard)
        .into_iter()
        .filter(|reference| {
            !registry.rule(reference).is_some_and(|rule| {
                rule.layouts.iter().any(|support| {
                    matches!(
                        support.lifecycle,
                        LifecycleState::AutomaticEvictionValidated { .. }
                    )
                })
            })
        })
        .collect()
}

/// Binds the grant of `guard` to the new revision, and removes from it
/// what the new scope does not use. Returns `false` when the generation of
/// the grant cannot become larger; the grant then stays as it is and does
/// not cover the new revision.
fn carry_forward(
    guard: &mut GuardAuthority,
    revision_id: &PolicyRevisionId,
    scope: &PolicyScope,
) -> bool {
    let policy: PolicyId = guard.policy;
    let Some(grant) = &mut guard.grant else {
        return false;
    };
    let Some(generation) = grant.generation.next() else {
        return false;
    };
    let classes = scope.action_classes(policy);
    let escalations = scope.escalations(policy);
    let rules = scope.rules(policy);
    grant.generation = generation;
    grant.policy_revision = revision_id.clone();
    grant.action_classes.retain(|class| classes.contains(class));
    grant
        .escalations
        .retain(|escalation| escalations.contains(escalation));
    grant.rules.retain(|rule| rules.contains(rule));
    grant.allow_volatile_journal_on_critical = grant.allow_volatile_journal_on_critical
        && policy == PolicyId::MemoryGuard
        && scope.memory.allow_volatile_journal_on_critical;
    true
}

/// The differences of a first activation or of a later one.
fn reported_differences(
    previous: Option<&ActiveRevision>,
    scope: &PolicyScope,
) -> Vec<ScopeDifference> {
    match previous {
        Some(active) => difference(&active.scope, scope),
        None => difference(&PolicyScope::none(), scope)
            .into_iter()
            .filter(|difference| difference.kind != ScopeDifferenceKind::Threshold)
            .collect(),
    }
}

fn check_expected(
    state: &AuthorityState,
    request: &ActivationRequest<'_>,
) -> Result<(), ActivationRefusal> {
    let active: Option<&PolicyRevision> = state.active.as_ref().map(|active| &active.revision);
    let active_id: Option<&PolicyRevisionId> = active.map(|revision| &revision.revision_id);
    if request.expected_revision.as_ref() != active_id {
        return Err(ActivationRefusal::RevisionConflict {
            expected: request.expected_revision.clone(),
            active: active_id.cloned(),
            content_is_active: active.is_some_and(|revision| revision.content == request.content),
        });
    }
    Ok(())
}

/// The report of a request whose content and scope are in effect already.
fn unchanged_report(
    state: &AuthorityState,
    active: &ActiveRevision,
    registry: &dyn RuleRegistry,
    now: WallTime,
) -> ActivationReport {
    let guards: Vec<GuardActivation> = PolicyId::ALL
        .iter()
        .map(|policy| GuardActivation {
            policy: *policy,
            effect: ScopeEffect::Neutral,
            standing: guard_standing(state, &InstanceInhibition::default(), *policy, now),
            uncovered: state
                .guard(*policy)
                .and_then(|guard| uncovered(guard, &active.scope))
                .unwrap_or_default(),
        })
        .collect();
    ActivationReport {
        revision: active.revision.clone(),
        previous: Some(active.revision.revision_id.clone()),
        unchanged: true,
        differences: Vec::new(),
        guards,
        invalidates_unconsumed_plans: false,
        rules_not_validated: rules_not_validated(&active.scope, registry),
    }
}

/// What the running instance inhibits when the activation cannot be
/// persisted, and what a durable activation makes unnecessary.
fn persistence_effects(guards: &[GuardActivation]) -> (Fallback, Settled) {
    let restriction = |policy: PolicyId| InhibitedGuard {
        policy,
        cause: InhibitionCause::Restriction,
    };
    // When the request cannot be persisted, the earlier revision stays in
    // effect. A guard that the request restricts is inhibited, also when
    // the request widens the scope of the other guard
    // (`docs/POLICY_SPEC.md` section 5).
    let on_failure: Fallback = Fallback {
        guards: guards
            .iter()
            .filter(|guard| guard.effect == ScopeEffect::Narrowing)
            .map(|guard| restriction(guard.policy))
            .collect(),
        pause: None,
    };
    // A durable activation makes each earlier restriction of an activation
    // durable or obsolete.
    let on_durable: Settled = Settled {
        clear_guards: PolicyId::ALL.iter().copied().map(restriction).collect(),
        ..Settled::default()
    };
    (on_failure, on_durable)
}

/// Activates a validated configuration.
///
/// The request names the revision that the client expects to be in
/// effect. A different revision in effect is a conflict, and the record
/// does not change. When the revision in effect already has the content
/// and the scope of the request, the report says so and no new revision is
/// made.
///
/// For each guard, the function compares the new scope with the scope that
/// the grant of the guard covers:
///
/// - No widening difference: the grant gets a larger generation, is bound
///   to the new revision, and loses what the new scope does not use. No
///   acceptance is necessary.
/// - A widening difference: the grant does not change. It stays bound to
///   the earlier revision, the guard has the standing
///   [`GuardStanding::AcceptanceRequired`], and
///   [`GuardActivation::uncovered`] lists what needs the acceptance.
///
/// The activation makes no grant, and the profile makes none.
///
/// When the record cannot be persisted, the earlier revision stays in
/// effect. The running instance inhibits each guard whose scope the
/// request makes narrower, and the acknowledgement is
/// [`super::AcknowledgementLevel::CurrentInstanceInhibition`]. When the
/// request makes no guard narrower, the acknowledgement is
/// [`super::AcknowledgementLevel::NotApplied`]. A wider scope never
/// applies without a durable record.
///
/// # Errors
///
/// Returns an [`ActivationRefusal`] when the user is not the user of the
/// record, when the expected revision is not the revision in effect, when
/// the new identity is in use, or when the configuration has no scope.
pub fn activate(
    state: &AuthorityState,
    request: &ActivationRequest<'_>,
    registry: &dyn RuleRegistry,
) -> Result<Change<ActivationReport>, ActivationRefusal> {
    if request.principal != state.principal {
        return Err(ActivationRefusal::WrongPrincipal);
    }
    check_expected(state, request)?;
    let scope: PolicyScope = PolicyScope::of(request.config, registry)?;
    let previous: Option<&ActiveRevision> = state.active.as_ref();
    let standing = |state: &AuthorityState, policy: PolicyId| {
        guard_standing(state, &InstanceInhibition::default(), policy, request.now)
    };

    if let Some(active) = previous
        .filter(|active| active.revision.content == request.content && active.scope == scope)
    {
        let report: ActivationReport = unchanged_report(state, active, registry, request.now);
        return Ok(Change::new(
            state,
            state.clone(),
            report,
            Fallback::default(),
            Settled::default(),
        ));
    }
    if previous.is_some_and(|active| active.revision.revision_id == request.revision_id) {
        return Err(ActivationRefusal::RevisionIdInUse);
    }

    let revision: PolicyRevision = PolicyRevision {
        revision_id: request.revision_id.clone(),
        schema_version: request.config.schema_version(),
        content: request.content.clone(),
        activated_at: request.now,
    };
    let differences: Vec<ScopeDifference> = reported_differences(previous, &scope);
    let mut next: AuthorityState = state.clone();
    next.active = Some(ActiveRevision {
        revision: revision.clone(),
        scope: scope.clone(),
    });
    let mut open: Vec<(PolicyId, Vec<ScopeDifference>)> = Vec::new();
    for guard in &mut next.guards {
        let Some(widening) = uncovered(guard, &scope) else {
            continue;
        };
        let revoked: bool = guard.grant.as_ref().is_some_and(|grant| grant.revoked);
        if widening.is_empty() && !revoked && carry_forward(guard, &request.revision_id, &scope) {
            guard.reviewed = Some(scope.clone());
        } else {
            open.push((guard.policy, widening));
        }
    }

    let guards: Vec<GuardActivation> = PolicyId::ALL
        .iter()
        .map(|policy| GuardActivation {
            policy: *policy,
            effect: effect_on(&differences, *policy),
            standing: standing(&next, *policy),
            uncovered: open
                .iter()
                .find(|(guard, _)| guard == policy)
                .map_or_default(|(_, widening)| widening.clone()),
        })
        .collect();
    let (on_failure, on_durable) = persistence_effects(&guards);
    let report: ActivationReport = ActivationReport {
        revision,
        previous: previous.map(|active| active.revision.revision_id.clone()),
        unchanged: false,
        differences,
        guards,
        invalidates_unconsumed_plans: true,
        rules_not_validated: rules_not_validated(&scope, registry),
    };
    Ok(Change::new(state, next, report, on_failure, on_durable))
}
