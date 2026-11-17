//! The authority state that the caller keeps, and the acknowledgement of a
//! change.
//!
//! [`AuthorityState`] is the durable record. [`InstanceInhibition`] is the
//! volatile record of the running instance: it can only remove authority,
//! and it has no JSON encoding, so it cannot be persisted by accident. The
//! authority in effect is the durable record less the inhibition.

use serde::{Deserialize, Serialize};

use super::pause::{MeasurementFloor, Pause};
use super::scope::PolicyScope;
use crate::authority::{ActionGrant, PolicyRevision};
use crate::policy::PolicyId;
use crate::process::Uid;

/// The JSON encoding of a [`PolicyId`]: its command name.
pub(super) mod policy_id {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::policy::PolicyId;

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde gives the field as a reference"
    )]
    pub(in crate::grant) fn serialize<S: Serializer>(
        policy: &PolicyId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(policy.as_str())
    }

    pub(in crate::grant) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PolicyId, D::Error> {
        let text: String = String::deserialize(deserializer)?;
        PolicyId::from_text(&text).ok_or_else(|| D::Error::custom("the policy is not known"))
    }
}

/// The policy revision in effect and the scope that it gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveRevision {
    /// The revision record.
    pub revision: PolicyRevision,
    /// The scope of the validated configuration of the revision.
    pub scope: PolicyScope,
}

/// The standing authority of one guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardAuthority {
    /// The guard.
    #[serde(with = "policy_id")]
    pub policy: PolicyId,
    /// True when the user enabled the guard and did not disable it.
    pub enabled: bool,
    /// The action grant of the guard. One guard has one grant; each change
    /// makes a larger generation.
    pub grant: Option<ActionGrant>,
    /// The scope that the latest acceptance reviewed, or the narrower scope
    /// that an activation carried the grant to. The grant covers no scope
    /// that is wider than this one.
    pub reviewed: Option<PolicyScope>,
}

impl GuardAuthority {
    const fn new(policy: PolicyId) -> Self {
        Self {
            policy,
            enabled: false,
            grant: None,
            reviewed: None,
        }
    }
}

/// The durable authority record of one user.
///
/// The caller reads the record from its store, gives it to a function of
/// this module, and writes the `next` record of the [`Change`] in one
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityState {
    /// The user that the record belongs to.
    pub principal: Uid,
    /// The policy revision in effect. `None` before the first activation.
    pub active: Option<ActiveRevision>,
    /// The guards. A guard with no entry has no authority.
    pub guards: Vec<GuardAuthority>,
    /// The pause of automatic intervention.
    pub pause: Option<Pause>,
}

impl AuthorityState {
    /// The record of a user with no activation, no grant, and no pause.
    pub const fn new(principal: Uid) -> Self {
        Self {
            principal,
            active: None,
            guards: Vec::new(),
            pause: None,
        }
    }

    /// The authority of `policy`. `None` when the record has no entry, and
    /// also when it has more than one: a record that does not agree with
    /// itself gives no authority.
    pub fn guard(&self, policy: PolicyId) -> Option<&GuardAuthority> {
        let mut entries = self.guards.iter().filter(|guard| guard.policy == policy);
        let first: &GuardAuthority = entries.next()?;
        entries.next().is_none().then_some(first)
    }

    /// The entry of `policy` for a change. A missing entry is added. Entries
    /// that occur more than one time are replaced by one entry with no
    /// authority.
    pub(super) fn guard_entry(&mut self, policy: PolicyId) -> &mut GuardAuthority {
        let count: usize = self
            .guards
            .iter()
            .filter(|guard| guard.policy == policy)
            .count();
        if count != 1 {
            self.guards.retain(|guard| guard.policy != policy);
            self.guards.push(GuardAuthority::new(policy));
        }
        let index: usize = self
            .guards
            .iter()
            .position(|guard| guard.policy == policy)
            .unwrap_or_default();
        &mut self.guards[index]
    }
}

/// The cause of a current-instance inhibition of a guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InhibitionCause {
    /// A disable request that was not persisted.
    Disable,
    /// A revocation that was not persisted.
    Revoke,
    /// An activation that restricts the guard and that was not persisted.
    Restriction,
}

/// One guard that the running instance inhibits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct InhibitedGuard {
    /// The guard.
    #[serde(serialize_with = "policy_id::serialize")]
    pub policy: PolicyId,
    /// The cause.
    pub cause: InhibitionCause,
}

/// The volatile control state of the running instance.
///
/// The value only removes authority. It is lost at a restart, and the
/// durable record then applies again (`docs/INTERFACES.md` section 13). It
/// has no decoding, so a store cannot give it back as durable state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstanceInhibition {
    /// The guards that do no new dispatch in this instance.
    pub guards: Vec<InhibitedGuard>,
    /// A pause that was not persisted.
    pub pause: Option<Pause>,
    /// The time of the latest resume. An automatic action needs a
    /// measurement that is not older.
    pub measurement_floor: Option<MeasurementFloor>,
}

impl InstanceInhibition {
    /// Whether the instance inhibits `policy`.
    pub fn inhibits(&self, policy: PolicyId) -> bool {
        self.guards.iter().any(|guard| guard.policy == policy)
    }

    fn add_guard(&mut self, guard: InhibitedGuard) {
        if !self.guards.contains(&guard) {
            self.guards.push(guard);
        }
    }
}

/// The result of the attempt to persist the `next` record of a [`Change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Persistence {
    /// The record is durable.
    Durable,
    /// The write failed, or no store was available.
    Failed,
}

/// The acknowledgement level of a control request
/// (`docs/INTERFACES.md` section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementLevel {
    /// The authoritative state persisted before the acknowledgement.
    DurablyApplied,
    /// Persistence failed. The running instance inhibits the affected
    /// dispatch; a restart can bring the earlier durable state back.
    CurrentInstanceInhibition,
    /// Persistence failed and the request adds authority. Nothing changed.
    NotApplied,
}

/// What the running instance inhibits when the record cannot be persisted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Fallback {
    pub(super) guards: Vec<InhibitedGuard>,
    pub(super) pause: Option<Pause>,
}

impl Fallback {
    fn is_empty(&self) -> bool {
        self.guards.is_empty() && self.pause.is_none()
    }
}

/// What a durable record makes unnecessary in the volatile state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Settled {
    pub(super) clear_guards: Vec<InhibitedGuard>,
    pub(super) clear_pause: bool,
    pub(super) floor: Option<MeasurementFloor>,
}

/// A change of the authority record that is not persisted yet.
///
/// Sequence for the caller:
///
/// 1. When [`Change::is_restriction`] is true, replace the volatile state
///    with [`Change::inhibit_now`], so that the restriction applies to new
///    dispatch at once.
/// 2. When [`Change::needs_persistence`] is true, write `next`.
/// 3. Give the result to [`Change::acknowledge`], and keep the state and the
///    inhibition of the [`Acknowledged`] value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change<R> {
    previous: AuthorityState,
    /// The record to persist.
    pub next: AuthorityState,
    /// The report of the change.
    pub report: R,
    on_failure: Fallback,
    on_durable: Settled,
}

/// A change with its acknowledgement level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledged<R> {
    /// The level that the client is told.
    pub level: AcknowledgementLevel,
    /// The durable record after the attempt: `next` when the write was
    /// durable, the earlier record when it failed.
    pub state: AuthorityState,
    /// The volatile state after the attempt.
    pub inhibition: InstanceInhibition,
    /// The report of the change.
    pub report: R,
}

impl<R> Change<R> {
    pub(super) fn new(
        previous: &AuthorityState,
        next: AuthorityState,
        report: R,
        on_failure: Fallback,
        on_durable: Settled,
    ) -> Self {
        Self {
            previous: previous.clone(),
            next,
            report,
            on_failure,
            on_durable,
        }
    }

    /// Whether `next` is different from the record that the change started
    /// from. When it is not, there is nothing to write.
    pub fn needs_persistence(&self) -> bool {
        self.next != self.previous
    }

    /// Whether the change removes authority, so that it applies to the
    /// running instance also when it cannot be persisted.
    pub fn is_restriction(&self) -> bool {
        !self.on_failure.is_empty()
    }

    /// The volatile state with the restriction of this change. Use it
    /// before the write, so that new dispatch stops at once.
    pub fn inhibit_now(&self, inhibition: &InstanceInhibition) -> InstanceInhibition {
        let mut inhibition: InstanceInhibition = inhibition.clone();
        for guard in &self.on_failure.guards {
            inhibition.add_guard(*guard);
        }
        if let Some(pause) = &self.on_failure.pause {
            inhibition.pause = Some(match inhibition.pause.take() {
                Some(current) => Pause::longer(current, pause.clone()),
                None => pause.clone(),
            });
        }
        inhibition
    }

    /// Completes the change with the result of the write.
    ///
    /// - A durable write gives [`AcknowledgementLevel::DurablyApplied`] and
    ///   the `next` record. A change with nothing to write counts as
    ///   durable: the durable record already has its content.
    /// - A failed write of a restriction gives
    ///   [`AcknowledgementLevel::CurrentInstanceInhibition`]: the durable
    ///   record is the earlier one, and the volatile state inhibits the
    ///   affected dispatch.
    /// - A failed write of a change that adds authority gives
    ///   [`AcknowledgementLevel::NotApplied`], and nothing changes.
    ///
    /// `inhibition` is the volatile state of the caller, with or without
    /// [`Change::inhibit_now`].
    pub fn acknowledge(
        self,
        inhibition: &InstanceInhibition,
        persistence: Persistence,
    ) -> Acknowledged<R> {
        let durable: bool = persistence == Persistence::Durable || !self.needs_persistence();
        if durable {
            let mut inhibition: InstanceInhibition = inhibition.clone();
            inhibition
                .guards
                .retain(|guard| !self.on_durable.clear_guards.contains(guard));
            if self.on_durable.clear_pause {
                inhibition.pause = None;
            }
            if let Some(floor) = self.on_durable.floor {
                inhibition.measurement_floor = Some(floor);
            }
            return Acknowledged {
                level: AcknowledgementLevel::DurablyApplied,
                state: self.next,
                inhibition,
                report: self.report,
            };
        }
        if self.is_restriction() {
            let inhibition: InstanceInhibition = self.inhibit_now(inhibition);
            return Acknowledged {
                level: AcknowledgementLevel::CurrentInstanceInhibition,
                state: self.previous,
                inhibition,
                report: self.report,
            };
        }
        Acknowledged {
            level: AcknowledgementLevel::NotApplied,
            state: self.previous,
            inhibition: inhibition.clone(),
            report: self.report,
        }
    }
}
