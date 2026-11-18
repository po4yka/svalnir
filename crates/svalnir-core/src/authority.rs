//! The three authority records.
//!
//! `docs/ARCHITECTURE.md` section 11 owns the records. A [`PolicyRevision`]
//! describes behavior, an [`ActionGrant`] authorizes product actions, and a
//! [`PrivilegeGrant`] limits the helper independently. They are distinct
//! types: one cannot be used in the place of another.
//!
//! This module has the records and the questions that a record can answer
//! about itself. The activation and revocation logic is in
//! [`crate::grant`].

use serde::{Deserialize, Serialize};

use crate::action::{ActionClass, Escalation, WorkCharge};
use crate::digest::ContentDigest;
use crate::encoding::{checked_arithmetic, unsigned_quantity};
use crate::id::{ActionGrantId, PolicyRevisionId, PrivilegeGrantId, RootId};
use crate::process::Uid;
use crate::rule::RuleRef;
use crate::time::WallTime;

unsigned_quantity! {
    /// The generation of a grant. Each change and each revocation of the
    /// grant makes a larger generation, so a plan that names an earlier
    /// generation does not match.
    Generation
}
checked_arithmetic!(Generation);

impl Generation {
    /// The generation after this one. `None` on overflow.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        self.checked_add(Self::new(1))
    }
}

/// The decoding of an optional field of an authority record that must be
/// present in the encoded form, with `null` for an absent value.
///
/// The derived decoding gives `None` for a key that is absent. For an
/// expiry, a pause, or a bound grant, `None` is the value that restricts
/// least, so a record with a missing or misspelled key would decode with
/// more authority than it was written with. With this function the absent
/// key is a decoding error.
pub(crate) mod required_option {
    use serde::{Deserialize, Deserializer};

    pub(crate) fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Option::<T>::deserialize(deserializer)
    }
}

/// One activated policy revision: the validated configuration that is in
/// effect.
///
/// The record cannot grant OS access and cannot broaden a helper limit. An
/// edit of the configuration file does not make a revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevision {
    /// The identity of the revision.
    pub revision_id: PolicyRevisionId,
    /// The schema version of the configuration.
    pub schema_version: u32,
    /// The digest of the validated configuration.
    pub content: ContentDigest,
    /// The wall-clock time of the activation, for history only.
    pub activated_at: WallTime,
}

/// A reference to one generation of an action grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionGrantRef {
    /// The grant.
    pub grant_id: ActionGrantId,
    /// The generation that the plan was built with.
    pub generation: Generation,
}

/// A reference to one generation of a privilege grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeGrantRef {
    /// The grant.
    pub grant_id: PrivilegeGrantId,
    /// The revocation generation that the plan was built with.
    pub generation: Generation,
}

/// Standing product consent for specified actions.
///
/// The record is same-user state. It is not independent proof of human
/// intent, and it does not make an incompatible rule or a broader target
/// valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionGrant {
    /// The identity of the grant.
    pub grant_id: ActionGrantId,
    /// The generation of this record.
    pub generation: Generation,
    /// The user that gave the consent.
    pub principal: Uid,
    /// The policy revision that the consent was given for.
    pub policy_revision: PolicyRevisionId,
    /// The action classes that the grant covers.
    pub action_classes: Vec<ActionClass>,
    /// The rule revisions that the grant covers for
    /// `EvictRegenerableData`.
    pub rules: Vec<RuleRef>,
    /// The force strategies that the grant permits, in addition to a
    /// graceful request: `force_after_grace`, `immediate_force`, or both.
    pub escalations: Vec<Escalation>,
    /// Whether the critical-memory exception of the journal is permitted.
    pub allow_volatile_journal_on_critical: bool,
    /// The wall-clock time of the consent, for history only.
    pub granted_at: WallTime,
    /// The time after which the grant does not apply. `None` means that the
    /// grant applies until it is revoked.
    #[serde(deserialize_with = "required_option::deserialize")]
    pub expires_at: Option<WallTime>,
    /// True when the grant was revoked. A revoked grant covers nothing.
    pub revoked: bool,
}

impl ActionGrant {
    /// The reference to this generation.
    pub fn reference(&self) -> ActionGrantRef {
        ActionGrantRef {
            grant_id: self.grant_id.clone(),
            generation: self.generation,
        }
    }

    /// Whether the grant applies at `now`: it is not revoked and not
    /// expired. The grant does not apply at its expiry time.
    pub fn is_in_effect(&self, now: WallTime) -> bool {
        !self.revoked && self.expires_at.is_none_or(|expiry| now < expiry)
    }

    /// Whether `reference` names this grant and this generation.
    pub fn matches(&self, reference: &ActionGrantRef) -> bool {
        self.grant_id == reference.grant_id && self.generation == reference.generation
    }

    /// Whether the grant covers `class` at `now`. A class that this build
    /// does not recognize is not covered.
    pub fn covers_class(&self, class: &ActionClass, now: WallTime) -> bool {
        self.is_in_effect(now) && class.is_recognized() && self.action_classes.contains(class)
    }

    /// Whether the grant covers the exact rule revision at `now`.
    pub fn covers_rule(&self, rule: &RuleRef, now: WallTime) -> bool {
        self.covers_class(&ActionClass::EvictRegenerableData, now) && self.rules.contains(rule)
    }

    /// Whether the grant permits an application intervention with the
    /// force strategy `escalation` at `now`: it covers the action class of
    /// each step, and it names the strategy when the strategy has a force
    /// step. An escalation that this build does not recognize is not
    /// permitted.
    pub fn permits_escalation(&self, escalation: &Escalation, now: WallTime) -> bool {
        let graceful: bool = self.covers_class(&ActionClass::RequestApplicationExit, now);
        let force: bool = self.covers_class(&ActionClass::ForceApplicationExit, now)
            && self.escalations.contains(escalation);
        match escalation {
            Escalation::None => graceful,
            // The graceful step comes first.
            Escalation::ForceAfterGrace => graceful && force,
            Escalation::ImmediateForce => force,
            Escalation::Unrecognized(_) => false,
        }
    }
}

/// Administrator-approved limits that the helper owns.
///
/// The helper enforces the record independently of the policy, the paths,
/// the catalogs, and the metrics of the caller. An agent counter cannot
/// authorize a helper action over this ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeGrant {
    /// The identity of the grant.
    pub grant_id: PrivilegeGrantId,
    /// The revocation generation of this record.
    pub generation: Generation,
    /// The user whose requests the grant covers.
    pub principal: Uid,
    /// The action classes that the helper can do for the principal.
    pub action_classes: Vec<ActionClass>,
    /// The approved roots. The helper resolves each root again.
    pub roots: Vec<RootId>,
    /// The ceiling of one delegated operation.
    pub ceiling: WorkCharge,
    /// Whether the helper permits the critical-memory exception of the
    /// journal.
    pub allow_volatile_journal_on_critical: bool,
    /// The wall-clock time of the approval, for history only.
    pub approved_at: WallTime,
    /// The time after which the grant does not apply.
    #[serde(deserialize_with = "required_option::deserialize")]
    pub expires_at: Option<WallTime>,
    /// True when the grant was revoked.
    pub revoked: bool,
}

impl PrivilegeGrant {
    /// The reference to this generation.
    pub fn reference(&self) -> PrivilegeGrantRef {
        PrivilegeGrantRef {
            grant_id: self.grant_id.clone(),
            generation: self.generation,
        }
    }

    /// Whether the grant applies at `now`: it is not revoked and not
    /// expired.
    pub fn is_in_effect(&self, now: WallTime) -> bool {
        !self.revoked && self.expires_at.is_none_or(|expiry| now < expiry)
    }

    /// Whether `reference` names this grant and this generation.
    pub fn matches(&self, reference: &PrivilegeGrantRef) -> bool {
        self.grant_id == reference.grant_id && self.generation == reference.generation
    }

    /// Whether the grant covers a delegated step of `class` for
    /// `principal` under `root` with `charge` at `now`.
    pub fn covers(
        &self,
        principal: Uid,
        class: &ActionClass,
        root: &RootId,
        charge: &WorkCharge,
        now: WallTime,
    ) -> bool {
        self.is_in_effect(now)
            && self.principal == principal
            && class.is_recognized()
            && self.action_classes.contains(class)
            && self.roots.contains(root)
            && charge.fits_in(&self.ceiling)
    }
}

/// The authority that a plan binds to. A change of one of these values
/// after the plan was built stops the plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBinding {
    /// The effective policy revision.
    pub policy_revision: PolicyRevisionId,
    /// The action grants and their generations. A manual plan can have
    /// none: its authority is the approval that is bound to the plan.
    pub action_grants: Vec<ActionGrantRef>,
    /// The privilege grant, when a helper does a step of the plan.
    #[serde(deserialize_with = "required_option::deserialize")]
    pub privilege_grant: Option<PrivilegeGrantRef>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ActionGrant, ActionGrantRef, AuthorityBinding, Generation, PolicyRevision, PrivilegeGrant,
    };
    use crate::action::{ActionClass, Escalation, WorkCharge};
    use crate::digest::ContentDigest;
    use crate::id::{
        ActionGrantId, PolicyRevisionId, PrivilegeGrantId, RootId, RuleId, RuleRevisionId,
    };
    use crate::process::Uid;
    use crate::quantity::{Bytes, EntryCount};
    use crate::rule::RuleRef;
    use crate::time::WallTime;

    fn at(seconds: i64) -> WallTime {
        WallTime::from_unix(seconds, 0).unwrap()
    }

    fn rule(revision: &str) -> RuleRef {
        RuleRef {
            id: RuleId::new("svalnir.expired-temporary").unwrap(),
            revision: RuleRevisionId::new(revision).unwrap(),
        }
    }

    fn action_grant() -> ActionGrant {
        ActionGrant {
            grant_id: ActionGrantId::new("grant_1").unwrap(),
            generation: Generation::new(3),
            principal: Uid::new(501),
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_classes: vec![
                ActionClass::EvictRegenerableData,
                ActionClass::RequestApplicationExit,
                ActionClass::ForceApplicationExit,
            ],
            rules: vec![rule("r1")],
            escalations: vec![Escalation::ForceAfterGrace],
            allow_volatile_journal_on_critical: false,
            granted_at: at(100),
            expires_at: Some(at(200)),
            revoked: false,
        }
    }

    fn privilege_grant() -> PrivilegeGrant {
        PrivilegeGrant {
            grant_id: PrivilegeGrantId::new("privilege_1").unwrap(),
            generation: Generation::new(1),
            principal: Uid::new(501),
            action_classes: vec![ActionClass::EvictRegenerableData],
            roots: vec![RootId::new("root_1").unwrap()],
            ceiling: WorkCharge::new(Bytes::new(1_000), EntryCount::new(10)),
            allow_volatile_journal_on_critical: false,
            approved_at: at(100),
            expires_at: None,
            revoked: false,
        }
    }

    #[test]
    fn a_generation_counts_up_and_does_not_wrap() {
        assert_eq!(Generation::new(1).next(), Some(Generation::new(2)));
        assert_eq!(Generation::MAX.next(), None);
        assert_eq!(serde_json::to_string(&Generation::new(7)).unwrap(), "\"7\"");
    }

    #[test]
    fn an_action_grant_covers_only_its_scope_before_its_expiry() {
        let grant = action_grant();
        let evict = ActionClass::EvictRegenerableData;
        assert!(grant.covers_class(&evict, at(199)));
        // The grant does not apply at its expiry time.
        assert!(!grant.covers_class(&evict, at(200)));
        assert!(!grant.covers_class(&ActionClass::DeleteSelectedFiles, at(150)));
        assert!(!grant.covers_class(&ActionClass::from_wire("EmptyTrash"), at(150)));
        assert!(grant.covers_rule(&rule("r1"), at(150)));
        // Another revision of the same rule is not covered.
        assert!(!grant.covers_rule(&rule("r2"), at(150)));
        assert!(!grant.covers_rule(&rule("r1"), at(200)));

        let revoked = ActionGrant {
            revoked: true,
            expires_at: None,
            ..grant.clone()
        };
        assert!(!revoked.is_in_effect(at(150)));
        assert!(!revoked.covers_class(&evict, at(150)));
        assert!(!revoked.permits_escalation(&Escalation::None, at(150)));
        let standing = ActionGrant {
            expires_at: None,
            ..grant
        };
        assert!(standing.is_in_effect(at(i64::from(u32::MAX))));
    }

    #[test]
    fn an_action_grant_permits_only_the_escalation_that_it_names() {
        let grant = action_grant();
        assert!(grant.permits_escalation(&Escalation::None, at(150)));
        assert!(grant.permits_escalation(&Escalation::ForceAfterGrace, at(150)));
        assert!(!grant.permits_escalation(&Escalation::ImmediateForce, at(150)));
        assert!(!grant.permits_escalation(&Escalation::from_wire("kill_group"), at(150)));
        assert!(!grant.permits_escalation(&Escalation::ForceAfterGrace, at(200)));
        // The named strategy alone is not the force action class.
        let no_force_class = ActionGrant {
            action_classes: vec![ActionClass::RequestApplicationExit],
            ..grant.clone()
        };
        assert!(no_force_class.permits_escalation(&Escalation::None, at(150)));
        assert!(!no_force_class.permits_escalation(&Escalation::ForceAfterGrace, at(150)));
        // Force after grace needs the graceful class also.
        let force_only = ActionGrant {
            action_classes: vec![ActionClass::ForceApplicationExit],
            escalations: vec![Escalation::ForceAfterGrace, Escalation::ImmediateForce],
            ..grant.clone()
        };
        assert!(!force_only.permits_escalation(&Escalation::ForceAfterGrace, at(150)));
        assert!(!force_only.permits_escalation(&Escalation::None, at(150)));
        assert!(force_only.permits_escalation(&Escalation::ImmediateForce, at(150)));
        // A cleanup grant permits no application intervention.
        let cleanup_only = ActionGrant {
            action_classes: vec![ActionClass::EvictRegenerableData],
            ..grant
        };
        assert!(!cleanup_only.permits_escalation(&Escalation::None, at(150)));
    }

    #[test]
    fn a_reference_matches_one_generation() {
        let grant = action_grant();
        assert!(grant.matches(&grant.reference()));
        let earlier = ActionGrantRef {
            generation: Generation::new(2),
            ..grant.reference()
        };
        assert!(!grant.matches(&earlier));
        let privilege = privilege_grant();
        assert!(privilege.matches(&privilege.reference()));
        let later = PrivilegeGrant {
            generation: Generation::new(2),
            ..privilege.clone()
        };
        assert!(!later.matches(&privilege.reference()));
    }

    #[test]
    fn a_privilege_grant_covers_only_its_ceiling_and_its_scope() {
        let grant = privilege_grant();
        let evict = ActionClass::EvictRegenerableData;
        let root = RootId::new("root_1").unwrap();
        let fits = WorkCharge::new(Bytes::new(1_000), EntryCount::new(10));
        let user = Uid::new(501);
        assert!(grant.covers(user, &evict, &root, &fits, at(150)));
        let over = WorkCharge::new(Bytes::new(1_001), EntryCount::new(1));
        assert!(!grant.covers(user, &evict, &root, &over, at(150)));
        assert!(!grant.covers(Uid::new(502), &evict, &root, &fits, at(150)));
        assert!(!grant.covers(
            user,
            &ActionClass::DeleteSelectedFiles,
            &root,
            &fits,
            at(150)
        ));
        let other_root = RootId::new("root_2").unwrap();
        assert!(!grant.covers(user, &evict, &other_root, &fits, at(150)));
        let revoked = PrivilegeGrant {
            revoked: true,
            ..grant.clone()
        };
        assert!(!revoked.covers(user, &evict, &root, &fits, at(150)));
        let expired = PrivilegeGrant {
            expires_at: Some(at(150)),
            ..grant
        };
        assert!(!expired.covers(user, &evict, &root, &fits, at(150)));
    }

    #[test]
    fn each_record_round_trips() {
        let grant = action_grant();
        let value = serde_json::to_value(&grant).unwrap();
        assert_eq!(value["generation"], json!("3"));
        assert_eq!(value["principal"], json!(501));
        assert_eq!(value["action_classes"][0], json!("EvictRegenerableData"));
        assert_eq!(value["expires_at"], json!("1970-01-01T00:03:20Z"));
        assert_eq!(serde_json::from_value::<ActionGrant>(value).unwrap(), grant);

        let privilege = privilege_grant();
        let value = serde_json::to_value(&privilege).unwrap();
        assert_eq!(
            serde_json::from_value::<PrivilegeGrant>(value.clone()).unwrap(),
            privilege
        );
        // The two grant records are not interchangeable.
        assert!(serde_json::from_value::<ActionGrant>(value).is_err());

        let revision = PolicyRevision {
            revision_id: PolicyRevisionId::new("policy_1").unwrap(),
            schema_version: 1,
            content: ContentDigest::of_bytes(b"config"),
            activated_at: at(100),
        };
        let value = serde_json::to_value(&revision).unwrap();
        assert_eq!(
            serde_json::from_value::<PolicyRevision>(value).unwrap(),
            revision
        );

        let binding = AuthorityBinding {
            policy_revision: PolicyRevisionId::new("policy_1").unwrap(),
            action_grants: vec![grant.reference()],
            privilege_grant: Some(privilege.reference()),
        };
        let value = serde_json::to_value(&binding).unwrap();
        assert_eq!(
            value["action_grants"][0],
            json!({ "grant_id": "grant_1", "generation": "3" })
        );
        assert_eq!(
            serde_json::from_value::<AuthorityBinding>(value).unwrap(),
            binding
        );
    }

    #[test]
    fn an_unknown_class_in_a_grant_stays_unrecognized() {
        let mut value = serde_json::to_value(action_grant()).unwrap();
        value["action_classes"] = json!(["EmptyTrash"]);
        let grant: ActionGrant = serde_json::from_value(value).unwrap();
        assert!(!grant.action_classes[0].is_recognized());
        for class in &ActionClass::ALL {
            assert!(!grant.covers_class(class, at(150)));
        }
        assert!(!grant.covers_class(&grant.action_classes[0], at(150)));
    }
}
