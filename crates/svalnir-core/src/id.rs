//! Opaque identities.
//!
//! `docs/RESOURCE_MODEL.md` section 2 and `docs/INTERFACES.md` section 3 own
//! the identities. Each identity is a distinct type and an opaque string in
//! JSON. An identity names a record that the agent holds. It is not
//! permission to inspect or change the entity, and a consumer must not read
//! meaning from its text.
//!
//! The text has 1 to 128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`,
//! and `-`.

use thiserror::Error;

/// The largest length of an identity, in bytes.
pub const MAX_ID_LENGTH: usize = 128;

/// The reason an identity text was rejected.
///
/// The error does not repeat the rejected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IdError {
    /// The text is empty.
    #[error("the identity is empty")]
    Empty,
    /// The text is longer than [`MAX_ID_LENGTH`].
    #[error("the identity is longer than 128 bytes")]
    TooLong,
    /// The text has a character outside the permitted set.
    #[error("the identity has a character other than a letter, a digit, `.`, `_`, `:`, or `-`")]
    InvalidCharacter,
}

fn validate(text: &str) -> Result<(), IdError> {
    if text.is_empty() {
        return Err(IdError::Empty);
    }
    if text.len() > MAX_ID_LENGTH {
        return Err(IdError::TooLong);
    }
    let is_permitted =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-');
    if !text.bytes().all(is_permitted) {
        return Err(IdError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! opaque_id {
    ($($(#[$meta:meta])* $name:ident;)+) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(String);

            impl $name {
                /// Makes the identity from its text.
                ///
                /// # Errors
                ///
                /// Returns an [`IdError`] when the text is empty, too long,
                /// or has a character outside the permitted set.
                pub fn new(text: impl Into<String>) -> Result<Self, IdError> {
                    let text: String = text.into();
                    validate(&text)?;
                    Ok(Self(text))
                }

                /// The text of the identity.
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl ::std::fmt::Display for $name {
                fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    formatter.write_str(&self.0)
                }
            }

            impl ::std::str::FromStr for $name {
                type Err = IdError;

                fn from_str(text: &str) -> Result<Self, Self::Err> {
                    Self::new(text)
                }
            }

            impl AsRef<str> for $name {
                fn as_ref(&self) -> &str {
                    &self.0
                }
            }

            impl ::serde::Serialize for $name {
                fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.serialize_str(&self.0)
                }
            }

            impl<'de> ::serde::Deserialize<'de> for $name {
                fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    let text: String = ::serde::Deserialize::deserialize(deserializer)?;
                    Self::new(text).map_err(::serde::de::Error::custom)
                }
            }
        )+
    };
}

opaque_id! {
    /// Identity of one scan and its recorded inventory.
    ScanId;
    /// Identity of one plan.
    PlanId;
    /// Identity of one admitted operation.
    OperationId;
    /// Identity of one step of an operation.
    StepId;
    /// Identity of one action target. The agent holds the identity evidence.
    TargetId;
    /// Correlation identity of one client request. It is not a plan,
    /// operation, or step identity.
    RequestId;
    /// Identity of one activated policy revision.
    PolicyRevisionId;
    /// Identity of one cleanup rule. A rule reference also needs the
    /// implementation revision of the rule.
    RuleId;
    /// Identity of one immutable implementation revision of a cleanup rule.
    RuleRevisionId;
    /// Identity of one policy incident. Its budgets and stop conditions
    /// govern automatic work.
    IncidentId;
    /// Identity of one policy decision.
    DecisionId;
    /// Identity of one executor lifetime. A restart makes a new epoch.
    ExecutorEpochId;
    /// Identity of one standing action grant.
    ActionGrantId;
    /// Identity of one privilege grant that the helper owns.
    PrivilegeGrantId;
    /// Identity of one resource lease.
    LeaseId;
    /// Identity of one approved cleanup root. The agent holds the identity
    /// evidence of the root.
    RootId;
    /// Identity of one authenticated client session.
    SessionId;

    /// Identity of the record that an observation scope refers to.
    IdentityId;
    /// Identity of one acquisition of a measurement.
    SampleId;
    /// Identity of one monotonic clock domain.
    ClockDomainId;
    /// Identity of one boot of the host.
    BootId;
    /// Identity of one collector lifetime. A restart makes a new epoch.
    CollectorEpochId;
    /// Identity of the process that collected a measurement.
    WorkerId;
    /// Identity of one collection adapter.
    AdapterId;

    /// Identity of one mounted volume record.
    VolumeId;
    /// Identity of one mount generation. A mount path can be used again.
    MountId;
    /// Identity of one verified shared-capacity relationship, such as an
    /// APFS container.
    CapacityDomainId;
    /// Identity of one process generation.
    ProcessGenerationId;
    /// Identity of one running application or managed-job instance.
    ApplicationInstanceId;
    /// Identity of one verified member list of an application. A membership
    /// change makes a new identity.
    MembershipSnapshotId;
}

impl RequestId {
    /// Makes a request identity from the wall-clock time and the process ID
    /// of the client. The result has the form `request_HEX_HEX`.
    pub fn from_client_parts(unix_nanoseconds: u128, process_id: u32) -> Self {
        Self(format!("request_{unix_nanoseconds:x}_{process_id:x}"))
    }
}

impl From<ScanId> for IdentityId {
    fn from(id: ScanId) -> Self {
        Self(id.0)
    }
}

impl From<VolumeId> for IdentityId {
    fn from(id: VolumeId) -> Self {
        Self(id.0)
    }
}

impl From<CapacityDomainId> for IdentityId {
    fn from(id: CapacityDomainId) -> Self {
        Self(id.0)
    }
}

impl From<ProcessGenerationId> for IdentityId {
    fn from(id: ProcessGenerationId) -> Self {
        Self(id.0)
    }
}

// An application scope refers to a membership snapshot. An application
// instance does not convert, because its members can change.
impl From<MembershipSnapshotId> for IdentityId {
    fn from(id: MembershipSnapshotId) -> Self {
        Self(id.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{IdError, IdentityId, MAX_ID_LENGTH, PlanId, RequestId, ScanId, VolumeId};

    #[test]
    fn an_identity_round_trips_as_a_string() {
        let id = ScanId::new("scan_01HZX:a-b.c").unwrap();
        let json: String = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"scan_01HZX:a-b.c\"");
        assert_eq!(serde_json::from_str::<ScanId>(&json).unwrap(), id);
        assert_eq!(id.to_string(), "scan_01HZX:a-b.c");
    }

    #[test]
    fn an_identity_outside_the_grammar_is_rejected() {
        assert_eq!(PlanId::new(""), Err(IdError::Empty));
        assert_eq!(
            PlanId::new("a".repeat(MAX_ID_LENGTH + 1)),
            Err(IdError::TooLong)
        );
        assert!(PlanId::new("a".repeat(MAX_ID_LENGTH)).is_ok());
        for text in [
            "plan 1",
            "plan/1",
            "plan\n",
            "plan\u{0}",
            "plán",
            "../x",
            "a\"b",
        ] {
            assert_eq!(PlanId::new(text), Err(IdError::InvalidCharacter), "{text}");
        }
        assert!(serde_json::from_str::<PlanId>("\"\"").is_err());
        assert!(serde_json::from_str::<PlanId>("\"plan 1\"").is_err());
        assert!(serde_json::from_str::<PlanId>("7").is_err());
        assert!(serde_json::from_str::<PlanId>("null").is_err());
    }

    #[test]
    fn a_generated_request_identity_is_valid() {
        let id = RequestId::from_client_parts(u128::MAX, u32::MAX);
        assert_eq!(RequestId::new(id.as_str()), Ok(id.clone()));
        assert_eq!(
            RequestId::from_client_parts(255, 16).as_str(),
            "request_ff_10"
        );
    }

    #[test]
    fn a_scope_identity_keeps_the_text_of_the_typed_identity() {
        let volume = VolumeId::new("vol_example").unwrap();
        assert_eq!(IdentityId::from(volume).as_str(), "vol_example");
    }
}
