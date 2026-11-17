//! The identity of the caller, as the transport supplies it.
//!
//! `docs/ARCHITECTURE.md` section 10 and `docs/INTERFACES.md` section 9 own
//! the rule: the user, the session, and the role come from the live
//! transport, and authority is never derived from a user ID or a process ID
//! that the caller supplies.

use svalnir_core::action::ClientRole;
use svalnir_core::id::SessionId;
use svalnir_core::process::Uid;
use thiserror::Error;

/// The largest length of one part of a code identity, in bytes.
pub const MAX_CODE_IDENTITY_BYTES: usize = 255;

/// The reason a code identity was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "a part of the code identity is empty, is longer than 255 bytes, or has a character that is not a visible ASCII character"
)]
pub struct CodeIdentityError;

/// A code-signing identity: the signing identifier and the team identifier
/// of a signed executable.
///
/// The value is a name. It is the identity of a caller only inside a
/// [`CallerIdentity`], which the transport makes after the operating system
/// verified the signature of the live peer. The helper also uses the value
/// to state which executable it expects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeIdentity {
    signing_identifier: String,
    team_identifier: String,
}

impl CodeIdentity {
    /// Makes the identity from its two parts.
    ///
    /// # Errors
    ///
    /// Returns a [`CodeIdentityError`] when a part is empty, is longer than
    /// [`MAX_CODE_IDENTITY_BYTES`], or has a character other than a visible
    /// ASCII character.
    pub fn new(
        signing_identifier: impl Into<String>,
        team_identifier: impl Into<String>,
    ) -> Result<Self, CodeIdentityError> {
        let signing_identifier: String = signing_identifier.into();
        let team_identifier: String = team_identifier.into();
        if !is_identity_part(&signing_identifier) || !is_identity_part(&team_identifier) {
            return Err(CodeIdentityError);
        }
        Ok(Self {
            signing_identifier,
            team_identifier,
        })
    }

    /// The signing identifier.
    pub fn signing_identifier(&self) -> &str {
        &self.signing_identifier
    }

    /// The team identifier.
    pub fn team_identifier(&self) -> &str {
        &self.team_identifier
    }
}

fn is_identity_part(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CODE_IDENTITY_BYTES
        && text.bytes().all(|byte: u8| byte.is_ascii_graphic())
}

/// The identity of the caller of one request.
///
/// Only the transport of this crate makes the value, from the live
/// connection: the code-signing identity that the operating system
/// verified, the audited user, the session, and the role that the handshake
/// selected. The type has no public constructor, no default value, and no
/// decoder, so a request body cannot supply it:
///
/// ```compile_fail
/// use svalnir_privileged::request::CallerIdentity;
///
/// // The type does not implement `serde::Deserialize`.
/// let forged: CallerIdentity = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use svalnir_privileged::request::CallerIdentity;
///
/// // The constructor is not visible outside the crate.
/// let forged = CallerIdentity::from_transport;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    code: CodeIdentity,
    audited_uid: Uid,
    session: Option<SessionId>,
    role: ClientRole,
}

impl CallerIdentity {
    /// Makes the identity from the evidence of the live connection.
    ///
    /// The caller of this function is the transport. Each argument must be
    /// a value that the operating system reported for the connection, and
    /// not a value that the peer sent.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the transport of Milestone 3 is the only caller; Milestone 2 has no transport"
        )
    )]
    pub(crate) fn from_transport(
        code: CodeIdentity,
        audited_uid: Uid,
        session: Option<SessionId>,
        role: ClientRole,
    ) -> Self {
        Self {
            code,
            audited_uid,
            session,
            role,
        }
    }

    /// The code-signing identity of the peer.
    pub fn code(&self) -> &CodeIdentity {
        &self.code
    }

    /// The audited user of the connection.
    pub fn audited_uid(&self) -> Uid {
        self.audited_uid
    }

    /// The session of the connection, when the transport has one.
    pub fn session(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }

    /// The role that the handshake selected.
    pub fn role(&self) -> &ClientRole {
        &self.role
    }
}
