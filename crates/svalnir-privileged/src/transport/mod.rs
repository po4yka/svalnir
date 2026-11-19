//! The transport interface of the helper.
//!
//! A transport gives the helper two things for each message: the bytes of
//! the message, and the facts that the platform reports for the live peer
//! ([`PeerFacts`]). The facts never come from the message. A request has
//! no field for a user, a session, a process, or a code identity, and only
//! a transport of this crate can make a [`PeerFacts`] value:
//!
//! ```compile_fail
//! use svalnir_privileged::transport::PeerFacts;
//!
//! // The constructor is not visible outside the crate.
//! let forged = PeerFacts::from_platform;
//! ```
//!
//! | Fact | Source on macOS | Use |
//! | --- | --- | --- |
//! | Code identity | The Security framework checks the code of the process that sent the message against the requirement of the product ([`PeerPolicy`]) | Only a verified peer is a caller. Each other peer is refused before its message is decoded. |
//! | Effective user | `xpc_connection_get_euid` | The principal of each grant lookup and of each step record. |
//! | Login session | `xpc_connection_get_asid`, the audit session identifier | Each step is bound to one login session. |
//!
//! The process identifier of the peer is not a fact of this interface: a
//! process identifier can name another process a moment later, and the
//! helper derives no authority from it.
//!
//! # Refusal of a peer that is not verified
//!
//! A build with no signing identity has no requirement that a peer can
//! satisfy ([`PeerPolicy::RefuseAll`]). Each real peer is then refused,
//! which is the correct result for an unsigned development build.
//!
//! Owning specifications: `docs/ARCHITECTURE.md` section 10,
//! `docs/INTERFACES.md` sections 9 and 10, and `docs/THREAT_MODEL.md`
//! (`T-01`).

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use svalnir_core::process::Uid;
use thiserror::Error;

use crate::request::{CodeIdentity, LoginSessionId};

#[cfg(test)]
pub(crate) mod fake;
#[cfg(target_os = "macos")]
pub mod xpc;

#[cfg(test)]
mod tests;

/// The Mach service name of the helper. The launch daemon definition of
/// the product registers this name; this crate registers nothing.
pub const MACH_SERVICE_NAME: &str = "dev.svalnir.privileged";

/// The signing identifier of the agent, the only caller of the helper.
pub const AGENT_SIGNING_IDENTIFIER: &str = "dev.svalnir.agent";

/// The largest number of live peer connections of a transport.
pub const MAX_PEER_CONNECTIONS: usize = 32;

/// The largest number of live peer connections of one user. The helper
/// has one caller for each user: the agent of that user.
pub const MAX_PEER_CONNECTIONS_PER_USER: usize = 2;

/// The count of the live peer connections, for each user of the platform.
///
/// The limit for one user stops a process that opens connections and
/// sends no message from using each connection of the transport: it can
/// use only the connections of its own user.
#[derive(Debug, Default)]
pub(crate) struct ConnectionCounter {
    by_user: BTreeMap<u32, usize>,
    total: usize,
}

impl ConnectionCounter {
    /// Counts a new connection of `user`. Returns `false`, and counts
    /// nothing, when the user or the transport has its largest number of
    /// connections.
    pub(crate) fn open(&mut self, user: u32) -> bool {
        let of_user: usize = self.by_user.get(&user).copied().unwrap_or(0);
        if self.total >= MAX_PEER_CONNECTIONS || of_user >= MAX_PEER_CONNECTIONS_PER_USER {
            return false;
        }
        self.by_user.insert(user, of_user.saturating_add(1));
        self.total = self.total.saturating_add(1);
        true
    }

    /// Removes one counted connection of `user`.
    pub(crate) fn close(&mut self, user: u32) {
        let Some(of_user) = self.by_user.get_mut(&user) else {
            return;
        };
        *of_user = of_user.saturating_sub(1);
        if *of_user == 0 {
            self.by_user.remove(&user);
        }
        self.total = self.total.saturating_sub(1);
    }
}

/// The largest number of penalized messages of one user in one
/// [`PENALTY_WINDOW`]. After that number, a transport handles no message
/// of the user until the window is complete (`docs/INTERFACES.md`
/// section 9: repeated malformed requests are rate-limited).
pub const MAX_PENALIZED_MESSAGES: u32 = 16;

/// The time for which the penalized messages of one user count.
pub const PENALTY_WINDOW: Duration = Duration::from_secs(10);

/// The largest number of users whose penalized messages a transport
/// counts at one time.
pub const MAX_PENALIZED_USERS: usize = 64;

/// The penalized messages of one user in the current window.
#[derive(Debug, Clone, Copy)]
struct Penalties {
    since: Instant,
    count: u32,
}

/// The rate limit of penalized messages, for each user of the platform.
///
/// The limit is for a user and not for a connection: an XPC client
/// connects again after the helper closed its connection, so a limit for
/// a connection limits nothing. The user is the effective user that the
/// platform reports for the connection. A process of a user can thus stop
/// the helper for the agent of the same user for one window; it cannot do
/// that for another user.
#[derive(Debug, Default)]
pub(crate) struct PenaltyLimiter {
    users: BTreeMap<u32, Penalties>,
}

impl PenaltyLimiter {
    fn forget_complete_windows(&mut self, now: Instant) {
        self.users.retain(|_, penalties: &mut Penalties| {
            now.saturating_duration_since(penalties.since) < PENALTY_WINDOW
        });
    }

    /// Whether the transport handles a message of `user` at `now`.
    ///
    /// The answer is `false` when the user has the largest number of
    /// penalized messages in the window. A user that the limiter does not
    /// count is permitted, also while the limiter counts the largest
    /// number of users: the penalties of other users do not stop a user
    /// that has none. The limiter then does not count the penalties of
    /// that user until a window is complete.
    pub(crate) fn permits(&mut self, user: u32, now: Instant) -> bool {
        self.forget_complete_windows(now);
        self.users
            .get(&user)
            .is_none_or(|penalties: &Penalties| penalties.count < MAX_PENALIZED_MESSAGES)
    }

    /// Counts one penalized message of `user` at `now`.
    pub(crate) fn penalize(&mut self, user: u32, now: Instant) {
        self.forget_complete_windows(now);
        if let Some(penalties) = self.users.get_mut(&user) {
            penalties.count = penalties.count.saturating_add(1);
        } else if self.users.len() < MAX_PENALIZED_USERS {
            self.users.insert(
                user,
                Penalties {
                    since: now,
                    count: 1,
                },
            );
        }
    }
}

/// The reason the platform did not verify the code identity of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnverifiedReason {
    /// The build has no requirement that a peer can satisfy.
    NoPolicy,
    /// The code of the peer does not satisfy the requirement of the
    /// product.
    RequirementNotSatisfied,
    /// The code of the peer has no signature.
    Unsigned,
    /// The platform gave no code object for the peer, or the check failed
    /// with another status. The value is the status of the platform.
    Platform(i32),
}

/// The result of the code identity check of one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeVerification {
    /// The platform verified that the code of the peer satisfies the
    /// requirement of the product for this identity.
    Verified(CodeIdentity),
    /// The platform did not verify the peer.
    Unverified(UnverifiedReason),
}

/// The facts that the platform reports for the peer of one message.
///
/// Only a transport of this crate makes the value. It has no public
/// constructor, no default value, and no decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFacts {
    code: CodeVerification,
    effective_uid: Option<Uid>,
    login_session: Option<LoginSessionId>,
}

impl PeerFacts {
    /// Makes the facts from the values of the platform.
    ///
    /// The caller of this function is a transport. Each argument must be a
    /// value that the operating system reported for the connection or for
    /// the message, and not a value that the peer sent. `audit_session` is
    /// the audit session identifier; a value that is not positive is not a
    /// login session.
    pub(crate) fn from_platform(
        code: CodeVerification,
        effective_uid: Option<u32>,
        audit_session: Option<i64>,
    ) -> Self {
        let login_session: Option<LoginSessionId> = audit_session
            .and_then(|session: i64| u32::try_from(session).ok())
            .and_then(NonZeroU32::new)
            .map(LoginSessionId::new);
        Self {
            code,
            effective_uid: effective_uid.map(Uid::new),
            login_session,
        }
    }

    /// The result of the code identity check.
    pub fn code(&self) -> &CodeVerification {
        &self.code
    }

    /// The effective user of the peer, when the platform gave one.
    pub fn effective_uid(&self) -> Option<Uid> {
        self.effective_uid
    }

    /// The login session of the peer, when the connection has one.
    pub fn login_session(&self) -> Option<LoginSessionId> {
        self.login_session
    }
}

/// The reason a peer policy has no requirement text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "a part of the code identity has a character that a code requirement cannot have without an escape"
)]
pub struct PolicyError;

/// Which peers a transport can verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPolicy {
    /// No peer can be verified. This is the policy of a build with no
    /// signing identity.
    RefuseAll,
    /// A peer is verified when its code satisfies the Developer ID
    /// requirement of the product for this identity.
    Require(CodeIdentity),
}

impl PeerPolicy {
    /// The policy of this build.
    ///
    /// The team identifier is a compile-time value of the build
    /// environment, `SVALNIR_TEAM_IDENTIFIER`. A build with no such value
    /// has no signing identity, and its policy is
    /// [`PeerPolicy::RefuseAll`]. A value that is not a permitted part of
    /// a code identity also gives [`PeerPolicy::RefuseAll`].
    pub fn compiled() -> Self {
        // TODO(npochaev): set `SVALNIR_TEAM_IDENTIFIER` in the release
        // build when a Developer ID is available, and validate the
        // requirement of `requirement_text` against a signed agent.
        option_env!("SVALNIR_TEAM_IDENTIFIER")
            .and_then(|team: &str| CodeIdentity::new(AGENT_SIGNING_IDENTIFIER, team).ok())
            .filter(|identity: &CodeIdentity| requirement_text(identity).is_ok())
            .map_or(Self::RefuseAll, Self::Require)
    }

    /// The identity that a verified peer has, when a peer can be verified.
    pub fn identity(&self) -> Option<&CodeIdentity> {
        match self {
            Self::RefuseAll => None,
            Self::Require(identity) => Some(identity),
        }
    }
}

/// The code requirement that a peer with `identity` must satisfy, in the
/// requirement language of the Security framework.
///
/// The text requires the signing identifier, the Apple anchor, a Developer
/// ID intermediate and leaf certificate, and the team identifier of the
/// leaf certificate. A team identifier alone is too broad
/// (`docs/ARCHITECTURE.md` section 10), so the signing identifier is a
/// part of each requirement. The text comes from the compiled policy of
/// the product and never from a peer.
///
/// # Errors
///
/// Returns a [`PolicyError`] when a part of the identity has a character
/// other than an ASCII letter, a digit, `.`, `-`, or `_`. The function
/// does not escape a character: it refuses the identity.
pub fn requirement_text(identity: &CodeIdentity) -> Result<String, PolicyError> {
    let is_plain = |text: &str| {
        text.bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    };
    if !is_plain(identity.signing_identifier()) || !is_plain(identity.team_identifier()) {
        return Err(PolicyError);
    }
    Ok(format!(
        "identifier \"{}\" and anchor apple generic \
         and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{}\"",
        identity.signing_identifier(),
        identity.team_identifier()
    ))
}

/// The reply of a handler to one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The encoded response.
    pub payload: Vec<u8>,
    /// Whether the message counts against the user of the peer: it was
    /// not a request of the protocol, or the peer was not verified. After
    /// [`MAX_PENALIZED_MESSAGES`] such messages in one [`PENALTY_WINDOW`],
    /// a transport handles no message of the user until the window is
    /// complete.
    pub penalized: bool,
}

/// The receiver of the messages of a transport: the service of the helper.
pub trait RequestHandler: Send + Sync {
    /// Handles one message of a peer. `message` is the bytes of the
    /// request frame. They are not trusted.
    fn handle(&self, peer: &PeerFacts, message: &[u8]) -> Reply;

    /// Makes the reply to a transport message that is not a request frame.
    fn malformed_frame(&self) -> Reply;
}

/// The reason a transport stopped.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// The platform refused the registration of the service, or it
    /// invalidated the listener. A process that the launch daemon
    /// definition of the product did not start gets this error.
    #[error(
        "the platform refused the registration of the service `{service}`, or it invalidated the listener"
    )]
    ListenerInvalid {
        /// The name of the service.
        service: String,
    },
    /// The name of the service cannot be given to the platform.
    #[error("the name of the service is not permitted")]
    ServiceName,
    /// The platform refused the code requirement of the peer policy.
    #[error("the platform refused the code requirement of the peer policy (status {status})")]
    Requirement {
        /// The status of the platform.
        status: i32,
    },
    /// The peer policy has no requirement text.
    #[error("{0}")]
    Policy(#[from] PolicyError),
    /// The platform gave no object for the listener or for its queue.
    #[error("the platform gave no listener")]
    Platform,
}

/// A transport of the helper.
pub trait Transport {
    /// Serves the messages of the peers to `handler` until the transport
    /// stops.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] when the platform refuses the
    /// registration of the service or invalidates the listener, or when
    /// the transport cannot start.
    fn serve(self, handler: Arc<dyn RequestHandler>) -> Result<(), TransportError>;
}
