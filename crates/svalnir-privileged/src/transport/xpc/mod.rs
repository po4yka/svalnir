//! The macOS XPC transport of the helper.
//!
//! # The frame
//!
//! A request is one XPC dictionary with exactly one entry: the key
//! `request` with a data value, the JSON form of one
//! [`HelperRequest`](crate::request::HelperRequest). The reply is the reply
//! dictionary of that message with one entry: the key `response` with a
//! data value, the JSON form of one
//! [`HelperResponse`](crate::response::HelperResponse). Each other message
//! is not a request frame. The dictionary has no other typed value, so the
//! strict decoder of the request sees each byte that the peer sent.
//!
//! # The facts of the peer
//!
//! | Fact | Call |
//! | --- | --- |
//! | Code identity | `SecCodeCreateWithXPCMessage` for the message, then `SecCodeCheckValidity` against the requirement of the [`PeerPolicy`] |
//! | Effective user | `xpc_connection_get_euid` |
//! | Login session | `xpc_connection_get_asid` |
//!
//! The Mach service listener also gives the requirement to XPC with
//! `xpc_connection_set_peer_code_signing_requirement` (macOS 12 and
//! later), so XPC drops a request of a peer that does not satisfy it before
//! the handler runs. The check of each message stays: it is the result
//! that the service gets.
//!
//! With [`PeerPolicy::RefuseAll`] the transport calls no code identity API
//! and reports each peer as not verified.
//!
//! # Limits
//!
//! The transport has one serial queue: the helper handles one message at a
//! time. It keeps at most
//! [`MAX_PEER_CONNECTIONS_PER_USER`](super::MAX_PEER_CONNECTIONS_PER_USER)
//! live peer connections of one user and
//! [`MAX_PEER_CONNECTIONS`](super::MAX_PEER_CONNECTIONS) in all, and cancels
//! a new one over a limit. After
//! [`MAX_PENALIZED_MESSAGES`](super::MAX_PENALIZED_MESSAGES) penalized
//! messages of one user in one window, it cancels each connection of that
//! user at its next message, with no reply and no code identity check,
//! until the window is complete.
//!
//! # What is not validated
//!
//! No signed peer was available for this code. The requirement text, the
//! behavior of the two code identity calls for a Developer ID peer, and
//! the registration as a launch daemon are native validation gates
//! (`docs/INTERFACES.md` section 9).

#[expect(
    unsafe_code,
    reason = "the XPC, libdispatch, and Security calls of the transport; each block has its safety argument"
)]
mod sys;

#[cfg(test)]
mod tests;

use std::ffi::{CStr, CString};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use super::{
    CodeVerification, ConnectionCounter, PeerFacts, PeerPolicy, PenaltyLimiter, Reply,
    RequestHandler, Transport, TransportError, UnverifiedReason, requirement_text,
};
use crate::request::{CodeIdentity, MAX_ENCODED_REQUEST_BYTES};

/// The key of the request data in a request dictionary.
pub const REQUEST_KEY: &CStr = c"request";

/// The key of the response data in a reply dictionary.
pub const RESPONSE_KEY: &CStr = c"response";

/// The label of the serial queue of the transport.
const QUEUE_LABEL: &CStr = c"dev.po4yka.svalnir.privileged.transport";

/// The code identity check of the transport.
#[derive(Debug)]
enum Verifier {
    /// No peer can be verified.
    RefuseAll,
    /// A peer is verified when its code satisfies the requirement.
    Require {
        identity: CodeIdentity,
        text: CString,
        requirement: sys::Requirement,
    },
}

impl Verifier {
    fn new(policy: &PeerPolicy) -> Result<Self, TransportError> {
        match policy {
            PeerPolicy::RefuseAll => Ok(Self::RefuseAll),
            PeerPolicy::Require(identity) => {
                Self::with_text(identity.clone(), &requirement_text(identity)?)
            }
        }
    }

    fn with_text(identity: CodeIdentity, text: &str) -> Result<Self, TransportError> {
        let requirement: sys::Requirement = sys::Requirement::compile(text)
            .map_err(|status: i32| TransportError::Requirement { status })?;
        let text: CString =
            CString::new(text).map_err(|_| TransportError::Requirement { status: -1 })?;
        Ok(Self::Require {
            identity,
            text,
            requirement,
        })
    }

    fn verify(&self, message: sys::Message<'_>) -> CodeVerification {
        match self {
            Self::RefuseAll => CodeVerification::Unverified(UnverifiedReason::NoPolicy),
            Self::Require {
                identity,
                requirement,
                ..
            } => match requirement.check(message) {
                Ok(()) => CodeVerification::Verified(identity.clone()),
                Err(sys::ERR_SEC_CS_REQ_FAILED) => {
                    CodeVerification::Unverified(UnverifiedReason::RequirementNotSatisfied)
                }
                Err(sys::ERR_SEC_CS_UNSIGNED) => {
                    CodeVerification::Unverified(UnverifiedReason::Unsigned)
                }
                Err(status) => CodeVerification::Unverified(UnverifiedReason::Platform(status)),
            },
        }
    }
}

/// Where the transport listens.
#[derive(Debug)]
enum Endpoint {
    /// A Mach service that the launch daemon definition registers.
    MachService(String),
    /// An anonymous listener, for the tests of this module.
    #[cfg(test)]
    Anonymous,
}

/// The XPC transport.
#[derive(Debug)]
pub struct XpcTransport {
    endpoint: Endpoint,
    policy: PeerPolicy,
    /// A requirement text that replaces the text of the policy, for the
    /// tests of this module.
    #[cfg(test)]
    requirement_override: Option<String>,
}

impl XpcTransport {
    /// Makes the transport of the Mach service `service`.
    ///
    /// The function registers nothing. [`Transport::serve`] asks the
    /// platform for the listener of the name, and the platform gives it
    /// only to the process that the launch daemon definition of the
    /// product started.
    pub fn mach_service(service: &str, policy: PeerPolicy) -> Self {
        Self {
            endpoint: Endpoint::MachService(service.to_owned()),
            policy,
            #[cfg(test)]
            requirement_override: None,
        }
    }

    fn verifier(&self) -> Result<Verifier, TransportError> {
        #[cfg(test)]
        if let (Some(text), Some(identity)) = (&self.requirement_override, self.policy.identity()) {
            return Verifier::with_text(identity.clone(), text);
        }
        Verifier::new(&self.policy)
    }

    /// Serves until the listener is invalid. `listening` gets the listener
    /// after it started.
    fn serve_with(
        self,
        handler: Arc<dyn RequestHandler>,
        listening: impl FnOnce(&sys::Connection),
    ) -> Result<(), TransportError> {
        let verifier: Arc<Verifier> = Arc::new(self.verifier()?);
        let queue: Arc<sys::Queue> =
            Arc::new(sys::Queue::serial(QUEUE_LABEL).ok_or(TransportError::Platform)?);
        let (service, listener): (String, sys::Connection) = match self.endpoint {
            Endpoint::MachService(service) => {
                let name: CString =
                    CString::new(service.as_str()).map_err(|_| TransportError::ServiceName)?;
                let listener: sys::Connection = sys::Connection::mach_listener(&name, &queue)
                    .ok_or(TransportError::Platform)?;
                // XPC also drops the request of a peer that does not
                // satisfy the requirement.
                if let Verifier::Require { text, .. } = verifier.as_ref() {
                    listener
                        .require_peer(text)
                        .map_err(|status| TransportError::Requirement { status })?;
                }
                (service, listener)
            }
            #[cfg(test)]
            Endpoint::Anonymous => (
                "anonymous".to_owned(),
                sys::Connection::anonymous_listener(&queue).ok_or(TransportError::Platform)?,
            ),
        };

        let (invalid, stopped) = sync_channel::<()>(1);
        let live: Arc<Mutex<ConnectionCounter>> = Arc::default();
        let limiter: Arc<Mutex<PenaltyLimiter>> = Arc::default();
        let peer_queue: Arc<sys::Queue> = Arc::clone(&queue);
        listener.set_event_handler(&sys::handler_block(
            move |event: sys::Event<'_>| match event {
                sys::Event::Peer(peer) => {
                    accept(&peer, &handler, &verifier, &peer_queue, &live, &limiter);
                }
                sys::Event::Invalid => report_invalid(&invalid),
                sys::Event::Message(_) | sys::Event::Other => {}
            },
        ));
        listener.resume();
        listening(&listener);
        // The handler sends one value when the listener is invalid. A
        // closed channel means that XPC released the handler, which also
        // ends the listener.
        let _stopped: Result<(), std::sync::mpsc::RecvError> = stopped.recv();
        Err(TransportError::ListenerInvalid { service })
    }
}

impl Transport for XpcTransport {
    fn serve(self, handler: Arc<dyn RequestHandler>) -> Result<(), TransportError> {
        self.serve_with(handler, |_: &sys::Connection| {})
    }
}

fn report_invalid(invalid: &SyncSender<()>) {
    // A full channel has the one value that the receiver needs.
    let _sent: Result<(), std::sync::mpsc::TrySendError<()>> = invalid.try_send(());
}

/// Starts the handling of one new peer connection.
fn accept(
    peer: &sys::Connection,
    handler: &Arc<dyn RequestHandler>,
    verifier: &Arc<Verifier>,
    queue: &sys::Queue,
    live: &Arc<Mutex<ConnectionCounter>>,
    limiter: &Arc<Mutex<PenaltyLimiter>>,
) {
    // The platform recorded the two values for the connection. They are
    // not values of a message.
    let effective_uid: u32 = peer.effective_uid();
    let audit_session: i64 = i64::from(peer.audit_session());
    // A counter that cannot count admits no connection.
    let counted: bool = live.lock().is_ok_and(|mut live| live.open(effective_uid));
    // The handler has a reference to its own connection, to reply and to
    // cancel. The invalid event removes it, so the two do not keep each
    // other.
    let connection: Mutex<Option<sys::Connection>> = Mutex::new(Some(peer.clone()));
    let handler: Arc<dyn RequestHandler> = Arc::clone(handler);
    let verifier: Arc<Verifier> = Arc::clone(verifier);
    let live: Arc<Mutex<ConnectionCounter>> = Arc::clone(live);
    let limiter: Arc<Mutex<PenaltyLimiter>> = Arc::clone(limiter);

    peer.set_target_queue(queue);
    peer.set_event_handler(&sys::handler_block(
        move |event: sys::Event<'_>| match event {
            sys::Event::Message(message) => {
                let Ok(connection) = connection.lock() else {
                    return;
                };
                let Some(connection) = connection.as_ref() else {
                    return;
                };
                let now: Instant = Instant::now();
                // A poisoned limiter cannot count, so it permits nothing.
                let permitted: bool = limiter
                    .lock()
                    .is_ok_and(|mut limiter| limiter.permits(effective_uid, now));
                if !permitted {
                    // No reply: the peer gets the error of a closed
                    // connection.
                    connection.cancel();
                    return;
                }
                let facts: PeerFacts = PeerFacts::from_platform(
                    verifier.verify(message),
                    Some(effective_uid),
                    Some(audit_session),
                );
                let reply: Reply = match request_bytes(message) {
                    Some(bytes) => handler.handle(&facts, bytes),
                    None => handler.malformed_frame(),
                };
                if let Some(mut answer) = message.create_reply() {
                    answer.set_data(RESPONSE_KEY, &reply.payload);
                    connection.send(&answer);
                }
                if reply.penalized
                    && let Ok(mut limiter) = limiter.lock()
                {
                    limiter.penalize(effective_uid, now);
                }
            }
            sys::Event::Invalid => {
                if counted && let Ok(mut live) = live.lock() {
                    live.close(effective_uid);
                }
                // Also after a panic of this handler: the connection and
                // its handler must not keep each other.
                *connection.lock().unwrap_or_else(PoisonError::into_inner) = None;
            }
            sys::Event::Peer(_) | sys::Event::Other => {}
        },
    ));
    peer.resume();
    if !counted {
        peer.cancel();
    }
}

/// The bytes of the request in a request frame. `None` when the message is
/// not a request frame.
fn request_bytes(message: sys::Message<'_>) -> Option<&[u8]> {
    if message.entry_count() != 1 {
        return None;
    }
    message
        .data(REQUEST_KEY)
        .filter(|bytes: &&[u8]| bytes.len() <= MAX_ENCODED_REQUEST_BYTES)
}
