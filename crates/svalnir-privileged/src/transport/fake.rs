//! A transport for tests: a list of exchanges with stated peer facts.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use super::{
    CodeVerification, PeerFacts, Reply, RequestHandler, Transport, TransportError, UnverifiedReason,
};
use crate::request::CodeIdentity;

/// The peer of one exchange, as a test states it. The fake transport makes
/// the [`PeerFacts`] from it, as a real transport makes them from the
/// platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FakePeer {
    /// The result of the code identity check.
    pub(crate) code: CodeVerification,
    /// The effective user.
    pub(crate) uid: Option<u32>,
    /// The audit session identifier.
    pub(crate) audit_session: Option<i64>,
}

impl FakePeer {
    /// A peer whose code the platform verified as `identity`.
    pub(crate) fn verified(identity: CodeIdentity, uid: u32, audit_session: NonZeroU32) -> Self {
        Self {
            code: CodeVerification::Verified(identity),
            uid: Some(uid),
            audit_session: Some(i64::from(audit_session.get())),
        }
    }

    /// The same user and session, with a code that the platform did not
    /// verify.
    pub(crate) fn unverified(mut self, reason: UnverifiedReason) -> Self {
        self.code = CodeVerification::Unverified(reason);
        self
    }

    /// The facts of the peer.
    pub(crate) fn facts(&self) -> PeerFacts {
        PeerFacts::from_platform(self.code.clone(), self.uid, self.audit_session)
    }
}

/// One message of a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FakeMessage {
    /// A request frame with these bytes.
    Frame(Vec<u8>),
    /// A transport message that is not a request frame.
    NotAFrame,
}

/// A transport that delivers a fixed list of exchanges and keeps the
/// replies.
#[derive(Debug, Default)]
pub(crate) struct FakeTransport {
    exchanges: Vec<(FakePeer, FakeMessage)>,
    replies: Arc<Mutex<Vec<Reply>>>,
    registration_refused: bool,
}

impl FakeTransport {
    /// A transport with the exchanges `exchanges`.
    pub(crate) fn new(exchanges: Vec<(FakePeer, FakeMessage)>) -> Self {
        Self {
            exchanges,
            replies: Arc::default(),
            registration_refused: false,
        }
    }

    /// A transport whose platform refuses the registration.
    pub(crate) fn refusing_registration() -> Self {
        Self {
            registration_refused: true,
            ..Self::default()
        }
    }

    /// The replies, in the sequence of the exchanges. The value is shared
    /// with the transport, so a test reads it after `serve`.
    pub(crate) fn replies(&self) -> Arc<Mutex<Vec<Reply>>> {
        Arc::clone(&self.replies)
    }
}

impl Transport for FakeTransport {
    fn serve(self, handler: Arc<dyn RequestHandler>) -> Result<(), TransportError> {
        if self.registration_refused {
            return Err(TransportError::ListenerInvalid {
                service: "fake".to_owned(),
            });
        }
        for (peer, message) in self.exchanges {
            let reply: Reply = match message {
                FakeMessage::Frame(bytes) => handler.handle(&peer.facts(), &bytes),
                FakeMessage::NotAFrame => handler.malformed_frame(),
            };
            if let Ok(mut replies) = self.replies.lock() {
                replies.push(reply);
            }
        }
        Ok(())
    }
}
