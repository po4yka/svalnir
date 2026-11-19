//! Tests of the XPC transport, with an anonymous listener in the test
//! process.
//!
//! An anonymous listener registers no name with the platform, and only a
//! holder of its endpoint can connect: the test process is its own peer.
//! No test installs a service or needs elevated rights. The test process
//! has no Developer ID signature, so it is the "real peer of an unsigned
//! build" of these tests.

use std::process::Command;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, spawn};
use std::time::Duration;

use super::sys::client::Answer;
use super::sys::{Connection, Dictionary};
use super::{Endpoint, REQUEST_KEY, RESPONSE_KEY, XpcTransport};
use crate::native;
use crate::request::MAX_ENCODED_REQUEST_BYTES;
use crate::response::{HelperResponse, decode_response};
use crate::testing::{Harness, agent_code, encode, rejection_of, request};
use crate::transport::{
    CodeVerification, MAX_PENALIZED_MESSAGES, PeerFacts, PeerPolicy, Reply, RequestHandler,
    TransportError, UnverifiedReason,
};

const START_TIMEOUT: Duration = Duration::from_secs(10);

impl XpcTransport {
    /// A transport with an anonymous listener.
    fn anonymous(policy: PeerPolicy) -> Self {
        Self {
            endpoint: Endpoint::Anonymous,
            policy,
            requirement_override: None,
        }
    }

    /// Uses `text` as the requirement in place of the text of the policy.
    fn with_requirement(mut self, text: &str) -> Self {
        self.requirement_override = Some(text.to_owned());
        self
    }
}

/// A running transport of a test.
struct Served {
    listener: Connection,
    thread: JoinHandle<Result<(), TransportError>>,
}

impl Served {
    fn start(transport: XpcTransport, handler: Arc<dyn RequestHandler>) -> Self {
        let (started, listener): (_, Receiver<Connection>) = channel();
        let thread = spawn(move || {
            transport.serve_with(handler, |listener: &Connection| {
                started.send(listener.clone()).unwrap();
            })
        });
        match listener.recv_timeout(START_TIMEOUT) {
            Ok(listener) => Self { listener, thread },
            Err(error) => panic!("the transport did not start: {error}: {:?}", thread.join()),
        }
    }

    fn connect(&self) -> Connection {
        Connection::connect_to(&self.listener).unwrap()
    }

    /// Cancels the listener and returns the result of `serve`.
    fn stop(self) -> Result<(), TransportError> {
        self.listener.cancel();
        self.thread.join().unwrap()
    }
}

fn frame(bytes: &[u8]) -> Dictionary {
    let mut dictionary: Dictionary = Dictionary::empty().unwrap();
    dictionary.set_data(REQUEST_KEY, bytes);
    dictionary
}

fn response_of(answer: Answer) -> HelperResponse {
    match answer {
        Answer::Dictionary(Some(bytes)) => decode_response(&bytes).unwrap(),
        other => panic!("the reply has no response: {other:?}"),
    }
}

/// A handler that records the facts and the bytes that the transport
/// gives, and that states which messages are penalized.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<(PeerFacts, Vec<u8>)>>,
    malformed_frames: Mutex<u32>,
    penalize: bool,
}

impl RequestHandler for Recorder {
    fn handle(&self, peer: &PeerFacts, message: &[u8]) -> Reply {
        self.seen
            .lock()
            .unwrap()
            .push((peer.clone(), message.to_vec()));
        Reply {
            payload: b"handled".to_vec(),
            penalized: self.penalize,
        }
    }

    fn malformed_frame(&self) -> Reply {
        *self.malformed_frames.lock().unwrap() += 1;
        Reply {
            payload: b"not a frame".to_vec(),
            penalized: true,
        }
    }
}

#[test]
fn a_real_peer_of_an_unsigned_build_is_refused() {
    // The service of the fixture, behind the real transport, with the
    // policy of a build that has no signing identity. The peer is a real
    // process: this one.
    let harness: Harness = Harness::new();
    let file = harness.fixture.file("a.tmp");
    let valid: Vec<u8> = encode(&request("step-1", vec![harness.fixture.entry("a.tmp")]));
    let Harness {
        service, fixture, ..
    } = harness;
    let service = Arc::new(service);
    let served: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::RefuseAll),
        Arc::clone(&service) as Arc<dyn RequestHandler>,
    );

    let response: HelperResponse = response_of(served.connect().call(&frame(&valid), RESPONSE_KEY));

    assert_eq!(
        rejection_of(&response).error.code.as_str(),
        "helper_peer_unverified"
    );
    assert_eq!(
        service.with_state(|state| state.consumed().len()).unwrap(),
        0
    );
    assert!(file.exists());
    drop(fixture);
    assert!(matches!(
        served.stop(),
        Err(TransportError::ListenerInvalid { .. })
    ));
}

#[test]
fn a_peer_that_does_not_satisfy_the_product_requirement_is_not_verified() {
    // The policy of a signed build: the Security framework checks the
    // code of the test process against the Developer ID requirement of
    // the agent, which it does not satisfy.
    let recorder: Arc<Recorder> = Arc::new(Recorder::default());
    let served: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::Require(agent_code())),
        Arc::clone(&recorder) as Arc<dyn RequestHandler>,
    );

    let answer: Answer = served
        .connect()
        .call(&frame(b"bytes of the peer"), RESPONSE_KEY);

    assert_eq!(answer, Answer::Dictionary(Some(b"handled".to_vec())));
    let seen = recorder.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (facts, bytes) = &seen[0];
    assert_eq!(bytes, b"bytes of the peer");
    match facts.code() {
        CodeVerification::Unverified(
            UnverifiedReason::RequirementNotSatisfied
            | UnverifiedReason::Unsigned
            | UnverifiedReason::Platform(_),
        ) => {}
        other => panic!("the peer is not refused by the platform check: {other:?}"),
    }
    // The user is the user of the peer process, from the platform.
    assert_eq!(
        facts.effective_uid().map(svalnir_core::process::Uid::get),
        Some(native::effective_uid())
    );
    drop(seen);
    served.stop().unwrap_err();
}

/// The signing identifier of the test executable, when it has a
/// signature. The linker gives an ad hoc signature on Apple silicon.
fn own_signing_identifier() -> Option<String> {
    let executable = std::env::current_exe().ok()?;
    let output = Command::new("/usr/bin/codesign")
        .arg("--display")
        .arg("--verbose=2")
        .arg(executable)
        .output()
        .ok()?;
    let text: String = String::from_utf8(output.stderr).ok()?;
    let identifier: &str = text
        .lines()
        .find_map(|line: &str| line.strip_prefix("Identifier="))?;
    let is_plain = identifier
        .bytes()
        .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    is_plain.then(|| identifier.to_owned())
}

#[test]
fn the_platform_check_verifies_a_peer_that_satisfies_its_requirement() {
    // The check is not a constant refusal: with a requirement that the
    // test process satisfies, the platform verifies the same peer. The
    // requirement of this test is not a requirement of the product.
    let Some(identifier) = own_signing_identifier() else {
        // An executable with no signature satisfies no requirement. The
        // refusal of such a peer is the subject of the test before this
        // one.
        let recorder: Arc<Recorder> = Arc::new(Recorder::default());
        let served: Served = Served::start(
            XpcTransport::anonymous(PeerPolicy::Require(agent_code()))
                .with_requirement("identifier \"no.signature\""),
            Arc::clone(&recorder) as Arc<dyn RequestHandler>,
        );
        served.connect().call(&frame(b"x"), RESPONSE_KEY);
        assert!(matches!(
            recorder.seen.lock().unwrap()[0].0.code(),
            CodeVerification::Unverified(_)
        ));
        served.stop().unwrap_err();
        return;
    };
    let recorder: Arc<Recorder> = Arc::new(Recorder::default());
    let served: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::Require(agent_code()))
            .with_requirement(&format!("identifier \"{identifier}\"")),
        Arc::clone(&recorder) as Arc<dyn RequestHandler>,
    );
    let other: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::Require(agent_code()))
            .with_requirement("identifier \"dev.svalnir.not-this-executable\""),
        Arc::clone(&recorder) as Arc<dyn RequestHandler>,
    );

    served.connect().call(&frame(b"first"), RESPONSE_KEY);
    other.connect().call(&frame(b"second"), RESPONSE_KEY);

    let seen = recorder.seen.lock().unwrap();
    assert_eq!(seen[0].0.code(), &CodeVerification::Verified(agent_code()));
    assert_eq!(
        seen[1].0.code(),
        &CodeVerification::Unverified(UnverifiedReason::RequirementNotSatisfied)
    );
    drop(seen);
    served.stop().unwrap_err();
    other.stop().unwrap_err();
}

#[test]
fn a_requirement_that_the_platform_refuses_stops_the_transport_before_it_listens() {
    let recorder: Arc<Recorder> = Arc::new(Recorder::default());

    let result = XpcTransport::anonymous(PeerPolicy::Require(agent_code()))
        .with_requirement("this is not a requirement")
        .serve_with(recorder, |_: &Connection| {
            panic!("the transport listens with no requirement")
        });

    assert!(matches!(result, Err(TransportError::Requirement { .. })));
}

#[test]
fn a_message_that_is_not_a_request_frame_does_not_reach_the_decoder() {
    let recorder: Arc<Recorder> = Arc::new(Recorder::default());
    let served: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::RefuseAll),
        Arc::clone(&recorder) as Arc<dyn RequestHandler>,
    );
    let client: Connection = served.connect();

    // No entry, a value that is not data, a second entry, another key, and
    // data over the size limit.
    let empty: Dictionary = Dictionary::empty().unwrap();
    let mut not_data: Dictionary = Dictionary::empty().unwrap();
    not_data.set_integer(REQUEST_KEY, 7);
    let mut second_entry: Dictionary = frame(b"bytes");
    second_entry.set_integer(c"uid", 0);
    let mut other_key: Dictionary = Dictionary::empty().unwrap();
    other_key.set_data(c"command", b"bytes");
    let large: Dictionary = frame(&vec![b' '; MAX_ENCODED_REQUEST_BYTES + 1]);
    for message in [&empty, &not_data, &second_entry, &other_key, &large] {
        assert_eq!(
            client.call(message, RESPONSE_KEY),
            Answer::Dictionary(Some(b"not a frame".to_vec()))
        );
    }
    assert!(recorder.seen.lock().unwrap().is_empty());
    assert_eq!(*recorder.malformed_frames.lock().unwrap(), 5);

    // A request frame of the same connection reaches the handler.
    assert_eq!(
        client.call(&frame(b"a frame"), RESPONSE_KEY),
        Answer::Dictionary(Some(b"handled".to_vec()))
    );
    assert_eq!(recorder.seen.lock().unwrap().len(), 1);
    served.stop().unwrap_err();
}

#[test]
fn repeated_penalized_messages_of_a_user_stop_the_handling_of_its_messages() {
    let recorder: Arc<Recorder> = Arc::new(Recorder {
        penalize: true,
        ..Recorder::default()
    });
    let served: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::RefuseAll),
        Arc::clone(&recorder) as Arc<dyn RequestHandler>,
    );
    let client: Connection = served.connect();

    for _ in 0..MAX_PENALIZED_MESSAGES {
        assert_eq!(
            client.call(&frame(b"penalized"), RESPONSE_KEY),
            Answer::Dictionary(Some(b"handled".to_vec()))
        );
    }
    let handled: usize = recorder.seen.lock().unwrap().len();
    assert_eq!(handled, usize::try_from(MAX_PENALIZED_MESSAGES).unwrap());

    // The user is at its limit. The transport gives no reply and closes
    // the connection. An XPC client connects again for its next message,
    // and a new connection of the same user gets the same result: the
    // limit is for the user.
    assert_eq!(client.call(&frame(b"later"), RESPONSE_KEY), Answer::Error);
    assert_eq!(client.call(&frame(b"again"), RESPONSE_KEY), Answer::Error);
    assert_eq!(
        served
            .connect()
            .call(&frame(b"new connection"), RESPONSE_KEY),
        Answer::Error
    );
    assert_eq!(recorder.seen.lock().unwrap().len(), handled);
    served.stop().unwrap_err();
}

#[test]
fn a_listener_that_the_platform_invalidates_ends_the_transport_with_an_error() {
    let recorder: Arc<Recorder> = Arc::new(Recorder::default());
    let served: Served = Served::start(
        XpcTransport::anonymous(PeerPolicy::RefuseAll),
        recorder as Arc<dyn RequestHandler>,
    );

    assert_eq!(
        served.stop(),
        Err(TransportError::ListenerInvalid {
            service: "anonymous".to_owned()
        })
    );
}
