//! Tests of the service: one message of a transport in, one response out.
//!
//! Each test uses a fake transport peer and a temporary directory.

use std::collections::BTreeMap;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use svalnir_core::action::{
    ActionError, DispatchState, Durability, ErrorFamily, NativeResult, PermittedNextStep,
    StepState, StopReason, TargetEffect,
};
use svalnir_core::time::MonotonicNanos;

use super::{HelperService, UnavailableStore};
use crate::executor::{EvictionExecutor, Execution, Gate};
use crate::request::{
    CodeIdentity, HelperOperation, HelperRequest, MAX_ENCODED_REQUEST_BYTES, MAX_NESTING_DEPTH,
    SupportedProtocols, decode_request,
};
use crate::response::{HelperResponse, ReportOrigin, StepReport, decode_response};
use crate::testing::{
    EXPIRES, Fixture, Harness, ISSUED, MemoryStore, OTHER_SESSION, OTHER_USER, TestClock, USER,
    assert_reports_agree, encode, entries_of, entry_of_absent, peer, query, refusal_of,
    rejection_of, replace_with_new_file, request, session, step_key, step_of,
};
use crate::transport::fake::{FakeMessage, FakePeer, FakeTransport};
use crate::transport::{RequestHandler as _, Transport as _, TransportError, UnverifiedReason};
use crate::validation::{BoundedEviction, HelperState};

fn code_of(error: &ActionError) -> &str {
    error.code.as_str()
}

fn step_state(harness: &Harness, step: &str) -> Option<StepState> {
    harness
        .service
        .with_state(|state: &HelperState| {
            state
                .consumed()
                .find(&step_key(step))
                .map(|recorded| recorded.state.clone())
        })
        .unwrap()
}

// The peer.

#[test]
fn a_peer_that_is_not_verified_is_refused_before_its_message_is_decoded() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("cache/a.tmp");
    let valid: Vec<u8> = encode(&request(
        "step-1",
        vec![harness.fixture.entry("cache/a.tmp")],
    ));

    for reason in [
        UnverifiedReason::NoPolicy,
        UnverifiedReason::RequirementNotSatisfied,
        UnverifiedReason::Unsigned,
        UnverifiedReason::Platform(-67_030),
    ] {
        // A request that the helper accepts from the agent, and bytes that
        // are not a request: the reply is the same, so the helper decoded
        // neither.
        for bytes in [valid.as_slice(), b"not a request".as_slice()] {
            let (response, reply) = harness.send_bytes(&peer().unverified(reason), bytes);
            let rejection = rejection_of(&response);
            assert_eq!(code_of(&rejection.error), "helper_peer_unverified");
            assert_eq!(rejection.error.family, ErrorFamily::Authority);
            assert_eq!(rejection.error.dispatch, DispatchState::NotSubmitted);
            assert_eq!(response.request_id, None);
            assert!(reply.penalized);
        }
    }
    assert_eq!(harness.consumed(), 0);
    assert_eq!(harness.store.lock().unwrap().consumed, Vec::new());
    assert!(file.exists());
}

#[test]
fn a_peer_with_no_user_is_refused() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let mut no_user: FakePeer = peer();
    no_user.uid = None;

    let (response, reply) = harness.send_bytes(
        &no_user,
        &encode(&request("step-1", vec![harness.fixture.entry("a.tmp")])),
    );

    assert_eq!(
        code_of(&rejection_of(&response).error),
        "helper_peer_user_unavailable"
    );
    assert!(reply.penalized);
    assert_eq!(harness.consumed(), 0);
    assert!(file.exists());
}

#[test]
fn a_caller_that_is_not_the_agent_is_refused() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    // The platform verified these peers, and neither is the agent of the
    // helper settings: another executable of the team, and the agent
    // identifier of another team.
    for (identifier, team) in [
        ("dev.po4yka.svalnir.cli", "TEAM123456"),
        ("dev.po4yka.svalnir.agent", "OTHERTEAM1"),
    ] {
        let other: FakePeer = FakePeer::verified(
            CodeIdentity::new(identifier, team).unwrap(),
            USER,
            session(crate::testing::SESSION),
        );
        let (response, reply) = harness.send_bytes(
            &other,
            &encode(&request("step-1", vec![harness.fixture.entry("a.tmp")])),
        );
        let refusal = refusal_of(&response);
        assert_eq!(code_of(&refusal.error), "helper_caller_not_permitted");
        assert_eq!(refusal.error.family, ErrorFamily::Authority);
        assert!(!reply.penalized);
    }
    assert_eq!(harness.consumed(), 0);
    assert!(file.exists());
}

#[test]
fn the_user_of_the_transport_and_not_the_request_selects_the_grant() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let mut other_user: FakePeer = peer();
    other_user.uid = Some(OTHER_USER);

    let (response, _) = harness.send_bytes(
        &other_user,
        &encode(&request("step-1", vec![harness.fixture.entry("a.tmp")])),
    );

    assert_eq!(
        code_of(&refusal_of(&response).error),
        "helper_grant_unknown"
    );
    assert!(file.exists());
}

// Malformed and oversized messages, and an unknown version.

#[test]
fn a_message_that_is_not_a_request_is_rejected_and_penalized() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let valid: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    let mut unknown_field: Value = serde_json::to_value(&valid).unwrap();
    unknown_field["uid"] = json!(0);
    let mut unknown_operation: Value = serde_json::to_value(&valid).unwrap();
    unknown_operation["operation"] = json!({ "run_command": { "text": "rm -rf /" } });
    let mut too_deep: Vec<u8> = vec![b'['; MAX_NESTING_DEPTH + 1];
    too_deep.extend(vec![b']'; MAX_NESTING_DEPTH + 1]);
    let mut truncated: Vec<u8> = encode(&valid);
    truncated.truncate(truncated.len() / 2);

    let cases: [(&str, Vec<u8>); 7] = [
        ("helper_request_malformed", b"not a request".to_vec()),
        ("helper_request_malformed", Vec::new()),
        ("helper_request_malformed", truncated),
        (
            "helper_request_malformed",
            serde_json::to_vec(&unknown_field).unwrap(),
        ),
        (
            "helper_request_malformed",
            serde_json::to_vec(&unknown_operation).unwrap(),
        ),
        ("helper_request_too_deep", too_deep),
        (
            "helper_request_too_large",
            vec![b' '; MAX_ENCODED_REQUEST_BYTES + 1],
        ),
    ];
    for (code, bytes) in cases {
        let (response, reply) = harness.send_bytes(&peer(), &bytes);
        let rejection = rejection_of(&response);
        assert_eq!(code_of(&rejection.error), code);
        assert_eq!(rejection.error.family, ErrorFamily::Request);
        assert_eq!(
            rejection.error.permitted_next_step(),
            PermittedNextStep::CorrectRequest
        );
        assert_eq!(response.request_id, None);
        assert!(reply.penalized, "{code}");
    }

    let frame = harness.service.malformed_frame();
    let response: HelperResponse = decode_response(&frame.payload).unwrap();
    assert_eq!(
        code_of(&rejection_of(&response).error),
        "helper_frame_malformed"
    );
    assert!(frame.penalized);

    assert_eq!(harness.consumed(), 0);
    assert!(file.exists());
}

#[test]
fn an_unknown_protocol_version_is_rejected() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let valid: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);

    let mut later_major: Value = serde_json::to_value(&valid).unwrap();
    later_major["protocol"]["major"] = json!(2);
    // A later major version can have a different request record.
    later_major["a_field_of_the_later_version"] = json!(true);
    let mut later_minor: Value = serde_json::to_value(&valid).unwrap();
    later_minor["protocol"]["minor"] = json!(1);

    for (code, value) in [
        ("helper_protocol_major_mismatch", later_major),
        ("helper_protocol_minor_unsupported", later_minor),
    ] {
        let (response, _) = harness.send_bytes(&peer(), &serde_json::to_vec(&value).unwrap());
        assert_eq!(code_of(&rejection_of(&response).error), code);
        assert_eq!(response.protocol.major, SupportedProtocols::CURRENT.major);
    }
    assert_eq!(harness.consumed(), 0);
    assert!(file.exists());
}

/// A small deterministic generator, so the test needs no new dependency
/// and each run has the same inputs.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next()).unwrap() % limit.max(1)
    }
}

#[test]
fn changed_bytes_of_a_request_never_decode_to_a_different_request() {
    let fixture: Fixture = Fixture::new();
    fixture.file("cache/a.tmp");
    fixture.file("b.tmp");
    let valid: Vec<u8> = encode(&request(
        "step-1",
        vec![fixture.entry("cache/a.tmp"), fixture.entry("b.tmp")],
    ));
    let interesting: &[u8] = b"{}[]\",:\\0123456789-.eE null true false\x00\xff uid pid";
    let mut generator: Generator = Generator(0x5eed);
    let mut accepted: u32 = 0;

    for _ in 0..20_000 {
        let mut bytes: Vec<u8> = valid.clone();
        for _ in 0..=generator.below(3) {
            let position: usize = generator.below(bytes.len());
            let byte: u8 = interesting[generator.below(interesting.len())];
            match generator.below(4) {
                0 => bytes[position] = byte,
                1 => bytes.insert(position, byte),
                2 => {
                    bytes.remove(position);
                }
                _ => bytes.truncate(position),
            }
            if bytes.is_empty() {
                break;
            }
        }
        // The decoder does not panic. When it accepts the bytes, the
        // request is exactly what the bytes state: no ignored field, no
        // second meaning.
        if let Ok(decoded) = decode_request(&bytes, SupportedProtocols::CURRENT) {
            let stated: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_value(&decoded).unwrap(), stated);
            accepted += 1;
        }
    }
    // Most changes break the form. Some keep it, for example a changed
    // digit of a number.
    assert!(accepted > 0);
    assert!(accepted < 10_000, "{accepted}");
}

// An eviction, its record, and a replay.

#[test]
fn an_eviction_removes_the_listed_entries_and_reports_each_one() {
    let harness: Harness = Harness::new();
    let first: PathBuf = harness.fixture.file("cache/a.tmp");
    let second: PathBuf = harness.fixture.file("cache/deep/b.tmp");
    let kept: PathBuf = harness.fixture.file("cache/kept.tmp");
    let sent: HelperRequest = request(
        "step-1",
        vec![
            harness.fixture.entry("cache/a.tmp"),
            harness.fixture.entry("cache/deep/b.tmp"),
        ],
    );

    let response: HelperResponse = harness.send(&sent);

    let step: &StepReport = step_of(&response);
    assert_eq!(response.request_id.as_ref(), Some(&sent.request_id));
    assert_eq!(step.correlation, sent.correlation);
    assert_eq!(step.origin, ReportOrigin::ThisRequest);
    assert_eq!(step.state, StepState::Completed);
    assert_eq!(step.durability, Durability::Durable);
    assert_eq!(step.error, None);
    let entries = entries_of(step);
    assert_eq!(entries.len(), 2);
    assert_reports_agree(entries);
    for entry in entries {
        assert_eq!(entry.effect, TargetEffect::Removed);
        assert_eq!(entry.dispatch, DispatchState::Submitted);
        assert_eq!(entry.evidence.native, NativeResult::Succeeded);
        // The call is not conditional on the identity of the object.
        assert_eq!(
            entry.attribution,
            svalnir_core::action::Attribution::Possible
        );
        assert_eq!(entry.removed.items.get(), 1);
    }
    assert!(!first.exists());
    assert!(!second.exists());
    assert!(kept.exists());
    assert!(harness.fixture.root.join("cache/deep").is_dir());

    // The consumption was durable before the result.
    let store = harness.store.lock().unwrap();
    assert_eq!(store.consumed, vec![step_key("step-1")]);
    assert_eq!(
        store.results,
        vec![(step_key("step-1"), StepState::Completed, Some(2))]
    );
}

#[test]
fn a_repeated_request_gets_the_record_and_no_second_call() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let sent: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    let first: HelperResponse = harness.send(&sent);
    assert!(!file.exists());

    // A new object at the same name, as a producer can make it.
    fs::write(&file, b"new content").unwrap();

    // The same bytes, the same request with a new transport identity, and
    // a status query.
    let mut new_transport_identity: HelperRequest = sent.clone();
    new_transport_identity.request_id = "request-second-transport-attempt".parse().unwrap();
    for repeat in [sent.clone(), new_transport_identity, query("step-1")] {
        let response: HelperResponse = harness.send(&repeat);
        let step: &StepReport = step_of(&response);
        assert_eq!(step.origin, ReportOrigin::Record);
        assert_eq!(step.state, StepState::Completed);
        assert_eq!(step.entries, step_of(&first).entries);
        assert_eq!(response.request_id.as_ref(), Some(&repeat.request_id));
    }

    assert!(file.exists(), "a repeat made a second native call");
    assert_eq!(harness.consumed(), 1);
    assert_eq!(harness.store.lock().unwrap().consumed.len(), 1);
}

#[test]
fn a_conflicting_duplicate_is_refused_and_removes_nothing() {
    let harness: Harness = Harness::new();
    harness.fixture.file("a.tmp");
    let other: PathBuf = harness.fixture.file("b.tmp");
    let sent: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    harness.send(&sent);

    // The same step identity with a different entry.
    let different_entry: HelperRequest = request("step-1", vec![harness.fixture.entry("b.tmp")]);
    // The same step identity with a new validity window.
    let mut later_window: HelperRequest = sent.clone();
    later_window.validity.expires_at = MonotonicNanos::new(EXPIRES + 50);

    for conflicting in [different_entry, later_window] {
        let response: HelperResponse = harness.send(&conflicting);
        let refusal = refusal_of(&response);
        assert_eq!(code_of(&refusal.error), "helper_conflicting_duplicate");
        assert_eq!(refusal.error.family, ErrorFamily::Request);
        assert_eq!(refusal.error.dispatch, DispatchState::NotSubmitted);
        assert_eq!(refusal.correlation, sent.correlation);
    }

    assert!(other.exists());
    assert_eq!(step_state(&harness, "step-1"), Some(StepState::Completed));
    assert_eq!(harness.consumed(), 1);
}

#[test]
fn a_request_of_another_login_session_is_refused() {
    let harness: Harness = Harness::new();
    harness.fixture.file("a.tmp");
    let other: PathBuf = harness.fixture.file("b.tmp");
    let sent: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    harness.send(&sent);

    let other_session: FakePeer =
        FakePeer::verified(crate::testing::agent_code(), USER, session(OTHER_SESSION));
    // A status query, a repeat, and a different content get one refusal,
    // with no state of the step.
    let different: HelperRequest = request("step-1", vec![harness.fixture.entry("b.tmp")]);
    for message in [query("step-1"), sent.clone(), different] {
        let (response, _) = harness.send_bytes(&other_session, &encode(&message));
        let refusal = refusal_of(&response);
        assert_eq!(code_of(&refusal.error), "helper_login_session_mismatch");
        assert_eq!(refusal.error.family, ErrorFamily::Authority);
    }

    // A peer with no login session: the audit session of the platform is
    // absent, zero, or not a session.
    for audit_session in [None, Some(0), Some(-1)] {
        let mut no_session: FakePeer = peer();
        no_session.audit_session = audit_session;
        let (response, _) = harness.send_bytes(
            &no_session,
            &encode(&request("step-2", vec![harness.fixture.entry("b.tmp")])),
        );
        assert_eq!(
            code_of(&refusal_of(&response).error),
            "helper_login_session_missing"
        );
    }
    assert!(other.exists());
    assert_eq!(harness.consumed(), 1);
}

#[test]
fn a_status_query_of_a_step_that_is_not_recorded_is_refused() {
    let harness: Harness = Harness::new();

    let response: HelperResponse = harness.send(&query("step-9"));

    assert_eq!(
        code_of(&refusal_of(&response).error),
        "helper_step_not_recorded"
    );
}

// Identity replacement and partial execution.

#[test]
fn an_object_that_is_replaced_before_the_step_is_not_removed() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    // The agent observed the object, and then another object got its name.
    let sent: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    replace_with_new_file(&file);

    let response: HelperResponse = harness.send(&sent);

    let step: &StepReport = step_of(&response);
    assert_eq!(step.state, StepState::NoAction);
    let entries = entries_of(step);
    assert_reports_agree(entries);
    assert_eq!(entries[0].effect, TargetEffect::Skipped);
    assert_eq!(entries[0].dispatch, DispatchState::NotSubmitted);
    assert_eq!(entries[0].evidence.native, NativeResult::NotCalled);
    assert_eq!(entries[0].stop_reason, StopReason::TargetSkipped);
    let failure: &ActionError = entries[0].failure.as_ref().unwrap();
    assert_eq!(code_of(failure), "helper_target_changed");
    assert_eq!(failure.family, ErrorFamily::Evidence);
    assert_eq!(
        failure.permitted_next_step(),
        PermittedNextStep::RefreshObservation
    );
    assert_eq!(fs::read(&file).unwrap(), b"not the planned object");
}

#[test]
fn an_object_that_is_replaced_during_the_step_is_not_removed() {
    // Reading 2 of the clock is the gate before the second entry: the
    // helper accepted the request and removed the first entry, and then
    // another object gets the name of the second entry.
    let replaced: Arc<std::sync::Mutex<Option<PathBuf>>> = Arc::default();
    let at_gate: Arc<std::sync::Mutex<Option<PathBuf>>> = Arc::clone(&replaced);
    let clock: TestClock = TestClock::fixed().with_hook(Box::new(move |reading: u64| {
        if reading == 2
            && let Some(path) = at_gate.lock().unwrap().as_ref()
        {
            replace_with_new_file(path);
        }
    }));
    let harness: Harness = Harness::with_clock(clock);
    let first: PathBuf = harness.fixture.file("a.tmp");
    let second: PathBuf = harness.fixture.file("b.tmp");
    let third: PathBuf = harness.fixture.file("c.tmp");
    let sent: HelperRequest = request(
        "step-1",
        vec![
            harness.fixture.entry("a.tmp"),
            harness.fixture.entry("b.tmp"),
            harness.fixture.entry("c.tmp"),
        ],
    );
    *replaced.lock().unwrap() = Some(second.clone());

    let response: HelperResponse = harness.send(&sent);

    let step: &StepReport = step_of(&response);
    assert_eq!(step.state, StepState::Partial);
    let entries = entries_of(step);
    assert_reports_agree(entries);
    assert_eq!(entries[0].effect, TargetEffect::Removed);
    assert_eq!(entries[1].effect, TargetEffect::Skipped);
    assert_eq!(
        code_of(entries[1].failure.as_ref().unwrap()),
        "helper_target_changed"
    );
    // The step continues with the next entry: a changed entry is skipped,
    // and it does not stop the step.
    assert_eq!(entries[2].effect, TargetEffect::Removed);
    assert!(!first.exists());
    assert_eq!(fs::read(&second).unwrap(), b"not the planned object");
    assert!(!third.exists());
}

#[test]
fn a_partial_execution_reports_each_entry_with_its_own_result() {
    let harness: Harness = Harness::new();
    let removed: PathBuf = harness.fixture.file("a.tmp");
    let replaced: PathBuf = harness.fixture.file("b.tmp");
    let in_directory: PathBuf = harness.fixture.file("full/inner.tmp");
    let directory: PathBuf = harness.fixture.root.join("full");
    let sent: HelperRequest = request(
        "step-1",
        vec![
            harness.fixture.entry("a.tmp"),
            harness.fixture.entry("b.tmp"),
            entry_of_absent("gone.tmp"),
            harness.fixture.entry("full"),
        ],
    );
    replace_with_new_file(&replaced);

    let response: HelperResponse = harness.send(&sent);

    let step: &StepReport = step_of(&response);
    let entries = entries_of(step);
    assert_reports_agree(entries);
    let effects: Vec<&TargetEffect> = entries.iter().map(|entry| &entry.effect).collect();
    assert_eq!(
        effects,
        [
            &TargetEffect::Removed,
            &TargetEffect::Skipped,
            &TargetEffect::AlreadyAbsent,
            &TargetEffect::Refused,
        ]
    );
    // A verified removal, and other work that was skipped and refused.
    assert_eq!(step.state, StepState::Partial);
    assert_eq!(step.durability, Durability::Durable);

    // The refused entry: the call was submitted and had no effect.
    let refused = &entries[3];
    assert_eq!(refused.dispatch, DispatchState::Submitted);
    assert_eq!(
        refused.evidence.native,
        NativeResult::Errno {
            errno: libc::ENOTEMPTY
        }
    );
    let failure: &ActionError = refused.failure.as_ref().unwrap();
    assert_eq!(code_of(failure), "helper_directory_not_empty");
    assert_eq!(failure.family, ErrorFamily::Native);
    // After a submitted call, the next step is reconciliation.
    assert_eq!(failure.permitted_next_step(), PermittedNextStep::Reconcile);

    assert!(!removed.exists());
    assert!(replaced.exists());
    assert!(directory.is_dir());
    assert!(in_directory.exists());
    assert_eq!(step_state(&harness, "step-1"), Some(StepState::Partial));

    // A status query gives the same entry results.
    let queried: HelperResponse = harness.send(&query("step-1"));
    assert_eq!(step_of(&queried).entries, step.entries);
    assert_eq!(step_of(&queried).state, StepState::Partial);
}

#[test]
fn a_deadline_in_the_step_stops_the_later_entries() {
    // The clock goes 50 forward after each reading: the admission is at
    // 1000, the gate of the first entry at 1050, and the gate of the
    // second entry at 1100, which is the expiry of the request.
    let harness: Harness = Harness::with_clock(TestClock::advancing(50));
    let first: PathBuf = harness.fixture.file("a.tmp");
    let second: PathBuf = harness.fixture.file("b.tmp");
    let third: PathBuf = harness.fixture.file("c.tmp");
    assert_eq!(EXPIRES - ISSUED, 200);
    let sent: HelperRequest = request(
        "step-1",
        vec![
            harness.fixture.entry("a.tmp"),
            harness.fixture.entry("b.tmp"),
            harness.fixture.entry("c.tmp"),
        ],
    );

    let response: HelperResponse = harness.send(&sent);

    let step: &StepReport = step_of(&response);
    let entries = entries_of(step);
    assert_reports_agree(entries);
    assert_eq!(entries[0].effect, TargetEffect::Removed);
    for stopped in &entries[1..] {
        assert_eq!(stopped.effect, TargetEffect::Skipped);
        assert_eq!(stopped.dispatch, DispatchState::NotSubmitted);
        assert_eq!(stopped.stop_reason, StopReason::DeadlineExpired);
        assert_eq!(stopped.failure, None);
    }
    assert_eq!(step.state, StepState::Partial);
    let error: &ActionError = step.error.as_ref().unwrap();
    assert_eq!(code_of(error), "helper_request_expired");
    assert_eq!(error.family, ErrorFamily::Limits);
    // An earlier entry got a call, so the error of the step does not
    // permit a retry before reconciliation.
    assert_eq!(error.dispatch, DispatchState::Submitted);
    assert_eq!(error.permitted_next_step(), PermittedNextStep::Reconcile);
    assert!(!first.exists());
    assert!(second.exists());
    assert!(third.exists());
}

#[test]
fn an_expired_request_is_refused_and_consumes_nothing() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let mut expired: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    expired.validity.expires_at = MonotonicNanos::new(crate::testing::NOW);

    let response: HelperResponse = harness.send(&expired);

    assert_eq!(
        code_of(&refusal_of(&response).error),
        "helper_request_expired"
    );
    assert_eq!(harness.consumed(), 0);
    assert!(file.exists());
}

// The record store and the clock.

#[test]
fn a_step_whose_record_is_not_durable_submits_no_call() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    harness.store.lock().unwrap().fail_consumed = true;
    let sent: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);

    let response: HelperResponse = harness.send(&sent);

    let step: &StepReport = step_of(&response);
    assert_eq!(step.state, StepState::NoAction);
    assert_eq!(step.durability, Durability::Volatile);
    assert_eq!(step.entries, None);
    let error: &ActionError = step.error.as_ref().unwrap();
    assert_eq!(code_of(error), "helper_record_not_durable");
    assert_eq!(error.family, ErrorFamily::Recording);
    assert_eq!(error.dispatch, DispatchState::NotSubmitted);
    assert_eq!(error.permitted_next_step(), PermittedNextStep::StopMutation);
    assert!(file.exists());

    // The step stays consumed: the same request does not get a second
    // admission when the store works again.
    harness.store.lock().unwrap().fail_consumed = false;
    let repeated: HelperResponse = harness.send(&sent);
    assert_eq!(step_of(&repeated).origin, ReportOrigin::Record);
    assert_eq!(step_of(&repeated).state, StepState::NoAction);
    assert!(file.exists());
    assert_eq!(harness.store.lock().unwrap().consumed, Vec::new());
}

#[test]
fn a_result_that_is_not_durable_is_reported() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    harness.store.lock().unwrap().fail_result = true;

    let response: HelperResponse =
        harness.send(&request("step-1", vec![harness.fixture.entry("a.tmp")]));

    let step: &StepReport = step_of(&response);
    // The effect occurred, and the report states that its record is not
    // durable: a restart of the helper restores the step as unknown.
    assert_eq!(step.state, StepState::Completed);
    assert_eq!(step.durability, Durability::PersistenceFailed);
    let error: &ActionError = step.error.as_ref().unwrap();
    assert_eq!(code_of(error), "helper_result_not_durable");
    assert_eq!(error.dispatch, DispatchState::Submitted);
    assert_eq!(error.permitted_next_step(), PermittedNextStep::Reconcile);
    assert!(!file.exists());
}

#[test]
fn the_store_of_this_build_submits_no_call() {
    let fixture: Fixture = Fixture::new();
    let file: PathBuf = fixture.file("a.tmp");
    let service = HelperService::new(
        fixture.state(),
        BTreeMap::new(),
        UnavailableStore,
        crate::executor::FsEvictor::new(),
        TestClock::fixed(),
    );

    let reply = service.handle(
        &peer().facts(),
        &encode(&request("step-1", vec![fixture.entry("a.tmp")])),
    );

    let response: HelperResponse = decode_response(&reply.payload).unwrap();
    assert_eq!(step_of(&response).state, StepState::NoAction);
    assert_eq!(
        code_of(step_of(&response).error.as_ref().unwrap()),
        "helper_record_not_durable"
    );
    assert!(file.exists());
}

#[test]
fn a_clock_that_is_not_available_refuses_the_request() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    harness.clock.set_unavailable();

    let response: HelperResponse =
        harness.send(&request("step-1", vec![harness.fixture.entry("a.tmp")]));

    let refusal = refusal_of(&response);
    assert_eq!(code_of(&refusal.error), "helper_clock_unavailable");
    assert_eq!(refusal.error.family, ErrorFamily::Evidence);
    assert_eq!(harness.consumed(), 0);
    assert!(file.exists());
}

/// An executor that panics, as a defect in an executor can.
struct PanickingExecutor;

impl EvictionExecutor for PanickingExecutor {
    fn evict(&mut self, _eviction: &BoundedEviction, _gate: &mut Gate<'_>) -> Execution {
        panic!("a defect in the executor");
    }
}

#[test]
fn a_panic_in_a_step_makes_the_state_unavailable() {
    let fixture: Fixture = Fixture::new();
    fixture.file("a.tmp");
    fixture.file("b.tmp");
    let service = HelperService::new(
        fixture.state(),
        BTreeMap::new(),
        MemoryStore::default(),
        PanickingExecutor,
        TestClock::fixed(),
    );
    let first: Vec<u8> = encode(&request("step-1", vec![fixture.entry("a.tmp")]));
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        service.handle(&peer().facts(), &first);
    }));
    assert!(panicked.is_err());

    // The step of the panic is possibly in work in the state. The service
    // does not decide with that state.
    for bytes in [
        first,
        encode(&request("step-2", vec![fixture.entry("b.tmp")])),
        encode(&query("step-1")),
    ] {
        let reply = service.handle(&peer().facts(), &bytes);
        let response: HelperResponse = decode_response(&reply.payload).unwrap();
        let rejection = rejection_of(&response);
        assert_eq!(code_of(&rejection.error), "helper_state_unavailable");
        assert_eq!(rejection.error.family, ErrorFamily::Recording);
    }
}

// The transport interface.

#[test]
fn the_service_runs_only_behind_a_transport() {
    let harness: Harness = Harness::new();
    let file: PathBuf = harness.fixture.file("a.tmp");
    let kept: PathBuf = harness.fixture.file("b.tmp");
    let valid: Vec<u8> = encode(&request("step-1", vec![harness.fixture.entry("a.tmp")]));
    let other: Vec<u8> = encode(&request("step-2", vec![harness.fixture.entry("b.tmp")]));
    let transport: FakeTransport = FakeTransport::new(vec![
        (
            peer().unverified(UnverifiedReason::Unsigned),
            FakeMessage::Frame(other),
        ),
        (peer(), FakeMessage::NotAFrame),
        (peer(), FakeMessage::Frame(valid.clone())),
        (peer(), FakeMessage::Frame(valid)),
    ]);
    let replies = transport.replies();
    let Harness { service, .. } = harness;

    transport.serve(Arc::new(service)).unwrap();

    let replies = replies.lock().unwrap();
    let responses: Vec<HelperResponse> = replies
        .iter()
        .map(|reply| decode_response(&reply.payload).unwrap())
        .collect();
    assert_eq!(
        code_of(&rejection_of(&responses[0]).error),
        "helper_peer_unverified"
    );
    assert_eq!(
        code_of(&rejection_of(&responses[1]).error),
        "helper_frame_malformed"
    );
    assert_eq!(step_of(&responses[2]).origin, ReportOrigin::ThisRequest);
    assert_eq!(step_of(&responses[3]).origin, ReportOrigin::Record);
    assert_eq!(
        replies
            .iter()
            .map(|reply| reply.penalized)
            .collect::<Vec<_>>(),
        [true, true, false, false]
    );
    assert!(!file.exists());
    assert!(kept.exists());
}

#[test]
fn a_refused_registration_is_an_error_of_the_transport() {
    let harness: Harness = Harness::new();
    let Harness { service, .. } = harness;

    let result = FakeTransport::refusing_registration().serve(Arc::new(service));

    assert_eq!(
        result,
        Err(TransportError::ListenerInvalid {
            service: "fake".to_owned()
        })
    );
}

#[test]
fn a_request_has_no_field_for_an_identity_of_the_caller() {
    let harness: Harness = Harness::new();
    harness.fixture.file("a.tmp");
    let valid: HelperRequest = request("step-1", vec![harness.fixture.entry("a.tmp")]);
    let HelperOperation::EvictEntries(_) = &valid.operation else {
        panic!("the request is not an eviction");
    };

    for field in [
        "uid",
        "euid",
        "pid",
        "audit_session",
        "login_session",
        "role",
    ] {
        let mut forged: Value = serde_json::to_value(&valid).unwrap();
        forged[field] = json!(0);
        let (response, _) = harness.send_bytes(&peer(), &serde_json::to_vec(&forged).unwrap());
        assert_eq!(
            code_of(&rejection_of(&response).error),
            "helper_request_malformed",
            "{field}"
        );
    }
    assert_eq!(harness.consumed(), 0);
}
