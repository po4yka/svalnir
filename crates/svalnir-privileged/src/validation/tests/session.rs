//! Tests of the login session of the caller.
//!
//! The record binds each step to the login session that the helper
//! accepted. A second login session of the same user gets one refusal for a
//! status query, a repeat, and a different content of that step.

use super::*;
use crate::validation::ConsumedRequest;

/// The state after the helper accepted `step-1` from the fixture caller.
fn state_with_step() -> HelperState {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));
    state
}

fn refused_for(
    state: &HelperState,
    caller: &CallerIdentity,
    request: &HelperRequest,
) -> RefusalReason {
    reason_of(&validate(state, caller, request, &clock()))
}

#[test]
fn a_request_without_a_login_session_is_refused() {
    let mut state: HelperState = state();
    let no_session: CallerIdentity = caller_in(None);
    for request in [request("step-1"), query("step-1")] {
        assert_eq!(
            refused_for(&state, &no_session, &request),
            RefusalReason::LoginSessionMissing
        );
        let admission: Admission = state.admit(&no_session, &request, &clock());
        let Admission::Refused(refusal) = admission else {
            panic!("the request is not refused: {admission:?}");
        };
        assert_eq!(refusal.reason, RefusalReason::LoginSessionMissing);
    }
    assert!(state.consumed().is_empty());

    // The reason has its own stable code.
    assert_eq!(
        RefusalReason::LoginSessionMissing.code(),
        "helper_login_session_missing"
    );
    assert_eq!(
        RefusalReason::LoginSessionMissing.family(),
        ErrorFamily::Authority
    );
}

#[test]
fn a_query_from_another_login_session_is_refused() {
    let state: HelperState = state_with_step();
    let other: CallerIdentity = caller_in(Some(OTHER_SESSION));

    // The verdict is a refusal: it has no state of the step.
    assert_eq!(
        refused_for(&state, &other, &query("step-1")),
        RefusalReason::LoginSessionMismatch
    );
    // A query under a different plan gets the same reason, so the other
    // session does not learn the correlation of the step.
    let mut different_plan: HelperRequest = query("step-1");
    different_plan.correlation.plan_digest = ContentDigest::of_bytes(b"plan-2");
    assert_eq!(
        refused_for(&state, &other, &different_plan),
        RefusalReason::LoginSessionMismatch
    );
    assert_eq!(
        RefusalReason::LoginSessionMismatch.code(),
        "helper_login_session_mismatch"
    );
}

#[test]
fn a_repeat_from_another_login_session_is_refused_and_consumes_nothing() {
    let mut state: HelperState = state_with_step();
    let before: HelperState = state.clone();
    let other: CallerIdentity = caller_in(Some(OTHER_SESSION));

    let mut new_transport: HelperRequest = request("step-1");
    new_transport.request_id = RequestId::new("request-other-session").unwrap();
    for request in [request("step-1"), new_transport] {
        let admission: Admission = state.admit(&other, &request, &clock());
        let Admission::Refused(refusal) = admission else {
            panic!("the repeat is not refused: {admission:?}");
        };
        assert_eq!(refusal.reason, RefusalReason::LoginSessionMismatch);
    }
    assert_eq!(state, before);
}

#[test]
fn a_collision_from_another_login_session_gets_the_same_refusal_as_a_repeat() {
    let mut state: HelperState = state_with_step();
    let before: HelperState = state.clone();
    let other: CallerIdentity = caller_in(Some(OTHER_SESSION));

    // The same step identity with a different content. The reason is not
    // `ConflictingDuplicate`, so the other session cannot learn whether its
    // content is the recorded content.
    let different_entry: HelperRequest = request_with("step-1", vec![entry("cache/other", 100, 1)]);
    let mut different_validity: HelperRequest = request("step-1");
    different_validity.validity = validity(NOW - 50, NOW + 150);
    for request in [different_entry, different_validity] {
        assert_eq!(
            refused_for(&state, &other, &request),
            RefusalReason::LoginSessionMismatch
        );
        assert!(matches!(
            state.admit(&other, &request, &clock()),
            Admission::Refused(_)
        ));
    }
    assert_eq!(state, before);
}

#[test]
fn the_login_session_of_the_step_still_gets_the_recorded_state() {
    let mut state: HelperState = state_with_step();

    // The repeat and the query of the accepting session.
    let Admission::Known(status) = admit(&mut state, &request("step-1")) else {
        panic!("the repeat is not answered with its state");
    };
    assert_eq!(status.state, StepState::DispatchConsumed);
    let Verdict::Known(status) = validate(&state, &caller(), &query("step-1"), &clock()) else {
        panic!("the query is not answered with the state");
    };
    assert_eq!(status.key, key("step-1"));
    // A different content from the same session is a conflicting
    // duplicate, as before.
    let different: HelperRequest = request_with("step-1", vec![entry("cache/other", 100, 1)]);
    assert_eq!(
        refused(&state, &different),
        RefusalReason::ConflictingDuplicate
    );

    // A new step of the other session is a new step.
    let other: CallerIdentity = caller_in(Some(OTHER_SESSION));
    let admission: Admission = state.admit(&other, &request("step-2"), &clock());
    let Admission::Dispatch(dispatch) = admission else {
        panic!("the new step is not accepted: {admission:?}");
    };
    let BoundedOperation::EvictEntries(eviction) = dispatch.operation();
    assert_eq!(eviction.login_session, login_session(OTHER_SESSION));
    let recorded = state.consumed().find(&key("step-2")).unwrap();
    assert_eq!(recorded.login_session, login_session(OTHER_SESSION));
}

#[test]
fn a_dispatch_is_not_covered_by_a_record_of_another_login_session() {
    let mut state: HelperState = state();
    let Admission::Dispatch(dispatch) = admit(&mut state, &request("step-1")) else {
        panic!("the request is not accepted");
    };
    assert_eq!(state.still_covers(&dispatch, &clock()), Ok(()));
    state
        .record_progress(&key("step-1"), StepState::NoAction)
        .unwrap();

    // After the retention, the record of the settled step goes, and the
    // other session gets the step identity as a new step.
    let late: HelperClock = clock_at(NOW + RETENTION);
    let mut later: HelperRequest = request("step-1");
    later.request_id = RequestId::new("request-later").unwrap();
    later.validity = validity(NOW + RETENTION - 100, NOW + RETENTION + 100);
    let other: CallerIdentity = caller_in(Some(OTHER_SESSION));
    assert!(matches!(
        state.admit(&other, &later, &late),
        Admission::Dispatch(_)
    ));

    // The earlier dispatch has the same key. The record is in work, but
    // for the other session, so it does not cover the earlier dispatch.
    assert_eq!(
        state.still_covers(&dispatch, &late),
        Err(RefusalReason::LoginSessionMismatch)
    );
}

#[test]
fn a_restored_record_keeps_the_login_session_of_each_step() {
    let state: HelperState = state_with_step();
    let records: Vec<ConsumedRequest> = state.consumed().requests().cloned().collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].login_session, login_session(SESSION));

    let restored = HelperState::restore(config(), state.grants().to_vec(), records).unwrap();
    assert_eq!(restored.changed, [key("step-1")]);
    let mut restored: HelperState = restored.state;
    assert_eq!(
        restored
            .consumed()
            .find(&key("step-1"))
            .unwrap()
            .login_session,
        login_session(SESSION)
    );

    // The other session is refused after the restore too.
    let other: CallerIdentity = caller_in(Some(OTHER_SESSION));
    assert_eq!(
        refused_for(&restored, &other, &query("step-1")),
        RefusalReason::LoginSessionMismatch
    );
    assert_eq!(
        refused_for(&restored, &other, &request("step-1")),
        RefusalReason::LoginSessionMismatch
    );
    // The session of the step gets the state that the restore recorded.
    let Admission::Known(status) = admit(&mut restored, &request("step-1")) else {
        panic!("the repeat is not answered with its state");
    };
    assert_eq!(status.state, StepState::UnknownOutcome);
}
