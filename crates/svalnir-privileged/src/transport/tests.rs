//! Tests of the transport interface.

use std::time::Instant;

use super::fake::FakePeer;
use super::{
    AGENT_SIGNING_IDENTIFIER, CodeVerification, MACH_SERVICE_NAME, MAX_PENALIZED_MESSAGES,
    MAX_PENALIZED_USERS, PENALTY_WINDOW, PeerFacts, PeerPolicy, PenaltyLimiter, PolicyError,
    UnverifiedReason, requirement_text,
};
use svalnir_core::process::Uid;

use crate::request::{CodeIdentity, LoginSessionId};
use crate::testing::{SESSION, USER, agent_code, session};

#[test]
fn the_requirement_names_the_identifier_the_anchor_and_the_team() {
    let text: String = requirement_text(&agent_code()).unwrap();

    assert_eq!(
        text,
        "identifier \"dev.svalnir.agent\" and anchor apple generic \
         and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"TEAM123456\""
    );
}

#[test]
fn an_identity_that_needs_an_escape_has_no_requirement() {
    // Each part is a permitted part of a code identity, and each has a
    // character that can change the meaning of a requirement text.
    for (identifier, team) in [
        ("dev.svalnir.agent\"", "TEAM123456"),
        ("dev.svalnir.agent", "TEAM\"or\"1"),
        ("dev.svalnir.agent", "TEAM\\"),
        ("dev.svalnir.*", "TEAM123456"),
        ("dev.svalnir.agent", "TEAM=1"),
    ] {
        let identity: CodeIdentity = CodeIdentity::new(identifier, team).unwrap();
        assert_eq!(
            requirement_text(&identity),
            Err(PolicyError),
            "{identity:?}"
        );
    }
}

#[test]
fn a_build_with_no_team_identifier_verifies_no_peer() {
    match option_env!("SVALNIR_TEAM_IDENTIFIER") {
        None => {
            assert_eq!(PeerPolicy::compiled(), PeerPolicy::RefuseAll);
            assert_eq!(PeerPolicy::compiled().identity(), None);
        }
        Some(team) => {
            let identity: CodeIdentity = CodeIdentity::new(AGENT_SIGNING_IDENTIFIER, team).unwrap();
            assert_eq!(PeerPolicy::compiled(), PeerPolicy::Require(identity));
        }
    }
}

#[test]
fn the_names_of_the_product_have_the_product_prefix() {
    assert_eq!(MACH_SERVICE_NAME, "dev.svalnir.privileged");
    assert_eq!(AGENT_SIGNING_IDENTIFIER, "dev.svalnir.agent");
}

#[test]
fn an_audit_session_that_is_not_positive_is_not_a_login_session() {
    let verified = || CodeVerification::Verified(agent_code());
    for audit_session in [None, Some(0), Some(-1), Some(i64::from(u32::MAX) + 1)] {
        let facts: PeerFacts = PeerFacts::from_platform(verified(), Some(USER), audit_session);
        assert_eq!(facts.login_session(), None, "{audit_session:?}");
    }
    let facts: PeerFacts =
        PeerFacts::from_platform(verified(), Some(USER), Some(i64::from(SESSION)));
    assert_eq!(
        facts.login_session().map(LoginSessionId::get),
        Some(session(SESSION))
    );
    assert_eq!(facts.effective_uid().map(Uid::get), Some(USER));
}

#[test]
fn the_fake_peer_states_the_facts_that_a_test_gives() {
    let peer: FakePeer = FakePeer::verified(agent_code(), USER, session(SESSION));
    assert_eq!(
        peer.facts().code(),
        &CodeVerification::Verified(agent_code())
    );

    let unverified: FakePeer = peer.unverified(UnverifiedReason::Unsigned);
    assert_eq!(
        unverified.facts().code(),
        &CodeVerification::Unverified(UnverifiedReason::Unsigned)
    );
    // The user and the session stay: only the code check changed.
    assert_eq!(unverified.facts().effective_uid().map(Uid::get), Some(USER));
}

#[test]
fn the_penalty_limit_is_for_one_user_and_one_window() {
    let start: Instant = Instant::now();
    let mut limiter: PenaltyLimiter = PenaltyLimiter::default();

    for _ in 0..MAX_PENALIZED_MESSAGES {
        assert!(limiter.permits(USER, start));
        limiter.penalize(USER, start);
    }
    // The user is at its limit until the window is complete. Another user
    // is not.
    let before_end: Instant = start + (PENALTY_WINDOW / 2);
    assert!(!limiter.permits(USER, start));
    assert!(!limiter.permits(USER, before_end));
    assert!(limiter.permits(USER + 1, before_end));
    // A message in the window does not make the window longer.
    limiter.penalize(USER, before_end);
    assert!(limiter.permits(USER, start + PENALTY_WINDOW));
}

#[test]
fn the_penalty_limiter_counts_a_bounded_number_of_users() {
    let start: Instant = Instant::now();
    let mut limiter: PenaltyLimiter = PenaltyLimiter::default();
    let users: u32 = u32::try_from(MAX_PENALIZED_USERS).unwrap();
    for user in 0..users {
        limiter.penalize(user, start);
    }

    // The limiter cannot count one more user, so it does not permit one.
    // A user that it counts and that is below the limit is permitted.
    assert!(!limiter.permits(users, start));
    limiter.penalize(users, start);
    assert!(!limiter.permits(users, start));
    assert!(limiter.permits(0, start));
    // When the windows are complete, the limiter has room again.
    assert!(limiter.permits(users, start + PENALTY_WINDOW));
}
