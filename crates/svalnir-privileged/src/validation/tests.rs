//! Tests of the request types and of the validation.
//!
//! The tests make values only. No test reads or changes a file, starts a
//! process, or uses the identity of a real user.

use std::path::{Component, Path};

use serde_json::{Value, json};
use svalnir_core::action::{
    ActionClass, ClientRole, DispatchState, ErrorCode, ErrorFamily, FileObjectType,
    PermittedNextStep, StepState, WorkCharge,
};
use svalnir_core::authority::{Generation, PrivilegeGrant, PrivilegeGrantRef};
use svalnir_core::digest::ContentDigest;
use svalnir_core::file::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath};
use svalnir_core::id::{
    BootId, ClockDomainId, OperationId, PlanId, PrivilegeGrantId, RequestId, RootId, RuleId,
    RuleRevisionId, SessionId, StepId,
};
use svalnir_core::process::Uid;
use svalnir_core::quantity::{Bytes, EntryCount, Nanoseconds};
use svalnir_core::rule::RuleRef;
use svalnir_core::time::{MonotonicNanos, WallTime};

use super::{
    Admission, ApprovedRoot, BoundedOperation, ConsumedRequests, EntryPath, GrantLimits,
    HelperClock, HelperConfig, HelperGrant, HelperState, MAX_COMPONENT_BYTES, MAX_PATH_BYTES,
    MAX_PATH_DEPTH, MAX_RECORD_CAPACITY, PathDefect, RateCeiling, RecordError, RefusalReason,
    RootPath, StateError, StepKey, Verdict, validate,
};
use crate::request::{
    CallerIdentity, CodeIdentity, DecodeError, EntryTarget, EvictEntries, HelperOperation,
    HelperRequest, MAX_ENCODED_REQUEST_BYTES, MAX_NESTING_DEPTH, MAX_TARGETS_PER_REQUEST,
    OperationKind, PROTOCOL_MAJOR, PROTOCOL_MINOR, ProtocolVersion, QueryStepStatus,
    RequestValidity, StepCorrelation, SupportedProtocols, decode_request,
};

// The fixture: one user, one grant with one root, and a clock.

const USER: u32 = 501;
const OTHER_USER: u32 = 502;
/// The monotonic time of the fixture clock.
const NOW: u64 = 1_000;
/// The wall-clock time of the fixture clock, in seconds.
const WALL_NOW: i64 = 1_000;
/// The wall-clock expiry of the fixture grant, in seconds.
const GRANT_EXPIRY: i64 = 2_000;
const CEILING_BYTES: u64 = 1_000;
const CEILING_ITEMS: u64 = 4;
const MAX_TARGETS: usize = 3;
const RATE_WINDOW: u64 = 400;
const RATE_REQUESTS: u32 = 2;
const RATE_BYTES: u64 = 1_500;
const RATE_ITEMS: u64 = 6;
const MAX_VALIDITY: u64 = 500;
const RETENTION: u64 = 1_000;
const CAPACITY: usize = 8;
const QUOTA: usize = 6;

fn wall(seconds: i64) -> WallTime {
    WallTime::from_unix(seconds, 0).unwrap()
}

fn charge(bytes: u64, items: u64) -> WorkCharge {
    WorkCharge::new(Bytes::new(bytes), EntryCount::new(items))
}

fn path(text: &str) -> LosslessPath {
    LosslessPath::from_bytes(text).unwrap()
}

fn rule() -> RuleRef {
    RuleRef {
        id: RuleId::new("svalnir.helper-temporary").unwrap(),
        revision: RuleRevisionId::new("rev-1").unwrap(),
    }
}

fn agent_code() -> CodeIdentity {
    CodeIdentity::new("io.svalnir.agent", "TEAM123456").unwrap()
}

fn caller_with(code: CodeIdentity, uid: u32, role: ClientRole) -> CallerIdentity {
    CallerIdentity::from_transport(
        code,
        Uid::new(uid),
        Some(SessionId::new("session-1").unwrap()),
        role,
    )
}

fn caller() -> CallerIdentity {
    caller_with(agent_code(), USER, ClientRole::Agent)
}

fn clock_at(monotonic: u64) -> HelperClock {
    HelperClock {
        wall: wall(WALL_NOW),
        monotonic: MonotonicNanos::new(monotonic),
        clock_domain: ClockDomainId::new("continuous").unwrap(),
        boot_id: BootId::new("boot-1").unwrap(),
    }
}

fn clock() -> HelperClock {
    clock_at(NOW)
}

fn grant_for(grant_id: &str, uid: u32, root_id: &str) -> PrivilegeGrant {
    PrivilegeGrant {
        grant_id: PrivilegeGrantId::new(grant_id).unwrap(),
        generation: Generation::new(3),
        principal: Uid::new(uid),
        action_classes: vec![ActionClass::EvictRegenerableData],
        roots: vec![RootId::new(root_id).unwrap()],
        ceiling: charge(CEILING_BYTES, CEILING_ITEMS),
        allow_volatile_journal_on_critical: false,
        approved_at: wall(0),
        expires_at: Some(wall(GRANT_EXPIRY)),
        revoked: false,
    }
}

fn limits() -> GrantLimits {
    GrantLimits {
        max_targets: MAX_TARGETS,
        rate: RateCeiling {
            window: Nanoseconds::new(RATE_WINDOW),
            max_requests: RATE_REQUESTS,
            work: charge(RATE_BYTES, RATE_ITEMS),
        },
    }
}

fn root(root_id: &str, root_path: &str) -> ApprovedRoot {
    ApprovedRoot::new(
        RootId::new(root_id).unwrap(),
        &path(root_path),
        vec![rule()],
    )
    .unwrap()
}

fn helper_grant(grant: PrivilegeGrant, limits: GrantLimits) -> HelperGrant {
    let roots: Vec<ApprovedRoot> = grant
        .roots
        .iter()
        .map(|root_id: &RootId| {
            root(
                root_id.as_str(),
                &format!("/Library/Application Support/Svalnir/{root_id}"),
            )
        })
        .collect();
    HelperGrant::new(grant, roots, limits).unwrap()
}

fn config() -> HelperConfig {
    HelperConfig {
        protocols: SupportedProtocols::CURRENT,
        agent: agent_code(),
        max_validity: Nanoseconds::new(MAX_VALIDITY),
        record_capacity: CAPACITY,
        principal_quota: QUOTA,
        retention: Nanoseconds::new(RETENTION),
    }
}

fn state_with(grant: PrivilegeGrant, limits: GrantLimits) -> HelperState {
    HelperState::new(config(), vec![helper_grant(grant, limits)]).unwrap()
}

fn state() -> HelperState {
    state_with(grant_for("grant-1", USER, "root-a"), limits())
}

fn entry(relative: &str, bytes: u64, items: u64) -> EntryTarget {
    EntryTarget {
        relative_entry: path(relative),
        object_type: FileObjectType::RegularFile,
        object: Some(FileObjectEvidence {
            device: DeviceNumber::new(1),
            inode: InodeNumber::new(42),
        }),
        charge: charge(bytes, items),
    }
}

fn validity(issued_at: u64, expires_at: u64) -> RequestValidity {
    RequestValidity {
        clock_domain: ClockDomainId::new("continuous").unwrap(),
        boot_id: BootId::new("boot-1").unwrap(),
        issued_at: MonotonicNanos::new(issued_at),
        expires_at: MonotonicNanos::new(expires_at),
    }
}

fn correlation(step: &str) -> StepCorrelation {
    StepCorrelation {
        plan_id: PlanId::new("plan-1").unwrap(),
        plan_digest: ContentDigest::of_bytes(b"plan-1"),
        operation_id: OperationId::new("operation-1").unwrap(),
        step_id: StepId::new(step).unwrap(),
    }
}

fn eviction(entries: Vec<EntryTarget>) -> EvictEntries {
    EvictEntries {
        grant: PrivilegeGrantRef {
            grant_id: PrivilegeGrantId::new("grant-1").unwrap(),
            generation: Generation::new(3),
        },
        root_id: RootId::new("root-a").unwrap(),
        rule: rule(),
        entries,
    }
}

/// An eviction request of `step` that the fixture state accepts.
fn request_with(step: &str, entries: Vec<EntryTarget>) -> HelperRequest {
    HelperRequest {
        protocol: ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        },
        request_id: RequestId::new(format!("request-{step}")).unwrap(),
        correlation: correlation(step),
        validity: validity(NOW - 100, NOW + 100),
        operation: HelperOperation::EvictEntries(eviction(entries)),
    }
}

fn request(step: &str) -> HelperRequest {
    request_with(step, vec![entry("cache/a.tmp", 100, 1)])
}

fn query(step: &str) -> HelperRequest {
    HelperRequest {
        request_id: RequestId::new(format!("query-{step}")).unwrap(),
        operation: HelperOperation::QueryStepStatus(QueryStepStatus {}),
        ..request(step)
    }
}

fn eviction_mut(request: &mut HelperRequest) -> &mut EvictEntries {
    match &mut request.operation {
        HelperOperation::EvictEntries(eviction) => eviction,
        HelperOperation::QueryStepStatus(_) => panic!("the request is not an eviction"),
    }
}

fn key(step: &str) -> StepKey {
    StepKey {
        principal: Uid::new(USER),
        operation_id: OperationId::new("operation-1").unwrap(),
        step_id: StepId::new(step).unwrap(),
    }
}

fn reason_of(verdict: &Verdict) -> RefusalReason {
    match verdict {
        Verdict::Refuse(refusal) => refusal.reason,
        other => panic!("the verdict is not a refusal: {other:?}"),
    }
}

fn refused(state: &HelperState, request: &HelperRequest) -> RefusalReason {
    reason_of(&validate(state, &caller(), request, &clock()))
}

fn is_accepted(state: &HelperState, request: &HelperRequest) -> bool {
    matches!(
        validate(state, &caller(), request, &clock()),
        Verdict::Accept(_)
    )
}

fn admit(state: &mut HelperState, request: &HelperRequest) -> Admission {
    state.admit(&caller(), request, &clock())
}

fn admit_ok(state: &mut HelperState, request: &HelperRequest) {
    let admission: Admission = admit(state, request);
    assert!(
        matches!(admission, Admission::Dispatch(_)),
        "the request is not accepted: {admission:?}"
    );
}

fn encode(request: &HelperRequest) -> Value {
    serde_json::to_value(request).unwrap()
}

fn decode(value: &Value) -> Result<HelperRequest, DecodeError> {
    decode_request(
        &serde_json::to_vec(value).unwrap(),
        SupportedProtocols::CURRENT,
    )
}

// Accepted requests: one for each operation.

#[test]
fn accepts_an_eviction_with_the_exact_bounded_operation() {
    let state: HelperState = state();
    let request: HelperRequest = request_with(
        "step-1",
        vec![entry("cache/a.tmp", 100, 1), entry("cache/b.tmp", 250, 2)],
    );

    let Verdict::Accept(operation) = validate(&state, &caller(), &request, &clock()) else {
        panic!("the request is not accepted");
    };
    let BoundedOperation::EvictEntries(accepted) = *operation;

    assert_eq!(accepted.key, key("step-1"));
    assert_eq!(accepted.correlation, request.correlation);
    assert_eq!(
        accepted.grant,
        grant_for("grant-1", USER, "root-a").reference()
    );
    assert_eq!(accepted.rule, rule());
    // The path of the root is the path of the helper record.
    let root_names: Vec<&[u8]> = accepted.root.path().names().collect();
    assert_eq!(
        root_names,
        [
            b"Library".as_slice(),
            b"Application Support",
            b"Svalnir",
            b"root-a"
        ]
    );
    let entry_names: Vec<Vec<&[u8]>> = accepted
        .entries
        .iter()
        .map(|entry| entry.path.names().collect())
        .collect();
    assert_eq!(
        entry_names,
        [
            vec![b"cache".as_slice(), b"a.tmp"],
            vec![b"cache".as_slice(), b"b.tmp"]
        ]
    );
    assert_eq!(accepted.entries[0].limit, charge(100, 1));
    assert_eq!(accepted.entries[1].limit, charge(250, 2));
    // The limit is the sum of the bounds of the request, not the ceiling
    // of the grant: a bound of the caller only makes the operation smaller.
    assert_eq!(accepted.limit, charge(350, 3));
    assert_eq!(accepted.deadline, MonotonicNanos::new(NOW + 100));
}

#[test]
fn accepts_each_supported_object_type() {
    for object_type in [
        FileObjectType::RegularFile,
        FileObjectType::Directory,
        FileObjectType::SymbolicLink,
    ] {
        let mut request: HelperRequest = request("step-1");
        eviction_mut(&mut request).entries[0].object_type = object_type;
        assert!(is_accepted(&state(), &request));
    }
}

#[test]
fn answers_a_status_query_with_the_recorded_state() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));

    let Verdict::Known(status) = validate(&state, &caller(), &query("step-1"), &clock()) else {
        panic!("the query has no recorded state");
    };
    assert_eq!(status.key, key("step-1"));
    assert_eq!(status.state, StepState::DispatchConsumed);

    state
        .record_progress(&key("step-1"), StepState::Verifying)
        .unwrap();
    state
        .record_progress(&key("step-1"), StepState::Completed)
        .unwrap();
    let Admission::Known(status) = admit(&mut state, &query("step-1")) else {
        panic!("the query has no recorded state");
    };
    assert_eq!(status.state, StepState::Completed);
    // A query is not a consumption.
    assert_eq!(state.consumed().len(), 1);
}

#[test]
fn a_status_query_needs_no_current_grant() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));
    state.grants[0].grant.revoked = true;

    assert!(matches!(
        validate(&state, &caller(), &query("step-1"), &clock()),
        Verdict::Known(_)
    ));
}

#[test]
fn validation_is_pure_and_deterministic() {
    let state: HelperState = state();
    let before: HelperState = state.clone();
    let request: HelperRequest = request("step-1");

    let first: Verdict = validate(&state, &caller(), &request, &clock());
    let second: Verdict = validate(&state, &caller(), &request, &clock());

    assert_eq!(first, second);
    assert!(matches!(first, Verdict::Accept(_)));
    assert_eq!(state, before);
    assert!(state.consumed().is_empty());
}

// The protocol version.

#[test]
fn refuses_a_different_protocol_major_version() {
    for major in [0, PROTOCOL_MAJOR + 1, u16::MAX] {
        let mut request: HelperRequest = request("step-1");
        request.protocol.major = major;
        assert_eq!(refused(&state(), &request), RefusalReason::ProtocolMajor);
    }
}

#[test]
fn refuses_a_later_protocol_minor_version() {
    let mut request: HelperRequest = request("step-1");
    request.protocol.minor = PROTOCOL_MINOR + 1;
    assert_eq!(refused(&state(), &request), RefusalReason::ProtocolMinor);
}

#[test]
fn the_decoder_reports_a_protocol_mismatch_before_an_unknown_field() {
    let mut value: Value = encode(&request("step-1"));
    value["protocol"]["major"] = json!(PROTOCOL_MAJOR + 1);
    // A request of a later major version can have fields that this build
    // does not know.
    value["new_field_of_a_later_version"] = json!(true);

    let error: DecodeError = decode(&value).unwrap_err();
    assert_eq!(error.code(), "helper_protocol_major_mismatch");

    // A later major version can change the version record itself.
    let mut value: Value = encode(&request("step-1"));
    value["protocol"] = json!({ "major": 2, "minor": 70_000, "patch": 1 });
    assert_eq!(
        decode(&value).unwrap_err().code(),
        "helper_protocol_major_mismatch"
    );
    // The same record with the supported major version is malformed.
    value["protocol"]["major"] = json!(PROTOCOL_MAJOR);
    assert_eq!(
        decode(&value).unwrap_err().code(),
        "helper_protocol_minor_unsupported"
    );
    value["protocol"]["minor"] = json!(PROTOCOL_MINOR);
    assert_eq!(decode(&value), Err(DecodeError::Malformed));

    let mut value: Value = encode(&request("step-1"));
    value["protocol"]["minor"] = json!(PROTOCOL_MINOR + 1);
    assert_eq!(
        decode(&value).unwrap_err().code(),
        "helper_protocol_minor_unsupported"
    );
}

// The identity and the role of the caller.

#[test]
fn refuses_a_caller_that_is_not_the_agent() {
    let state: HelperState = state();
    for code in [
        CodeIdentity::new("io.svalnir.cli", "TEAM123456").unwrap(),
        // The team alone is not the identity.
        CodeIdentity::new("io.example.other", "TEAM123456").unwrap(),
        CodeIdentity::new("io.svalnir.agent", "OTHERTEAM1").unwrap(),
    ] {
        let caller: CallerIdentity = caller_with(code, USER, ClientRole::Agent);
        for request in [request("step-1"), query("step-1")] {
            assert_eq!(
                reason_of(&validate(&state, &caller, &request, &clock())),
                RefusalReason::CallerNotPermitted
            );
        }
    }
}

#[test]
fn refuses_each_role_other_than_the_agent_for_each_operation() {
    let state: HelperState = state();
    for role in [
        ClientRole::Cli,
        ClientRole::Gui,
        ClientRole::from_wire("administrator"),
    ] {
        let caller: CallerIdentity = caller_with(agent_code(), USER, role);
        for request in [request("step-1"), query("step-1")] {
            assert_eq!(
                reason_of(&validate(&state, &caller, &request, &clock())),
                RefusalReason::RoleNotPermitted
            );
        }
    }
    assert_eq!(OperationKind::ALL.len(), 2);
    assert!(OperationKind::EvictEntries.is_mutation());
    assert!(!OperationKind::QueryStepStatus.is_mutation());
}

#[test]
fn a_forged_identity_field_in_the_body_is_rejected() {
    // At the top level of the request.
    for field in ["uid", "pid", "principal", "caller", "role", "audited_uid"] {
        let mut value: Value = encode(&request("step-1"));
        value[field] = json!(0);
        assert_eq!(decode(&value), Err(DecodeError::Malformed), "{field}");
    }
    // In the operation and in an entry.
    for pointer in [
        "/operation/evict_entries",
        "/operation/evict_entries/entries/0",
        "/correlation",
        "/validity",
    ] {
        let mut value: Value = encode(&request("step-1"));
        value.pointer_mut(pointer).unwrap()["uid"] = json!(0);
        assert_eq!(decode(&value), Err(DecodeError::Malformed), "{pointer}");
    }
    // In a record of `svalnir-core`. The grant reference and the charge
    // reject an unknown field in their own decoding. The rule and the
    // object evidence accept it, and the exactness check rejects it.
    for (pointer, error) in [
        ("/operation/evict_entries/grant", DecodeError::Malformed),
        ("/operation/evict_entries/rule", DecodeError::NotExact),
        (
            "/operation/evict_entries/entries/0/charge",
            DecodeError::Malformed,
        ),
        (
            "/operation/evict_entries/entries/0/object",
            DecodeError::NotExact,
        ),
    ] {
        let mut value: Value = encode(&request("step-1"));
        value.pointer_mut(pointer).unwrap()["principal"] = json!(0);
        assert_eq!(decode(&value), Err(error), "{pointer}");
    }
}

#[test]
fn the_audited_user_and_not_the_request_selects_the_grant() {
    let state: HelperState = state();
    // The same request from a different audited user. The request has no
    // field that can state the user of the grant.
    let other: CallerIdentity = caller_with(agent_code(), OTHER_USER, ClientRole::Agent);
    assert_eq!(
        reason_of(&validate(&state, &other, &request("step-1"), &clock())),
        RefusalReason::GrantUnknown
    );
    // The root user has no special authority.
    let root_user: CallerIdentity = caller_with(agent_code(), 0, ClientRole::Agent);
    assert_eq!(
        reason_of(&validate(&state, &root_user, &request("step-1"), &clock())),
        RefusalReason::GrantUnknown
    );
}

// The grant.

#[test]
fn refuses_a_grant_that_the_helper_does_not_have() {
    let mut request: HelperRequest = request("step-1");
    eviction_mut(&mut request).grant.grant_id = PrivilegeGrantId::new("grant-9").unwrap();
    assert_eq!(refused(&state(), &request), RefusalReason::GrantUnknown);
}

#[test]
fn refuses_an_expired_grant() {
    let request: HelperRequest = request("step-1");
    let state: HelperState = state();

    // The request expires 100 ns after the time of the fixture clock. The
    // grant applies until the request expires, and not later.
    let mut before: HelperClock = clock();
    before.wall = WallTime::from_unix(GRANT_EXPIRY - 1, 999_999_900).unwrap();
    assert!(matches!(
        validate(&state, &caller(), &request, &before),
        Verdict::Accept(_)
    ));

    // The grant does not apply at its expiry time.
    for seconds in [GRANT_EXPIRY, GRANT_EXPIRY + 1] {
        let mut expired: HelperClock = clock();
        expired.wall = wall(seconds);
        assert_eq!(
            reason_of(&validate(&state, &caller(), &request, &expired)),
            RefusalReason::GrantExpired
        );
    }
}

#[test]
fn refuses_a_revoked_grant() {
    let mut grant: PrivilegeGrant = grant_for("grant-1", USER, "root-a");
    grant.revoked = true;
    assert_eq!(
        refused(&state_with(grant, limits()), &request("step-1")),
        RefusalReason::GrantRevoked
    );
}

#[test]
fn refuses_a_grant_of_an_older_generation() {
    // The grant changed after the plan was built: the helper has
    // generation 4, and the request names generation 3.
    let mut grant: PrivilegeGrant = grant_for("grant-1", USER, "root-a");
    grant.generation = Generation::new(4);
    assert_eq!(
        refused(&state_with(grant, limits()), &request("step-1")),
        RefusalReason::GrantGenerationStale
    );
}

#[test]
fn refuses_a_generation_that_the_helper_does_not_have() {
    // A later generation in a request does not move the helper to it.
    let mut request: HelperRequest = request("step-1");
    eviction_mut(&mut request).grant.generation = Generation::new(4);
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::GrantGenerationUnknown
    );
}

#[test]
fn refuses_a_root_that_the_grant_does_not_have() {
    // The helper has the root, but for the grant of a different user.
    let state: HelperState = HelperState::new(
        config(),
        vec![
            helper_grant(grant_for("grant-1", USER, "root-a"), limits()),
            helper_grant(grant_for("grant-2", OTHER_USER, "root-b"), limits()),
        ],
    )
    .unwrap();
    for root_id in ["root-b", "root-z"] {
        let mut request: HelperRequest = request("step-1");
        eviction_mut(&mut request).root_id = RootId::new(root_id).unwrap();
        assert_eq!(refused(&state, &request), RefusalReason::RootNotGranted);
    }
}

#[test]
fn refuses_a_rule_revision_that_the_root_does_not_have() {
    let mut request: HelperRequest = request("step-1");
    eviction_mut(&mut request).rule.revision = RuleRevisionId::new("rev-2").unwrap();
    assert_eq!(refused(&state(), &request), RefusalReason::RuleNotSupported);

    let mut request: HelperRequest = self::request("step-1");
    eviction_mut(&mut request).rule.id = RuleId::new("xcode.inactive-derived-data").unwrap();
    assert_eq!(refused(&state(), &request), RefusalReason::RuleNotSupported);
}

#[test]
fn the_final_check_of_the_grant_refuses_a_record_that_does_not_agree() {
    // `HelperGrant::new` refuses this record. The test makes it directly,
    // to show that the decision does not depend on that check alone.
    let mut state: HelperState = state();
    state.grants[0].grant.action_classes = vec![ActionClass::DeleteSelectedFiles];
    assert_eq!(
        refused(&state, &request("step-1")),
        RefusalReason::GrantDoesNotCover
    );
}

// The ceilings.

#[test]
fn the_bytes_ceiling_is_inclusive() {
    let state: HelperState = state();
    let at: HelperRequest = request_with("step-1", vec![entry("a", CEILING_BYTES, 1)]);
    assert!(is_accepted(&state, &at));

    let over: HelperRequest = request_with("step-1", vec![entry("a", CEILING_BYTES + 1, 1)]);
    assert_eq!(refused(&state, &over), RefusalReason::BytesCeiling);

    // The sum of the entries counts, not the largest entry.
    let sum: HelperRequest = request_with(
        "step-1",
        vec![entry("a", CEILING_BYTES, 1), entry("b", 1, 1)],
    );
    assert_eq!(refused(&state, &sum), RefusalReason::BytesCeiling);
}

#[test]
fn the_items_ceiling_is_inclusive() {
    let state: HelperState = state();
    let at: HelperRequest = request_with("step-1", vec![entry("a", 1, CEILING_ITEMS)]);
    assert!(is_accepted(&state, &at));

    let over: HelperRequest = request_with("step-1", vec![entry("a", 1, CEILING_ITEMS + 1)]);
    assert_eq!(refused(&state, &over), RefusalReason::ItemsCeiling);
}

#[test]
fn the_ceiling_of_one_operation_is_exact_in_a_small_domain() {
    let mut grant: PrivilegeGrant = grant_for("grant-1", USER, "root-a");
    grant.ceiling = charge(5, 3);
    let state: HelperState = state_with(grant, limits());

    for bytes in 0..=8 {
        for items in 1..=6 {
            let request: HelperRequest = request_with("step-1", vec![entry("a", bytes, items)]);
            let expected: bool = bytes <= 5 && items <= 3;
            assert_eq!(
                is_accepted(&state, &request),
                expected,
                "{bytes} bytes, {items} items"
            );
        }
    }
}

#[test]
fn the_target_ceiling_is_inclusive() {
    let state: HelperState = state();
    let entries = |count: usize| -> Vec<EntryTarget> {
        (0..count)
            .map(|index: usize| entry(&format!("entry-{index}"), 1, 1))
            .collect()
    };

    assert!(is_accepted(
        &state,
        &request_with("step-1", entries(MAX_TARGETS))
    ));
    assert_eq!(
        refused(&state, &request_with("step-1", entries(MAX_TARGETS + 1))),
        RefusalReason::TargetCeiling
    );
    assert_eq!(
        refused(&state, &request_with("step-1", Vec::new())),
        RefusalReason::NoTarget
    );
}

#[test]
fn the_target_ceiling_of_the_protocol_applies_to_each_grant() {
    let mut wide: GrantLimits = limits();
    wide.max_targets = MAX_TARGETS_PER_REQUEST;
    let mut grant: PrivilegeGrant = grant_for("grant-1", USER, "root-a");
    grant.ceiling = charge(1_000_000, 1_000);
    wide.rate.work = charge(1_000_000, 1_000);
    let state: HelperState = state_with(grant, wide);
    let entries = |count: usize| -> Vec<EntryTarget> {
        (0..count)
            .map(|index: usize| entry(&format!("entry-{index}"), 1, 1))
            .collect()
    };

    assert!(is_accepted(
        &state,
        &request_with("step-1", entries(MAX_TARGETS_PER_REQUEST))
    ));
    assert_eq!(
        refused(
            &state,
            &request_with("step-1", entries(MAX_TARGETS_PER_REQUEST + 1))
        ),
        RefusalReason::TargetCeiling
    );

    // A grant record cannot set a larger ceiling.
    let mut too_wide: GrantLimits = limits();
    too_wide.max_targets = MAX_TARGETS_PER_REQUEST + 1;
    assert_eq!(
        HelperGrant::new(
            grant_for("grant-1", USER, "root-a"),
            vec![root("root-a", "/srv/root-a")],
            too_wide
        ),
        Err(StateError::Limits)
    );
}

#[test]
fn the_rate_ceiling_counts_accepted_requests_in_the_window() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));
    // The second request is at the ceiling.
    admit_ok(&mut state, &request("step-2"));
    // The third request is over it.
    assert_eq!(
        refused(&state, &request("step-3")),
        RefusalReason::RateCeiling
    );

    // The request stays refused until the window of the first one is
    // complete.
    let mut later: HelperRequest = request("step-3");
    later.validity = validity(NOW + RATE_WINDOW - 1, NOW + RATE_WINDOW + 100);
    assert_eq!(
        reason_of(&validate(
            &state,
            &caller(),
            &later,
            &clock_at(NOW + RATE_WINDOW - 1)
        )),
        RefusalReason::RateCeiling
    );
    let mut later: HelperRequest = request("step-3");
    later.validity = validity(NOW + RATE_WINDOW, NOW + RATE_WINDOW + 100);
    assert!(matches!(
        validate(&state, &caller(), &later, &clock_at(NOW + RATE_WINDOW)),
        Verdict::Accept(_)
    ));
}

#[test]
fn the_rate_ceiling_counts_accepted_work_in_the_window() {
    let mut state: HelperState = state();
    admit_ok(
        &mut state,
        &request_with("step-1", vec![entry("a", CEILING_BYTES, 1)]),
    );

    // The work of the window is at its ceiling.
    let at: HelperRequest = request_with("step-2", vec![entry("b", RATE_BYTES - CEILING_BYTES, 1)]);
    assert!(is_accepted(&state, &at));
    let over: HelperRequest = request_with(
        "step-2",
        vec![entry("b", RATE_BYTES - CEILING_BYTES + 1, 1)],
    );
    assert_eq!(refused(&state, &over), RefusalReason::RateWorkCeiling);

    // The items of the window have their own ceiling.
    let mut state: HelperState = self::state();
    admit_ok(
        &mut state,
        &request_with("step-1", vec![entry("a", 1, CEILING_ITEMS)]),
    );
    let at: HelperRequest = request_with("step-2", vec![entry("b", 1, RATE_ITEMS - CEILING_ITEMS)]);
    assert!(is_accepted(&state, &at));
    let over: HelperRequest = request_with(
        "step-2",
        vec![entry("b", 1, RATE_ITEMS - CEILING_ITEMS + 1)],
    );
    assert_eq!(refused(&state, &over), RefusalReason::RateWorkCeiling);
}

#[test]
fn a_new_generation_of_the_grant_does_not_start_a_new_rate_window() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));
    admit_ok(&mut state, &request("step-2"));

    state.grants[0].grant.generation = Generation::new(4);
    let mut request: HelperRequest = request("step-3");
    eviction_mut(&mut request).grant.generation = Generation::new(4);
    assert_eq!(refused(&state, &request), RefusalReason::RateCeiling);
}

#[test]
fn a_refused_request_does_not_count_against_the_rate() {
    let mut state: HelperState = state();
    let over: HelperRequest = request_with("step-1", vec![entry("a", CEILING_BYTES + 1, 1)]);
    for _ in 0..5 {
        assert!(matches!(admit(&mut state, &over), Admission::Refused(_)));
    }
    assert!(state.consumed().is_empty());
    admit_ok(&mut state, &request("step-2"));
}

#[test]
fn a_sum_that_does_not_fit_is_refused_and_not_saturated() {
    let request: HelperRequest =
        request_with("step-1", vec![entry("a", u64::MAX, 1), entry("b", 1, 1)]);
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ArithmeticOverflow
    );

    let request: HelperRequest =
        request_with("step-1", vec![entry("a", 1, u64::MAX), entry("b", 1, 1)]);
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ArithmeticOverflow
    );
}

#[test]
fn an_entry_bound_without_an_item_is_refused() {
    let request: HelperRequest = request_with("step-1", vec![entry("a", 10, 0)]);
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ChargeWithoutItem
    );
}

// The validity of the request.

#[test]
fn refuses_an_expired_request() {
    let state: HelperState = state();
    let request: HelperRequest = request("step-1");

    // The request is valid one nanosecond before its expiry.
    assert!(matches!(
        validate(&state, &caller(), &request, &clock_at(NOW + 99)),
        Verdict::Accept(_)
    ));
    for now in [NOW + 100, NOW + 101, u64::MAX] {
        assert_eq!(
            reason_of(&validate(&state, &caller(), &request, &clock_at(now))),
            RefusalReason::RequestExpired
        );
    }
}

#[test]
fn an_expired_request_that_the_helper_never_recorded_is_not_fresh() {
    // The request names an identity that the record does not have. Its
    // expiry, not the absence of a record, decides.
    let mut request: HelperRequest = request("step-old");
    request.validity = validity(NOW - 300, NOW - 200);
    assert_eq!(refused(&state(), &request), RefusalReason::RequestExpired);
}

#[test]
fn refuses_a_validity_that_is_longer_than_the_limit_of_the_helper() {
    let mut request: HelperRequest = request("step-1");
    request.validity = validity(NOW, NOW + MAX_VALIDITY);
    assert!(is_accepted(&state(), &request));

    request.validity = validity(NOW, NOW + MAX_VALIDITY + 1);
    assert_eq!(refused(&state(), &request), RefusalReason::ValidityTooLong);

    request.validity = validity(NOW, u64::MAX);
    assert_eq!(refused(&state(), &request), RefusalReason::ValidityTooLong);
}

#[test]
fn refuses_an_empty_validity() {
    for (issued_at, expires_at) in [(NOW, NOW), (NOW, NOW - 1)] {
        let mut request: HelperRequest = request("step-1");
        request.validity = validity(issued_at, expires_at);
        assert_eq!(refused(&state(), &request), RefusalReason::ValidityEmpty);
    }
}

#[test]
fn refuses_times_that_cannot_be_compared_with_the_clock() {
    let mut request: HelperRequest = request("step-1");
    request.validity.boot_id = BootId::new("boot-0").unwrap();
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ClockNotComparable
    );

    let mut request: HelperRequest = self::request("step-1");
    request.validity.clock_domain = ClockDomainId::new("uptime").unwrap();
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ClockNotComparable
    );

    // A request from a time after the clock of the helper.
    let mut request: HelperRequest = self::request("step-1");
    request.validity = validity(NOW + 1, NOW + 100);
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ClockNotComparable
    );
}

#[test]
fn the_validity_check_is_exact_in_a_small_domain() {
    let mut config: HelperConfig = config();
    config.max_validity = Nanoseconds::new(3);
    let state: HelperState = HelperState::new(
        config,
        vec![helper_grant(grant_for("grant-1", USER, "root-a"), limits())],
    )
    .unwrap();

    for issued_at in 0..8 {
        for expires_at in 0..8 {
            for now in 0..8 {
                let mut request: HelperRequest = request("step-1");
                request.validity = validity(issued_at, expires_at);
                let accepted: bool = matches!(
                    validate(&state, &caller(), &request, &clock_at(now)),
                    Verdict::Accept(_)
                );
                let expected: bool =
                    issued_at <= now && now < expires_at && expires_at - issued_at <= 3;
                assert_eq!(accepted, expected, "{issued_at} {expires_at} {now}");
            }
        }
    }
}

// Replay and duplicates.

#[test]
fn a_consumed_request_is_never_accepted_again() {
    let mut state: HelperState = state();
    let request: HelperRequest = request("step-1");
    admit_ok(&mut state, &request);

    // The same request again, in flight.
    for _ in 0..3 {
        let Admission::Known(status) = admit(&mut state, &request) else {
            panic!("the repeated request is not answered with its state");
        };
        assert_eq!(status.state, StepState::DispatchConsumed);
    }

    // The same request again, after the step settled.
    state
        .record_progress(&key("step-1"), StepState::Verifying)
        .unwrap();
    state
        .record_progress(&key("step-1"), StepState::Completed)
        .unwrap();
    let Admission::Known(status) = admit(&mut state, &request) else {
        panic!("the repeated request is not answered with its state");
    };
    assert_eq!(status.state, StepState::Completed);
    assert_eq!(state.consumed().len(), 1);
}

#[test]
fn a_duplicate_in_flight_returns_the_known_state_and_consumes_nothing() {
    let mut state: HelperState = state();
    let request: HelperRequest = request("step-1");
    admit_ok(&mut state, &request);
    let before: HelperState = state.clone();

    assert!(matches!(
        validate(&state, &caller(), &request, &clock()),
        Verdict::Known(_)
    ));
    assert!(matches!(admit(&mut state, &request), Admission::Known(_)));

    // No second record, and no second charge against the rate.
    assert_eq!(state, before);
    let usage = state
        .consumed()
        .usage(
            &PrivilegeGrantId::new("grant-1").unwrap(),
            &clock(),
            Nanoseconds::new(RATE_WINDOW),
        )
        .unwrap();
    assert_eq!(usage.requests, 1);
    assert_eq!(usage.work, charge(100, 1));
}

#[test]
fn a_new_transport_identity_does_not_make_the_step_executable_again() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));

    let mut again: HelperRequest = request("step-1");
    again.request_id = RequestId::new("request-new").unwrap();
    assert!(matches!(admit(&mut state, &again), Admission::Known(_)));
    assert_eq!(state.consumed().len(), 1);
}

#[test]
fn a_recorded_step_with_a_different_content_is_refused() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));

    let different_entry: HelperRequest = request_with("step-1", vec![entry("cache/other", 100, 1)]);
    let mut different_validity: HelperRequest = request("step-1");
    different_validity.validity = validity(NOW - 50, NOW + 150);
    let mut different_plan: HelperRequest = request("step-1");
    different_plan.correlation.plan_digest = ContentDigest::of_bytes(b"plan-2");

    for request in [different_entry, different_validity, different_plan.clone()] {
        assert_eq!(
            refused(&state, &request),
            RefusalReason::ConflictingDuplicate
        );
    }
    // A query for the step under a different plan is refused too.
    let mut query: HelperRequest = query("step-1");
    query.correlation = different_plan.correlation;
    assert_eq!(refused(&state, &query), RefusalReason::ConflictingDuplicate);
}

#[test]
fn a_recorded_transport_identity_is_refused_for_a_different_step() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));

    let mut other: HelperRequest = request("step-2");
    other.request_id = request("step-1").request_id;
    assert_eq!(refused(&state, &other), RefusalReason::RequestIdReused);
}

#[test]
fn a_repeated_step_gets_its_state_also_after_its_grant_was_revoked() {
    let mut state: HelperState = state();
    let request: HelperRequest = request("step-1");
    admit_ok(&mut state, &request);
    state.grants[0].grant.revoked = true;

    assert!(matches!(admit(&mut state, &request), Admission::Known(_)));
    // A new step of the revoked grant is refused.
    assert_eq!(
        refused(&state, &self::request("step-2")),
        RefusalReason::GrantRevoked
    );
}

/// Admits `step-1`, applies `change` to the state, and asks `still_covers`
/// at `at`.
fn coverage_after(
    change: impl FnOnce(&mut HelperState),
    at: &HelperClock,
) -> Result<(), RefusalReason> {
    let mut state: HelperState = state();
    let Admission::Dispatch(dispatch) = admit(&mut state, &request("step-1")) else {
        panic!("the request is not accepted");
    };
    assert_eq!(state.still_covers(&dispatch, &clock()), Ok(()));
    change(&mut state);
    state.still_covers(&dispatch, at)
}

#[test]
fn a_step_in_work_is_not_covered_after_its_grant_changed() {
    // Directly after the admission, and while the request is valid, the
    // grant covers the step. The deadline of the request is `NOW + 100`.
    assert_eq!(coverage_after(|_| {}, &clock()), Ok(()));
    assert_eq!(coverage_after(|_| {}, &clock_at(NOW + 99)), Ok(()));
    let verifying = |state: &mut HelperState| {
        state
            .record_progress(&key("step-1"), StepState::Verifying)
            .unwrap();
    };
    assert_eq!(coverage_after(verifying, &clock()), Ok(()));

    // A revocation applies at the next call.
    assert_eq!(
        coverage_after(|state| state.grants[0].grant.revoked = true, &clock()),
        Err(RefusalReason::GrantRevoked)
    );
    // A later generation does not cover the step of an earlier one.
    assert_eq!(
        coverage_after(
            |state| state.grants[0].grant.generation = Generation::new(4),
            &clock()
        ),
        Err(RefusalReason::GrantGenerationStale)
    );
    // The clock at the deadline, and after it.
    assert_eq!(
        coverage_after(|_| {}, &clock_at(NOW + 100)),
        Err(RefusalReason::RequestExpired)
    );
    assert_eq!(
        coverage_after(|_| {}, &clock_at(NOW + 101)),
        Err(RefusalReason::RequestExpired)
    );
    // A wall-clock time after the expiry of the grant.
    let late: HelperClock = HelperClock {
        wall: wall(GRANT_EXPIRY + 1),
        ..clock()
    };
    assert_eq!(
        coverage_after(|_| {}, &late),
        Err(RefusalReason::GrantExpired)
    );
    // A clock of a different boot is not comparable.
    let other_boot: HelperClock = HelperClock {
        boot_id: BootId::new("boot-2").unwrap(),
        ..clock()
    };
    assert_eq!(
        coverage_after(|_| {}, &other_boot),
        Err(RefusalReason::ClockNotComparable)
    );
    // A step that settled has no work to cover.
    let settled = |state: &mut HelperState| {
        state
            .record_progress(&key("step-1"), StepState::NoAction)
            .unwrap();
    };
    assert_eq!(
        coverage_after(settled, &clock()),
        Err(RefusalReason::StepNotRecorded)
    );
    // The grant of a different user, and a changed root.
    assert_eq!(
        coverage_after(
            |state| state.grants[0].grant.principal = Uid::new(OTHER_USER),
            &clock()
        ),
        Err(RefusalReason::GrantUnknown)
    );
    assert_eq!(
        coverage_after(
            |state| {
                state.grants[0].roots[0] = root("root-a", "/Library/Application Support/Other");
            },
            &clock()
        ),
        Err(RefusalReason::RootNotGranted)
    );

    // A state with no record of the step does not cover it.
    let mut admitting: HelperState = state();
    let Admission::Dispatch(dispatch) = admit(&mut admitting, &request("step-1")) else {
        panic!("the request is not accepted");
    };
    assert_eq!(
        state().still_covers(&dispatch, &clock()),
        Err(RefusalReason::StepNotRecorded)
    );
}

#[test]
fn a_removed_record_does_not_make_its_request_fresh() {
    let mut state: HelperState = state();
    let request: HelperRequest = request("step-1");
    admit_ok(&mut state, &request);
    state
        .record_progress(&key("step-1"), StepState::NoAction)
        .unwrap();

    // Before the retention is complete, the record stays.
    assert_eq!(state.remove_expired(&clock_at(NOW + RETENTION - 1)), 0);
    // After it, the record goes, and the request is refused for its
    // expiry.
    let late: HelperClock = clock_at(NOW + RETENTION);
    let admission: Admission = state.admit(&caller(), &request, &late);
    let Admission::Refused(refusal) = admission else {
        panic!("the old request is not refused: {admission:?}");
    };
    assert_eq!(refusal.reason, RefusalReason::RequestExpired);
    assert!(state.consumed().is_empty());
}

#[test]
fn the_step_of_one_user_is_not_the_step_of_another_user() {
    let mut state: HelperState = HelperState::new(
        config(),
        vec![
            helper_grant(grant_for("grant-1", USER, "root-a"), limits()),
            helper_grant(grant_for("grant-2", OTHER_USER, "root-b"), limits()),
        ],
    )
    .unwrap();
    admit_ok(&mut state, &request("step-1"));

    let other: CallerIdentity = caller_with(agent_code(), OTHER_USER, ClientRole::Agent);
    // The other user cannot read the state of the step.
    assert_eq!(
        reason_of(&validate(&state, &other, &query("step-1"), &clock())),
        RefusalReason::StepNotRecorded
    );
    // The same operation and step identities of the other user are a
    // different step. The first record does not hide it.
    let mut theirs: HelperRequest = request("step-1");
    theirs.request_id = RequestId::new("request-theirs").unwrap();
    let eviction: &mut EvictEntries = eviction_mut(&mut theirs);
    eviction.grant.grant_id = PrivilegeGrantId::new("grant-2").unwrap();
    eviction.root_id = RootId::new("root-b").unwrap();
    assert!(matches!(
        state.admit(&other, &theirs, &clock()),
        Admission::Dispatch(_)
    ));
    assert_eq!(state.consumed().len(), 2);
}

#[test]
fn a_query_of_a_step_that_is_not_recorded_is_refused() {
    assert_eq!(
        refused(&state(), &query("step-1")),
        RefusalReason::StepNotRecorded
    );
}

// The record of consumed requests.

#[test]
fn a_full_record_refuses_each_new_request_and_removes_nothing() {
    let mut config: HelperConfig = config();
    config.record_capacity = 2;
    config.principal_quota = 2;
    let mut state: HelperState = HelperState::new(
        config,
        vec![
            helper_grant(grant_for("grant-1", USER, "root-a"), limits()),
            helper_grant(grant_for("grant-2", OTHER_USER, "root-b"), limits()),
        ],
    )
    .unwrap();
    let other: CallerIdentity = caller_with(agent_code(), OTHER_USER, ClientRole::Agent);
    let mut theirs: HelperRequest = request("step-theirs");
    let eviction: &mut EvictEntries = eviction_mut(&mut theirs);
    eviction.grant.grant_id = PrivilegeGrantId::new("grant-2").unwrap();
    eviction.root_id = RootId::new("root-b").unwrap();

    admit_ok(&mut state, &request("step-1"));
    assert!(matches!(
        state.admit(&other, &theirs, &clock()),
        Admission::Dispatch(_)
    ));
    assert!(state.consumed().is_full());

    // The user is below the quota, and the record has no room.
    for _ in 0..3 {
        let Admission::Refused(refusal) = admit(&mut state, &request("step-2")) else {
            panic!("a full record accepted a request");
        };
        assert_eq!(refusal.reason, RefusalReason::RecordFull);
    }
    assert_eq!(state.consumed().len(), 2);
    assert!(state.consumed().find(&key("step-1")).is_some());
    assert_eq!(state.consumed().count_for(Uid::new(OTHER_USER)), 1);

    // A repeated step and a query are answered when the record is full.
    assert!(matches!(
        admit(&mut state, &request("step-1")),
        Admission::Known(_)
    ));
    assert!(matches!(
        admit(&mut state, &query("step-1")),
        Admission::Known(_)
    ));

    // A step in work stays, also after its expiry and its retention.
    let late: HelperClock = clock_at(NOW + RETENTION + 1);
    assert_eq!(state.remove_expired(&late), 0);
    assert!(state.consumed().is_full());
}

#[test]
fn a_record_is_removed_only_when_no_replay_is_possible() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-settled"));
    admit_ok(&mut state, &request("step-unknown"));
    state
        .record_progress(&key("step-settled"), StepState::NoAction)
        .unwrap();
    state
        .record_progress(&key("step-unknown"), StepState::UnknownOutcome)
        .unwrap();

    // The request is not expired.
    assert_eq!(state.remove_expired(&clock_at(NOW + 99)), 0);
    // The request is expired, but the retention is not complete.
    assert_eq!(state.remove_expired(&clock_at(NOW + RETENTION - 1)), 0);
    // The settled step goes. The step with an unknown outcome stays.
    assert_eq!(state.remove_expired(&clock_at(NOW + RETENTION)), 1);
    assert!(state.consumed().find(&key("step-settled")).is_none());
    assert!(state.consumed().find(&key("step-unknown")).is_some());
}

#[test]
fn a_restart_of_the_host_does_not_free_a_record_or_a_rate_window() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-settled"));
    admit_ok(&mut state, &request("step-in-work"));
    state
        .record_progress(&key("step-settled"), StepState::NoAction)
        .unwrap();
    let mut next_boot: HelperClock = clock_at(5);
    next_boot.boot_id = BootId::new("boot-2").unwrap();

    // The two steps of the boot before stay and count against the rate.
    assert_eq!(state.remove_expired(&next_boot), 0);
    let usage = state
        .consumed()
        .usage(
            &PrivilegeGrantId::new("grant-1").unwrap(),
            &next_boot,
            Nanoseconds::new(RATE_WINDOW),
        )
        .unwrap();
    assert_eq!(usage.requests, 2);
    let mut fresh: HelperRequest = request("step-3");
    fresh.validity = validity(1, 100);
    fresh.validity.boot_id = BootId::new("boot-2").unwrap();
    assert_eq!(
        reason_of(&validate(&state, &caller(), &fresh, &next_boot)),
        RefusalReason::RateCeiling
    );

    // The settled step with a new validity of the new boot is not a new
    // step: its identity is consumed.
    let mut again: HelperRequest = request("step-settled");
    again.request_id = RequestId::new("request-after-restart").unwrap();
    again.validity = fresh.validity.clone();
    let Admission::Refused(refusal) = state.admit(&caller(), &again, &next_boot) else {
        panic!("a consumed step was accepted again after a restart");
    };
    assert_eq!(refusal.reason, RefusalReason::ConflictingDuplicate);

    // The retention of the fixture is less than one second. The record
    // stays for that second and one more, on the wall clock.
    next_boot.wall = wall(WALL_NOW + 1);
    assert_eq!(state.remove_expired(&next_boot), 0);
    // A wall clock that went back removes nothing.
    next_boot.wall = wall(WALL_NOW - 1_000);
    assert_eq!(state.remove_expired(&next_boot), 0);
    // After the retention, the settled step goes. The step that is not
    // settled stays.
    next_boot.wall = wall(WALL_NOW + 2);
    assert_eq!(state.remove_expired(&next_boot), 1);
    assert!(state.consumed().find(&key("step-settled")).is_none());
    assert!(state.consumed().find(&key("step-in-work")).is_some());
}

#[test]
fn one_user_cannot_fill_the_record_of_the_helper() {
    let mut wide: GrantLimits = limits();
    wide.rate.max_requests = 100;
    wide.rate.work = charge(100_000, 100);
    let mut state: HelperState = HelperState::new(
        config(),
        vec![
            helper_grant(grant_for("grant-1", USER, "root-a"), wide),
            helper_grant(grant_for("grant-2", OTHER_USER, "root-b"), wide),
        ],
    )
    .unwrap();

    for index in 0..QUOTA {
        admit_ok(&mut state, &request(&format!("step-{index}")));
    }
    let Admission::Refused(refusal) = admit(&mut state, &request("step-over")) else {
        panic!("a user went over the record quota");
    };
    assert_eq!(refusal.reason, RefusalReason::RecordQuota);
    assert!(!state.consumed().is_full());

    // The other user has room.
    let other: CallerIdentity = caller_with(agent_code(), OTHER_USER, ClientRole::Agent);
    let mut theirs: HelperRequest = request("step-theirs");
    let eviction: &mut EvictEntries = eviction_mut(&mut theirs);
    eviction.grant.grant_id = PrivilegeGrantId::new("grant-2").unwrap();
    eviction.root_id = RootId::new("root-b").unwrap();
    // The transport identity of a request of the first user is not
    // examined for the other user.
    theirs.request_id = request("step-0").request_id;
    assert!(matches!(
        state.admit(&other, &theirs, &clock()),
        Admission::Dispatch(_)
    ));

    // A quota of zero or over the capacity is refused.
    for quota in [0, CAPACITY + 1] {
        let mut changed: HelperConfig = config();
        changed.principal_quota = quota;
        assert_eq!(
            HelperState::new(changed, Vec::new()),
            Err(StateError::Quota)
        );
    }
}

#[test]
fn an_entry_without_native_identifiers_is_refused() {
    let mut request: HelperRequest = request("step-1");
    eviction_mut(&mut request).entries[0].object = None;
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::ObjectEvidenceAbsent
    );
    assert_eq!(
        RefusalReason::ObjectEvidenceAbsent.family(),
        ErrorFamily::Evidence
    );
}

#[test]
fn the_record_permits_only_the_transitions_of_a_consumed_step() {
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));

    for next in [
        StepState::Admitted,
        StepState::IntentCommitted,
        StepState::DispatchConsumed,
        // A result needs a submitted call first.
        StepState::Completed,
        StepState::Partial,
        StepState::from_wire("Finished"),
    ] {
        assert_eq!(
            state.record_progress(&key("step-1"), next),
            Err(RecordError::State)
        );
    }
    assert_eq!(
        state.record_progress(&key("step-9"), StepState::Verifying),
        Err(RecordError::NotRecorded)
    );

    state
        .record_progress(&key("step-1"), StepState::Verifying)
        .unwrap();
    state
        .record_progress(&key("step-1"), StepState::UnknownOutcome)
        .unwrap();
    // Reconciliation settles an unknown outcome.
    let status = state
        .record_progress(&key("step-1"), StepState::Incomplete)
        .unwrap();
    assert_eq!(status.state, StepState::Incomplete);
    // A settled step does not change.
    assert_eq!(
        state.record_progress(&key("step-1"), StepState::Completed),
        Err(RecordError::State)
    );
}

#[test]
fn the_record_has_a_bounded_capacity() {
    let retention: Nanoseconds = Nanoseconds::new(RETENTION);
    assert_eq!(
        ConsumedRequests::new(0, retention),
        Err(RecordError::Capacity)
    );
    assert_eq!(
        ConsumedRequests::new(MAX_RECORD_CAPACITY + 1, retention),
        Err(RecordError::Capacity)
    );
    assert!(ConsumedRequests::new(MAX_RECORD_CAPACITY, retention).is_ok());

    // A restored record does not drop a request to make the others fit.
    let mut state: HelperState = state();
    admit_ok(&mut state, &request("step-1"));
    admit_ok(&mut state, &request("step-2"));
    let requests = || state.consumed().requests().cloned();
    assert_eq!(
        ConsumedRequests::restore(1, retention, requests()),
        Err(RecordError::Full)
    );
    assert_eq!(
        ConsumedRequests::restore(4, retention, requests().chain(requests())),
        Err(RecordError::Duplicate)
    );
    let restored = ConsumedRequests::restore(2, retention, requests()).unwrap();
    // The two steps were in work, so the restore changed the two.
    assert_eq!(restored.changed, [key("step-1"), key("step-2")]);
    let restored: ConsumedRequests = restored.state;
    assert_eq!(restored.len(), 2);

    // A restored state refuses the replay of a restored step.
    let mut restored_state: HelperState = HelperState::restore(
        config(),
        vec![helper_grant(grant_for("grant-1", USER, "root-a"), limits())],
        requests().collect(),
    )
    .unwrap()
    .state;
    assert!(matches!(
        admit(&mut restored_state, &request("step-1")),
        Admission::Known(_)
    ));
}

// The targets.

#[test]
fn refuses_each_entry_that_leaves_its_root() {
    let cases: [(&str, PathDefect); 12] = [
        ("/etc/passwd", PathDefect::Absolute),
        ("/", PathDefect::Absolute),
        ("..", PathDefect::ParentDirectory),
        ("../outside", PathDefect::ParentDirectory),
        ("cache/../../outside", PathDefect::ParentDirectory),
        ("cache/..", PathDefect::ParentDirectory),
        (".", PathDefect::CurrentDirectory),
        ("./cache", PathDefect::CurrentDirectory),
        ("cache/./a", PathDefect::CurrentDirectory),
        ("cache//a", PathDefect::EmptyComponent),
        ("cache/", PathDefect::EmptyComponent),
        ("cache/a/", PathDefect::EmptyComponent),
    ];
    let state: HelperState = state();
    for (relative, defect) in cases {
        let request: HelperRequest = request_with("step-1", vec![entry(relative, 1, 1)]);
        assert_eq!(
            refused(&state, &request),
            RefusalReason::TargetPath(defect),
            "{relative}"
        );
    }

    // One entry that is not permitted refuses the request, not only that
    // entry.
    let request: HelperRequest =
        request_with("step-1", vec![entry("a", 1, 1), entry("../b", 1, 1)]);
    assert_eq!(
        refused(&state, &request),
        RefusalReason::TargetPath(PathDefect::ParentDirectory)
    );
}

#[test]
fn names_that_only_look_like_a_parent_directory_are_names() {
    for relative in ["...", "..a", "a..", ".hidden", "a/..b/c", "a b/c"] {
        let request: HelperRequest = request_with("step-1", vec![entry(relative, 1, 1)]);
        assert!(is_accepted(&state(), &request), "{relative}");
    }
}

#[test]
fn refuses_an_entry_over_a_length_limit() {
    let long_name: String = "n".repeat(MAX_COMPONENT_BYTES + 1);
    assert_eq!(
        EntryPath::parse(&path(&long_name)),
        Err(PathDefect::ComponentTooLong)
    );
    assert!(EntryPath::parse(&path(&"n".repeat(MAX_COMPONENT_BYTES))).is_ok());

    let deep: String = vec!["d"; MAX_PATH_DEPTH + 1].join("/");
    assert_eq!(EntryPath::parse(&path(&deep)), Err(PathDefect::TooDeep));
    let at_depth: EntryPath =
        EntryPath::parse(&path(&vec!["d"; MAX_PATH_DEPTH].join("/"))).unwrap();
    assert_eq!(at_depth.depth(), MAX_PATH_DEPTH);

    let long_path: String = vec!["0123456789abcdef"; 61].join("/");
    assert!(long_path.len() > MAX_PATH_BYTES);
    assert_eq!(
        EntryPath::parse(&path(&long_path)),
        Err(PathDefect::TooLong)
    );

    // A path with a NUL byte or with no byte has no encoding.
    assert!(LosslessPath::from_bytes(b"a\0b".to_vec()).is_err());
    assert!(LosslessPath::from_bytes(Vec::new()).is_err());
}

#[test]
fn an_entry_that_is_not_utf8_is_checked_by_its_bytes() {
    let names: EntryPath =
        EntryPath::parse(&LosslessPath::from_bytes(b"\xff/\xfe".to_vec()).unwrap()).unwrap();
    assert_eq!(names.names().collect::<Vec<&[u8]>>(), [b"\xff", b"\xfe"]);
    assert_eq!(
        EntryPath::parse(&LosslessPath::from_bytes(b"\xff/../x".to_vec()).unwrap()),
        Err(PathDefect::ParentDirectory)
    );
}

/// An independent statement of the rule, with the path parser of the
/// standard library: each component is a normal name, and the components
/// give the text back, so the text has no name that the parser removed.
fn oracle_accepts_entry(text: &str) -> bool {
    let components: Vec<Component<'_>> = Path::new(text).components().collect();
    let names: Vec<&str> = components
        .iter()
        .filter_map(|component: &Component<'_>| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    !names.is_empty() && names.len() == components.len() && names.join("/") == text
}

#[test]
fn the_entry_check_agrees_with_an_independent_rule_for_each_short_path() {
    // Each text of 1 to 8 characters from `a`, `.`, and `/`: 9840 paths.
    let alphabet: [char; 3] = ['a', '.', '/'];
    let mut texts: Vec<String> = vec![String::new()];
    let mut checked: usize = 0;
    for _ in 0..8 {
        texts = texts
            .iter()
            .flat_map(|text: &String| {
                alphabet.iter().map(move |character: &char| {
                    let mut longer: String = text.clone();
                    longer.push(*character);
                    longer
                })
            })
            .collect();
        for text in &texts {
            let accepted: bool = EntryPath::parse(&path(text)).is_ok();
            assert_eq!(accepted, oracle_accepts_entry(text), "{text:?}");
            if accepted {
                // No accepted entry has a name that leaves its directory.
                let entry: EntryPath = EntryPath::parse(&path(text)).unwrap();
                assert!(entry.names().all(|name: &[u8]| {
                    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/')
                }));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 9840);
}

#[test]
fn refuses_one_entry_two_times_and_an_unknown_object_type() {
    let request: HelperRequest =
        request_with("step-1", vec![entry("a/b", 1, 1), entry("a/b", 1, 1)]);
    assert_eq!(refused(&state(), &request), RefusalReason::DuplicateTarget);

    let mut request: HelperRequest = self::request("step-1");
    eviction_mut(&mut request).entries[0].object_type = FileObjectType::from_wire("socket");
    assert_eq!(refused(&state(), &request), RefusalReason::ObjectType);
}

// The state of the helper.

#[test]
fn a_root_is_an_absolute_path_of_names_below_the_filesystem_root() {
    let cases: [(&str, PathDefect); 8] = [
        ("relative/root", PathDefect::Relative),
        ("~/Library/Caches", PathDefect::Relative),
        ("/", PathDefect::FilesystemRoot),
        ("/srv/../etc", PathDefect::ParentDirectory),
        ("/srv/./cache", PathDefect::CurrentDirectory),
        ("//srv", PathDefect::EmptyComponent),
        ("/srv/", PathDefect::EmptyComponent),
        ("/srv//cache", PathDefect::EmptyComponent),
    ];
    for (text, defect) in cases {
        assert_eq!(RootPath::parse(&path(text)), Err(defect), "{text}");
        assert_eq!(
            ApprovedRoot::new(RootId::new("root-a").unwrap(), &path(text), vec![rule()]),
            Err(StateError::RootPath(defect)),
            "{text}"
        );
    }
    assert!(RootPath::parse(&path("/srv/cache")).is_ok());
}

#[test]
fn a_root_needs_a_bounded_list_of_distinct_rules() {
    let root_id = || RootId::new("root-a").unwrap();
    let root_path: LosslessPath = path("/srv/cache");
    assert_eq!(
        ApprovedRoot::new(root_id(), &root_path, Vec::new()),
        Err(StateError::Rules)
    );
    assert_eq!(
        ApprovedRoot::new(root_id(), &root_path, vec![rule(), rule()]),
        Err(StateError::Rules)
    );
    let many: Vec<RuleRef> = (0..=super::MAX_RULES_PER_ROOT)
        .map(|index: usize| RuleRef {
            id: RuleId::new("svalnir.helper-temporary").unwrap(),
            revision: RuleRevisionId::new(format!("rev-{index}")).unwrap(),
        })
        .collect();
    assert_eq!(
        ApprovedRoot::new(root_id(), &root_path, many),
        Err(StateError::Rules)
    );
}

#[test]
fn a_grant_record_that_does_not_agree_is_refused() {
    let new = |grant: PrivilegeGrant, roots: Vec<ApprovedRoot>, limits: GrantLimits| {
        HelperGrant::new(grant, roots, limits)
    };
    let base = || grant_for("grant-1", USER, "root-a");
    let base_roots = || vec![root("root-a", "/srv/root-a")];
    assert!(new(base(), base_roots(), limits()).is_ok());

    // Action classes: only the class that this build can do.
    for classes in [
        Vec::new(),
        vec![ActionClass::DeleteSelectedFiles],
        vec![
            ActionClass::EvictRegenerableData,
            ActionClass::ForceApplicationExit,
        ],
        vec![
            ActionClass::EvictRegenerableData,
            ActionClass::EvictRegenerableData,
        ],
        vec![ActionClass::from_wire("RunCommand")],
    ] {
        let mut grant: PrivilegeGrant = base();
        grant.action_classes = classes;
        assert_eq!(
            new(grant, base_roots(), limits()),
            Err(StateError::ActionClasses)
        );
    }

    // The critical-memory exception is not a power of the helper.
    let mut grant: PrivilegeGrant = base();
    grant.allow_volatile_journal_on_critical = true;
    assert_eq!(
        new(grant, base_roots(), limits()),
        Err(StateError::VolatileException)
    );

    // Roots: the same set in the grant and in the records.
    assert_eq!(new(base(), Vec::new(), limits()), Err(StateError::Roots));
    assert_eq!(
        new(base(), vec![root("root-b", "/srv/root-b")], limits()),
        Err(StateError::Roots)
    );
    assert_eq!(
        new(
            base(),
            vec![root("root-a", "/srv/root-a"), root("root-b", "/srv/root-b")],
            limits()
        ),
        Err(StateError::Roots)
    );
    let mut no_root: PrivilegeGrant = base();
    no_root.roots = Vec::new();
    assert_eq!(new(no_root, Vec::new(), limits()), Err(StateError::Roots));
    // One root below another root.
    let mut two_roots: PrivilegeGrant = base();
    two_roots.roots.push(RootId::new("root-b").unwrap());
    assert_eq!(
        new(
            two_roots.clone(),
            vec![
                root("root-a", "/srv/cache"),
                root("root-b", "/srv/cache/inner")
            ],
            limits()
        ),
        Err(StateError::Roots)
    );
    assert!(
        new(
            two_roots,
            vec![root("root-a", "/srv/cache"), root("root-b", "/srv/cache-2")],
            limits()
        )
        .is_ok()
    );

    // Limits: none is zero.
    let mut no_items: PrivilegeGrant = base();
    no_items.ceiling = charge(100, 0);
    assert_eq!(
        new(no_items, base_roots(), limits()),
        Err(StateError::Limits)
    );
    let zero_limits: [fn(&mut GrantLimits); 4] = [
        |limits| limits.max_targets = 0,
        |limits| limits.rate.window = Nanoseconds::ZERO,
        |limits| limits.rate.max_requests = 0,
        |limits| limits.rate.work = charge(100, 0),
    ];
    for change in zero_limits {
        let mut changed: GrantLimits = limits();
        change(&mut changed);
        assert_eq!(new(base(), base_roots(), changed), Err(StateError::Limits));
    }
}

type ConfigChange = fn(&mut HelperConfig);

#[test]
fn a_state_that_does_not_agree_is_refused() {
    let grants = || vec![helper_grant(grant_for("grant-1", USER, "root-a"), limits())];
    assert!(HelperState::new(config(), grants()).is_ok());
    assert!(HelperState::new(config(), Vec::new()).is_ok());

    // Two grants with one identity.
    let twice: Vec<HelperGrant> = grants().into_iter().chain(grants()).collect();
    assert_eq!(HelperState::new(config(), twice), Err(StateError::Grants));
    // More grants than the limit.
    let many: Vec<HelperGrant> = (0..=super::MAX_GRANTS)
        .map(|index: usize| {
            helper_grant(
                grant_for(&format!("grant-{index}"), USER, &format!("root-{index}")),
                limits(),
            )
        })
        .collect();
    assert_eq!(HelperState::new(config(), many), Err(StateError::Grants));

    let cases: [(ConfigChange, StateError); 5] = [
        (
            |config| config.max_validity = Nanoseconds::ZERO,
            StateError::Retention,
        ),
        (
            |config| config.retention = Nanoseconds::new(MAX_VALIDITY - 1),
            StateError::Retention,
        ),
        (
            // Shorter than the rate window, with a short validity.
            |config| {
                config.max_validity = Nanoseconds::new(10);
                config.retention = Nanoseconds::new(RATE_WINDOW - 1);
            },
            StateError::Retention,
        ),
        (
            |config| config.record_capacity = 0,
            StateError::Record(RecordError::Capacity),
        ),
        (
            |config| config.record_capacity = MAX_RECORD_CAPACITY + 1,
            StateError::Record(RecordError::Capacity),
        ),
    ];
    for (change, error) in cases {
        let mut changed: HelperConfig = config();
        change(&mut changed);
        assert_eq!(HelperState::new(changed, grants()), Err(error));
    }
}

#[test]
fn a_code_identity_is_bounded_visible_text() {
    assert!(CodeIdentity::new("io.svalnir.agent", "TEAM123456").is_ok());
    for (signing, team) in [
        ("", "TEAM123456"),
        ("io.svalnir.agent", ""),
        ("io.svalnir agent", "TEAM123456"),
        ("io.svalnir.agent\n", "TEAM123456"),
        ("io.svalnir.агент", "TEAM123456"),
    ] {
        assert!(CodeIdentity::new(signing, team).is_err(), "{signing:?}");
    }
    let long: String = "a".repeat(crate::request::MAX_CODE_IDENTITY_BYTES + 1);
    assert!(CodeIdentity::new(long, "TEAM123456").is_err());

    let caller: CallerIdentity = caller();
    assert_eq!(caller.code().signing_identifier(), "io.svalnir.agent");
    assert_eq!(caller.code().team_identifier(), "TEAM123456");
    assert_eq!(caller.audited_uid(), Uid::new(USER));
    assert_eq!(caller.role(), &ClientRole::Agent);
    assert_eq!(caller.session().map(SessionId::as_str), Some("session-1"));
}

// The encoded form.

#[test]
fn the_encoded_form_of_each_operation_decodes_to_the_same_request() {
    for request in [request("step-1"), query("step-1")] {
        let bytes: Vec<u8> = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            decode_request(&bytes, SupportedProtocols::CURRENT),
            Ok(request)
        );
    }
    // The spelling of the two operations.
    let value: Value = encode(&request("step-1"));
    assert!(value["operation"]["evict_entries"].is_object());
    assert_eq!(
        encode(&query("step-1"))["operation"],
        json!({ "query_step_status": {} })
    );
    assert_eq!(value["protocol"], json!({ "major": 1, "minor": 0 }));
}

#[test]
fn an_unknown_operation_is_rejected() {
    let operations: [Value; 9] = [
        json!({ "run_command": { "command": "rm -rf /" } }),
        json!({ "delete_path": { "path": "/Users", "recursive": true } }),
        json!({ "signal_process": { "pid": 1, "signal": 9 } }),
        json!({ "execute": { "executable": "/bin/sh", "arguments": ["-c", "true"] } }),
        json!({ "EvictEntries": {} }),
        json!({}),
        json!("evict_entries"),
        json!(null),
        json!({ "kind": "evict_entries" }),
    ];
    for operation in operations {
        let mut value: Value = encode(&request("step-1"));
        value["operation"] = operation.clone();
        assert_eq!(decode(&value), Err(DecodeError::Malformed), "{operation}");
    }

    // Two operations in one request.
    let mut value: Value = encode(&request("step-1"));
    value["operation"]["query_step_status"] = json!({});
    assert_eq!(decode(&value), Err(DecodeError::Malformed));
}

#[test]
fn an_unknown_field_is_rejected_at_each_level() {
    let pointers: [(&str, DecodeError); 9] = [
        ("", DecodeError::Malformed),
        ("/protocol", DecodeError::Malformed),
        ("/correlation", DecodeError::Malformed),
        ("/validity", DecodeError::Malformed),
        ("/operation/evict_entries", DecodeError::Malformed),
        ("/operation/evict_entries/entries/0", DecodeError::Malformed),
        (
            "/operation/evict_entries/entries/0/relative_entry",
            DecodeError::Malformed,
        ),
        ("/operation/evict_entries/grant", DecodeError::Malformed),
        ("/operation/evict_entries/rule", DecodeError::NotExact),
    ];
    for (pointer, error) in pointers {
        let mut value: Value = encode(&request("step-1"));
        value.pointer_mut(pointer).unwrap()["approved"] = json!(true);
        assert_eq!(decode(&value), Err(error), "{pointer:?}");
    }
    // A field in the status query, which has none.
    let mut value: Value = encode(&query("step-1"));
    value["operation"]["query_step_status"]["all_users"] = json!(true);
    assert_eq!(decode(&value), Err(DecodeError::Malformed));

    // A record of `svalnir-core` that does not reject an unknown field
    // itself is covered by the exactness check.
    let mut value: Value = encode(&request("step-1"));
    value["operation"]["evict_entries"]["rule"]["mode"] = json!("automatic_eviction");
    assert_eq!(decode(&value), Err(DecodeError::NotExact));
    // The grant reference rejects an unknown field itself.
    let mut value: Value = encode(&request("step-1"));
    value["operation"]["evict_entries"]["grant"]["ceiling"] = json!("999999");
    assert_eq!(decode(&value), Err(DecodeError::Malformed));
}

#[test]
fn an_unknown_authority_bearing_value_is_rejected() {
    // An object type that this build does not recognize decodes, because
    // `svalnir-core` keeps it as an explicit unrecognized value. The
    // validation refuses it.
    let mut value: Value = encode(&request("step-1"));
    value["operation"]["evict_entries"]["entries"][0]["object_type"] = json!("whole_tree");
    let request: HelperRequest = decode(&value).unwrap();
    assert_eq!(refused(&state(), &request), RefusalReason::ObjectType);

    // A value that is not in its canonical encoding.
    for (pointer, replacement) in [
        ("/operation/evict_entries/grant/generation", json!(3)),
        ("/operation/evict_entries/grant/generation", json!("03")),
        ("/operation/evict_entries/grant/generation", json!("-3")),
        (
            "/operation/evict_entries/entries/0/charge/work_bytes",
            json!("1e2"),
        ),
        (
            "/operation/evict_entries/entries/0/charge/work_bytes",
            json!("unlimited"),
        ),
        (
            "/operation/evict_entries/entries/0/charge/items",
            json!(null),
        ),
        ("/validity/expires_at", json!("18446744073709551616")),
        ("/validity/expires_at", json!("never")),
        ("/protocol/major", json!("1")),
        ("/protocol/major", json!(1.5)),
        ("/protocol/major", json!(-1)),
        ("/request_id", json!("")),
        ("/request_id", json!("has space")),
        ("/correlation/plan_digest", json!("md5:abc")),
        ("/operation/evict_entries/root_id", json!("/Users")),
        (
            "/operation/evict_entries/entries/0/relative_entry",
            json!("cache/a.tmp"),
        ),
        (
            "/operation/evict_entries/entries/0/relative_entry",
            json!({ "encoding": "hex", "value": "6361636865" }),
        ),
        (
            "/operation/evict_entries/entries/0/relative_entry",
            json!({ "encoding": "utf8", "value": "" }),
        ),
    ] {
        let mut value: Value = encode(&self::request("step-1"));
        *value.pointer_mut(pointer).unwrap() = replacement.clone();
        // The preamble and the strict decoding fail first, also for the
        // protocol version.
        assert_eq!(
            decode(&value),
            Err(DecodeError::Malformed),
            "{pointer} = {replacement}"
        );
    }
}

#[test]
fn an_absent_field_and_a_repeated_field_are_rejected() {
    for field in [
        "protocol",
        "request_id",
        "correlation",
        "validity",
        "operation",
    ] {
        let mut value: Value = encode(&request("step-1"));
        value.as_object_mut().unwrap().remove(field);
        assert_eq!(decode(&value), Err(DecodeError::Malformed), "{field}");
    }

    // An optional field must be present: `null` states that the evidence
    // is absent.
    let mut value: Value = encode(&request("step-1"));
    let entry: &mut Value = value
        .pointer_mut("/operation/evict_entries/entries/0")
        .unwrap();
    entry.as_object_mut().unwrap().remove("object");
    assert_eq!(decode(&value), Err(DecodeError::NotExact));
    let mut value: Value = encode(&request("step-1"));
    value["operation"]["evict_entries"]["entries"][0]["object"] = json!(null);
    assert!(decode(&value).is_ok());

    // A field two times, with two different values.
    let text: String = serde_json::to_string(&request("step-1")).unwrap();
    let repeated: String = text.replacen(
        "\"request_id\":",
        "\"request_id\":\"request-other\",\"request_id\":",
        1,
    );
    assert_ne!(text, repeated);
    assert_eq!(
        decode_request(repeated.as_bytes(), SupportedProtocols::CURRENT),
        Err(DecodeError::Malformed)
    );
    let repeated_root: String =
        text.replacen("\"root_id\":", "\"root_id\":\"root-b\",\"root_id\":", 1);
    assert_ne!(text, repeated_root);
    assert_eq!(
        decode_request(repeated_root.as_bytes(), SupportedProtocols::CURRENT),
        Err(DecodeError::Malformed)
    );
}

#[test]
fn an_encoded_form_over_a_limit_or_that_is_not_json_is_rejected() {
    let supported: SupportedProtocols = SupportedProtocols::CURRENT;
    for bytes in [
        b"".as_slice(),
        b"null",
        b"[]",
        b"\"evict\"",
        b"{",
        b"}",
        b"{\"protocol\":{\"major\":1,\"minor\":0}}",
        b"\xff\xfe",
    ] {
        assert_eq!(
            decode_request(bytes, supported),
            Err(DecodeError::Malformed),
            "{bytes:?}"
        );
    }

    // The size limit, before a parser reads the bytes.
    let large: Vec<u8> = vec![b' '; MAX_ENCODED_REQUEST_BYTES + 1];
    assert_eq!(
        decode_request(&large, supported),
        Err(DecodeError::TooLarge)
    );
    let at_limit: Vec<u8> = vec![b' '; MAX_ENCODED_REQUEST_BYTES];
    assert_eq!(
        decode_request(&at_limit, supported),
        Err(DecodeError::Malformed)
    );

    // The nesting limit.
    let nested = |depth: usize| -> Vec<u8> {
        let mut text: String = "[".repeat(depth);
        text.push_str(&"]".repeat(depth));
        text.into_bytes()
    };
    assert_eq!(
        decode_request(&nested(MAX_NESTING_DEPTH + 1), supported),
        Err(DecodeError::TooDeep)
    );
    assert_eq!(
        decode_request(&nested(MAX_NESTING_DEPTH), supported),
        Err(DecodeError::Malformed)
    );
    // A bracket in a string is not nesting.
    let mut value: Value = encode(&request("step-1"));
    value["operation"]["evict_entries"]["entries"][0]["relative_entry"]["value"] =
        json!("[[[[[[[[[[[[[[[[[[[[\\\"{{{{");
    assert!(decode(&value).is_ok());

    // More entries than the protocol permits decode, and the validation
    // refuses them.
    let entries: Vec<EntryTarget> = (0..=MAX_TARGETS_PER_REQUEST)
        .map(|index: usize| entry(&format!("entry-{index}"), 1, 1))
        .collect();
    let request: HelperRequest = decode(&encode(&request_with("step-1", entries))).unwrap();
    assert_eq!(refused(&state(), &request), RefusalReason::TargetCeiling);
}

// Evidence of the caller cannot widen the authority.

#[test]
fn evidence_of_the_caller_cannot_raise_a_limit() {
    // The request has no field for a measurement, an approval, a budget,
    // or a recording exception.
    let statements: [(&str, Value); 8] = [
        ("memory_pressure", json!("critical")),
        ("disk_pressure", json!("critical")),
        ("approved", json!(true)),
        (
            "ceiling",
            json!({ "work_bytes": "999999999", "items": "999999" }),
        ),
        ("remaining_budget", json!("999999999")),
        ("recording", json!("volatile_critical_exception")),
        ("max_targets", json!(100_000)),
        ("force", json!(true)),
    ];
    for (field, statement) in &statements {
        for pointer in [
            "",
            "/operation/evict_entries",
            "/operation/evict_entries/entries/0",
        ] {
            let mut value: Value = encode(&request("step-1"));
            value.pointer_mut(pointer).unwrap()[field] = statement.clone();
            assert_eq!(
                decode(&value),
                Err(DecodeError::Malformed),
                "{field} at {pointer:?}"
            );
        }
    }

    // A reference to a later generation does not give its ceilings. The
    // charge is over the ceiling of the recorded generation. With the
    // generation of the record, the same entry fails on the ceiling; with a
    // later generation, it fails on the generation before any ceiling. The
    // two results together show that the reference selects no ceiling.
    let mut request: HelperRequest = request_with("step-1", vec![entry("a", CEILING_BYTES + 1, 1)]);
    assert_eq!(refused(&state(), &request), RefusalReason::BytesCeiling);
    eviction_mut(&mut request).grant.generation = Generation::new(99);
    assert_eq!(
        refused(&state(), &request),
        RefusalReason::GrantGenerationUnknown
    );

    // A large bound does not raise the ceiling, and a small bound makes
    // the accepted operation smaller.
    let state: HelperState = state();
    let large: HelperRequest = request_with("step-1", vec![entry("a", u64::MAX, CEILING_ITEMS)]);
    assert_eq!(refused(&state, &large), RefusalReason::BytesCeiling);
    let small: HelperRequest = request_with("step-1", vec![entry("a", 7, 1)]);
    let Verdict::Accept(operation) = validate(&state, &caller(), &small, &clock()) else {
        panic!("the request is not accepted");
    };
    let BoundedOperation::EvictEntries(accepted) = *operation;
    assert_eq!(accepted.limit, charge(7, 1));
}

// The refusal.

#[test]
fn each_reason_has_a_valid_code_and_the_family_of_its_control() {
    let mut codes: Vec<&str> = Vec::new();
    for reason in RefusalReason::ALL {
        assert!(ErrorCode::new(reason.code()).is_ok(), "{reason:?}");
        assert!(reason.code().starts_with("helper_"));
        assert!(!codes.contains(&reason.code()), "{reason:?}");
        codes.push(reason.code());
        assert!(reason.family().is_recognized());
    }
    for error in [
        DecodeError::TooLarge,
        DecodeError::TooDeep,
        DecodeError::Malformed,
        DecodeError::NotExact,
    ] {
        assert!(ErrorCode::new(error.code()).is_ok());
        assert!(!codes.contains(&error.code()));
    }

    let families: [(RefusalReason, ErrorFamily); 9] = [
        (RefusalReason::ProtocolMajor, ErrorFamily::Request),
        (RefusalReason::ConflictingDuplicate, ErrorFamily::Request),
        (
            RefusalReason::TargetPath(PathDefect::Absolute),
            ErrorFamily::Request,
        ),
        (RefusalReason::CallerNotPermitted, ErrorFamily::Authority),
        (RefusalReason::GrantRevoked, ErrorFamily::Authority),
        (RefusalReason::ClockNotComparable, ErrorFamily::Evidence),
        (RefusalReason::RequestExpired, ErrorFamily::Limits),
        (RefusalReason::BytesCeiling, ErrorFamily::Limits),
        (RefusalReason::RecordFull, ErrorFamily::Limits),
    ];
    for (reason, family) in families {
        assert_eq!(reason.family(), family, "{reason:?}");
    }
}

#[test]
fn a_refusal_is_an_action_error_with_no_submitted_call() {
    let mut request: HelperRequest = request("step-1");
    request.validity = validity(NOW - 300, NOW - 200);
    let Verdict::Refuse(refusal) = validate(&state(), &caller(), &request, &clock()) else {
        panic!("the request is not refused");
    };

    let error = refusal.to_action_error().unwrap();
    assert_eq!(error.code.as_str(), "helper_request_expired");
    assert_eq!(error.family, ErrorFamily::Limits);
    assert_eq!(error.dispatch, DispatchState::NotSubmitted);
    assert_eq!(
        error.permitted_next_step(),
        PermittedNextStep::RespectLimits
    );
    assert_eq!(error.plan_id, Some(request.correlation.plan_id));
    assert_eq!(error.operation_id, Some(request.correlation.operation_id));
    assert_eq!(error.step_id, Some(request.correlation.step_id));
}

// Regression tests of the review of the validation.

#[test]
fn refuses_a_request_that_is_valid_after_the_expiry_of_its_grant() {
    let request: HelperRequest = request("step-1");
    let mut state: HelperState = state();

    // The grant is in effect at the time of the check, and it expires
    // 1 ns before the request does. The executor could submit a call in
    // that time.
    let mut late: HelperClock = clock();
    late.wall = WallTime::from_unix(GRANT_EXPIRY - 1, 999_999_901).unwrap();
    assert_eq!(
        reason_of(&validate(&state, &caller(), &request, &late)),
        RefusalReason::GrantExpiresBeforeRequest
    );
    assert!(matches!(
        state.admit(&caller(), &request, &late),
        Admission::Refused(_)
    ));
    assert!(state.consumed().is_empty());

    // A grant with no expiry applies for each validity.
    let mut open: PrivilegeGrant = grant_for("grant-1", USER, "root-a");
    open.expires_at = None;
    assert!(matches!(
        validate(&state_with(open, limits()), &caller(), &request, &late),
        Verdict::Accept(_)
    ));
}

#[test]
fn a_restored_step_that_was_in_work_has_an_outcome_that_is_not_known() {
    for in_work in [StepState::DispatchConsumed, StepState::Verifying] {
        let mut first: HelperState = state();
        admit_ok(&mut first, &request("step-1"));
        if in_work == StepState::Verifying {
            first
                .record_progress(&key("step-1"), StepState::Verifying)
                .unwrap();
        }
        admit_ok(&mut first, &request("step-2"));
        first
            .record_progress(&key("step-2"), StepState::NoAction)
            .unwrap();

        // The helper starts again with its durable record.
        let consumed: Vec<_> = first.consumed().requests().cloned().collect();
        let restored = HelperState::restore(
            config(),
            vec![helper_grant(grant_for("grant-1", USER, "root-a"), limits())],
            consumed,
        )
        .unwrap();
        // The restore names the step that it changed, and only that step:
        // the storage layer writes its record back.
        assert_eq!(restored.changed, [key("step-1")]);
        let mut restored: HelperState = restored.state;
        // The record of the changed step has the new state. A second
        // restore of it changes nothing more.
        let again = HelperState::restore(
            config(),
            vec![helper_grant(grant_for("grant-1", USER, "root-a"), limits())],
            restored.consumed().requests().cloned().collect(),
        )
        .unwrap();
        assert_eq!(again.changed, Vec::new());
        assert_eq!(again.state.consumed(), restored.consumed());
        let status = |state: &HelperState, step: &str| match validate(
            state,
            &caller(),
            &query(step),
            &clock(),
        ) {
            Verdict::Known(status) => status.state,
            other => panic!("the query has no recorded state: {other:?}"),
        };
        assert_eq!(status(&restored, "step-1"), StepState::UnknownOutcome);
        assert_eq!(status(&restored, "step-2"), StepState::NoAction);
        // The step stays consumed: the same request gets the state and no
        // second acceptance.
        assert!(matches!(
            admit(&mut restored, &request("step-1")),
            Admission::Known(_)
        ));
        // Reconciliation can settle it.
        restored
            .record_progress(&key("step-1"), StepState::Completed)
            .unwrap();
    }
}

#[test]
fn a_restored_record_with_a_state_before_consumption_is_refused() {
    let mut first: HelperState = state();
    admit_ok(&mut first, &request("step-1"));
    let grants = || vec![helper_grant(grant_for("grant-1", USER, "root-a"), limits())];
    for state in [
        StepState::Admitted,
        StepState::IntentCommitted,
        StepState::from_wire("Finished"),
    ] {
        let mut record = first.consumed().requests().next().unwrap().clone();
        record.state = state;
        assert_eq!(
            HelperState::restore(config(), grants(), vec![record]).err(),
            Some(StateError::Record(RecordError::State))
        );
    }
    // More records than the capacity: none is dropped to make room.
    let mut small: HelperConfig = config();
    small.record_capacity = 1;
    small.principal_quota = 1;
    let mut two: HelperState = state();
    admit_ok(&mut two, &request("step-1"));
    admit_ok(&mut two, &request("step-2"));
    assert_eq!(
        HelperState::restore(
            small,
            grants(),
            two.consumed().requests().cloned().collect()
        )
        .err(),
        Some(StateError::Record(RecordError::Full))
    );
}

#[test]
fn the_dry_run_refuses_a_new_step_for_a_full_record() {
    let mut small: HelperConfig = config();
    small.record_capacity = 1;
    small.principal_quota = 1;
    let mut generous: GrantLimits = limits();
    generous.rate.max_requests = 10;
    let mut state: HelperState = HelperState::new(
        small,
        vec![helper_grant(grant_for("grant-1", USER, "root-a"), generous)],
    )
    .unwrap();
    admit_ok(&mut state, &request("step-1"));
    // The quota of the user is the first limit.
    assert_eq!(
        refused(&state, &request("step-2")),
        RefusalReason::RecordQuota
    );
    // With room in the quota, the capacity of the record is the limit.
    state.config.principal_quota = 2;
    assert_eq!(
        refused(&state, &request("step-2")),
        RefusalReason::RecordFull
    );
}

#[test]
fn the_target_ceiling_of_the_protocol_does_not_depend_on_the_grant() {
    let mut state: HelperState = state();
    // A record that did not pass `HelperGrant::new`.
    state.grants[0].limits.max_targets = MAX_TARGETS_PER_REQUEST + 2;
    let entries: Vec<EntryTarget> = (0..=MAX_TARGETS_PER_REQUEST)
        .map(|index: usize| entry(&format!("cache/{index}.tmp"), 0, 1))
        .collect();
    assert_eq!(
        refused(&state, &request_with("step-1", entries)),
        RefusalReason::TargetCeiling
    );
}

#[test]
fn a_rate_sum_that_does_not_fit_is_refused_and_not_saturated() {
    let mut grant: PrivilegeGrant = grant_for("grant-1", USER, "root-a");
    grant.ceiling = charge(u64::MAX, CEILING_ITEMS);
    let mut wide: GrantLimits = limits();
    wide.rate.work = charge(u64::MAX, RATE_ITEMS);
    let mut state: HelperState = state_with(grant, wide);
    admit_ok(
        &mut state,
        &request_with("step-1", vec![entry("cache/a.tmp", u64::MAX, 1)]),
    );
    assert_eq!(
        refused(
            &state,
            &request_with("step-2", vec![entry("cache/b.tmp", 1, 1)])
        ),
        RefusalReason::ArithmeticOverflow
    );
}

#[test]
fn a_key_two_times_in_a_nested_record_is_rejected() {
    let text: String = serde_json::to_string(&encode(&request("step-1"))).unwrap();
    // The grant reference with its generation two times: a parser that
    // keeps the last value would see the generation 3.
    let needle: &str = "\"generation\":\"3\"";
    assert_eq!(text.matches(needle).count(), 1);
    let doubled: String = text.replace(needle, "\"generation\":\"9\",\"generation\":\"3\"");
    assert_eq!(
        decode_request(doubled.as_bytes(), SupportedProtocols::CURRENT),
        Err(DecodeError::Malformed)
    );
}
