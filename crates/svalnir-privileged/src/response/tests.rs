//! Tests of the response messages.

use svalnir_core::action::{
    ActionStage, DispatchState, Durability, ErrorCode, ErrorFamily, StepState,
};
use svalnir_core::id::RequestId;

use super::{
    Condition, FALLBACK_CODE, HelperResponse, MAX_ENCODED_RESPONSE_BYTES, RefusalReport, Rejection,
    ReportOrigin, ResponseBody, StepReport, action_error, decode_response, fallback_code,
};
use crate::request::{DecodeError, MAX_NESTING_DEPTH, PROTOCOL_MAJOR, ProtocolMismatch};
use crate::testing::correlation;
use crate::validation::RefusalReason;

fn step_response() -> HelperResponse {
    HelperResponse::new(
        Some(RequestId::new("request-1").unwrap()),
        ResponseBody::Step(StepReport {
            correlation: correlation("step-1"),
            origin: ReportOrigin::ThisRequest,
            state: StepState::NoAction,
            durability: Durability::Volatile,
            entries: None,
            error: Some(Condition::RecordNotDurable.to_action_error(
                ActionStage::Dispatch,
                DispatchState::NotSubmitted,
                Some(&correlation("step-1")),
            )),
        }),
    )
}

#[test]
fn each_condition_has_a_permitted_code_and_a_known_family() {
    let mut codes: Vec<&str> = Vec::new();
    for condition in Condition::ALL {
        let code: &str = condition.code();
        assert!(ErrorCode::new(code).is_ok(), "{code}");
        assert!(code.starts_with("helper_"), "{code}");
        assert!(condition.family().is_recognized());
        assert!(!codes.contains(&code), "{code} is there two times");
        codes.push(code);
    }
    // No condition has the code of a refusal reason of the validation or
    // of a decoding error.
    for reason in RefusalReason::ALL {
        assert!(!codes.contains(&reason.code()), "{}", reason.code());
    }
    for error in [
        DecodeError::TooLarge,
        DecodeError::TooDeep,
        DecodeError::Malformed,
        DecodeError::NotExact,
        DecodeError::Protocol(ProtocolMismatch::Major),
        DecodeError::Protocol(ProtocolMismatch::Minor),
    ] {
        assert!(ErrorCode::new(error.code()).is_ok());
        assert!(!codes.contains(&error.code()), "{}", error.code());
    }
    assert_eq!(fallback_code().as_str(), FALLBACK_CODE);
}

#[test]
fn an_error_of_a_step_names_its_plan_operation_and_step() {
    let named = action_error(
        "helper_target_changed",
        ErrorFamily::Evidence,
        ActionStage::Dispatch,
        DispatchState::NotSubmitted,
        Some(&correlation("step-1")),
    );
    assert_eq!(named.plan_id, Some(correlation("step-1").plan_id));
    assert_eq!(named.operation_id, Some(correlation("step-1").operation_id));
    assert_eq!(named.step_id, Some(correlation("step-1").step_id));

    let rejected: HelperResponse =
        HelperResponse::rejected("helper_peer_unverified", ErrorFamily::Authority);
    let ResponseBody::Rejected(Rejection { error }) = &rejected.body else {
        panic!("the response is not a rejection");
    };
    assert_eq!(error.plan_id, None);
    assert_eq!(error.operation_id, None);
    assert_eq!(error.step_id, None);
    assert_eq!(error.stage, ActionStage::Admission);
    assert_eq!(error.dispatch, DispatchState::NotSubmitted);
    assert_eq!(rejected.request_id, None);
}

#[test]
fn each_body_has_one_encoded_form_that_a_client_decodes() {
    let refused: HelperResponse = HelperResponse::new(
        Some(RequestId::new("request-2").unwrap()),
        ResponseBody::Refused(RefusalReport {
            correlation: correlation("step-2"),
            error: action_error(
                "helper_grant_revoked",
                ErrorFamily::Authority,
                ActionStage::Admission,
                DispatchState::NotSubmitted,
                Some(&correlation("step-2")),
            ),
        }),
    );
    let rejected: HelperResponse =
        HelperResponse::rejected("helper_request_malformed", ErrorFamily::Request);

    for (response, body) in [
        (step_response(), "step"),
        (refused, "refused"),
        (rejected, "rejected"),
    ] {
        let bytes: Vec<u8> = response.encode().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["protocol"]["major"], PROTOCOL_MAJOR);
        assert!(value["body"][body].is_object(), "{value}");
        assert_eq!(value["body"].as_object().unwrap().len(), 1);
        assert_eq!(decode_response(&bytes).unwrap(), response);
    }
}

#[test]
fn a_response_with_an_unknown_field_or_a_different_major_version_is_rejected() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&step_response().encode().unwrap()).unwrap();
    value["approved"] = serde_json::json!(true);
    assert_eq!(
        decode_response(&serde_json::to_vec(&value).unwrap()),
        Err(DecodeError::Malformed)
    );

    let mut value: serde_json::Value =
        serde_json::from_slice(&step_response().encode().unwrap()).unwrap();
    value["body"]["step"]["approved"] = serde_json::json!(true);
    assert_eq!(
        decode_response(&serde_json::to_vec(&value).unwrap()),
        Err(DecodeError::Malformed)
    );

    let mut value: serde_json::Value =
        serde_json::from_slice(&step_response().encode().unwrap()).unwrap();
    value["protocol"]["major"] = serde_json::json!(PROTOCOL_MAJOR + 1);
    assert_eq!(
        decode_response(&serde_json::to_vec(&value).unwrap()),
        Err(DecodeError::Protocol(ProtocolMismatch::Major))
    );
}

#[test]
fn a_response_over_a_limit_is_rejected() {
    assert_eq!(
        decode_response(&vec![b' '; MAX_ENCODED_RESPONSE_BYTES + 1]),
        Err(DecodeError::TooLarge)
    );
    let mut deep: Vec<u8> = vec![b'['; MAX_NESTING_DEPTH + 1];
    deep.extend(vec![b']'; MAX_NESTING_DEPTH + 1]);
    assert_eq!(decode_response(&deep), Err(DecodeError::TooDeep));
    assert_eq!(decode_response(b"{"), Err(DecodeError::Malformed));
}

#[test]
fn a_state_that_the_reader_does_not_recognize_is_kept_as_such() {
    let mut value: serde_json::Value =
        serde_json::from_slice(&step_response().encode().unwrap()).unwrap();
    value["body"]["step"]["state"] = serde_json::json!("AStateOfALaterBuild");

    let decoded: HelperResponse = decode_response(&serde_json::to_vec(&value).unwrap()).unwrap();

    let ResponseBody::Step(step) = &decoded.body else {
        panic!("the response is not a step report");
    };
    // The reader does not read the value as a known state.
    assert!(!step.state.is_recognized());
    assert!(!step.state.is_settled());
}
