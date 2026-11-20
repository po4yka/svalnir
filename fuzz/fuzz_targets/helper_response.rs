//! The response decoder of the helper
//! (`svalnir_privileged::response::decode_response`).
//!
//! Properties: no panic, and a decoded response that
//! `HelperResponse::encode` encodes decodes to the same response.

#![no_main]

use libfuzzer_sys::fuzz_target;
use svalnir_privileged::response::{HelperResponse, decode_response};

fuzz_target!(|data: &[u8]| {
    let Ok(response) = decode_response(data) else {
        return;
    };
    let Ok(encoded) = response.encode() else {
        return;
    };
    let decoded: HelperResponse = decode_response(&encoded).expect("an encoded response decodes");
    assert_eq!(response, decoded);
});
