//! The request decoder of the helper
//! (`svalnir_privileged::request::decode_request`).
//!
//! Properties of the contract (`docs/INTERFACES.md` section 9 and the
//! decoder documentation): no panic, and an accepted request is the exact
//! encoding of its content, so its `serde_json` encoding is accepted again
//! and decodes to the same request.

#![no_main]

use libfuzzer_sys::fuzz_target;
use svalnir_privileged::request::{
    HelperRequest, MAX_ENCODED_REQUEST_BYTES, SupportedProtocols, decode_request,
};

fuzz_target!(|data: &[u8]| {
    let Ok(request) = decode_request(data, SupportedProtocols::CURRENT) else {
        return;
    };
    let encoded: Vec<u8> = serde_json::to_vec(&request).expect("a decoded request encodes");
    if encoded.len() > MAX_ENCODED_REQUEST_BYTES {
        return;
    }
    let decoded: HelperRequest = decode_request(&encoded, SupportedProtocols::CURRENT)
        .expect("the encoding of an accepted request is accepted");
    assert_eq!(request, decoded);
});
