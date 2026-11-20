//! The record types that the operation journal of `svalnir-agent` decodes
//! from its text columns.
//!
//! The decoders of the journal (`decode` in `journal/mod.rs`, and the plan
//! version probe in `journal/durable.rs`) are private and read their text
//! from an SQLite row, so the target cannot call them without a database.
//! They are `serde_json::from_str` of these types, which this target calls
//! on the same text. Properties: no panic, and a value that decodes
//! encodes to a text that decodes to the same value, because the journal
//! writes each record with `serde_json` and reads it again.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use svalnir_agent::journal::{QueuedRequest, RequestCompletion};
use svalnir_core::action::{ActionError, Operation, Principal, RequestEnvelope, Step};

fn round_trip<T>(text: &str)
where
    T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug,
{
    let Ok(value) = serde_json::from_str::<T>(text) else {
        return;
    };
    let encoded: String = serde_json::to_string(&value).expect("a decoded value encodes");
    let decoded: T = serde_json::from_str(&encoded).expect("an encoded value decodes");
    assert_eq!(value, decoded);
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    round_trip::<Operation>(text);
    round_trip::<Step>(text);
    round_trip::<RequestEnvelope>(text);
    round_trip::<Principal>(text);
    round_trip::<ActionError>(text);
    round_trip::<QueuedRequest>(text);
    round_trip::<RequestCompletion>(text);
});
