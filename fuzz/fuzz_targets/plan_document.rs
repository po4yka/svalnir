//! The decoders of a sealed plan (`svalnir_core::action::Plan`, which the
//! journal stores) and of a plan outcome (`svalnir_core::plan::PlanOutcome`,
//! the body of the plan document of the CLI).
//!
//! The plan document type itself is private to `svalnir-cli`, so the target
//! decodes the public types that the document has. Properties: no panic,
//! and a value that decodes encodes to a text that decodes to the same value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use svalnir_core::action::Plan;
use svalnir_core::plan::PlanOutcome;

fn round_trip<T>(data: &[u8])
where
    T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug,
{
    let Ok(value) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let encoded: Vec<u8> = serde_json::to_vec(&value).expect("a decoded value encodes");
    let decoded: T = serde_json::from_slice(&encoded).expect("an encoded value decodes");
    assert_eq!(value, decoded);
}

fuzz_target!(|data: &[u8]| {
    round_trip::<Plan>(data);
    round_trip::<PlanOutcome>(data);
});
