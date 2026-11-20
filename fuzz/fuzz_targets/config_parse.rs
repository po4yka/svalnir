//! The configuration parser and its portable checks
//! (`svalnir_core::config::parse_and_validate`).
//!
//! Properties of the contract: the function does not panic, and it is pure,
//! so two calls on the same text give the same result. A result with a
//! validated configuration has no findings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use svalnir_core::config::{Validation, parse_and_validate};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let first: Validation = parse_and_validate(text);
    let second: Validation = parse_and_validate(text);
    assert_eq!(first, second, "parse_and_validate is not deterministic");
    if first.config().is_some() {
        assert!(first.findings().is_empty());
    }
});
