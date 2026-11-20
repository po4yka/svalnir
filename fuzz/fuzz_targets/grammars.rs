//! The duration and byte-size grammars of `svalnir-core`
//! (`duration::parse_duration`, `byte_size::parse_byte_size`).
//!
//! Properties: no panic, and an accepted value has the same value in the
//! smallest unit of its grammar (`ms` for a duration, `B` for a size), when
//! that value is in the range of the grammar.

#![no_main]

use libfuzzer_sys::fuzz_target;
use svalnir_core::byte_size::parse_byte_size;
use svalnir_core::duration::parse_duration;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(duration) = parse_duration(text)
        && let Ok(millis) = u64::try_from(duration.as_millis())
        && u128::from(millis) * 1_000_000 == duration.as_nanos()
    {
        assert_eq!(parse_duration(&format!("{millis}ms")), Ok(duration));
    }
    if let Ok(size) = parse_byte_size(text) {
        assert_eq!(parse_byte_size(&format!("{}B", size.get())), Ok(size));
    }
});
