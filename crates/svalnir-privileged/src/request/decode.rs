//! Decoding of the JSON form of a request.
//!
//! `docs/INTERFACES.md` section 9 owns the limits of the encoded form, and
//! sections 2 and 3 own the rule that a mutation request rejects an unknown
//! field and an unknown value.

use serde::Deserialize;
use thiserror::Error;

use super::operation::{HelperRequest, ProtocolMismatch, SupportedProtocols};

/// The largest encoded request, in bytes: 1 MiB.
pub const MAX_ENCODED_REQUEST_BYTES: usize = 1 << 20;

/// The largest nesting of objects and arrays in an encoded request.
pub const MAX_NESTING_DEPTH: usize = 16;

/// The reason an encoded request was rejected. The error does not repeat
/// the rejected bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The encoded form is longer than [`MAX_ENCODED_REQUEST_BYTES`].
    #[error("the encoded request is larger than the limit")]
    TooLarge,
    /// The encoded form has more than [`MAX_NESTING_DEPTH`] nested objects
    /// and arrays.
    #[error("the encoded request is nested deeper than the limit")]
    TooDeep,
    /// The protocol version of the request is not supported. The decoder
    /// reads the version before it reads the remainder of the request.
    #[error("{0}")]
    Protocol(#[from] ProtocolMismatch),
    /// The encoded form is not JSON, has an unknown operation, an unknown
    /// field, a field two times, an absent field, or a value that its type
    /// rejects.
    #[error("the encoded request is malformed")]
    Malformed,
    /// The encoded form has content that the decoded request does not
    /// have: an unknown field in a nested record, an absent optional
    /// field, or a value that is not in its canonical encoding.
    #[error("the encoded request is not the exact encoding of its content")]
    NotExact,
}

impl DecodeError {
    /// The stable code of the error: lower-case letters, digits, and `_`.
    /// The error family of each decoding error is `request`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "helper_request_too_large",
            Self::TooDeep => "helper_request_too_deep",
            Self::Protocol(ProtocolMismatch::Major) => "helper_protocol_major_mismatch",
            Self::Protocol(ProtocolMismatch::Minor) => "helper_protocol_minor_unsupported",
            Self::Malformed => "helper_request_malformed",
            Self::NotExact => "helper_request_not_exact",
        }
    }
}

/// The only part of a request that the decoder reads before it knows that
/// the protocol major version is supported.
///
/// The two records are lenient: they ignore a field that they do not know,
/// and each number has the full range. Thus a request of a later major
/// version is rejected for its version also when that version changed the
/// version record itself. The strict decoding comes after the version
/// check.
#[derive(Deserialize)]
struct Preamble {
    protocol: PreambleVersion,
}

#[derive(Deserialize)]
struct PreambleVersion {
    major: u64,
    minor: u64,
}

impl PreambleVersion {
    fn check(&self, supported: SupportedProtocols) -> Result<(), ProtocolMismatch> {
        if self.major != u64::from(supported.major) {
            return Err(ProtocolMismatch::Major);
        }
        if self.minor > u64::from(supported.max_minor) {
            return Err(ProtocolMismatch::Minor);
        }
        Ok(())
    }
}

/// Decodes the JSON form of one request.
///
/// The decoder applies these checks in sequence and stops at the first
/// failure:
///
/// 1. The size limit and the nesting limit.
/// 2. The protocol version, so that a request of a different major version
///    is rejected for its version and not for a field that this build does
///    not know.
/// 3. Strict decoding: an unknown operation, an unknown field, and a
///    repeated field are errors.
/// 4. Exactness: the encoded form must be equal to the encoding of the
///    decoded request. This check finds an unknown field in a nested
///    record of `svalnir-core` that does not reject unknown fields itself.
///    An optional field must be present, with `null` for an absent value.
///
/// A decoded request has no authority. Give it to
/// [`HelperState::admit`](crate::validation::HelperState::admit).
///
/// # Errors
///
/// Returns a [`DecodeError`] for the first check that fails.
pub fn decode_request(
    bytes: &[u8],
    supported: SupportedProtocols,
) -> Result<HelperRequest, DecodeError> {
    if bytes.len() > MAX_ENCODED_REQUEST_BYTES {
        return Err(DecodeError::TooLarge);
    }
    check_nesting(bytes)?;
    let preamble: Preamble = serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
    preamble.protocol.check(supported)?;
    let request: HelperRequest =
        serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
    let received: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
    let canonical: serde_json::Value =
        serde_json::to_value(&request).map_err(|_| DecodeError::Malformed)?;
    if received != canonical {
        return Err(DecodeError::NotExact);
    }
    Ok(request)
}

/// Checks the nesting of objects and arrays before a parser reads the
/// bytes. The scan uses no memory that depends on the input.
fn check_nesting(bytes: &[u8]) -> Result<(), DecodeError> {
    let mut depth: usize = 0;
    let mut in_string: bool = false;
    let mut escaped: bool = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.checked_add(1).ok_or(DecodeError::TooDeep)?;
                if depth > MAX_NESTING_DEPTH {
                    return Err(DecodeError::TooDeep);
                }
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(DecodeError::Malformed)?;
            }
            _ => {}
        }
    }
    Ok(())
}
