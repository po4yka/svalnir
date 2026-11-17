//! Structured findings of configuration validation.

use std::fmt;

use serde::Serialize;

use super::check::CheckId;

/// The stable code of a finding.
///
/// The text of a code does not change between releases. A client selects on
/// the code, not on the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FindingCode {
    /// The text is not a TOML document.
    Syntax,
    /// The text is larger than [`super::MAX_DOCUMENT_BYTES`].
    DocumentTooLarge,
    /// The document has more findings than [`super::MAX_FINDINGS`]; the
    /// remaining findings are not in the list.
    TooManyFindings,
    /// `schema_version` is not a supported version.
    UnsupportedSchemaVersion,
    /// The key or table is not in the schema.
    UnknownKey,
    /// A required key is absent.
    MissingKey,
    /// The value has a different TOML type from the type in the schema.
    WrongType,
    /// The text is not in the byte-size grammar.
    InvalidSize,
    /// The text is not in the duration grammar.
    InvalidDuration,
    /// The size, duration, or count is zero or negative.
    NotPositive,
    /// The value is larger than the supported range.
    OutOfRange,
    /// The text is not one of the values of the enumeration.
    UnknownValue,
    /// The text is not in the grammar of the identifier.
    InvalidIdentifier,
    /// The identifier occurs more than one time.
    DuplicateIdentifier,
    /// The text is not an accepted path.
    InvalidPath,
    /// The list has more entries than the schema permits.
    TooManyEntries,
    /// A built-in protection is set to `false`.
    ProtectionDisabled,
    /// The disk or footprint thresholds are not in the required order.
    ThresholdOrder,
    /// The byte or item limits are not in the required order.
    LimitOrder,
    /// Two timing values do not agree.
    TimingOrder,
    /// An enabled guard selects nothing.
    EmptySelection,
}

impl FindingCode {
    /// The stable text of the code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::DocumentTooLarge => "document_too_large",
            Self::TooManyFindings => "too_many_findings",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::UnknownKey => "unknown_key",
            Self::MissingKey => "missing_key",
            Self::WrongType => "wrong_type",
            Self::InvalidSize => "invalid_size",
            Self::InvalidDuration => "invalid_duration",
            Self::NotPositive => "not_positive",
            Self::OutOfRange => "out_of_range",
            Self::UnknownValue => "unknown_value",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::DuplicateIdentifier => "duplicate_identifier",
            Self::InvalidPath => "invalid_path",
            Self::TooManyEntries => "too_many_entries",
            Self::ProtectionDisabled => "protection_disabled",
            Self::ThresholdOrder => "threshold_order",
            Self::LimitOrder => "limit_order",
            Self::TimingOrder => "timing_order",
            Self::EmptySelection => "empty_selection",
        }
    }

    /// The check that reports this code. `too_many_findings` has no check:
    /// it shows that the list was cut, not that a check found a problem.
    pub const fn check(self) -> Option<CheckId> {
        Some(match self {
            Self::TooManyFindings => return None,
            Self::Syntax | Self::DocumentTooLarge => CheckId::Syntax,
            Self::ThresholdOrder | Self::LimitOrder | Self::TimingOrder | Self::EmptySelection => {
                CheckId::Relationships
            }
            Self::UnsupportedSchemaVersion
            | Self::UnknownKey
            | Self::MissingKey
            | Self::WrongType
            | Self::InvalidSize
            | Self::InvalidDuration
            | Self::NotPositive
            | Self::OutOfRange
            | Self::UnknownValue
            | Self::InvalidIdentifier
            | Self::DuplicateIdentifier
            | Self::InvalidPath
            | Self::TooManyEntries
            | Self::ProtectionDisabled => CheckId::Schema,
        })
    }
}

impl fmt::Display for FindingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A position in the configuration text. Only a syntax finding has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Location {
    /// The line, from 1.
    pub line: u32,
    /// The column in characters, from 1.
    pub column: u32,
}

/// One problem in a configuration document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The stable code.
    pub code: FindingCode,
    /// The key path, for example `disk_guard.warn_below` or
    /// `memory_guard.app_budgets[0].id`. The path is empty when the finding
    /// applies to the document.
    pub path: String,
    /// The explanation. It names keys and permitted values. It does not
    /// repeat a value from the document.
    pub message: String,
    /// The position in the text, when the parser gives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(formatter, "{} [{}]", self.message, self.code)
        } else {
            write!(formatter, "{}: {} [{}]", self.path, self.message, self.code)
        }
    }
}
