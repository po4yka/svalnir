//! Reads typed values from a parsed TOML table and collects the findings.
//!
//! The reader does not stop at the first problem. `serde` deserialization
//! into a structure stops at the first error, thus this module reads the
//! `toml::Table` key by key.

use std::collections::BTreeSet;
use std::time::Duration;

use toml::{Table, Value};

use super::finding::{Finding, FindingCode, Location};
use crate::byte_size::{ByteSizeParseError, parse_byte_size};
use crate::duration::{DurationParseError, parse_duration};
use crate::quantity::Bytes;

/// The largest number of findings in one result. One more finding with the
/// code `too_many_findings` shows that the list is not complete.
pub const MAX_FINDINGS: usize = 128;

/// The largest number of entries in one list of the document.
pub const MAX_LIST_ENTRIES: usize = 1024;

/// The largest number of characters of a key in a finding path.
const MAX_KEY_CHARACTERS: usize = 64;

const ZERO_NOT_PERMITTED: &str =
    "must be larger than zero; a zero value does not disable a protection";

/// The findings and the explicit keys of one validation.
#[derive(Debug, Default)]
pub(super) struct Context {
    findings: Vec<Finding>,
    explicit: BTreeSet<String>,
}

impl Context {
    pub(super) fn report(&mut self, code: FindingCode, path: &str, message: impl Into<String>) {
        self.report_at(code, path, message, None);
    }

    pub(super) fn report_at(
        &mut self,
        code: FindingCode,
        path: &str,
        message: impl Into<String>,
        location: Option<Location>,
    ) {
        if self.findings.len() > MAX_FINDINGS {
            return;
        }
        if self.findings.len() == MAX_FINDINGS {
            self.findings.push(Finding {
                code: FindingCode::TooManyFindings,
                path: String::new(),
                message: format!(
                    "the document has more than {MAX_FINDINGS} findings; the list is not complete"
                ),
                location: None,
            });
            return;
        }
        self.findings.push(Finding {
            code,
            path: path.to_owned(),
            message: message.into(),
            location,
        });
    }

    pub(super) fn is_explicit(&self, path: &str) -> bool {
        self.explicit.contains(path)
    }

    pub(super) fn into_parts(self) -> (Vec<Finding>, BTreeSet<String>) {
        (self.findings, self.explicit)
    }
}

/// The result of a read of one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Read<T> {
    /// The document does not have the key.
    Absent,
    /// The document has the key, and a finding tells why the value is not
    /// accepted.
    Invalid,
    /// The document has the key with an accepted value.
    Valid(T),
}

impl<T> Read<T> {
    /// The value for the relationship checks: the template value for an
    /// absent key, `None` for a value that has a finding.
    pub(super) fn or_template(self, template: T) -> Option<T> {
        match self {
            Self::Absent => Some(template),
            Self::Invalid => None,
            Self::Valid(value) => Some(value),
        }
    }

    fn and_then<U>(self, convert: impl FnOnce(T) -> Option<U>) -> Read<U> {
        match self {
            Self::Absent => Read::Absent,
            Self::Invalid => Read::Invalid,
            Self::Valid(value) => convert(value).map_or(Read::Invalid, Read::Valid),
        }
    }
}

/// Makes a key safe for a finding path: a bare key stays as it is, another
/// key is quoted and escaped, and a long key is cut.
fn path_segment(key: &str) -> String {
    let bare: bool = !key.is_empty()
        && key
            .chars()
            .all(|character: char| character.is_ascii_alphanumeric() || "_-".contains(character));
    let mut cut: String = key.chars().take(MAX_KEY_CHARACTERS).collect();
    if cut.len() < key.len() {
        cut.push('…');
    }
    if bare && cut.len() == key.len() {
        cut
    } else {
        format!("\"{}\"", cut.escape_default())
    }
}

/// Joins a table path and a key.
pub(super) fn join_path(table: &str, key: &str) -> String {
    if table.is_empty() {
        path_segment(key)
    } else {
        format!("{table}.{}", path_segment(key))
    }
}

/// A table of the document, or the position of an absent table.
#[derive(Debug)]
pub(super) struct TableReader<'a> {
    table: Option<&'a Table>,
    path: String,
    known: Vec<&'static str>,
}

impl<'a> TableReader<'a> {
    pub(super) fn new(table: Option<&'a Table>, path: String) -> Self {
        Self {
            table,
            path,
            known: Vec::new(),
        }
    }

    /// The path of a key of this table.
    pub(super) fn key_path(&self, key: &str) -> String {
        join_path(&self.path, key)
    }

    /// The path of this table.
    pub(super) fn path(&self) -> &str {
        &self.path
    }

    fn take(&mut self, context: &mut Context, key: &'static str) -> Option<(String, &'a Value)> {
        self.known.push(key);
        let value: &Value = self.table?.get(key)?;
        let path: String = self.key_path(key);
        context.explicit.insert(path.clone());
        Some((path, value))
    }

    fn read<T>(
        &mut self,
        context: &mut Context,
        key: &'static str,
        convert: impl FnOnce(&mut Context, &str, &'a Value) -> Option<T>,
    ) -> Read<T> {
        match self.take(context, key) {
            None => Read::Absent,
            Some((path, value)) => {
                convert(context, &path, value).map_or(Read::Invalid, Read::Valid)
            }
        }
    }

    /// Reports an absent required key.
    pub(super) fn require<T>(
        &self,
        context: &mut Context,
        key: &'static str,
        read: Read<T>,
    ) -> Option<T> {
        match read {
            Read::Absent => {
                context.report(
                    FindingCode::MissingKey,
                    &self.key_path(key),
                    "the key is required",
                );
                None
            }
            Read::Invalid => None,
            Read::Valid(value) => Some(value),
        }
    }

    /// A child table. A value of another type gives a finding.
    pub(super) fn table(&mut self, context: &mut Context, key: &'static str) -> Self {
        let path: String = self.key_path(key);
        let table: Option<&'a Table> = match self.take(context, key) {
            None => None,
            Some((_, Value::Table(table))) => Some(table),
            Some((path, _)) => {
                context.report(FindingCode::WrongType, &path, "must be a table");
                None
            }
        };
        Self::new(table, path)
    }

    /// The tables of an array of tables, each with its path.
    pub(super) fn table_array(
        &mut self,
        context: &mut Context,
        key: &'static str,
        max_entries: usize,
    ) -> Vec<Self> {
        let Some((path, value)) = self.take(context, key) else {
            return Vec::new();
        };
        let Value::Array(items) = value else {
            context.report(FindingCode::WrongType, &path, "must be an array of tables");
            return Vec::new();
        };
        if items.len() > max_entries {
            context.report(
                FindingCode::TooManyEntries,
                &path,
                format!("must have no more than {max_entries} entries"),
            );
            return Vec::new();
        }
        let mut readers: Vec<Self> = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let item_path: String = format!("{path}[{index}]");
            if let Value::Table(table) = item {
                readers.push(Self::new(Some(table), item_path));
            } else {
                context.report(FindingCode::WrongType, &item_path, "must be a table");
            }
        }
        readers
    }

    pub(super) fn boolean(&mut self, context: &mut Context, key: &'static str) -> Read<bool> {
        self.read(context, key, |context, path, value| {
            if let Value::Boolean(flag) = value {
                Some(*flag)
            } else {
                context.report(FindingCode::WrongType, path, "must be `true` or `false`");
                None
            }
        })
    }

    pub(super) fn integer(&mut self, context: &mut Context, key: &'static str) -> Read<i64> {
        self.read(context, key, |context, path, value| {
            if let Value::Integer(number) = value {
                Some(*number)
            } else {
                context.report(FindingCode::WrongType, path, "must be an integer");
                None
            }
        })
    }

    /// A count that is larger than zero.
    pub(super) fn positive_count(&mut self, context: &mut Context, key: &'static str) -> Read<u64> {
        let path: String = self.key_path(key);
        self.integer(context, key)
            .and_then(|number: i64| match u64::try_from(number) {
                Ok(count) if count > 0 => Some(count),
                _ => {
                    context.report(FindingCode::NotPositive, &path, ZERO_NOT_PERMITTED);
                    None
                }
            })
    }

    /// A string, with the path of the key.
    pub(super) fn text(
        &mut self,
        context: &mut Context,
        key: &'static str,
    ) -> Read<(String, &'a str)> {
        self.read(context, key, |context, path, value| {
            text_value(context, path, value).map(|text: &str| (path.to_owned(), text))
        })
    }

    /// A byte size that is larger than zero.
    pub(super) fn size(&mut self, context: &mut Context, key: &'static str) -> Read<Bytes> {
        self.read(context, key, |context, path, value| {
            let text: &str = text_value(context, path, value)?;
            match parse_byte_size(text) {
                Ok(Bytes::ZERO) => {
                    context.report(FindingCode::NotPositive, path, ZERO_NOT_PERMITTED);
                    None
                }
                Ok(size) => Some(size),
                Err(error) => {
                    let (code, message) = size_problem(&error);
                    context.report(code, path, message);
                    None
                }
            }
        })
    }

    /// A duration that is larger than zero and fits 64-bit nanoseconds.
    pub(super) fn duration(&mut self, context: &mut Context, key: &'static str) -> Read<Duration> {
        self.read(context, key, |context, path, value| {
            let text: &str = text_value(context, path, value)?;
            match parse_duration(text) {
                Ok(duration) if duration.is_zero() => {
                    context.report(FindingCode::NotPositive, path, ZERO_NOT_PERMITTED);
                    None
                }
                Ok(duration) if u64::try_from(duration.as_nanos()).is_err() => {
                    context.report(
                        FindingCode::OutOfRange,
                        path,
                        "the duration is larger than the supported range",
                    );
                    None
                }
                Ok(duration) => Some(duration),
                Err(error) => {
                    let (code, message) = duration_problem(&error);
                    context.report(code, path, message);
                    None
                }
            }
        })
    }

    /// A list of strings, each with its path.
    pub(super) fn text_list(
        &mut self,
        context: &mut Context,
        key: &'static str,
    ) -> Read<Vec<(String, &'a str)>> {
        self.read(context, key, |context, path, value| {
            let Value::Array(items) = value else {
                context.report(FindingCode::WrongType, path, "must be an array of strings");
                return None;
            };
            if items.len() > MAX_LIST_ENTRIES {
                context.report(
                    FindingCode::TooManyEntries,
                    path,
                    format!("must have no more than {MAX_LIST_ENTRIES} entries"),
                );
                return None;
            }
            let mut texts: Vec<(String, &'a str)> = Vec::with_capacity(items.len());
            let mut complete: bool = true;
            for (index, item) in items.iter().enumerate() {
                let item_path: String = format!("{path}[{index}]");
                match text_value(context, &item_path, item) {
                    Some(text) => texts.push((item_path, text)),
                    None => complete = false,
                }
            }
            complete.then_some(texts)
        })
    }

    /// Reports each key of the table that the schema does not have.
    pub(super) fn finish(self, context: &mut Context) {
        let Some(table) = self.table else {
            return;
        };
        for key in table.keys() {
            if !self.known.contains(&key.as_str()) {
                context.report(
                    FindingCode::UnknownKey,
                    &join_path(&self.path, key),
                    "the key is not in schema version 1",
                );
            }
        }
    }
}

fn text_value<'a>(context: &mut Context, path: &str, value: &'a Value) -> Option<&'a str> {
    if let Value::String(text) = value {
        Some(text)
    } else {
        context.report(FindingCode::WrongType, path, "must be a string");
        None
    }
}

/// The code and a message that does not repeat the value.
fn size_problem(error: &ByteSizeParseError) -> (FindingCode, &'static str) {
    const UNITS: &str = "use an integer and one of the units `B`, `KiB`, `MiB`, `GiB`, or `TiB`, \
                         for example `20GiB`";
    match error {
        ByteSizeParseError::Empty => (FindingCode::InvalidSize, "the size is empty"),
        ByteSizeParseError::MissingValue(_) => (
            FindingCode::InvalidSize,
            "the size does not start with an integer; a sign is not permitted",
        ),
        ByteSizeParseError::NonCanonical(_) => (
            FindingCode::InvalidSize,
            "the integer of the size has a leading zero",
        ),
        ByteSizeParseError::MissingUnit(_) | ByteSizeParseError::UnknownUnit(_) => {
            (FindingCode::InvalidSize, UNITS)
        }
        ByteSizeParseError::OutOfRange(_) => (
            FindingCode::OutOfRange,
            "the size is larger than the supported range",
        ),
    }
}

/// The code and a message that does not repeat the value.
fn duration_problem(error: &DurationParseError) -> (FindingCode, &'static str) {
    const UNITS: &str = "use an integer and one of the units `ms`, `s`, `m`, `h`, or `d`, \
                         for example `30s`";
    match error {
        DurationParseError::Empty => (FindingCode::InvalidDuration, "the duration is empty"),
        DurationParseError::MissingValue(_) => (
            FindingCode::InvalidDuration,
            "the duration does not start with an integer; a sign is not permitted",
        ),
        DurationParseError::NonCanonical(_) => (
            FindingCode::InvalidDuration,
            "the integer of the duration has a leading zero",
        ),
        DurationParseError::MissingUnit(_) | DurationParseError::UnknownUnit(_) => {
            (FindingCode::InvalidDuration, UNITS)
        }
        DurationParseError::OutOfRange(_) => (
            FindingCode::OutOfRange,
            "the duration is larger than the supported range",
        ),
    }
}
