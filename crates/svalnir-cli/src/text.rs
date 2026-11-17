//! Helpers for the human-readable output.
//!
//! Each label that comes from the host (a path, an executable name, a bundle
//! identifier) goes through [`escape`] or `LosslessPath::display_label`, so a
//! name cannot inject a terminal command or a false status line
//! (`docs/INTERFACES.md` section 8).

use serde_json::Value;
use svalnir_core::observation::{Observation, ObservationValue, Reading};
use svalnir_core::quantity::{Bytes, Nanoseconds};

/// Appends one formatted line to a `String`.
macro_rules! put_line {
    ($out:expr, $($argument:tt)*) => {{
        $out.push_str(&format!($($argument)*));
        $out.push('\n');
    }};
}
pub(crate) use put_line;

/// Escapes text for display. A backslash is `\\`, and a control character or
/// an invisible format character is `\u{..}`.
pub(crate) fn escape(text: &str) -> String {
    let mut label = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '\\' {
            label.push_str("\\\\");
        } else if character.is_control() || is_invisible_format(character) {
            label.extend(character.escape_unicode());
        } else {
            label.push(character);
        }
    }
    label
}

/// Whether the character changes how the text around it is shown and has no
/// glyph of its own. The list is that of `LosslessPath::display_label`.
fn is_invisible_format(character: char) -> bool {
    matches!(
        character,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// A byte count in binary units with one decimal place, for example
/// `12.3 GiB`. The value is truncated, not rounded up.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut unit: u128 = 1024;
    let mut name: &str = UNITS[0];
    for next in &UNITS[1..] {
        if u128::from(bytes) < unit * 1024 {
            break;
        }
        unit *= 1024;
        name = next;
    }
    let tenths: u128 = u128::from(bytes) * 10 / unit;
    format!("{}.{} {name}", tenths / 10, tenths % 10)
}

/// A signed byte count in binary units, with its sign.
pub(crate) fn human_byte_delta(delta: i128) -> String {
    let magnitude: u64 = u64::try_from(delta.unsigned_abs()).unwrap_or(u64::MAX);
    let sign: &str = if delta < 0 { "-" } else { "+" };
    format!("{sign}{}", human_bytes(magnitude))
}

/// A duration in the largest unit that keeps one decimal place.
pub(crate) fn human_duration(duration: Nanoseconds) -> String {
    let nanoseconds: u64 = duration.get();
    let (unit, name): (u64, &str) = if nanoseconds >= 3_600_000_000_000 {
        (3_600_000_000_000, "h")
    } else if nanoseconds >= 60_000_000_000 {
        (60_000_000_000, "min")
    } else if nanoseconds >= 1_000_000_000 {
        (1_000_000_000, "s")
    } else if nanoseconds >= 1_000_000 {
        (1_000_000, "ms")
    } else if nanoseconds >= 1_000 {
        (1_000, "us")
    } else {
        return format!("{nanoseconds} ns");
    };
    let tenths: u128 = u128::from(nanoseconds) * 10 / u128::from(unit);
    format!("{}.{} {name}", tenths / 10, tenths % 10)
}

/// The text of a reading that has no value. It always names the reason, so
/// an unavailable measurement is not read as zero.
pub(crate) fn unavailable<T>(reading: &Reading<T>) -> String {
    match reading {
        Reading::Unavailable(reason) => format!("unavailable ({})", escape(reason.as_str())),
        Reading::Unrecognized(_) => "unavailable (availability not recognized)".to_owned(),
        Reading::Available(_) => "unavailable (unit not recognized)".to_owned(),
    }
}

/// The text of an observation, with `show` for an available value.
pub(crate) fn observed<T: ObservationValue>(
    observation: &Observation<T>,
    show: impl FnOnce(&T) -> String,
) -> String {
    observation
        .value()
        .map_or_else(|| unavailable(&observation.reading), show)
}

/// The text of a byte observation.
pub(crate) fn observed_bytes(observation: &Observation<Bytes>) -> String {
    observed(observation, |bytes| human_bytes(bytes.get()))
}

/// One aligned table. A column of `right` is aligned to the right.
pub(crate) fn table(headers: &[&str], right: &[bool], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let header_row: Vec<String> = headers.iter().map(|header| (*header).to_owned()).collect();
    for row in std::iter::once(&header_row).chain(rows) {
        let mut line = String::new();
        for (index, cell) in row.iter().enumerate() {
            let width: usize = widths.get(index).copied().unwrap_or(0);
            let padding: usize = width.saturating_sub(cell.chars().count());
            let align_right: bool = right.get(index).copied().unwrap_or(false);
            if index > 0 {
                line.push_str("  ");
            }
            if align_right {
                line.push_str(&" ".repeat(padding));
                line.push_str(cell);
            } else {
                line.push_str(cell);
                line.push_str(&" ".repeat(padding));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// One `label  value` line with the label padded to `width`.
pub(crate) fn field(out: &mut String, label: &str, width: usize, value: &str) {
    put_line!(out, "  {label:<width$}  {value}");
}

/// Renders a JSON value as indented `key: value` lines.
///
/// The reports of the configuration and policy commands have many typed
/// fields. This rendering shows each of them with its machine name, so the
/// text form and the JSON form cannot disagree. The keys of an object are in
/// lexical sequence. Each string is escaped.
pub(crate) fn json_tree(value: &Value) -> String {
    let mut out = String::new();
    write_tree(&mut out, value, 0);
    out
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("none".to_owned()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => Some(escape(text)),
        Value::Array(items) if items.is_empty() => Some("[]".to_owned()),
        Value::Object(fields) if fields.is_empty() => Some("{}".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn write_tree(out: &mut String, value: &Value, depth: usize) {
    let indent: String = "  ".repeat(depth);
    match value {
        Value::Object(fields) => {
            // The sequence of a JSON object depends on a feature of
            // `serde_json` that another crate of the build can enable. A
            // sorted sequence gives the same text in each build.
            let mut entries: Vec<(&String, &Value)> = fields.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (key, item) in entries {
                let key: String = escape(key);
                if let Some(text) = scalar(item) {
                    put_line!(out, "{indent}{key}: {text}");
                } else {
                    put_line!(out, "{indent}{key}:");
                    write_tree(out, item, depth + 1);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                if let Some(text) = scalar(item) {
                    put_line!(out, "{indent}- {text}");
                } else {
                    put_line!(out, "{indent}-");
                    write_tree(out, item, depth + 1);
                }
            }
        }
        other => {
            let text: String = scalar(other).unwrap_or_default();
            put_line!(out, "{indent}{text}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{escape, human_byte_delta, human_bytes, human_duration, json_tree, table};
    use svalnir_core::quantity::Nanoseconds;

    #[test]
    fn control_and_format_characters_are_escaped() {
        assert_eq!(escape("a\x1b[31mb"), "a\\u{1b}[31mb");
        assert_eq!(escape("line\nstatus: ok"), "line\\u{a}status: ok");
        assert_eq!(escape("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(escape("back\\slash"), "back\\\\slash");
        assert_eq!(escape("plain name"), "plain name");
    }

    #[test]
    fn byte_counts_use_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(20 * 1024 * 1024 * 1024), "20.0 GiB");
        assert_eq!(human_bytes(u64::MAX), "15.9 EiB");
        assert_eq!(human_byte_delta(-2048), "-2.0 KiB");
        assert_eq!(human_byte_delta(0), "+0 B");
    }

    #[test]
    fn durations_use_the_largest_unit() {
        assert_eq!(human_duration(Nanoseconds::new(999)), "999 ns");
        assert_eq!(human_duration(Nanoseconds::new(218_833)), "218.8 us");
        assert_eq!(human_duration(Nanoseconds::new(1_500_000)), "1.5 ms");
        assert_eq!(human_duration(Nanoseconds::new(90_000_000_000)), "1.5 min");
    }

    #[test]
    fn a_table_aligns_each_column() {
        let text = table(
            &["NAME", "SIZE"],
            &[false, true],
            &[
                vec!["a".to_owned(), "1.0 KiB".to_owned()],
                vec!["longer".to_owned(), "2 B".to_owned()],
            ],
        );
        assert_eq!(text, "NAME       SIZE\na       1.0 KiB\nlonger      2 B\n");
    }

    #[test]
    fn a_json_tree_shows_each_field_and_escapes_strings() {
        let value = serde_json::json!({
            "enabled": false,
            "name": "a\nb",
            "list": ["x", {"k": null}],
            "empty": [],
        });
        assert_eq!(
            json_tree(&value),
            "empty: []\nenabled: false\nlist:\n  - x\n  -\n    k: none\nname: a\\u{a}b\n"
        );
    }
}
