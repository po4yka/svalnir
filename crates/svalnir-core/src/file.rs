//! Lossless filesystem names and file-object evidence.
//!
//! `docs/RESOURCE_MODEL.md` section 2 and `docs/INTERFACES.md` section 3 own
//! these contracts. A path is presentation data and addressing data; it is
//! not target identity. A name that is not valid UTF-8 keeps its bytes.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::encoding::unsigned_quantity;

/// The reason a path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PathError {
    /// The path has no bytes.
    #[error("the path is empty")]
    Empty,
    /// The path has a NUL byte.
    #[error("the path has a NUL byte")]
    ContainsNul,
    /// The `hex` text is not lowercase hexadecimal byte pairs.
    #[error("the path is not lowercase hexadecimal byte pairs")]
    MalformedHex,
    /// The `hex` encoding was used for bytes that are valid UTF-8.
    #[error("the path is valid UTF-8 and must use the `utf8` encoding")]
    NotCanonical,
    /// The encoding tag is not `utf8` or `hex`.
    #[error("the path has an encoding that is not supported")]
    UnsupportedEncoding,
}

/// A filesystem path that keeps its exact bytes.
///
/// JSON encodes the path as a tagged object. A path that is valid UTF-8 is
/// `{"encoding": "utf8", "value": "/Users/a"}`. Another path is
/// `{"encoding": "hex", "value": "2f66ff"}`: its bytes as lowercase
/// hexadecimal. Each path has one encoding, so decoding rejects `hex` for
/// bytes that are valid UTF-8. Decoding also rejects an empty path, a NUL
/// byte, an unknown encoding, and a field other than `encoding` and `value`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "PathWire", into = "PathWire")]
pub struct LosslessPath(Vec<u8>);

impl LosslessPath {
    /// Makes a path from its bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] when the path is empty or has a NUL byte.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, PathError> {
        let bytes: Vec<u8> = bytes.into();
        if bytes.is_empty() {
            return Err(PathError::Empty);
        }
        if bytes.contains(&0) {
            return Err(PathError::ContainsNul);
        }
        Ok(Self(bytes))
    }

    /// The exact bytes of the path.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The path as text, when its bytes are valid UTF-8.
    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Text for display only. A backslash is `\\`, a control character or an
    /// invisible format character (for example a bidirectional override) is
    /// `\u{..}`, and a byte that is not valid UTF-8 is `\xNN`. Do not use
    /// the label to address a file.
    pub fn display_label(&self) -> String {
        let mut label = String::with_capacity(self.0.len());
        for chunk in self.0.utf8_chunks() {
            for character in chunk.valid().chars() {
                if character == '\\' {
                    label.push_str("\\\\");
                } else if character.is_control() || is_invisible_format(character) {
                    label.extend(character.escape_unicode());
                } else {
                    label.push(character);
                }
            }
            for byte in chunk.invalid() {
                label.push_str("\\x");
                push_hex(&mut label, *byte);
            }
        }
        label
    }
}

/// Whether the character changes how the text around it is shown and has no
/// glyph of its own: zero-width characters, bidirectional controls, and line
/// and paragraph separators.
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

#[cfg(unix)]
impl LosslessPath {
    /// Makes a path from a platform path.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] when the path is empty or has a NUL byte.
    pub fn from_path(path: &std::path::Path) -> Result<Self, PathError> {
        use std::os::unix::ffi::OsStrExt as _;
        Self::from_bytes(path.as_os_str().as_bytes())
    }

    /// The platform path with the same bytes.
    pub fn to_path_buf(&self) -> std::path::PathBuf {
        use std::os::unix::ffi::OsStrExt as _;
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&self.0))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathWire {
    encoding: String,
    value: String,
}

const ENCODING_UTF8: &str = "utf8";
const ENCODING_HEX: &str = "hex";

impl From<LosslessPath> for PathWire {
    fn from(path: LosslessPath) -> Self {
        match String::from_utf8(path.0) {
            Ok(text) => Self {
                encoding: ENCODING_UTF8.to_owned(),
                value: text,
            },
            Err(error) => {
                let bytes: &[u8] = error.as_bytes();
                let mut hex = String::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    push_hex(&mut hex, *byte);
                }
                Self {
                    encoding: ENCODING_HEX.to_owned(),
                    value: hex,
                }
            }
        }
    }
}

/// Appends the two lowercase hexadecimal digits of `byte`.
fn push_hex(text: &mut String, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    text.push(char::from(DIGITS[usize::from(byte >> 4)]));
    text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl TryFrom<PathWire> for LosslessPath {
    type Error = PathError;

    fn try_from(wire: PathWire) -> Result<Self, Self::Error> {
        match wire.encoding.as_str() {
            ENCODING_UTF8 => Self::from_bytes(wire.value),
            ENCODING_HEX => {
                let (pairs, remainder) = wire.value.as_bytes().as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(PathError::MalformedHex);
                }
                let bytes: Vec<u8> = pairs
                    .iter()
                    .map(|[high, low]| Some(hex_digit(*high)? << 4 | hex_digit(*low)?))
                    .collect::<Option<Vec<u8>>>()
                    .ok_or(PathError::MalformedHex)?;
                if !bytes.is_empty() && std::str::from_utf8(&bytes).is_ok() {
                    return Err(PathError::NotCanonical);
                }
                Self::from_bytes(bytes)
            }
            _ => Err(PathError::UnsupportedEncoding),
        }
    }
}

/// A device number as `stat` and `statfs` report it (`dev_t`).
///
/// The number identifies a mounted filesystem only while it stays mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceNumber(i32);

impl DeviceNumber {
    /// Makes the value from the native number.
    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    /// The native number.
    pub const fn get(self) -> i32 {
        self.0
    }
}

unsigned_quantity! {
    /// A file serial number as `stat` reports it (`st_ino`).
    InodeNumber
}

/// The native identifiers of one file object.
///
/// Two names with the same evidence on one mount generation are the same
/// object, for example hard links. The evidence alone is not a durable
/// identity: a filesystem can use an inode number again, and a device number
/// can name another filesystem after a remount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FileObjectEvidence {
    /// The device that holds the object.
    pub device: DeviceNumber,
    /// The file serial number on that device.
    pub inode: InodeNumber,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DeviceNumber, FileObjectEvidence, InodeNumber, LosslessPath, PathError};

    #[test]
    fn a_utf8_path_round_trips_as_text() {
        let path = LosslessPath::from_bytes("/Users/a/Библиотека").unwrap();
        let value = serde_json::to_value(&path).unwrap();
        assert_eq!(
            value,
            json!({ "encoding": "utf8", "value": "/Users/a/Библиотека" })
        );
        assert_eq!(serde_json::from_value::<LosslessPath>(value).unwrap(), path);
        assert_eq!(path.as_utf8(), Some("/Users/a/Библиотека"));
    }

    #[test]
    fn a_path_that_is_not_utf8_keeps_its_bytes() {
        let path = LosslessPath::from_bytes(b"/f\xff".to_vec()).unwrap();
        let value = serde_json::to_value(&path).unwrap();
        assert_eq!(value, json!({ "encoding": "hex", "value": "2f66ff" }));
        let decoded: LosslessPath = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.as_bytes(), b"/f\xff");
        assert_eq!(decoded.as_utf8(), None);
        assert_eq!(decoded.display_label(), "/f\\xff");
    }

    #[test]
    fn the_display_label_escapes_invisible_format_characters() {
        let path = LosslessPath::from_bytes("/a/\u{202E}gpj.exe\u{200B}".as_bytes()).unwrap();
        assert_eq!(path.display_label(), "/a/\\u{202e}gpj.exe\\u{200b}");
    }

    #[test]
    fn the_display_label_escapes_control_characters_and_backslashes() {
        let path = LosslessPath::from_bytes("/a\nb\\c").unwrap();
        assert_eq!(path.display_label(), "/a\\u{a}b\\\\c");
    }

    #[test]
    fn decoding_rejects_a_path_outside_the_contract() {
        for (value, error) in [
            (json!({ "encoding": "utf8", "value": "" }), PathError::Empty),
            (json!({ "encoding": "hex", "value": "" }), PathError::Empty),
            (
                json!({ "encoding": "utf8", "value": "/a\u{0}b" }),
                PathError::ContainsNul,
            ),
            (
                json!({ "encoding": "hex", "value": "2f00ff" }),
                PathError::ContainsNul,
            ),
            (
                json!({ "encoding": "hex", "value": "2f6" }),
                PathError::MalformedHex,
            ),
            (
                json!({ "encoding": "hex", "value": "2F66FF" }),
                PathError::MalformedHex,
            ),
            (
                json!({ "encoding": "hex", "value": "zz" }),
                PathError::MalformedHex,
            ),
            (
                json!({ "encoding": "hex", "value": "2f66" }),
                PathError::NotCanonical,
            ),
            (
                json!({ "encoding": "base64", "value": "L2Y=" }),
                PathError::UnsupportedEncoding,
            ),
        ] {
            let message: String = serde_json::from_value::<LosslessPath>(value)
                .unwrap_err()
                .to_string();
            assert_eq!(message, error.to_string());
        }
        assert!(serde_json::from_value::<LosslessPath>(json!("/a")).is_err());
        // A second representation in one object is ambiguous.
        let competing = json!({ "encoding": "utf8", "value": "/a", "bytes": "2f62" });
        assert!(serde_json::from_value::<LosslessPath>(competing).is_err());
        assert_eq!(LosslessPath::from_bytes(Vec::new()), Err(PathError::Empty));
    }

    #[cfg(unix)]
    #[test]
    fn a_platform_path_converts_without_loss() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        use std::path::Path;

        let native: &Path = Path::new(OsStr::from_bytes(b"/tmp/\xfe name"));
        let path = LosslessPath::from_path(native).unwrap();
        assert_eq!(path.to_path_buf(), native);
    }

    #[test]
    fn file_object_evidence_round_trips() {
        let evidence = FileObjectEvidence {
            device: DeviceNumber::new(16_777_234),
            inode: InodeNumber::new(u64::MAX),
        };
        let value = serde_json::to_value(evidence).unwrap();
        assert_eq!(
            value,
            json!({ "device": 16_777_234, "inode": "18446744073709551615" })
        );
        assert_eq!(
            serde_json::from_value::<FileObjectEvidence>(value).unwrap(),
            evidence
        );
    }
}
