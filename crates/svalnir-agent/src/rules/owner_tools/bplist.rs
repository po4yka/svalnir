//! A reader for the top-level dictionary of a binary property list, the
//! second form that the inspection of a simulator device accepts for its
//! `device.plist`.
//!
//! The reader accepts one form only: a `bplist00` file whose top object is
//! a dictionary with string keys. It decodes the values that are ASCII or
//! UTF-16 strings, integers of at most 8 bytes, and booleans; another
//! value is [`Scalar::Other`]. It reads no nested container, so a value
//! that is an array or a dictionary is not examined. A file that does not
//! have this form gives `None`, and the caller does not recognize the
//! layout.

/// The largest number of objects of a file that the reader accepts.
const MAX_OBJECTS: u64 = 4096;

/// The largest number of entries of the top dictionary.
const MAX_ENTRIES: u64 = 256;

/// One value of the top dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Scalar {
    /// A string.
    Text(String),
    /// An integer.
    Integer(i64),
    /// A boolean.
    Boolean(bool),
    /// Another type.
    Other,
}

/// The fields of the trailer of a binary property list.
struct Trailer {
    offset_size: usize,
    reference_size: usize,
    objects: u64,
    top: u64,
    table: usize,
}

/// The big-endian unsigned integer of `bytes`, of at most 8 bytes.
fn unsigned(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

struct Reader<'a> {
    bytes: &'a [u8],
    trailer: Trailer,
}

impl Reader<'_> {
    /// The offset of the object `index`.
    fn offset(&self, index: u64) -> Option<usize> {
        if index >= self.trailer.objects {
            return None;
        }
        let size: usize = self.trailer.offset_size;
        let start: usize = self
            .trailer
            .table
            .checked_add(usize::try_from(index).ok()?.checked_mul(size)?)?;
        let value: u64 = unsigned(self.bytes.get(start..start.checked_add(size)?)?)?;
        let offset: usize = usize::try_from(value).ok()?;
        // An object is between the header and the offset table.
        (offset >= 8 && offset < self.trailer.table).then_some(offset)
    }

    /// The marker of the object at `offset` and the length of a container
    /// or a string, with the offset of its content.
    fn header(&self, offset: usize) -> Option<(u8, u64, usize)> {
        let marker: u8 = *self.bytes.get(offset)?;
        let low: u8 = marker & 0x0f;
        let mut content: usize = offset.checked_add(1)?;
        let length: u64 = if low == 0x0f {
            // The length is an integer object that follows the marker.
            let integer: u8 = *self.bytes.get(content)?;
            if integer & 0xf0 != 0x10 {
                return None;
            }
            let size: usize = 1_usize.checked_shl(u32::from(integer & 0x0f))?;
            let start: usize = content.checked_add(1)?;
            let value: u64 = unsigned(self.bytes.get(start..start.checked_add(size)?)?)?;
            content = start.checked_add(size)?;
            value
        } else {
            u64::from(low)
        };
        Some((marker >> 4, length, content))
    }

    /// The reference `index` of a container whose references start at
    /// `start`.
    fn reference(&self, start: usize, index: u64) -> Option<u64> {
        let size: usize = self.trailer.reference_size;
        let at: usize = start.checked_add(usize::try_from(index).ok()?.checked_mul(size)?)?;
        if at.checked_add(size)? > self.trailer.table {
            return None;
        }
        unsigned(self.bytes.get(at..at.checked_add(size)?)?)
    }

    /// The string of the object `index`, when it is one.
    fn text(&self, index: u64) -> Option<String> {
        let offset: usize = self.offset(index)?;
        let (kind, length, content) = self.header(offset)?;
        let length: usize = usize::try_from(length).ok()?;
        match kind {
            0x5 => {
                let bytes: &[u8] = self.bytes.get(content..content.checked_add(length)?)?;
                bytes
                    .is_ascii()
                    .then(|| String::from_utf8_lossy(bytes).into_owned())
            }
            0x6 => {
                let end: usize = content.checked_add(length.checked_mul(2)?)?;
                let units: Vec<u16> = self
                    .bytes
                    .get(content..end)?
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect();
                String::from_utf16(&units).ok()
            }
            _ => None,
        }
    }

    /// The scalar of the object `index`.
    fn scalar(&self, index: u64) -> Option<Scalar> {
        let offset: usize = self.offset(index)?;
        let marker: u8 = *self.bytes.get(offset)?;
        Some(match marker {
            0x08 => Scalar::Boolean(false),
            0x09 => Scalar::Boolean(true),
            0x10..=0x13 => {
                let size: usize = 1_usize << (marker & 0x0f);
                let start: usize = offset.checked_add(1)?;
                let raw: u64 = unsigned(self.bytes.get(start..start.checked_add(size)?)?)?;
                // An integer of 8 bytes is signed; a shorter one is not.
                Scalar::Integer(if size == 8 {
                    i64::from_be_bytes(raw.to_be_bytes())
                } else {
                    i64::try_from(raw).ok()?
                })
            }
            _ => match self.text(index) {
                Some(text) => Scalar::Text(text),
                None => Scalar::Other,
            },
        })
    }
}

/// The entries of the top dictionary of the binary property list
/// `bytes`, in the sequence of the file. `None` when the file does not
/// have the accepted form, or has a key two times.
pub(super) fn parse_dictionary(bytes: &[u8]) -> Option<Vec<(String, Scalar)>> {
    if bytes.get(..8)? != b"bplist00" || bytes.len() < 8 + 32 {
        return None;
    }
    let tail: &[u8] = bytes.get(bytes.len() - 32..)?;
    let trailer: Trailer = Trailer {
        offset_size: usize::from(tail[6]),
        reference_size: usize::from(tail[7]),
        objects: unsigned(&tail[8..16])?,
        top: unsigned(&tail[16..24])?,
        table: usize::try_from(unsigned(&tail[24..32])?).ok()?,
    };
    let table_end: usize = trailer.table.checked_add(
        usize::try_from(trailer.objects)
            .ok()?
            .checked_mul(trailer.offset_size)?,
    )?;
    if !(1..=8).contains(&trailer.offset_size)
        || !(1..=8).contains(&trailer.reference_size)
        || trailer.objects == 0
        || trailer.objects > MAX_OBJECTS
        || trailer.table < 8
        || table_end > bytes.len() - 32
    {
        return None;
    }
    let reader: Reader<'_> = Reader { bytes, trailer };
    let top: usize = reader.offset(reader.trailer.top)?;
    let (kind, count, references) = reader.header(top)?;
    if kind != 0xd || count > MAX_ENTRIES {
        return None;
    }
    let mut entries: Vec<(String, Scalar)> = Vec::new();
    for index in 0..count {
        let key: String = reader.text(reader.reference(references, index)?)?;
        let value: Scalar =
            reader.scalar(reader.reference(references, count.checked_add(index)?)?)?;
        if entries.iter().any(|(known, _)| *known == key) {
            return None;
        }
        entries.push((key, value));
    }
    Some(entries)
}
