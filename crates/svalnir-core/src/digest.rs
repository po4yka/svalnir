//! Content digests.
//!
//! A digest binds an approval or a record to exact content. It is not a
//! secret and not an authorization: a client that has the digest of a plan
//! does not have permission to apply the plan.
//!
//! The text is `sha256:` and 64 lowercase hexadecimal digits. The digest of
//! a record is the SHA-256 of its JSON encoding as `serde_json` writes it:
//! the fields in declaration sequence, no insignificant white space. The
//! JSON encoding of each record type that has a digest is a part of its
//! schema version.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PREFIX: &str = "sha256:";
const HEX_LENGTH: usize = 64;

/// The reason a digest text was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the digest is not `sha256:` and 64 lowercase hexadecimal digits")]
pub struct DigestError;

/// The SHA-256 digest of the content of one record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentDigest(String);

impl ContentDigest {
    /// The digest of `bytes`.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self::of_hash(&Sha256::digest(bytes))
    }

    /// The digest of the bytes that `reader` gives, to its end, with at
    /// most `limit` bytes. A read that a signal interrupts is read again.
    ///
    /// # Errors
    ///
    /// Returns the error of the reader, or an error of the kind
    /// [`std::io::ErrorKind::FileTooLarge`] when the reader gives more than
    /// `limit` bytes.
    pub fn of_reader(mut reader: impl std::io::Read, limit: u64) -> std::io::Result<Self> {
        let mut hasher = Sha256::new();
        let mut buffer: [u8; 8192] = [0; 8192];
        let mut total: u64 = 0;
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return Ok(Self::of_hash(&hasher.finalize())),
                Ok(count) => {
                    total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                    if total > limit {
                        return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
                    }
                    hasher.update(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn of_hash(hash: &[u8]) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";

        let mut text: String = String::with_capacity(PREFIX.len() + HEX_LENGTH);
        text.push_str(PREFIX);
        for byte in hash {
            text.push(char::from(DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        Self(text)
    }

    /// The digest of the JSON encoding of `record`.
    ///
    /// # Errors
    ///
    /// Returns the error of the encoder when `record` has no JSON encoding.
    pub fn of_json<T: Serialize>(record: &T) -> Result<Self, serde_json::Error> {
        Ok(Self::of_bytes(&serde_json::to_vec(record)?))
    }

    /// Makes the digest from its text.
    ///
    /// # Errors
    ///
    /// Returns a [`DigestError`] when the text does not have the form
    /// `sha256:` and 64 lowercase hexadecimal digits.
    pub fn new(text: impl Into<String>) -> Result<Self, DigestError> {
        let text: String = text.into();
        let is_lower_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
        match text.strip_prefix(PREFIX) {
            Some(hex) if hex.len() == HEX_LENGTH && hex.bytes().all(is_lower_hex) => Ok(Self(text)),
            _ => Err(DigestError),
        }
    }

    /// The text of the digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ContentDigest {
    type Error = DigestError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<ContentDigest> for String {
    fn from(digest: ContentDigest) -> Self {
        digest.0
    }
}

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::ContentDigest;

    #[test]
    fn the_digest_of_known_content_is_the_published_value() {
        // The SHA-256 test vectors of FIPS 180-4 for the empty message and
        // for "abc".
        assert_eq!(
            ContentDigest::of_bytes(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ContentDigest::of_bytes(b"abc").as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_digest_of_a_record_is_the_digest_of_its_json() {
        let record = ("plan", 1_u32);
        assert_eq!(
            ContentDigest::of_json(&record).unwrap(),
            ContentDigest::of_bytes(br#"["plan",1]"#)
        );
        assert_ne!(
            ContentDigest::of_json(&("plan", 2_u32)).unwrap(),
            ContentDigest::of_json(&record).unwrap()
        );
    }

    #[test]
    fn a_digest_round_trips_and_a_bad_text_is_rejected() {
        let digest = ContentDigest::of_bytes(b"abc");
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(
            serde_json::from_str::<ContentDigest>(&json).unwrap(),
            digest
        );
        assert_eq!(digest.to_string(), digest.as_str());
        let hex = "a".repeat(64);
        assert!(ContentDigest::new(format!("sha256:{hex}")).is_ok());
        for bad in [
            String::new(),
            hex.clone(),
            format!("sha1:{hex}"),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "g".repeat(64)),
        ] {
            assert!(ContentDigest::new(bad.clone()).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<ContentDigest>("\"sha256:00\"").is_err());
    }
}
