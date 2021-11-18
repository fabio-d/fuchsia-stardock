// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// A sha256 digest. Exactly 64 characters long.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256Digest {
    digest: String,
}

impl Sha256Digest {
    pub fn from_str_with_prefix(s: &str) -> Result<Self, Error> {
        if let Some(("sha256", digest)) = s.split_once(':') {
            Self::from_str(digest)
        } else {
            anyhow::bail!("Invalid sha256 digest (missing \"sha256:\" prefix)");
        }
    }

    pub fn as_str(&self) -> &str {
        self.digest.as_str()
    }

    pub fn starts_with(&self, prefix_to_test: &str) -> bool {
        self.as_str().starts_with(prefix_to_test)
    }
}

impl FromStr for Sha256Digest {
    type Err = Error;

    /// From hex string (lowercase letters only) without prefix
    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            anyhow::bail!("Invalid sha256 digest (empty string)");
        } else if !is_lowercase_hex_string(s) {
            anyhow::bail!("Invalid sha256 digest (invalid characters)");
        } else if s.len() < 64 {
            anyhow::bail!("Invalid sha256 digest (too short)");
        } else if s.len() > 64 {
            anyhow::bail!("Invalid sha256 digest (too long)");
        } else {
            Ok(Self { digest: s.to_string() })
        }
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("sha256:{}", self.as_str());
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Sha256Digest::from_str_with_prefix(&s).map_err(serde::de::Error::custom)
    }
}

/// Helper function that checks whether all characters in a str are 0-9 or a-f
pub(crate) fn is_lowercase_hex_string(text: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^[0-9a-f]*$").unwrap();
    }

    RE.is_match(text)
}

#[cfg(test)]
mod tests {
    use super::{is_lowercase_hex_string, Sha256Digest};
    use matches::assert_matches;
    use test_case::test_case;

    // Valid input
    #[test_case("sha256:da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "valid")]
    fn from_str_with_prefix_ok(text: &str) {
        assert_matches!(
            Sha256Digest::from_str_with_prefix(text),
            Ok(Sha256Digest { digest }) if format!("sha256:{}", digest) == text
        );
    }

    // Bad combinations of "sha256:" prefix and digest
    #[test_case("" ; "empty string")]
    #[test_case(":" ; "colon")]
    #[test_case("da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "no prefix")]
    #[test_case(":da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "colon prefix")]
    #[test_case("sha257:da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "bad prefix")]
    #[test_case("sha256" ; "prefix only")]
    #[test_case("sha256:" ; "prefix and colon")]
    fn from_str_with_prefix_err(text: &str) {
        assert_matches!(Sha256Digest::from_str_with_prefix(text), Err(_));
    }

    // Valid input
    #[test_case("da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "valid")]
    fn from_str_ok(text: &str) {
        assert_matches!(
            text.parse::<Sha256Digest>(),
            Ok(Sha256Digest { digest }) if digest == text
        );
    }

    // No upper case letters and other invalid characters
    #[test_case("Da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "upper-case letter")]
    #[test_case("za42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95" ; "junk at start")]
    #[test_case("da42a055f277cb4acbe7c9a077zzzzzz6486579b5cd30d1a3e1ae17a884f5d95" ; "junk at mid")]
    #[test_case("da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d9z" ; "junk at end")]
    // Invalid length
    #[test_case("" ; "empty string")]
    #[test_case("da42a055f277cb4acb" ; "too short")]
    #[test_case("da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d955555555" ; "too long")]
    fn from_str_err(text: &str) {
        assert_matches!(text.parse::<Sha256Digest>(), Err(_));
    }

    #[test]
    fn as_str() {
        let text = "da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95";
        assert_eq!(Sha256Digest { digest: text.to_string() }.as_str(), text);
    }

    #[test]
    fn starts_with() {
        let full_text = "da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95";
        let full = Sha256Digest { digest: full_text.to_string() };

        assert!(full.starts_with(full_text));
        assert!(full.starts_with("da42a055f277"));
        assert!(!full.starts_with("c788fb58866a"));
    }

    #[test_case("" => true)]
    #[test_case("abc" => true)]
    #[test_case("!abc" => false)]
    #[test_case("a\nbc" => false)]
    #[test_case("abc\n" => false)]
    fn is_lowercase_hex_string_expect(text: &str) -> bool {
        is_lowercase_hex_string(text)
    }

    #[test]
    fn serde() {
        let text = "da42a055f277cb4acbe7c9a077dac41a6486579b5cd30d1a3e1ae17a884f5d95";
        let digest = Sha256Digest { digest: text.to_string() };
        let expected_json = format!("\"sha256:{}\"", text);

        assert_eq!(
            serde_json::to_string(&digest).expect("Serialization failed"),
            expected_json
        );

        assert_eq!(
            serde_json::from_str::<Sha256Digest>(&expected_json).expect("Deserialization failed"),
            digest
        );
    }
}
