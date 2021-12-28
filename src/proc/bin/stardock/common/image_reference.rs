// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_stardock as fstardock;
use lazy_static::lazy_static;
use regex::Regex;
use std::convert::TryFrom;
use std::str::FromStr;

use crate::digest;

/// The result of parsing an image reference string.
///
/// This enum mirrors the FIDL ImageReference type. See the FIDL file for its description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageReference {
    ByNameAndTag(String, String),
    ByNameAndDigest(String, digest::Sha256Digest),
    ByNameOrImageId(String, ImageReferenceAmbiguityType),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageReferenceAmbiguityType {
    NameOnly,
    ImageIdOnly,
    NameOrImageId,
}

impl TryFrom<fstardock::ImageReference> for ImageReference {
    type Error = Error;

    fn try_from(val: fstardock::ImageReference) -> Result<ImageReference, Error> {
        match val {
            fstardock::ImageReference::ByNameAndTag(fstardock::ByNameAndTag { name, tag }) => {
                if validate_name(&name) && validate_tag(&tag) {
                    return Ok(ImageReference::ByNameAndTag(name, tag));
                }
            }

            fstardock::ImageReference::ByNameAndDigest(fstardock::ByNameAndDigest { name, digest }) => {
                if validate_name(&name) {
                    return Ok(ImageReference::ByNameAndDigest(name, digest.parse()?));
                }
            }

            fstardock::ImageReference::ByNameOrImageId(fstardock::ByNameOrImageId { text, search_domain }) => {
                match search_domain {
                    fstardock::ImageReferenceAmbiguityType::NameOnly => {
                        if validate_name(&text) {
                            return Ok(ImageReference::ByNameOrImageId(
                                text,
                                ImageReferenceAmbiguityType::NameOnly,
                            ));
                        }
                    }

                    fstardock::ImageReferenceAmbiguityType::ImageIdOnly => {
                        if validate_abbreviated_image_id(&text) {
                            return Ok(ImageReference::ByNameOrImageId(
                                text,
                                ImageReferenceAmbiguityType::ImageIdOnly,
                            ));
                        }
                    }

                    fstardock::ImageReferenceAmbiguityType::NameOrImageId => {
                        if validate_name(&text) && validate_abbreviated_image_id(&text) {
                            return Ok(ImageReference::ByNameOrImageId(
                                text,
                                ImageReferenceAmbiguityType::NameOrImageId,
                            ));
                        }
                    }
                }
            }
        }

        anyhow::bail!("Invalid FIDL ImageReference");
    }
}

impl Into<fstardock::ImageReference> for ImageReference {
    fn into(self) -> fstardock::ImageReference {
        match self {
            ImageReference::ByNameAndTag(name, tag) => {
                fstardock::ImageReference::ByNameAndTag(fstardock::ByNameAndTag {
                    name,
                    tag,
                })
            }

            ImageReference::ByNameAndDigest(name, digest) => {
                fstardock::ImageReference::ByNameAndDigest(fstardock::ByNameAndDigest {
                    name,
                    digest: digest.as_str().to_string(),
                })
            }

            ImageReference::ByNameOrImageId(text, search_domain) => {
                fstardock::ImageReference::ByNameOrImageId(fstardock::ByNameOrImageId {
                    text,
                    search_domain: match search_domain {
                        ImageReferenceAmbiguityType::NameOnly =>
                            fstardock::ImageReferenceAmbiguityType::NameOnly,

                        ImageReferenceAmbiguityType::ImageIdOnly =>
                            fstardock::ImageReferenceAmbiguityType::ImageIdOnly,

                        ImageReferenceAmbiguityType::NameOrImageId =>
                            fstardock::ImageReferenceAmbiguityType::NameOrImageId,
                    },
                })
            }
        }
    }
}

impl FromStr for ImageReference {
    type Err = Error;

    fn from_str(s: &str) -> Result<ImageReference, Error> {
        if s.starts_with("sha256:") {
            // sha256:ABBREVIATED_IMAGE_ID
            let s_after_prefix = &s[7..];
            if validate_abbreviated_image_id(s_after_prefix) {
                return Ok(ImageReference::ByNameOrImageId(
                    s_after_prefix.to_string(),
                    ImageReferenceAmbiguityType::ImageIdOnly,
                ));
            }
        } else if let [name_and_tag, sha256_digest] = s.splitn(2, '@').collect::<Vec<&str>>().as_slice() {
            match name_and_tag.splitn(2, ':').collect::<Vec<&str>>().as_slice() {
                [name, tag] => {
                    // NAME:TAG@sha256:DIGEST (TAG is discarded)
                    if validate_name(name) && validate_tag(tag) {
                        return Ok(ImageReference::ByNameAndDigest(
                            name.to_string(),
                            digest::Sha256Digest::from_str_with_prefix(sha256_digest)?,
                        ));
                    }
                }

                [name] => {
                    // NAME@sha256:DIGEST
                    if validate_name(name) {
                        return Ok(ImageReference::ByNameAndDigest(
                            name.to_string(),
                            digest::Sha256Digest::from_str_with_prefix(sha256_digest)?,
                        ));
                    }
                }

                _ => unreachable!(),
            }
        } else {
            match s.splitn(2, ':').collect::<Vec<&str>>().as_slice() {
                [name, tag] => {
                    // NAME:tag
                    if validate_name(name) && validate_tag(tag) {
                        return Ok(ImageReference::ByNameAndTag(name.to_string(), tag.to_string()));
                    }
                }

                [text] => {
                    // ABBREVIATED_IMAGE_ID or NAME - This is an ambiguous case
                    if validate_name(text) {
                        if validate_abbreviated_image_id(text) {
                            return Ok(ImageReference::ByNameOrImageId(
                                text.to_string(),
                                ImageReferenceAmbiguityType::NameOrImageId,
                            ));
                        } else {
                            return Ok(ImageReference::ByNameOrImageId(
                                text.to_string(),
                                ImageReferenceAmbiguityType::NameOnly,
                            ));
                        }
                    } else if validate_abbreviated_image_id(text) {
                        return Ok(ImageReference::ByNameOrImageId(
                            text.to_string(),
                            ImageReferenceAmbiguityType::ImageIdOnly,
                        ));
                    }
                }

                _ => unreachable!(),
            }
        }

        anyhow::bail!("Invalid image reference");
    }
}

// Reference for naming constraints: https://docs.docker.com/engine/reference/commandline/tag/

fn validate_name_component(text: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^([0-9a-z](\.|__?|-+)?)*[0-9a-z]$").unwrap();
    }

    RE.is_match(text)
}

fn validate_name(text: &str) -> bool {
    text.len() >= 1
        && text.len() <= (fstardock::MAX_NAME_LENGTH as usize)
        && text != "sha256"
        && text.split('/').all(validate_name_component)
}

fn validate_tag(text: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$").unwrap();
    }

    text.len() >= 1 && text.len() <= (fstardock::MAX_TAG_LENGTH as usize) && RE.is_match(text)
}

fn validate_abbreviated_image_id(text: &str) -> bool {
    text.len() >= 1 && text.len() <= 64 && digest::is_lowercase_hex_string(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use matches::assert_matches;
    use test_case::test_case;

    // Valid input
    #[test_case("example:latest" ; "name and tag")]
    #[test_case("ex.a-mp__le:my-tAg" ; "name and tag with separators")]
    #[test_case("ex---le:my-Tag." ; "name and tag ending with a period")]
    #[test_case("ex.a.le:MY._.TAG-" ; "name and tag ending with a dash")]
    #[test_case("foo/bar:latest" ; "name with multiple components and tag")]
    #[test_case("sha256/bar:latest" ; "name with sha256 as the first component")]
    #[test_case("foo/sha256:latest" ; "name with sha256 as the last component")]
    #[test_case("foo/sha256/bar:latest" ; "name with sha256 as mid component")]
    fn from_str_by_name_and_tag(text: &str) {
        assert_matches!(
            text.parse::<ImageReference>(),
            Ok(ImageReference::ByNameAndTag(name, tag))
                if format!("{}:{}", name, tag) == text);
    }

    // Valid input (NOTE: the tag is correctly ignored in the second case)
    #[test_case("example@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name and digest")]
    #[test_case("example:mytag@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name and digest with tag")]
    fn from_str_by_name_and_digest(text: &str) {
        assert_matches!(
            text.parse::<ImageReference>(),
            Ok(ImageReference::ByNameAndDigest(name, digest))
                if name == "example" && digest.as_str() == "717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159");
    }

    // Valid input (NOTE: the tag is correctly ignored in the second case)
    #[test_case("example1/example2@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name with multiple components and digest")]
    #[test_case("example1/example2:mytag@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name with multiple components and digest with tag")]
    fn from_str_by_name_with_multiple_components_and_digest(text: &str) {
        assert_matches!(
            text.parse::<ImageReference>(),
            Ok(ImageReference::ByNameAndDigest(name, digest))
                if name == "example1/example2" && digest.as_str() == "717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159");
    }

    // Valid input
    #[test_case("ex4mp1e" ; "name only")]
    #[test_case("e__x.a-m_p__le" ; "with separators")]
    #[test_case("e----le" ; "with many dashes as a separator")]
    #[test_case("717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de931599999999999" ; "too long to be a digest")]
    #[test_case("sha256/bar" ; "with sha256 as the first component")]
    #[test_case("foo/sha256" ; "with sha256 as the last component")]
    #[test_case("foo/sha256/bar" ; "with sha256 as mid component")]
    #[test_case("12345678/12345678" ; "with numeric components")]
    fn from_str_by_name(text: &str) {
        assert_matches!(
            text.parse::<ImageReference>(),
            Ok(ImageReference::ByNameOrImageId(name, ImageReferenceAmbiguityType::NameOnly))
                if name == text);
    }

    // Valid input
    #[test_case("7" ; "min length")]
    #[test_case("717ca7b71" ; "abbreviated")]
    #[test_case("717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "full length")]
    fn from_str_by_image_id(text: &str) {
        // test without prefix
        assert_matches!(
            text.parse::<ImageReference>(),
            Ok(ImageReference::ByNameOrImageId(digest, ImageReferenceAmbiguityType::NameOrImageId))
                if digest.as_str() == text);

        // test again, with prefix
        assert_matches!(
            format!("sha256:{}", text).parse::<ImageReference>(),
            Ok(ImageReference::ByNameOrImageId(digest, ImageReferenceAmbiguityType::ImageIdOnly))
                if digest.as_str() == text);
    }

    // Bad input
    #[test_case("" ; "empty string")]
    #[test_case("@" ; "only at")]
    #[test_case(":" ; "only colon")]
    #[test_case("sha256:" ; "only sha256 and colon")]
    #[test_case("sha256:eeeeez" ; "bad digest")]
    #[test_case("name@" ; "name and at")]
    #[test_case("name@sha256:" ; "name and prefix only")]
    #[test_case("name@sha256:ZZZca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "good name and bad digest characters")]
    #[test_case("nAme@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "bad name and good digest")]
    #[test_case("name:@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "good name, empty tag and good digest")]
    #[test_case("name:-abc@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "good name, bad tag and good digest")]
    #[test_case("@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "empty name and good digest")]
    #[test_case("name@717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "good name and good digest, but missing prefix")]
    #[test_case("name@sha256:717ca7b714817307d6000a9149f" ; "good name and digest too short")]
    #[test_case("name@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de931595555555" ; "good name and digest too long")]
    #[test_case("example@sha321:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name and digest with bad prefix 1")]
    #[test_case("example@sha256::717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name and digest with bad prefix 2")]
    #[test_case("sha256" ; "digest algorithm as a name")]
    #[test_case(":mytag" ; "empty name and good tag")]
    #[test_case("name:" ; "good name and empty tag")]
    #[test_case("name:.abc" ; "good name and bad tag 1")]
    #[test_case("name:-abc" ; "good name and bad tag 2")]
    #[test_case("name:ab%c" ; "good name and bad tag 3")]
    #[test_case("naMe" ; "name is not lowercase")]
    #[test_case(".name" ; "name starts with period")]
    #[test_case("-name" ; "name starts with dash")]
    #[test_case("_name" ; "name starts with underscore")]
    #[test_case("name." ; "name ends with period")]
    #[test_case("name-" ; "name ends with dash")]
    #[test_case("name_" ; "name ends with underscore")]
    #[test_case("na..me" ; "invalid separator, two periods")]
    #[test_case("na___me" ; "invalid separator, three underscores")]
    #[test_case("na_-me" ; "consecutive separators 1")]
    #[test_case("na._me" ; "consecutive separators 2")]
    #[test_case("foo//bar" ; "consecutive slashes")]
    fn from_str_err(text: &str) {
        assert_matches!(text.parse::<ImageReference>(), Err(_));
    }

    #[test]
    fn from_str_name_length() {
        let goodname = "a".repeat(fstardock::MAX_NAME_LENGTH as usize);
        assert_matches!(
            goodname.parse::<ImageReference>(),
            Ok(ImageReference::ByNameOrImageId(name, ImageReferenceAmbiguityType::NameOnly))
                if name == goodname);

        let toolong = goodname + "a";
        assert_matches!(toolong.parse::<ImageReference>(), Err(_));
    }

    #[test]
    fn from_str_tag_length() {
        let goodtag = "a".repeat(fstardock::MAX_TAG_LENGTH as usize);
        let goodref = format!("test:{}", goodtag);
        assert_matches!(
            goodref.parse::<ImageReference>(),
            Ok(ImageReference::ByNameAndTag(name, tag))
                if name == "test" && tag == goodtag);

        let toolong = goodref + "a";
        assert_matches!(toolong.parse::<ImageReference>(), Err(_));
    }

    lazy_static! {
        static ref MAX_LENGTH_TESTCASE: String = format!(
            "{}:{}",
            "a".repeat(fstardock::MAX_NAME_LENGTH as usize),
            "a".repeat(fstardock::MAX_TAG_LENGTH as usize)
        );
    }

    #[test_case("example:latest" ; "name and tag")]
    #[test_case("example@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name and digest")]
    #[test_case("example:mytag@sha256:717ca7b714817307d6000a9149f6a0f6a2fb58efd677e37e66b4b7147de93159" ; "name and digest with tag")]
    #[test_case("example" ; "name only")]
    #[test_case("sha256:717ca7b71" ; "abbreviated digest")]
    #[test_case("717ca7b71" ; "name or abbreviated digest")]
    #[test_case(MAX_LENGTH_TESTCASE.as_str() ; "max length")]
    fn fidl_roundtrip(text: &str) {
        let imgref: ImageReference = text.parse().expect("from_str");
        let fidl: fstardock::ImageReference = imgref.clone().into();
        assert_eq!(imgref, ImageReference::try_from(fidl).expect("from FIDL"));
    }
}
