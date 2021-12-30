// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_net as fnet;
use fidl_fuchsia_stardock as fstardock;
use lazy_static::lazy_static;
use regex::Regex;
use std::convert::{TryFrom, TryInto};
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

/// The result of parsing a registry reference string.
///
/// This enum mirrors the FIDL RegistryReference type. See the FIDL file for its description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryReference
{
    pub hostname: String,
    pub port: u16,
}

impl TryFrom<fstardock::RegistryReference> for RegistryReference {
    type Error = Error;

    fn try_from(val: fstardock::RegistryReference) -> Result<RegistryReference, Error> {
        if validate_hostname(&val.hostname) && val.port != 0 {
            Ok(RegistryReference { hostname: val.hostname, port: val.port })
        } else {
            anyhow::bail!("Invalid FIDL RegistryReference");
        }
    }
}

impl Into<fstardock::RegistryReference> for RegistryReference {
    fn into(self) -> fstardock::RegistryReference {
        fstardock::RegistryReference { hostname: self.hostname, port: self.port }
    }
}

impl FromStr for RegistryReference {
    type Err = Error;

    fn from_str(text: &str) -> Result<RegistryReference, Error> {
        match text.rsplitn(2, ':').collect::<Vec<&str>>().as_slice() {
            [port, hostname] => {
                // HOSTNAME:PORT
                if validate_hostname(hostname) {
                    let port = port.parse::<u16>()?;
                    if port != 0 {
                        return Ok(RegistryReference { hostname: hostname.to_string(), port });
                    }
                }
            }

            [hostname] => {
                // HOSTNAME
                if validate_hostname(hostname) {
                    return Ok(RegistryReference { hostname: hostname.to_string(), port: 443 });
                }
            }

            _ => unreachable!(),
        }

        anyhow::bail!("Invalid registry reference");
    }
}

/// The result of parsing an image reference string with an optional registry reference.
///
/// This enum mirrors the FIDL RegistryReference type. See the FIDL file for its description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryAndImageReference(pub Option<RegistryReference>, pub ImageReference);

impl TryFrom<fstardock::RegistryAndImageReference> for RegistryAndImageReference {
    type Error = Error;

    fn try_from(val: fstardock::RegistryAndImageReference) -> Result<RegistryAndImageReference, Error> {
        let registry_reference = match val.registry_reference {
            Some(boxed) => Some((*boxed).try_into()?),
            None => None,
        };
        Ok(RegistryAndImageReference(
            registry_reference,
            val.image_reference.try_into()?,
        ))
    }
}

impl Into<fstardock::RegistryAndImageReference> for RegistryAndImageReference {
    fn into(self) -> fstardock::RegistryAndImageReference {
        let registry_reference = self.0.map(|v| Box::new(v.into()));
        fstardock::RegistryAndImageReference { registry_reference, image_reference: self.1.into() }
    }
}

impl FromStr for RegistryAndImageReference {
    type Err = Error;

    fn from_str(text: &str) -> Result<RegistryAndImageReference, Error> {
        if let [registry, image] = text.splitn(2, '/').collect::<Vec<&str>>().as_slice() {
            if *registry == "localhost" || registry.contains(|c| c == '.' || c == ':') {
                // REGISTRY_REFERENCE/IMAGE_REFERENCE
                return Ok(RegistryAndImageReference(Some(registry.parse()?), image.parse()?));
            }
        }

        // IMAGE_REFERENCE
        Ok(RegistryAndImageReference(None, text.parse()?))
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

fn validate_hostname(text: &str) -> bool {
    text.len() >= 1
        && text.len() <= (fnet::MAX_HOSTNAME_SIZE as usize)
        && validate_name_component(text)
}

#[cfg(test)]
mod image_reference_tests {
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

#[cfg(test)]
mod registry_reference_tests {
    use super::*;
    use matches::assert_matches;
    use test_case::test_case;

    // Valid input
    #[test_case("example.com" ; "hostname 1")]
    #[test_case("registry.example.com" ; "hostname 2")]
    #[test_case("example" ; "hostname 3")]
    #[test_case("1.2.3.4" ; "IPv4 address")]
    #[test_case("localhost" ; "localhost")]
    fn from_str_without_port(text: &str) {
        assert_matches!(
            text.parse::<RegistryReference>(),
            Ok(RegistryReference { hostname, port })
                if hostname == text && port == 443);
    }

    // Valid input
    #[test_case("example.com", 80 ; "hostname 1")]
    #[test_case("registry.example.com", 443 ; "hostname 2")]
    #[test_case("1.2.3.4", 8888 ; "IPv4 address")]
    #[test_case("localhost", 8080 ; "localhost")]
    fn from_str_with_port(hostname_text: &str, port_num: u16) {
        assert_matches!(
            format!("{}:{}", hostname_text, port_num).parse::<RegistryReference>(),
            Ok(RegistryReference { hostname, port })
                if hostname == hostname_text && port == port_num);
    }

    // Bad input
    #[test_case("" ; "empty string")]
    #[test_case(":" ; "only colon")]
    #[test_case("example.com:" ; "only hostname")]
    #[test_case("1.2.3.4:" ; "only IPv4 address")]
    #[test_case("localhost:" ; "only localhost")]
    #[test_case(":80" ; "only port")]
    #[test_case("example:0" ; "invalid port 1")]
    #[test_case("example:65536" ; "invalid port 2")]
    #[test_case("127.0.0:65536" ; "invalid IPv4 address 1")]
    #[test_case("127.0.0.256:65536" ; "invalid IPv4 address 2")]
    fn from_str_err(text: &str) {
        assert_matches!(text.parse::<RegistryReference>(), Err(_));
    }

    #[test]
    fn default_port() {
        assert_matches!(
            "example".parse::<RegistryReference>(),
            Ok(RegistryReference { hostname: _, port: 443 })
        );
    }

    lazy_static! {
        static ref MAX_LENGTH_TESTCASE: String =
            format!("{}:123", "a".repeat(fnet::MAX_HOSTNAME_SIZE as usize)
        );
    }

    #[test_case("example:1" ; "hostname and port")]
    #[test_case("12.34.56.78:65535" ; "IPv4 and port")]
    #[test_case(MAX_LENGTH_TESTCASE.as_str() ; "max length")]
    fn fidl_roundtrip(text: &str) {
        let imgref: RegistryReference = text.parse().expect("from_str");
        let fidl: fstardock::RegistryReference = imgref.clone().into();
        assert_eq!(imgref, RegistryReference::try_from(fidl).expect("from FIDL"));
    }
}

#[cfg(test)]
mod registry_and_image_reference_tests {
    use super::*;
    use matches::assert_matches;
    use test_case::test_case;

    // Valid input
    #[test_case("example.com", "example" ; "hostname 1")]
    #[test_case("localhost", "example1/example2" ; "hostname 2")]
    #[test_case("123.123.123.123", "example" ; "IPv4 address")]
    #[test_case("hello:123", "example1/example2/example3" ; "hostname and port")]
    #[test_case("sha256:1234", "example" ; "hostname is sha256")]
    fn from_str_with_registry(registry: &str, image: &str) {
        assert_matches!(
            format!("{}/{}", registry, image).parse::<RegistryAndImageReference>(),
            Ok(RegistryAndImageReference(Some(registry_reference), image_reference))
                if registry_reference == registry.parse().unwrap()
                    && image_reference == image.parse().unwrap());
    }

    // Valid input
    #[test_case("example1" ; "no registry, one name component")]
    #[test_case("example1/example2" ; "no registry, two name components")]
    #[test_case("example1/example2/example3" ; "no registry, three name components")]
    fn from_str_without_registry(text: &str) {
        assert_matches!(
            text.parse::<RegistryAndImageReference>(),
            Ok(RegistryAndImageReference(None, image_reference))
                if image_reference == text.parse().unwrap());
    }

    // Bad input
    #[test_case("" ; "empty")]
    #[test_case("/" ; "slash only")]
    #[test_case("/example" ; "empty registry")]
    #[test_case("example.com/" ; "empty image")]
    #[test_case("/1.2.3.4/x" ; "begin with slash")]
    #[test_case("1.2.3.4/x/" ; "end with slash")]
    fn from_str_err(text: &str) {
        assert_matches!(text.parse::<RegistryReference>(), Err(_));
    }
}
