// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::channel::ChannelConfigs;
use anyhow::{Context as _, Error};
use fuchsia_url::pkg_url::PkgUrl;
use omaha_client::cup_ecdsa::PublicKeys;
use serde::Deserialize;
use std::io;

const EAGER_PACKAGE_CONFIG_PATH: &str = "/config/data/eager_package_config.json";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct OmahaServer {
    pub service_url: String,
    pub public_keys: PublicKeys,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EagerPackageConfig {
    pub url: PkgUrl,
    pub flavor: Option<String>,
    pub channel_config: ChannelConfigs,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EagerPackageConfigs {
    pub server: Option<OmahaServer>,
    pub packages: Vec<EagerPackageConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct EagerPackageConfigsJson {
    pub eager_package_configs: Vec<EagerPackageConfigs>,
}

impl EagerPackageConfigs {
    /// Load the eager package config from namespace.
    pub fn from_namespace() -> Result<Self, Error> {
        let file = std::fs::File::open(EAGER_PACKAGE_CONFIG_PATH)
            .context("opening eager package config file")?;
        Self::from_reader(io::BufReader::new(file))
    }

    fn from_reader(reader: impl io::Read) -> Result<Self, Error> {
        let eager_package_configs_json: EagerPackageConfigsJson =
            serde_json::from_reader(reader).context("parsing eager package config")?;
        // Omaha client only supports one Omaha server at a time; just take the
        // first server config in this file.
        if eager_package_configs_json.eager_package_configs.len() > 1 {
            log::error!(
                "Warning: this eager package config JSON file contained more \
                than one Omaha server config, but omaha-client only supports \
                one Omaha server."
            );
        }
        let eager_package_configs =
            eager_package_configs_json.eager_package_configs.into_iter().next().ok_or(
                anyhow::anyhow!(
                    "Eager package config JSON did not contain any server-and-package configs."
                ),
            )?;
        for package in &eager_package_configs.packages {
            package.channel_config.validate().context("validating eager package channel config")?;
        }

        Ok(eager_package_configs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelConfig;
    use assert_matches::assert_matches;
    use omaha_client::cup_ecdsa::{PublicKey, PublicKeyAndId};
    use pretty_assertions::assert_eq;
    use std::{convert::TryInto, str::FromStr};

    #[test]
    fn parse_eager_package_configs_json() {
        let json = br#"
        {
            "eager_package_configs": [ 
                {
                    "server": {
                        "service_url": "https://example.com",
                        "public_keys": {
                            "latest": {
                                "id": 123,
                                "key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHKz/tV8vLO/YnYnrN0smgRUkUoAt\n7qCZFgaBN9g5z3/EgaREkjBNfvZqwRe+/oOo0I8VXytS+fYY3URwKQSODw==\n-----END PUBLIC KEY-----"
                            },
                            "historical": []
                        }
                    },
                    "packages":
                    [
                        {
                            "url": "fuchsia-pkg://example.com/package",
                            "flavor": "debug",
                            "channel_config":
                                {
                                    "channels":
                                        [
                                            {
                                                "name": "stable",
                                                "repo": "stable",
                                                "appid": "1a2b3c4d"
                                            },
                                            {
                                                "name": "beta",
                                                "repo": "beta",
                                                "appid": "1a2b3c4d"
                                            },
                                            {
                                                "name": "alpha",
                                                "repo": "alpha",
                                                "appid": "1a2b3c4d"
                                            },
                                            {
                                                "name": "test",
                                                "repo": "test",
                                                "appid": "2b3c4d5e"
                                            }
                                        ],
                                    "default_channel": "stable"
                                }
                        },
                        {
                            "url": "fuchsia-pkg://example.com/package2",
                            "channel_config":
                                {
                                    "channels":
                                        [
                                            {
                                                "name": "stable",
                                                "repo": "stable",
                                                "appid": "3c4d5e6f"
                                            }
                                        ]
                                }
                        }
                    ]
                } 
            ]
        }"#;

        assert_eq!(
            EagerPackageConfigs::from_reader(&json[..]).unwrap(),
            EagerPackageConfigs {
                server: Some(OmahaServer {
                    service_url: "https://example.com".into(),
                    public_keys: PublicKeys {
                        latest: PublicKeyAndId {
                            id: 123.try_into().unwrap(),
                            key: PublicKey::from_str(
                                r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHKz/tV8vLO/YnYnrN0smgRUkUoAt
7qCZFgaBN9g5z3/EgaREkjBNfvZqwRe+/oOo0I8VXytS+fYY3URwKQSODw==
-----END PUBLIC KEY-----"#,
                            )
                            .unwrap()
                        },
                        historical: vec![],
                    }
                }),
                packages: vec![
                    EagerPackageConfig {
                        url: PkgUrl::parse("fuchsia-pkg://example.com/package").unwrap(),
                        flavor: Some("debug".into()),
                        channel_config: ChannelConfigs {
                            default_channel: Some("stable".into()),
                            known_channels: vec![
                                ChannelConfig {
                                    name: "stable".into(),
                                    repo: "stable".into(),
                                    appid: Some("1a2b3c4d".into()),
                                    check_interval_secs: None,
                                },
                                ChannelConfig {
                                    name: "beta".into(),
                                    repo: "beta".into(),
                                    appid: Some("1a2b3c4d".into()),
                                    check_interval_secs: None,
                                },
                                ChannelConfig {
                                    name: "alpha".into(),
                                    repo: "alpha".into(),
                                    appid: Some("1a2b3c4d".into()),
                                    check_interval_secs: None,
                                },
                                ChannelConfig {
                                    name: "test".into(),
                                    repo: "test".into(),
                                    appid: Some("2b3c4d5e".into()),
                                    check_interval_secs: None,
                                },
                            ]
                        },
                    },
                    EagerPackageConfig {
                        url: PkgUrl::parse("fuchsia-pkg://example.com/package2").unwrap(),
                        flavor: None,
                        channel_config: ChannelConfigs {
                            default_channel: None,
                            known_channels: vec![ChannelConfig {
                                name: "stable".into(),
                                repo: "stable".into(),
                                appid: Some("3c4d5e6f".into()),
                                check_interval_secs: None,
                            },]
                        },
                    },
                ]
            }
        );
    }

    #[test]
    fn parse_eager_package_configs_json_reject_invalid() {
        let json = br#"
        {
            "eager_package_configs": [ 
                {
                    "server": {},
                    "packages":
                    [
                        {
                            "url": "fuchsia-pkg://example.com/package",
                            "channel_config":
                                {
                                    "channels":
                                        [
                                            {
                                                "name": "stable",
                                                "repo": "stable",
                                            }
                                        ],
                                    "default_channel": "invalid"
                                }
                        }
                    ]
                } 
            ]
        }"#;
        assert_matches!(EagerPackageConfigs::from_reader(&json[..]), Err(_));
    }
}
