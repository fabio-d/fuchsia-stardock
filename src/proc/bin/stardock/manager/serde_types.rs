// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use stardock_common::digest::Sha256Digest;

// This file implements parsers for JSON struct defined in various specifications

// ManifestV2
// Type: application/vnd.docker.distribution.manifest.v2+json
// https://docs.docker.com/registry/spec/manifest-v2-2/

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ManifestV2 {
    pub schema_version: u32,
    pub media_type: String,
    pub config: ManifestV2Config,
    pub layers: Vec<ManifestV2Layer>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ManifestV2Config {
    pub media_type: String,
    pub size: u32,
    pub digest: Sha256Digest,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ManifestV2Layer {
    pub media_type: String,
    pub size: u32,
    pub digest: Sha256Digest,
}

// ImageV1
// Type: application/vnd.docker.container.image.v1+json
// https://github.com/opencontainers/image-spec/blob/main/config.md (docker spec?)

#[derive(Deserialize, Debug)]
pub struct ImageV1 {
    pub architecture: String,
    pub os: String,
    #[serde(rename = "rootfs")]
    pub root_fs: ImageV1RootFs,
}

#[derive(Deserialize, Debug)]
pub struct ImageV1RootFs {
    pub r#type: String,
    pub diff_ids: Vec<Sha256Digest>,
}
