// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use futures::io::AsyncReadExt;
use log::info;
use serde_json::Value;
use stardock_common::digest;

pub struct Image {
    // TODO: not implemented yet
}

// TODO: this is a preliminary implementation that cannot actually persist images yet
pub struct ImageRegistry;

impl ImageRegistry {
    // Preliminary implementation that simply fetches the manifest and the referenced blob, without
    // actually storing the resulting image
    pub async fn fetch_image(
        image_fetcher: &fstardock::ImageFetcherProxy,
    ) -> Result<(), Error> {
        let manifest_response = image_fetcher.fetch_manifest().await?
            .ok_or_else(|| anyhow::anyhow!("Client failed to fetch manifest"))?;

        // Read and parse manifest as JSON
        let manifest = {
            let mut data = Vec::new();
            // FIXME: this reads the socket into an unbounded buffer, potentially exhausting this
            // process' memory
            fasync::Socket::from_socket(manifest_response)?.read_to_end(&mut data).await?;
            serde_json::from_slice::<Value>(&data)?
        };

        info!("Fetched manifest {:?}", manifest);

        let config = manifest["config"].as_object().ok_or(anyhow::anyhow!("Missing config object"))?;
        let digest = config["digest"].as_str().ok_or(anyhow::anyhow!("Missing digest string"))?;
        let digest = digest::Sha256Digest::from_str_with_prefix(digest)?;
        image_fetcher.fetch_blob(digest.as_str()).await?;

        let layers = manifest["layers"].as_array().ok_or(anyhow::anyhow!("Missing layers array"))?;
        for layer in layers {
            let layer = layer.as_object().ok_or(anyhow::anyhow!("Invalid layer object"))?;
            let digest = layer["digest"].as_str().ok_or(anyhow::anyhow!("Missing digest string"))?;
            let digest = digest::Sha256Digest::from_str_with_prefix(digest)?;
            image_fetcher.fetch_blob(digest.as_str()).await?;
        }

        Ok(())
    }
}
