// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use futures::io::AsyncReadExt;
use log::info;

use crate::serde_types;

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
            serde_json::from_slice::<serde_types::ManifestV2>(&data)?
        };

        info!("Fetched manifest {:?}", manifest);

        let config_digest = &manifest.config.digest;
        let configuration_response = image_fetcher.fetch_blob(config_digest.as_str()).await?
            .ok_or_else(|| anyhow::anyhow!("Client failed to fetch image configuration"))?;

        // Read and parse configuration as JSON
        let configuration = {
            let mut data = Vec::new();
            // FIXME: this reads the socket into an unbounded buffer, potentially exhausting this
            // process' memory
            fasync::Socket::from_socket(configuration_response)?.read_to_end(&mut data).await?;
            info!("DATA: {:?}", String::from_utf8(data.clone()));
            serde_json::from_slice::<serde_types::ImageV1>(&data)?
        };

        info!("Fetched configuration {:?}", configuration);

        for serde_types::ManifestV2Layer { digest, .. } in manifest.layers {
            image_fetcher.fetch_blob(digest.as_str()).await?;
        }

        Ok(())
    }
}
