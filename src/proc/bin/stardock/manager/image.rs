// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context as _, Error};
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use futures::io::AsyncReadExt;
use log::info;
use sha2::Digest;
use stardock_common::digest;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};
use std::path::Path;
use tempfile::NamedTempFile;

use crate::serde_types;

const READ_BUFFER_SIZE: usize = 4096;

pub struct Image {
    // TODO: not implemented yet
}

// TODO: this is a preliminary implementation that cannot actually persist images yet
pub struct ImageRegistry {
    blobs_dir: Box<Path>, // where blobs are stored
}

impl ImageRegistry {
    pub fn new(storage_path: &Path) -> Result<ImageRegistry, Error> {
        // Create "blobs" subdirectory if it does not exist
        let mut blobs_dir = storage_path.to_path_buf();
        blobs_dir.push("blobs");
        if !blobs_dir.is_dir() {
            std::fs::create_dir(&blobs_dir).context("Failed to create blobs directory")?;
        }

        // TODO: remove orphan files (e.g. leftovers from a past crash)

        let result = ImageRegistry { blobs_dir: blobs_dir.into_boxed_path() };
        Ok(result)
    }

    // Preliminary implementation that simply downloads the manifest and the referenced blobs into
    // temporary files and then drops them.
    //
    // image_registry is never kept borrowed across an await
    pub async fn fetch_image(
        image_registry: &RefCell<ImageRegistry>,
        image_fetcher: &fstardock::ImageFetcherProxy,
    ) -> Result<(), Error> {
        // Create our copy of the blobs_dir to avoid keeping the image_registry borrowed while
        // waiting
        let blobs_dir = image_registry.borrow().blobs_dir.to_owned();

        // Download and parse manifest JSON blob
        let manifest_response = image_fetcher.fetch_manifest().await?
            .ok_or_else(|| anyhow::anyhow!("Client failed to fetch manifest"))?;
        let manifest = {
            let mut data = Vec::new();
            // FIXME: this reads the socket into an unbounded buffer, potentially exhausting this
            // process' memory
            fasync::Socket::from_socket(manifest_response)?.read_to_end(&mut data).await?;
            serde_json::from_slice::<serde_types::ManifestV2>(&data)?
        };

        info!("Fetched manifest {:?}", manifest);

        // Download and parse image configuration JSON blob
        let config_digest = &manifest.config.digest;
        let mut config_tmpfile = download_blob(
            &blobs_dir,
            &config_digest,
            &image_fetcher
        ).await.context("Failed to fetch image configuration")?;
        let config: serde_types::ImageV1 = read_json_from_file(&mut config_tmpfile)?;

        info!("Fetched configuration {:?}", config);

        // Verify information about the layer blobs:
        // - manifest.layers is the vector of compressed sha256 digests
        // - config.root_fs.diff_ids is the vector of uncompressed sha256 digests
        // They both refer to the same layers, in the same order.
        let config_layers = &config.root_fs.diff_ids;
        if manifest.layers.len() != config_layers.len() {
            anyhow::bail!("Manifest and image configuration differ in number of layers");
        }

        // Download (and uncompress) .tar.gz layer blobs
        for (
            serde_types::ManifestV2Layer { digest: compressed_digest, .. },
            uncompressed_digest,
        ) in manifest.layers.into_iter().zip(config_layers.into_iter()) {
            // This will download and uncompress the blob, then immediately throw it away (because
            // storage is not implemented yet)
            download_compressed_blob(
                &blobs_dir,
                &compressed_digest,
                &uncompressed_digest,
                &image_fetcher
            ).await.context("Failed to fetch layer")?;
        }

        Ok(())
    }
}

/// Download and verify a blob into a temporary file.
///
/// The blob to be downloaded is identified by its sha256 digest.
///
/// Note: blobs must be downloaded into the same filesystem as ImageRegistry's blobs_dir, to ensure
/// that they can later be persist()'ed as non-temporary files within that directory.
async fn download_blob(
    blobs_dir: &Path,
    digest: &digest::Sha256Digest,
    image_fetcher: &fstardock::ImageFetcherProxy,
) -> Result<NamedTempFile, Error> {
    let response = image_fetcher.fetch_blob(digest.as_str()).await?
        .ok_or_else(|| anyhow::anyhow!("Client failed to fetch blob"))?;

    let mut tmpfile = NamedTempFile::new_in(blobs_dir).expect("Failed to create temporary file");

    info!(
        "Downloading blob {} into temporary file {}",
        digest.as_str(),
        tmpfile.path().display(),
    );

    // Store response into tmpfile + compute actual digest
    let mut socket = fasync::Socket::from_socket(response)?;
    let mut buffer = vec![0; READ_BUFFER_SIZE];
    let mut actual_digest = sha2::Sha256::new();
    loop {
        let nbytes = socket.read(&mut buffer).await?;
        if nbytes == 0 {
            break;
        } else {
            actual_digest.update(&buffer[..nbytes]);
            tmpfile.write_all(&buffer[..nbytes])?;
        }
    }

    if hex::encode(actual_digest.finalize()) != digest.as_str() {
        anyhow::bail!("Digest mismatch");
    }

    Ok(tmpfile)
}

/// Download, uncompress and verify a blob into a temporary file.
///
/// The blob to be downloaded is identified by the sha256 digest of its compressed contents. The
/// expected digest of the uncompressed contents is also verified.
///
/// Note: this function behaves like download_blob, but with an extra gzip uncompression step.
async fn download_compressed_blob(
    blobs_dir: &Path,
    compressed_digest: &digest::Sha256Digest,
    uncompressed_digest: &digest::Sha256Digest,
    image_fetcher: &fstardock::ImageFetcherProxy,
) -> Result<NamedTempFile, Error> {
    let response = image_fetcher.fetch_blob(compressed_digest.as_str()).await?
        .ok_or_else(|| anyhow::anyhow!("Client failed to fetch blob"))?;

    let mut tmpfile = NamedTempFile::new_in(blobs_dir).expect("Failed to create temporary file");

    info!(
        "Downloading and uncompressing blob {} into temporary file {}",
        compressed_digest.as_str(),
        tmpfile.path().display(),
    );

    // Uncompress response into tmpfile + compute actual digests
    let mut socket = fasync::Socket::from_socket(response)?;
    let mut buffer_in = vec![0; READ_BUFFER_SIZE];
    let mut actual_compressed_digest = sha2::Sha256::new();
    let mut actual_uncompressed_digest = sha2::Sha256::new();
    let mut decoder = flate2::write::GzDecoder::new(Vec::new());
    loop {
        let nbytes = socket.read(&mut buffer_in).await?;
        if nbytes == 0 {
            break;
        } else {
            // Push compressed data...
            actual_compressed_digest.update(&buffer_in[..nbytes]);
            decoder.write_all(&buffer_in[..nbytes])?;

            // ...and pull uncompressed data
            let buffer_out = decoder.get_mut();
            actual_uncompressed_digest.update(&buffer_out[..]);
            tmpfile.write_all(&buffer_out[..])?;
            buffer_out.clear();
        }
    }

    let final_buffer_out = decoder.finish()?;
    actual_uncompressed_digest.update(&final_buffer_out[..]);
    tmpfile.write_all(&final_buffer_out[..])?;

    if hex::encode(actual_compressed_digest.finalize()) != compressed_digest.as_str() {
        anyhow::bail!("Compressed digest mismatch");
    }

    if hex::encode(actual_uncompressed_digest.finalize()) != uncompressed_digest.as_str() {
        anyhow::bail!("Uncompressed digest mismatch");
    }

    Ok(tmpfile)
}

fn read_json_from_file<T: serde::de::DeserializeOwned, F: Read + Seek>(
    file: &mut F,
) -> Result<T, Error> {
    // FIXME: this reads the file into an unbounded buffer, potentially exhausting this
    // process' memory
    let mut data = Vec::new();
    file.rewind().expect("Failed to rewind file");
    file.read_to_end(&mut data).expect("Failed to read file");

    serde_json::from_slice::<T>(&data).context("Failed to deserialize")
}
