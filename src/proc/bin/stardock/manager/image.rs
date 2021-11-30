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
use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::rc::Rc;
use tempfile::NamedTempFile;

use crate::serde_types;

const READ_BUFFER_SIZE: usize = 4096;

#[derive(Debug)]
pub struct Image {
    config_blob: Blob,
    layers: Vec<Rc<Blob>>,
}

#[derive(Debug)]
pub struct Blob {
    digest: digest::Sha256Digest,
    file_path: Box<Path>,
}

#[derive(Debug)]
pub struct ImageRegistry {
    blobs_dir: Box<Path>, // where blobs are stored
    blobs: HashMap<digest::Sha256Digest, BlobTypeAndData>,
}

#[derive(Debug)]
enum BlobTypeAndData {
    Image(Rc<Image>),
    Layer(Rc<Blob>),
}

#[derive(Debug)]
enum NewLayerData {
    PersistentFile(Rc<Blob>),
    TemporaryFile(NamedTempFile),
}

impl Image {
    pub fn id(&self) -> &digest::Sha256Digest {
        &self.config_blob.digest
    }

    pub fn layers(&self) -> &[Rc<Blob>] {
        &self.layers
    }
}

impl Blob {
    pub fn digest(&self) -> &digest::Sha256Digest {
        &self.digest
    }

    pub fn link_at(&self, dest_dir: &Path) {
        let mut dest_path = dest_dir.to_path_buf();
        dest_path.push(self.digest.as_str());

        std::fs::hard_link(self.file_path.to_owned(), dest_path)
            .expect("Failed to create hard link to blob");
    }
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

        let result = ImageRegistry {
            blobs_dir: blobs_dir.into_boxed_path(),
            blobs: HashMap::new(), // TODO: load from storage
        };

        Ok(result)
    }

    /// Download the manifest (and, if necessary, the image blobs) and return an Image instance.
    ///
    /// Note: image_registry is never kept borrowed across an await
    pub async fn fetch_image(
        image_registry: &RefCell<ImageRegistry>,
        image_fetcher: &fstardock::ImageFetcherProxy,
        expected_manifest_digest: Option<&digest::Sha256Digest>,
    ) -> Result<Rc<Image>, Error> {
        // Create our copy of the blobs_dir to avoid keeping the image_registry borrowed while
        // waiting
        let blobs_dir = image_registry.borrow().blobs_dir.to_owned();

        // Download and parse manifest JSON blob
        let manifest = download_manifest(&image_fetcher, expected_manifest_digest)
            .await.context("Failed to fetch manifest")?;
        info!("Fetched manifest {:?}", manifest);

        // Download and parse image JSON blob, unless it is already present in our registry
        let config_digest = &manifest.config.digest;
        let mut config_tmpfile = match image_registry.borrow().blobs.get(&config_digest) {
            Some(BlobTypeAndData::Image(image)) => {
                // already present: we can simply return the existing image
                info!("Image {} is already present", config_digest.as_str());
                return Ok(Rc::clone(image));
            }
            Some(BlobTypeAndData::Layer(_)) => {
                // digest is already present as a layer (very unlikely): type mismatch
                anyhow::bail!(
                    "Image {} is already present as a layer",
                    config_digest.as_str(),
                );
            }
            None => {
                // digest is not present in our registry: download it
                download_blob(
                    &blobs_dir,
                    &config_digest,
                    &image_fetcher
                ).await.context("Failed to fetch image configuration")?
            }
        };

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
        let mut new_layers = Vec::with_capacity(config_layers.len());
        for (
            serde_types::ManifestV2Layer { digest: compressed_digest, .. },
            uncompressed_digest,
        ) in manifest.layers.into_iter().zip(config_layers.into_iter()) {
            let new_layer_data = match image_registry.borrow().blobs.get(&uncompressed_digest) {
                Some(BlobTypeAndData::Image(_)) => {
                    // digest is already present as an image (very unlikely): type mismatch
                    anyhow::bail!(
                        "Layer {} is already present as an image",
                        uncompressed_digest.as_str(),
                    );
                }
                Some(BlobTypeAndData::Layer(blob)) => {
                    // layer is already present
                    info!("Layer {} is already present", uncompressed_digest.as_str());
                    NewLayerData::PersistentFile(Rc::clone(blob))
                }
                None => {
                    // download it
                    let tmpfile = download_compressed_blob(
                        &blobs_dir,
                        &compressed_digest,
                        &uncompressed_digest,
                        &image_fetcher,
                    ).await.context("Failed to fetch layer")?;
                    NewLayerData::TemporaryFile(tmpfile)
                }
            };

            new_layers.push((uncompressed_digest, new_layer_data));
        }

        // Make the downloaded image persistent. Note that insert_image will re-check whether each
        // blob that we are trying to insert is already present or not; this is necessary because
        // this is an async function and another client might have downloaded and inserted blobs
        // since our past check. Conversely, insert_image is not async and it can check atomically.
        image_registry.borrow_mut().insert_image(
            (config_digest, config_tmpfile),
            new_layers,
        )
    }

    /// Insert a new image into the registry and return an Image instance.
    ///
    /// If the image is already present, a reference to the existing Image will be returned;
    /// otherwise, a new Image will be instanced. If one or more layers are already present, they
    /// will be shared with the new image.
    fn insert_image(
        &mut self,
        image: (&digest::Sha256Digest, NamedTempFile),
        layers: Vec<(&digest::Sha256Digest, NewLayerData)>,
    ) -> Result<Rc<Image>, Error> {
        // If the image is already present, we can simply return it
        let (image_digest, image_tmpfile) = image;
        if let Some(value) = self.blobs.get(&image_digest) {
            if let BlobTypeAndData::Image(image) = value {
                // image is already present
                return Ok(Rc::clone(image));
            } else {
                // digest type mismatch
                anyhow::bail!("Image {} is already present as a layer", image_digest.as_str());
            }
        }

        // If we are here, it means we are going to insert the new image. Let us check that we are
        // not going to re-insert layers that are already present, and persist temporary files with
        // new layers
        let mut layers_digests = Vec::with_capacity(layers.len());
        let mut layers_refs = Vec::with_capacity(layers.len());
        for (layer_digest, new_layer_data) in layers {
            let layer_ref = match self.blobs.get(&layer_digest) {
                Some(BlobTypeAndData::Image(_)) => {
                    // digest type mismatch
                    anyhow::bail!("Layer {} is already present as an image", layer_digest.as_str());
                }
                Some(BlobTypeAndData::Layer(blob)) => {
                    // layer is already present
                    Rc::clone(blob)
                }
                None => {
                    // layer is not present in our registry: create it and insert it
                    match new_layer_data {
                        NewLayerData::PersistentFile(blob) =>
                            blob,
                        NewLayerData::TemporaryFile(tmpfile) =>
                            Rc::new(self.persist_blob(layer_digest, tmpfile)),
                    }
                }
            };

            layers_digests.push(layer_digest);
            layers_refs.push(layer_ref);
        }

        // Commit the new image into self.blobs
        for (layer_digest, layer_ref) in layers_digests.into_iter().zip(layers_refs.iter()) {
            self.blobs.insert(layer_digest.clone(), BlobTypeAndData::Layer(Rc::clone(layer_ref)));
        }

        let image_ref = Rc::new(Image {
            config_blob: self.persist_blob(image_digest, image_tmpfile),
            layers: layers_refs,
        });

        self.blobs.insert(image_digest.clone(), BlobTypeAndData::Image(Rc::clone(&image_ref)));
        info!(
            "Inserted image {:?} {:?} {:?}",
            image_ref.id(),
            image_ref.config_blob,
            image_ref.layers,
        );

        Ok(image_ref)
    }

    /// Given a temporary file and its digest, store it as a persistent file within blobs_dir.
    fn persist_blob(&self, digest: &digest::Sha256Digest, tmpfile: NamedTempFile) -> Blob {
        // We always download files in blobs_dir (so that they are in the same filesystem as
        // persistent storage)
        assert_eq!(*tmpfile.path().parent().expect("Invalid temporary file path"), *self.blobs_dir);

        let tmppath = tmpfile.path().to_owned();
        let newpath = self.blobs_dir.join(digest.as_str());

        if let Err(e) = tmpfile.persist(newpath.to_owned()) {
            panic!(
                "Failed to persist temporary file {} as {}: {}",
                tmppath.display(),
                newpath.display(),
                e.error,
            );
        }

        info!("Persisted temporary file {} as {}", tmppath.display(), newpath.display());
        Blob { digest: digest.clone(), file_path: newpath.into_boxed_path() }
    }
}

/// Download, (optionally) verify and parse a manifest.
async fn download_manifest(
    image_fetcher: &fstardock::ImageFetcherProxy,
    expected_digest: Option<&digest::Sha256Digest>,
) -> Result<serde_types::ManifestV2, Error> {
    let response = image_fetcher.fetch_manifest().await?
        .ok_or_else(|| anyhow::anyhow!("Client failed to fetch manifest"))?;

    let mut data = Vec::new();
    // FIXME: this reads the socket into an unbounded buffer, potentially exhausting this
    // process' memory
    fasync::Socket::from_socket(response)?.read_to_end(&mut data).await?;

    let manifest = serde_json::from_slice::<serde_types::ManifestV2>(&data)?;

    if let Some(expected_digest) = expected_digest {
        let actual_digest = hex::encode(sha2::Sha256::digest(&data))
            .parse::<digest::Sha256Digest>().unwrap();

        if actual_digest != *expected_digest {
            anyhow::bail!("Manifest digest mismatch");
        }
    }

    Ok(manifest)
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
