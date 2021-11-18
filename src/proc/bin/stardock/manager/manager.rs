// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_stardock as fstardock;
use futures::TryStreamExt;
use log::{error, info};
use stardock_common::image_reference;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use crate::image;

pub struct Manager {
    image_registry: RefCell<image::ImageRegistry>,
}

impl Manager {
    pub fn new(storage_path: &Path) -> Result<Rc<Manager>, Error> {
        if !storage_path.is_dir() {
            anyhow::bail!("Storage directory {} does not exist", storage_path.display());
        }

        let manager =
            Manager { image_registry: RefCell::new(image::ImageRegistry::new(&storage_path)?) };

        Ok(Rc::new(manager))
    }

    async fn open_image(
        &self,
        image_reference: Option<image_reference::ImageReference>,
        image_fetcher: Option<fstardock::ImageFetcherProxy>,
    ) -> Option<Rc<image::Image>> {
        // Searching in the local registry is not implemented yet: the image reference value is
        // currently ignored
        std::mem::drop(image_reference);

        // If an image_fetcher was given by the client, try to fetch the image
        if let Some(image_fetcher) = image_fetcher {
            let result = image::ImageRegistry::fetch_image(
                &self.image_registry,
                &image_fetcher,
            ).await;

            if let Err(err) = result {
                error!("Failed to fetch image: {}", err);
            } else {
                info!("Image was fetched correctly, but nothing else is implemented yet");
            }
        }

        return None;
    }

    pub async fn handle_client(
        self: Rc<Manager>,
        mut stream: fstardock::ManagerRequestStream,
    ) -> Result<(), Error> {
        while let Some(request) = stream.try_next().await? {
            match request {
                fstardock::ManagerRequest::OpenImage { image_reference, image_fetcher, responder } => {
                    // Convert from FIDL ImageReference to image_reference::ImageReference
                    let image_reference = match image_reference {
                        Some(boxed) => Some(image_reference::ImageReference::from_fidl(boxed.borrow())?),
                        None => None,
                    };

                    // Wrap image_fetcher as an ImageFetcherProxy
                    let image_fetcher = match image_fetcher {
                        Some(client) => Some(client.into_proxy()?),
                        None => None,
                    };

                    // Fetch/open image and return a handle on success
                    if let Some(_image) = self.open_image(image_reference, image_fetcher).await {
                        anyhow::bail!("Returning an image handle is not implemented yet");
                    } else {
                        responder.send(None)?;
                    }
                }
            }
        }

        Ok(())
    }
}
