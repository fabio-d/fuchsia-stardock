// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl::endpoints::{create_request_stream, ClientEnd};
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use futures::TryStreamExt;
use log::error;
use stardock_common::{digest, image_reference};
use std::borrow::Borrow;
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use crate::container;
use crate::image;

pub struct Manager {
    image_registry: RefCell<image::ImageRegistry>,
    container_registry: RefCell<container::ContainerRegistry>,
}

impl Manager {
    pub fn new(storage_path: &Path) -> Result<Rc<Manager>, Error> {
        if !storage_path.is_dir() {
            anyhow::bail!("Storage directory {} does not exist", storage_path.display());
        }

        let manager = Manager {
            image_registry: RefCell::new(image::ImageRegistry::new(&storage_path)?),
            container_registry: RefCell::new(container::ContainerRegistry::new(&storage_path)?),
        };

        Ok(Rc::new(manager))
    }

    async fn open_image(
        &self,
        image_reference: Option<image_reference::ImageReference>,
        image_fetcher: Option<fstardock::ImageFetcherProxy>,
    ) -> Option<Rc<image::Image>> {
        // Searching in the local registry is not implemented yet; therefore, the image reference
        // value is ignored unless it is a manifest digest, which can already be used to validate
        // the manifest to be downloaded
        let expected_manifest_digest = match &image_reference {
            Some(image_reference::ImageReference::ByNameAndDigest(_, digest)) => Some(digest),
            _ => None,
        };

        // If an image_fetcher was given by the client, try to fetch the image
        if let Some(image_fetcher) = image_fetcher {
            let result = image::ImageRegistry::fetch_image(
                &self.image_registry,
                &image_fetcher,
                expected_manifest_digest,
            ).await;

            match result {
                Ok(image) => return Some(image),
                Err(err) => error!("Failed to fetch image: {}", err),
            }
        }

        return None;
    }

    fn make_container_handle(
        self: &Rc<Manager>,
        container: Rc<container::Container>,
    ) -> ClientEnd<fstardock::ContainerMarker> {
        let (client, request_stream) =
            create_request_stream::<fstardock::ContainerMarker>().unwrap();

        let manager = Rc::clone(&self);
        fasync::Task::local(async move {
            if let Err(e) = manager.handle_container(container, request_stream).await {
                error!("Manager::handle_container error: {:?}", e);
            }
        })
        .detach();

        client
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
                    if let Some(image) = self.open_image(image_reference, image_fetcher).await {
                        let (client, request_stream) =
                            create_request_stream::<fstardock::ImageMarker>().unwrap();

                        let manager = Rc::clone(&self);
                        fasync::Task::local(async move {
                            if let Err(e) = manager.handle_image(image, request_stream).await {
                                error!("Manager::handle_image error: {:?}", e);
                            }
                        })
                        .detach();

                        responder.send(Some(client))?;
                    } else {
                        responder.send(None)?;
                    }
                }
                fstardock::ManagerRequest::OpenContainer { container_id, responder } => {
                    let container_id = container_id.parse::<digest::Sha256Digest>()?;
                    let container = self.container_registry.borrow().open_container(&container_id);

                    if let Some(container) = container {
                        let handle = self.make_container_handle(container);
                        responder.send(Some(handle))?;
                    } else {
                        responder.send(None)?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_image(
        self: Rc<Manager>,
        image: Rc<image::Image>,
        mut stream: fstardock::ImageRequestStream,
    ) -> Result<(), Error> {
        while let Some(request) = stream.try_next().await? {
            match request {
                fstardock::ImageRequest::GetImageId { responder } => {
                    responder.send(&image.id().as_str())?;
                }
                fstardock::ImageRequest::CreateContainer { responder } => {
                    let container =
                        self.container_registry.borrow_mut().create_container(Rc::clone(&image));

                    responder.send(self.make_container_handle(container))?;
                }
            }
        }

        Ok(())
    }

    async fn handle_container(
        self: Rc<Manager>,
        container: Rc<container::Container>,
        mut stream: fstardock::ContainerRequestStream,
    ) -> Result<(), Error> {
        while let Some(request) = stream.try_next().await? {
            match request {
                fstardock::ContainerRequest::GetContainerId { responder } => {
                    responder.send(&container.id().as_str())?;
                }
                fstardock::ContainerRequest::GetImageId { responder } => {
                    responder.send(&container.image_id().as_str())?;
                }
                fstardock::ContainerRequest::Run { stdin, stdout, stderr, responder } => {
                    let container = Rc::clone(&container);
                    fasync::Task::local(async move {
                        if let Err(e) = container.run(stdin, stdout, stderr).await {
                            error!("Container::run error: {:?}", e);
                        }

                        let _ = responder.send();
                    })
                    .detach();
                }
            }
        }

        Ok(())
    }
}
