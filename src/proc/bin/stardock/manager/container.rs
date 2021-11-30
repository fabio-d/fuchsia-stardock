// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context as _, Error};
use fidl::endpoints::{create_proxy, Proxy};
use fidl::HandleBased;
use fidl_fuchsia_component as fcomponent;
use fidl_fuchsia_component_decl as fdecl;
use fidl_fuchsia_process as fprocess;
use fidl_fuchsia_starnix_developer as fstardev;
use fuchsia_component::client::connect_to_protocol;
use fuchsia_runtime::{HandleInfo, HandleType};
use log::info;
use rand::Rng;
use stardock_common::digest;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use crate::image;

static CONTAINER_COLLECTION_NAME: &str = "container";

#[derive(Debug)]
pub struct Container {
    id: digest::Sha256Digest,
    image: Rc<image::Image>,
    run_mutex: futures::lock::Mutex<()>,
}

#[derive(Debug)]
pub struct ContainerRegistry {
    containers_dir: Box<Path>, // where containers are stored
    containers: HashMap<digest::Sha256Digest, Rc<Container>>,
}

impl Container {
    fn new(id: &digest::Sha256Digest, image: Rc<image::Image>) -> Container {
        Container { id: id.clone(), image, run_mutex: futures::lock::Mutex::new(()) }
    }

    pub fn id(&self) -> &digest::Sha256Digest {
        &self.id
    }

    pub fn image_id(&self) -> &digest::Sha256Digest {
        self.image.id()
    }

    pub async fn run(
        &self,
        stdin: fidl::Socket,
        stdout: fidl::Socket,
        stderr: fidl::Socket,
    ) -> Result<(), Error> {
        // Prevent multiple running instances of the same container
        let run_guard = self.run_mutex.try_lock();
        if run_guard.is_none() {
            anyhow::bail!("Container {} is already running", self.id.as_str());
        }

        let realm = connect_to_protocol::<fcomponent::RealmMarker>()
            .expect("failed to obtain Realm proxy");

        let (shell_controller, server) =
            create_proxy::<fstardev::ShellControllerMarker>().unwrap();

        let args = fcomponent::CreateChildArgs {
            numbered_handles: Some(vec![
                fprocess::HandleInfo {
                    handle: stdin.into_handle(),
                    id: HandleInfo::new(HandleType::FileDescriptor, 0).as_raw(),
                },
                fprocess::HandleInfo {
                    handle: stdout.into_handle(),
                    id: HandleInfo::new(HandleType::FileDescriptor, 1).as_raw(),
                },
                fprocess::HandleInfo {
                    handle: stderr.into_handle(),
                    id: HandleInfo::new(HandleType::FileDescriptor, 2).as_raw(),
                },
                fprocess::HandleInfo {
                    handle: server.into_channel().into_handle(),
                    id: HandleInfo::new(HandleType::User0, 0).as_raw(),
                },
            ]),
            ..fcomponent::CreateChildArgs::EMPTY
        };

        let child_decl = fdecl::Child {
            name: Some(self.id.as_str().to_string()),
            url: Some("fuchsia-pkg://fuchsia.com/hello-starnix#meta/hello_starnix.cm".to_string()),
            startup: Some(fdecl::StartupMode::Lazy),
            ..fdecl::Child::EMPTY
        };

        info!("Container {}: starting", self.id.as_str());
        let mut collection_ref =
            fdecl::CollectionRef { name: CONTAINER_COLLECTION_NAME.to_string() };
        realm.create_child(&mut collection_ref, child_decl, args).await?
            .map_err(|e| anyhow::anyhow!("failed to create child: {:?}", e))?;

        // Wait for starnix task to exit
        shell_controller.on_closed().await?;
        info!("Container {}: exited", self.id.as_str());

        Ok(())
    }
}

impl ContainerRegistry {
    pub fn new(storage_path: &Path) -> Result<ContainerRegistry, Error> {
        // Create "containers" subdirectory if it does not exist
        let mut containers_dir = storage_path.to_path_buf();
        containers_dir.push("containers");
        if !containers_dir.is_dir() {
            std::fs::create_dir(&containers_dir).context("Failed to create containers directory")?;
        }

        // TODO: remove orphan files (e.g. leftovers from a past crash)

        let result = ContainerRegistry {
            containers_dir: containers_dir.into_boxed_path(),
            containers: HashMap::new(), // TODO: load from storage
        };

        Ok(result)
    }

    pub fn create_container(
        &mut self,
        image: Rc<image::Image>,
    ) -> Rc<Container> {
        let id = {
            // generate random container ID
            let mut id_bytes: Vec<u8> = vec![0; 32];
            rand::thread_rng().fill(&mut id_bytes[..]);
            hex::encode(id_bytes).parse::<digest::Sha256Digest>().unwrap()
        };

        info!("Creating container {} from image {}", id.as_str(), image.id().as_str());

        // Create and populate container directory with hard links to the layer blobs
        let mut container_dir = self.containers_dir.to_path_buf();
        container_dir.push(id.as_str());
        std::fs::create_dir(&container_dir).expect("Failed to create container directory");
        for layer in image.layers() {
            layer.link_at(&container_dir);
        }

        let result = Rc::new(Container::new(&id, image));
        self.containers.insert(id, Rc::clone(&result));

        result
    }

    pub fn open_container(
        &self,
        id: &digest::Sha256Digest,
    ) -> Option<Rc<Container>> {
        self.containers.get(id).map(Rc::clone)
    }
}
