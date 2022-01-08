// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context as _, Error};
use fidl::endpoints::{create_proxy, ClientEnd, Proxy};
use fidl::HandleBased;
use fidl_fuchsia_component as fcomponent;
use fidl_fuchsia_component_decl as fdecl;
use fidl_fuchsia_data as fdata;
use fidl_fuchsia_io as fio;
use fidl_fuchsia_mem as fmem;
use fidl_fuchsia_process as fprocess;
use fidl_fuchsia_starnix_developer as fstardev;
use fidl_fuchsia_sys2 as fsys;
use fuchsia_component::client::connect_to_protocol;
use fuchsia_runtime::{HandleInfo, HandleType};
use itertools::Itertools;
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
    container_dir: Box<Path>,
    run_mutex: futures::lock::Mutex<()>,
}

#[derive(Debug)]
pub struct ContainerRegistry {
    containers_dir: Box<Path>, // where containers are stored
    containers: HashMap<digest::Sha256Digest, Rc<Container>>,
}

impl Container {
    fn new(
        id: &digest::Sha256Digest,
        image: Rc<image::Image>,
        container_dir: Box<Path>,
    ) -> Container {
        Container { id: id.clone(), image, container_dir, run_mutex: futures::lock::Mutex::new(()) }
    }

    pub fn id(&self) -> &digest::Sha256Digest {
        &self.id
    }

    pub fn image_id(&self) -> &digest::Sha256Digest {
        self.image.id()
    }

    pub fn build_url(&self) -> String {
        format!("stardock://{}", self.id.as_str())
    }

    pub fn build_component(&self) -> fsys::Component {
        let layers = self.image.layers();
        let layer_digests: Vec<&str> =
            layers.iter().map(|layer| layer.digest().as_str()).collect();

        let url = self.build_url();
        let package_dir = io_util::directory::open_in_namespace(
            self.container_dir.to_str().expect("container_dir contains invalid characters"),
            fio::OPEN_RIGHT_READABLE,
        ).unwrap().into_channel().unwrap().into_zx_channel();

        let program_info = vec![
            fdata::DictionaryEntry {
                key: "binary".to_string(),
                value: Some(Box::new(fdata::DictionaryValue::Str("/bin/sh".to_string()))),
            },
            fdata::DictionaryEntry {
                key: "args".to_string(),
                value: Some(Box::new(fdata::DictionaryValue::StrVec(vec![
                    "-i".to_string(),
                ]))),
            },
            fdata::DictionaryEntry {
                key: "environ".to_string(),
                value: Some(Box::new(fdata::DictionaryValue::StrVec(self.image.env().to_vec()))),
            },
            fdata::DictionaryEntry {
                key: "mounts".to_string(),
                value: Some(Box::new(fdata::DictionaryValue::StrVec(vec![
                    format!("/:tarfs:{}", layer_digests.join(":")),
                    "/dev:devfs".to_string(),
                    "/tmp:tmpfs".to_string(),
                    "/proc:proc".to_string(),
                ]))),
            },
            fdata::DictionaryEntry {
                key: "user".to_string(),
                value: Some(Box::new(fdata::DictionaryValue::Str("root:x:0:0".to_string()))),
            },
        ];

        let mut decl = fdecl::Component {
            program: Some(fdecl::Program {
                runner: Some("starnix".to_string()),
                info: Some(fdata::Dictionary {
                    entries: Some(program_info),
                    ..fdata::Dictionary::EMPTY
                }),
                ..fdecl::Program::EMPTY
            }),
            ..fdecl::Component::EMPTY
        };

        let package = fsys::Package {
            package_url: Some(url.clone()),
            package_dir: Some(ClientEnd::from(package_dir)),
            ..fsys::Package::EMPTY
        };

        fsys::Component {
            resolved_url: Some(url),
            decl: Some(fmem::Data::Bytes(fidl::encoding::encode_persistent(&mut decl).unwrap())),
            package: Some(package),
            ..fsys::Component::EMPTY
        }
    }

    pub async fn run(
        &self,
        stdin: fidl::Handle,
        stdout: fidl::Handle,
        stderr: fidl::Handle,
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
                    handle: stdin,
                    id: HandleInfo::new(HandleType::FileDescriptor, 0).as_raw(),
                },
                fprocess::HandleInfo {
                    handle: stdout,
                    id: HandleInfo::new(HandleType::FileDescriptor, 1).as_raw(),
                },
                fprocess::HandleInfo {
                    handle: stderr,
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
            url: Some(self.build_url()),
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
        for layer in image.layers().iter().unique_by(|v| v.digest()) {
            layer.link_at(&container_dir);
        }

        let result = Rc::new(Container::new(&id, image, container_dir.into_boxed_path()));
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
