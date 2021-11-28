// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use log::info;
use rand::Rng;
use stardock_common::digest;
use std::collections::HashMap;
use std::rc::Rc;

use crate::image;

#[derive(Debug)]
pub struct Container {
    id: digest::Sha256Digest,
    image: Rc<image::Image>,
}

#[derive(Debug)]
pub struct ContainerRegistry {
    containers: HashMap<digest::Sha256Digest, Rc<Container>>,
}

impl Container {
    pub fn id(&self) -> &digest::Sha256Digest {
        &self.id
    }

    pub fn image_id(&self) -> &digest::Sha256Digest {
        self.image.id()
    }
}

impl ContainerRegistry {
    pub fn new() -> ContainerRegistry {
        ContainerRegistry {
            containers: HashMap::new(), // TODO: load from storage
        }
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

        let result = Rc::new(Container { id: id.clone(), image });
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
