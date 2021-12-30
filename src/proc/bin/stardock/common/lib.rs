// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use lazy_static::lazy_static;

pub mod digest;
pub mod image_reference;

lazy_static! {
    pub static ref DOCKERHUB: image_reference::RegistryReference =
        "registry.hub.docker.com:443".parse().unwrap();
}

pub fn canonicalize_image_name(
    registry_reference: &image_reference::RegistryReference,
    image_name: &str,
) -> String {
    if *registry_reference == *DOCKERHUB && !image_name.contains('/') {
        format!("library/{}", image_name)
    } else {
        image_name.to_string()
    }
}

pub fn format_registry_url(
    registry_reference: &image_reference::RegistryReference,
) -> String {
    let image_reference::RegistryReference { hostname, port } = registry_reference;
    match port {
        80 => format!("http://{}", hostname),
        443 => format!("https://{}", hostname),
        _ => format!("http://{}:{}", hostname, port),
    }
}
