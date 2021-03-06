// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    fidl_fidl_examples_routing_echo as fecho, fidl_fuchsia_component as fcomponent,
    fidl_fuchsia_component_decl as fdecl, fidl_fuchsia_sys2 as fsys,
    files_async::readdir,
    fuchsia_component::client::connect_to_protocol_at_path,
    io_util::{open_directory_in_namespace, open_file_in_namespace},
    tracing::info,
};

pub async fn expect_dir_listing(path: &str, mut expected_listing: Vec<&str>) {
    info!("{} should contain {:?}", path, expected_listing);
    let dir_proxy = open_directory_in_namespace(path, io_util::OpenFlags::RIGHT_READABLE).unwrap();
    let actual_listing = readdir(&dir_proxy).await.unwrap();

    for actual_entry in &actual_listing {
        let index = expected_listing
            .iter()
            .position(|expected_entry| *expected_entry == actual_entry.name)
            .unwrap();
        expected_listing.remove(index);
    }

    assert_eq!(expected_listing.len(), 0);
}

pub async fn expect_dir_listing_with_optionals(
    path: &str,
    mut must_have: Vec<&str>,
    mut may_have: Vec<&str>,
) {
    info!("{} should contain {:?}", path, must_have);
    info!("{} may contain {:?}", path, may_have);
    let dir_proxy = open_directory_in_namespace(path, io_util::OpenFlags::RIGHT_READABLE).unwrap();
    let mut actual_listing = readdir(&dir_proxy).await.unwrap();

    actual_listing.retain(|actual_entry| {
        if let Some(index) =
            must_have.iter().position(|must_entry| *must_entry == actual_entry.name)
        {
            must_have.remove(index);
            return false;
        }
        if let Some(index) = may_have.iter().position(|may_entry| *may_entry == actual_entry.name) {
            may_have.remove(index);
            return false;
        }
        return true;
    });

    // All must_haves are present
    assert_eq!(must_have.len(), 0);
    // No actuals are unexpected
    assert_eq!(actual_listing.len(), 0);
}

pub async fn expect_file_content(path: &str, expected_file_content: &str) {
    info!("{} should contain \"{}\"", path, expected_file_content);
    let file_proxy = open_file_in_namespace(path, io_util::OpenFlags::RIGHT_READABLE).unwrap();
    let actual_file_content = io_util::read_file(&file_proxy).await.unwrap();
    assert_eq!(expected_file_content, actual_file_content);
}

pub async fn expect_echo_service(path: &str) {
    info!("{} should be an Echo service", path);
    let echo_proxy = connect_to_protocol_at_path::<fecho::EchoMarker>(path).unwrap();
    let result = echo_proxy.echo_string(Some("hippos")).await.unwrap().unwrap();
    assert_eq!(&result, "hippos");
}

pub async fn resolve_component(path: &str, relative_moniker: &str, expect_success: bool) {
    info!("Attempting to resolve {} from {}", relative_moniker, path);
    let lifecycle_controller_proxy =
        connect_to_protocol_at_path::<fsys::LifecycleControllerMarker>(path).unwrap();
    let result = lifecycle_controller_proxy.resolve(relative_moniker).await.unwrap();
    if expect_success {
        result.unwrap();
    } else {
        result.unwrap_err();
    }
}

pub async fn start_component(path: &str, relative_moniker: &str, expect_success: bool) {
    info!("Attempting to start {} from {}", relative_moniker, path);
    let lifecycle_controller_proxy =
        connect_to_protocol_at_path::<fsys::LifecycleControllerMarker>(path).unwrap();
    let result = lifecycle_controller_proxy.start(relative_moniker).await.unwrap();
    if expect_success {
        result.unwrap();
    } else {
        result.unwrap_err();
    }
}

pub async fn stop_component(path: &str, relative_moniker: &str, expect_success: bool) {
    info!("Attempting to stop {} from {}", relative_moniker, path);
    let lifecycle_controller_proxy =
        connect_to_protocol_at_path::<fsys::LifecycleControllerMarker>(path).unwrap();
    let result = lifecycle_controller_proxy.stop(relative_moniker, false).await.unwrap();
    if expect_success {
        result.unwrap();
    } else {
        result.unwrap_err();
    }
}

pub async fn create_component(
    path: &str,
    parent_moniker: &str,
    collection: &mut fdecl::CollectionRef,
    decl: fdecl::Child,
    expect_success: bool,
) {
    info!("Attempting to create {} from {}", decl.name.as_ref().unwrap(), path);
    let lifecycle_controller_proxy =
        connect_to_protocol_at_path::<fsys::LifecycleControllerMarker>(path).unwrap();
    let result = lifecycle_controller_proxy
        .create_child(parent_moniker, collection, decl, fcomponent::CreateChildArgs::EMPTY)
        .await
        .unwrap();
    if expect_success {
        result.unwrap();
    } else {
        result.unwrap_err();
    }
}

pub async fn destroy_child(
    path: &str,
    parent_moniker: &str,
    child: &mut fdecl::ChildRef,
    expect_success: bool,
) {
    info!("Attempting to destroy {} from {}", child.name, path);
    let lifecycle_controller_proxy =
        connect_to_protocol_at_path::<fsys::LifecycleControllerMarker>(path).unwrap();
    let result = lifecycle_controller_proxy.destroy_child(parent_moniker, child).await.unwrap();
    if expect_success {
        result.unwrap();
    } else {
        result.unwrap_err();
    }
}
