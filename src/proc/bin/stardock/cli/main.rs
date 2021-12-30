// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context as _, Error};
use clap::{App, AppSettings, Arg, SubCommand};
use fidl::endpoints::{create_request_stream, ClientEnd};
use fidl_fuchsia_net_http as fnethttp;
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use fuchsia_component::client::connect_to_protocol;
use stardock_common::image_reference;
use std::pin::Pin;

mod image_fetcher;
mod stdio_forwarder;

fn app<'a, 'b>() -> App<'a, 'b> {
    App::new("stardock")
        .about("Tool to manage starnix containers")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("pull")
            .about("Download an image from a public registry (default: Docker Hub)")
            .arg(Arg::with_name("IMAGE")
                .help("Image reference, format: [REGISTRY/]NAME[:TAG|@sha256:DIGEST]")
                .required(true)
                .takes_value(true),
            ),
        )
        .subcommand(SubCommand::with_name("create")
            .about("Create a container")
            .arg(Arg::with_name("IMAGE")
                .help("Image reference, format: IMAGE_ID or [REGISTRY/]NAME[:TAG|@sha256:DIGEST]")
                .required(true)
                .takes_value(true),
            ),
        )
        .subcommand(SubCommand::with_name("start")
            .about("Start a container")
            .arg(Arg::with_name("CONTAINER")
                .help("Container reference, format: CONTAINER_ID or NAME")
                .required(true)
                .takes_value(true),
            ),
        )
        .subcommand(SubCommand::with_name("run")
            .about("Create and start a container")
            .arg(Arg::with_name("IMAGE")
                .help("Image reference, format: IMAGE_ID or [REGISTRY/]NAME[:TAG|@sha256:DIGEST]")
                .required(true)
                .takes_value(true),
            ),
        )
}

/// Start an ImageFetcher server that can fetch the requested image and return its client end.
///
/// This function also returns a future that becomes ready when the client end is closed.
fn make_fetcher(
    registry_and_image_reference: &image_reference::RegistryAndImageReference,
) -> Option<(ClientEnd<fstardock::ImageFetcherMarker>, Pin<Box<impl futures::Future>>)> {
    // If no registry reference is provided, select the default one.
    let registry_reference = match &registry_and_image_reference.0 {
        Some(v) => v.clone(),
        None => stardock_common::DOCKERHUB.clone(),
    };

    let (image_name, image_reference) = match &registry_and_image_reference.1 {
        image_reference::ImageReference::ByNameAndTag(name, tag) =>
            (name.clone(), tag.clone()),

        image_reference::ImageReference::ByNameAndDigest(name, digest) =>
            (name.clone(), format!("sha256:{}", digest.as_str())),

        image_reference::ImageReference::ByNameOrImageId(text, ambiguity_type) =>
            match ambiguity_type {
                image_reference::ImageReferenceAmbiguityType::NameOnly |
                image_reference::ImageReferenceAmbiguityType::NameOrImageId =>
                    (text.clone(), "latest".to_string()),

                image_reference::ImageReferenceAmbiguityType::ImageIdOnly =>
                    return None, // Image ID cannot be used to locate images in a remote registry
            }
    };

    let http_loader =
        connect_to_protocol::<fnethttp::LoaderMarker>().expect("failed to obtain HTTP loader");

    let registry_url = stardock_common::format_registry_url(&registry_reference);
    let canonical_name = stardock_common::canonicalize_image_name(&registry_reference, &image_name);
    let base_url = format!("{}/v2/{}", registry_url, canonical_name);
    let mut fetcher = image_fetcher::ImageFetcher::new(http_loader, &base_url, &image_reference);

    let (client, request_stream) =
        create_request_stream::<fstardock::ImageFetcherMarker>().unwrap();

    let done_fut = Box::pin(async move {
        if let Err(e) = fetcher.handle_client(request_stream).await {
            eprintln!("ImageFetcher::handle_client error: {:?}", e);
        }
    });

    return Some((client, done_fut));
}

/// Get an image handle, fetching the image from the remote registry if it is not present.
async fn open_image(
    manager: &fstardock::ManagerProxy,
    image: &str,
) -> Result<fstardock::ImageProxy, Error> {
    let reference = image.parse::<image_reference::RegistryAndImageReference>()?;

    let open_image_result =
        if let Some((fetcher_client_end, fetcher_done_fut)) = make_fetcher(&reference) {
            let open_image_fut =
                manager.open_image(Some(&mut reference.into()), Some(fetcher_client_end));

            // Serve fetcher and collect result
            futures::join!(open_image_fut, fetcher_done_fut).0
        } else {
            manager.open_image(Some(&mut reference.into()), None).await
        };

    if let Some(image) = open_image_result? {
        Ok(image.into_proxy()?)
    } else {
        anyhow::bail!("Failed to find the requested image");
    }
}

/// Create a new container backed by the requested image.
async fn create_container(
    manager: &fstardock::ManagerProxy,
    image: &str,
) -> Result<fstardock::ContainerProxy, Error> {
    let image = open_image(manager, image).await?;
    let container = image.create_container().await?.into_proxy()?;
    Ok(container)
}

/// Open the container identified by the given container reference string.
async fn open_container(
    manager: &fstardock::ManagerProxy,
    container: &str,
) -> Result<fstardock::ContainerProxy, Error> {
    match manager.open_container(&container).await? {
        Some(handle) => Ok(handle.into_proxy()?),
        None => anyhow::bail!("Failed to find the requested container"),
    }
}

async fn do_pull(
    manager: &fstardock::ManagerProxy,
    image: &str,
) -> Result<(), Error> {
    let reference = image.parse::<image_reference::RegistryAndImageReference>()?;

    if let Some((fetcher_client_end, fetcher_done_fut)) = make_fetcher(&reference) {
        // We do not propagate the requested image reference and, instead, set None because we
        // always want to attempt to (re)download the image, even if it already exists locally
        // (because a newer online version might be available). The only exception is when the user
        // requests a specific digest, which, by definition, cannot be modified online.
        let mut loose_reference_fidl = match &reference.1 {
            image_reference::ImageReference::ByNameAndDigest(_, _) =>
                Some(reference.into()),
            _ =>
                None,
        };

        let open_image_fut =
            manager.open_image(loose_reference_fidl.as_mut(), Some(fetcher_client_end));

        // Serve fetcher and collect result
        let (open_image_result, _) = futures::join!(open_image_fut, fetcher_done_fut);

        if let Some(image) = open_image_result? {
            // Print image ID
            println!("{}", image.into_proxy()?.get_image_id().await?);
        } else {
            anyhow::bail!("Failed to pull the requested image");
        }
    } else {
        anyhow::bail!("Cannot pull image by ID");
    }

    Ok(())
}

async fn do_create(
    manager: &fstardock::ManagerProxy,
    image: &str,
) -> Result<(), Error> {
    // Create new container
    let container = create_container(manager, image).await?;

    // Print container ID
    println!("{}", container.get_container_id().await?);

    Ok(())
}

async fn do_start(
    manager: &fstardock::ManagerProxy,
    container: &str,
) -> Result<(), Error> {
    // Open existing container
    let container = open_container(manager, container).await?;

    // Run it
    stdio_forwarder::run_container_with_stdio(&container).await?;

    Ok(())
}

async fn do_run(
    manager: &fstardock::ManagerProxy,
    image: &str,
) -> Result<(), Error> {
    // Create new container
    let container = create_container(manager, image).await?;

    // Run it
    stdio_forwarder::run_container_with_stdio(&container).await?;

    Ok(())
}

#[fasync::run_singlethreaded]
async fn main() -> Result<(), Error> {
    let args = app().get_matches();

    let manager = connect_to_protocol::<fstardock::ManagerMarker>()
        .context("Failed to connect to stardock service")?;

    match args.subcommand() {
        ("pull", Some(cmd)) => {
            do_pull(&manager, cmd.value_of("IMAGE").unwrap()).await
        }
        ("create", Some(cmd)) => {
            do_create(&manager, cmd.value_of("IMAGE").unwrap()).await
        }
        ("start", Some(cmd)) => {
            do_start(&manager, cmd.value_of("CONTAINER").unwrap()).await
        }
        ("run", Some(cmd)) => {
            do_run(&manager, cmd.value_of("IMAGE").unwrap()).await
        }
        (_, _) => {
            // clap never returns invalid subcommands
            unreachable!()
        }
    }
}
