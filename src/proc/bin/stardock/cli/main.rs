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

// These are hardcoded at the moment. Maybe someday we will support other registries
static REGISTRY_URL: &str = "https://registry.hub.docker.com";
static REGISTRY_IMAGE_PREFIX: &str = "library/";

fn app<'a, 'b>() -> App<'a, 'b> {
    App::new("stardock")
        .about("Tool to manage starnix containers")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("pull")
            .about("Download an image from Docker Hub")
            .arg(Arg::with_name("IMAGE")
                .help("Image reference, format: NAME[:TAG|@sha256:DIGEST]")
                .required(true)
                .takes_value(true),
            ),
        )
}

/// Start an ImageFetcher server that can fetch the requested image and return its client end.
///
/// This function also returns a future that becomes ready when the client end is closed.
fn make_fetcher(
    image_reference: &image_reference::ImageReference,
) -> Option<(ClientEnd<fstardock::ImageFetcherMarker>, Pin<Box<impl futures::Future>>)> {
    let (image_name, image_reference) = match image_reference {
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

    let base_url = format!("{}/v2/{}{}", REGISTRY_URL, REGISTRY_IMAGE_PREFIX, image_name);
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

async fn do_pull(
    manager: &fstardock::ManagerProxy,
    image: &str,
) -> Result<(), Error> {
    let image_reference = image.parse::<image_reference::ImageReference>()?;

    if let Some((fetcher_client_end, fetcher_done_fut)) = make_fetcher(&image_reference) {
        let open_image_fut = manager.open_image(None, Some(fetcher_client_end));

        // Serve fetcher and collect result
        let (open_image_result, _) = futures::join!(open_image_fut, fetcher_done_fut);

        if let Some(_image) = open_image_result? {
            println!("Success!"); // TODO: print image ID instead
        } else {
            anyhow::bail!("Failed to pull the requested image");
        }
    } else {
        anyhow::bail!("Cannot pull image by ID");
    }

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
        (_, _) => {
            // clap never returns invalid subcommands
            unreachable!()
        }
    }
}
