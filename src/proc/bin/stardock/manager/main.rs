// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fuchsia_async as fasync;
use fuchsia_component::server::ServiceFs;
use futures::StreamExt;
use log::{error, info};
use std::path::Path;
use std::rc::Rc;

mod container;
mod image;
mod manager;
mod serde_types;

#[fasync::run_singlethreaded]
async fn main() -> Result<(), Error> {
    diagnostics_log::init!(&[&"stardock-manager"]);
    info!("starting");

    let manager = manager::Manager::new(Path::new("/data"))?;
    let mut fs = ServiceFs::new_local();

    fs.dir("svc").add_fidl_service(|stream| {
        let manager = Rc::clone(&manager);

        fasync::Task::local(async move {
            if let Err(e) = manager.handle_client(stream).await {
                error!("Manager::handle_client error: {:?}", e);
            }
        })
        .detach();
    });

    fs.dir("svc").add_fidl_service(|stream| {
        let manager = Rc::clone(&manager);

        fasync::Task::local(async move {
            if let Err(e) = manager.handle_resolver(stream).await {
                error!("Manager::handle_resolver error: {:?}", e);
            }
        })
        .detach();
    });

    fs.take_and_serve_directory_handle()?;
    fs.collect::<()>().await;

    Ok(())
}
