// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context as _, Error};
use fidl_fuchsia_stardock as fstardock;
use fuchsia_async as fasync;
use fuchsia_component::client::connect_to_protocol;

#[fasync::run_singlethreaded]
async fn main() -> Result<(), Error> {
    let manager = connect_to_protocol::<fstardock::ManagerMarker>()
        .context("Failed to connect to stardock service")?;

    println!("Hello {}", manager.hello("world").await?);

    Ok(())
}
