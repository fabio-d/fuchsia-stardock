// Copyright 2021 Fabio D'Urso. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fidl_fuchsia_stardock as fstardock;
use futures::TryStreamExt;
use log::info;
use std::rc::Rc;

pub struct Manager {}

impl Manager {
    pub fn new() -> Rc<Manager> {
        let manager = Manager {};
        Rc::new(manager)
    }

    pub async fn handle_client(
        self: Rc<Manager>,
        mut stream: fstardock::ManagerRequestStream,
    ) -> Result<(), Error> {
        while let Some(request) = stream.try_next().await? {
            match request {
                fstardock::ManagerRequest::Hello { text, responder } => {
                    info!("handle_client: Hello {:#?}", text);
                    responder.send(&text)?;
                }
            }
        }

        Ok(())
    }
}
