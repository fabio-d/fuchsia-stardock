// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::*;
use crate::prelude::*;
use crate::spinel::*;
use futures::prelude::*;
use mock::*;

use lowpan_driver_common::Driver as _;

#[fasync::run_until_stalled(test)]
async fn test_spinel_lowpan_driver() {
    let (device_client, device_stream, ncp_task) = new_fake_spinel_pair();

    let driver = SpinelDriver::from(device_client);
    let driver_stream = driver.wrap_inbound_stream(device_stream);

    let app_task = async {
        for i in 1u8..32 {
            traceln!("app_task: Iteration {}", i);

            traceln!("app_task: Attempting a reset...");
            assert_eq!(driver.reset().await, Ok(()));
            traceln!("app_task: Did reset!");
        }
    };

    futures::select! {
        ret = driver_stream.try_for_each(|_|futures::future::ready(Ok(()))).fuse()
            => panic!("Driver stream error: {:?}", ret),
        ret = ncp_task.fuse()
            => panic!("NCP task error: {:?}", ret),
        _ = app_task.boxed_local().fuse() => (),
    }
}
