// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use fuchsia_zircon::{Duration, DurationNum};

// TODO(fxbug.dev/98163): Once all v1 tests are migrated, remove v1 harnesses and subsequently
// remove the `_v2` suffix for the v2 harness mods.
pub mod access;
pub mod access_v2;
pub mod bootstrap;
pub mod bootstrap_v2;
pub mod core_realm;
pub mod emulator;
pub mod host_driver;
pub mod host_watcher;
pub mod host_watcher_v2;
pub mod inspect_v2;
pub mod low_energy_central_v2;
pub mod low_energy_peripheral_v2;
pub mod profile_v2;

// Use a framework-wide timeout of 4 minutes.
//
// This time is expected to be:
//   a) sufficient to avoid flakes due to infra or resource contention, except in many standard
//      deviations of unlikeliness
//   b) short enough to still provide useful feedback in those cases where asynchronous operations
//      fail
//   c) short enough to fail before the overall infra-imposed test timeout (currently 5 minutes),
//      so that we can produce specific test-relevant information in the case of failure.
const TIMEOUT_SECONDS: i64 = 4 * 60;

pub fn timeout_duration() -> Duration {
    TIMEOUT_SECONDS.seconds()
}
