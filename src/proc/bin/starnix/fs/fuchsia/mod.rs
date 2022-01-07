// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use fuchsia_zircon as zx;

use crate::fs::FileHandle;
use crate::task::Kernel;
use crate::types::*;

mod remote;
mod syslog;
mod timer;

pub use remote::*;
pub use syslog::*;
pub use timer::*;

/// Create a non-seekable FileHandle from a zxio-compatible handle.
pub fn create_file_from_handle(kern: &Kernel, handle: zx::Handle) -> Result<FileHandle, Errno> {
    create_fuchsia_pipe(kern, handle)
}

#[cfg(test)]
mod test {
    use super::*;
    use fuchsia_zircon::HandleBased;

    #[test]
    fn test_create_from_invalid_handle() {
        assert!(create_file_from_handle(&Kernel::new_for_testing(), zx::Handle::invalid()).is_err());
    }

    #[test]
    fn test_create_pipe_from_handle() {
        let kern = Kernel::new_for_testing();
        let (left_handle, right_handle) =
            zx::Socket::create(zx::SocketOpts::STREAM).expect("failed to create socket");
        create_file_from_handle(&kern, left_handle.into_handle())
            .expect("failed to create left FileHandle");
        create_file_from_handle(&kern, right_handle.into_handle())
            .expect("failed to create right FileHandle");
    }
}
