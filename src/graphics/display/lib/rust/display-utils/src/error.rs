// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    fidl_fuchsia_hardware_display::{ClientCompositionOp, ClientCompositionOpcode, ConfigResult},
    fuchsia_zircon as zx,
    futures::channel::mpsc,
    thiserror::Error,
};

use crate::{
    controller::VsyncEvent,
    types::{DisplayId, LayerId},
};

/// Library error type.
#[derive(Error, Debug)]
pub enum Error {
    /// Error encountered while connecting to a display-controller device via devfs.
    #[error("could not find a display-controller device")]
    DeviceNotFound,

    /// No displays were reported by the display driver when expected.
    #[error("device did not enumerate initial displays")]
    NoDisplays,

    /// Failed to enumerate display-controller devices via devfs.
    #[error("failed to watch files in device directory")]
    VfsWatcherError,

    /// A request handling task (such as one that owns a FIDL event stream that can only be
    /// started once) was already been initiated before.
    #[error("a singleton task was already initiated")]
    AlreadyRequested,

    /// Error while allocating shared sysmem buffers.
    #[error("sysmem buffer collection allocation failed")]
    BuffersNotAllocated,

    /// Error while establishing a connection to sysmem.
    #[error("error while setting up a sysmem connection")]
    SysmemConnection,

    /// Ran out of free client-assigned identifiers.
    #[error("ran out of identifiers")]
    IdsExhausted,

    /// Wrapper for errors from FIDL bindings.
    #[error("FIDL error: {0}")]
    FidlError(#[from] fidl::Error),

    /// Wrapper for system file I/O errors.
    #[error("OS I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Wrapper for errors from zircon syscalls.
    #[error("zircon error: {0}")]
    ZxError(#[from] zx::Status),

    /// Error that occurred while notifying vsync event listeners over an in-process async channel.
    #[error("failed to notify vsync: {0}")]
    CouldNotSendVsyncEvent(#[from] mpsc::TrySendError<VsyncEvent>),

    /// UTF-8 validation error.
    #[error("invalid UTF-8 string")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

/// Library Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// An error generated by `fuchsia.hardware.display.Controller.CheckConfig`.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failure due to an invalid configuration.
    #[error("invalid configuration - error_code: {error_code:#?}, actions: {actions:#?}")]
    Invalid {
        /// The reason for the failure.
        error_code: ConfigResult,

        /// Suggested actions that the client can take to resolve the failure.
        actions: Vec<ClientCompositionAction>,
    },

    /// Failure due to a FIDL transport error.
    #[error("FIDL channel error")]
    Fidl(#[from] fidl::Error),
}

/// Represents a suggested client composition action generated by the driver.
#[derive(Debug, Clone)]
pub struct ClientCompositionAction {
    /// The ID of the display that concerns the action.
    pub display_id: DisplayId,

    /// The ID of the layer that the action should be taken on.
    pub layer_id: LayerId,

    /// Description of the action.
    pub opcode: ClientCompositionOpcode,
}

impl ConfigError {
    /// Create an `Invalid` configuration error variant from FIDL output.
    pub fn invalid(error_code: ConfigResult, actions: Vec<ClientCompositionOp>) -> ConfigError {
        ConfigError::Invalid {
            error_code,
            actions: actions.into_iter().map(ClientCompositionAction::from).collect(),
        }
    }
}

impl From<ClientCompositionOp> for ClientCompositionAction {
    fn from(src: ClientCompositionOp) -> Self {
        Self {
            display_id: DisplayId(src.display_id),
            layer_id: LayerId(src.layer_id),
            opcode: src.opcode,
        }
    }
}
