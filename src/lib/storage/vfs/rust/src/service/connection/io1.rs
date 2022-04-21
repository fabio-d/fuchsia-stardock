// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of an individual connection to a file.

use crate::{
    common::{inherit_rights_for_clone, send_on_open_with_error},
    execution_scope::ExecutionScope,
    service::common::{new_connection_validate_flags, POSIX_READ_WRITE_PROTECTION_ATTRIBUTES},
};

use {
    anyhow::Error,
    fidl::endpoints::ServerEnd,
    fidl_fuchsia_io as fio,
    fuchsia_zircon::{
        sys::{ZX_ERR_ACCESS_DENIED, ZX_ERR_NOT_SUPPORTED, ZX_OK},
        Status,
    },
    futures::stream::StreamExt,
};

/// Represents a FIDL connection to a service.
pub struct Connection {
    /// Execution scope this connection and any async operations and connections it creates will
    /// use.
    scope: ExecutionScope,

    /// Wraps a FIDL connection, providing messages coming from the client.
    requests: fio::FileRequestStream,
}

/// Return type for [`handle_request()`] functions.
enum ConnectionState {
    /// Connection is still alive.
    Alive,
    /// Connection have received Node::Close message, it was dropped by the peer, or an error had
    /// occurred.  As we do not perform any actions, except for closing our end we do not distiguish
    /// those cases, unlike file and directory connections.
    Closed,
}

impl Connection {
    /// Initialized a NODE_REFERENCE service connection, which will be running in the context of
    /// the specified execution `scope`.  This function will also check the flags and will send the
    /// `OnOpen` event if necessary.
    pub fn create_connection(
        scope: ExecutionScope,
        flags: fio::OpenFlags,
        mode: u32,
        server_end: ServerEnd<fio::NodeMarker>,
    ) {
        let task = Self::create_connection_task(scope.clone(), flags, mode, server_end);
        // If we failed to send the task to the executor, it is probably shut down or is in the
        // process of shutting down (this is the only error state currently).  So there is nothing
        // for us to do, but to ignore the open.  `server_end` will be closed when the object will
        // be dropped - there seems to be no error to report there.
        let _ = scope.spawn(Box::pin(task));
    }

    async fn create_connection_task(
        scope: ExecutionScope,
        flags: fio::OpenFlags,
        mode: u32,
        server_end: ServerEnd<fio::NodeMarker>,
    ) {
        let flags = match new_connection_validate_flags(flags, mode) {
            Ok(updated) => updated,
            Err(status) => {
                send_on_open_with_error(flags, server_end, status);
                return;
            }
        };

        let (requests, control_handle) =
            match ServerEnd::<fio::FileMarker>::new(server_end.into_channel())
                .into_stream_and_control_handle()
            {
                Ok((requests, control_handle)) => (requests, control_handle),
                Err(_) => {
                    // As we report all errors on `server_end`, if we failed to send an error over
                    // this connection, there is nowhere to send the error to.
                    return;
                }
            };

        if flags.intersects(fio::OpenFlags::DESCRIBE) {
            let mut info = fio::NodeInfo::Service(fio::Service);
            match control_handle.send_on_open_(Status::OK.into_raw(), Some(&mut info)) {
                Ok(()) => (),
                Err(_) => return,
            }
        }

        let handle_requests = Connection { scope: scope.clone(), requests }.handle_requests();
        handle_requests.await;
    }

    async fn handle_requests(mut self) {
        while let Some(request_or_err) = self.requests.next().await {
            match request_or_err {
                Err(_) => {
                    // FIDL level error, such as invalid message format and alike.  Close the
                    // connection on any unexpected error.
                    // TODO: Send an epitaph.
                    break;
                }
                Ok(request) => {
                    match self.handle_request(request).await {
                        Ok(ConnectionState::Alive) => (),
                        Ok(ConnectionState::Closed) | Err(_) => {
                            // Err(_) means a protocol level error.  Close the connection on any
                            // unexpected error.  TODO: Send an epitaph.
                            break;
                        }
                    }
                }
            }
        }
    }

    /// POSIX protection attributes are hard coded, as we are expecting them to be removed from the
    /// fuchsia.io altogether.
    fn posix_protection_attributes(&self) -> u32 {
        POSIX_READ_WRITE_PROTECTION_ATTRIBUTES
    }

    /// Handle a [`FileRequest`]. This function is responsible for handing all the file operations
    /// that operate on the connection-specific buffer.
    async fn handle_request(&mut self, req: fio::FileRequest) -> Result<ConnectionState, Error> {
        match req {
            fio::FileRequest::Clone { flags, object, control_handle: _ } => {
                self.handle_clone(flags, object);
            }
            fio::FileRequest::Reopen { options, object_request, control_handle: _ } => {
                let _ = object_request;
                todo!("https://fxbug.dev/77623: options={:?}", options);
            }
            fio::FileRequest::CloseDeprecated { responder } => {
                responder.send(ZX_OK)?;
                return Ok(ConnectionState::Closed);
            }
            fio::FileRequest::Close { responder } => {
                responder.send(&mut Ok(()))?;
                return Ok(ConnectionState::Closed);
            }
            fio::FileRequest::Describe { responder } => {
                let mut info = fio::NodeInfo::Service(fio::Service);
                responder.send(&mut info)?;
            }
            fio::FileRequest::Describe2 { query: _, responder } => {
                let info = fio::ConnectionInfo {
                    representation: Some(fio::Representation::Connector(fio::ConnectorInfo::EMPTY)),
                    ..fio::ConnectionInfo::EMPTY
                };
                responder.send(info)?;
            }
            fio::FileRequest::SyncDeprecated { responder } => {
                responder.send(ZX_ERR_NOT_SUPPORTED)?;
            }
            fio::FileRequest::Sync { responder } => {
                responder.send(&mut Err(ZX_ERR_NOT_SUPPORTED))?;
            }
            fio::FileRequest::GetAttr { responder } => {
                let mut attrs = fio::NodeAttributes {
                    mode: fio::MODE_TYPE_SERVICE | self.posix_protection_attributes(),
                    id: fio::INO_UNKNOWN,
                    content_size: 0,
                    storage_size: 0,
                    link_count: 1,
                    creation_time: 0,
                    modification_time: 0,
                };
                responder.send(ZX_OK, &mut attrs)?;
            }
            fio::FileRequest::SetAttr { flags: _, attributes: _, responder } => {
                // According to https://fuchsia.googlesource.com/fuchsia/+/HEAD/sdk/fidl/fuchsia.io/
                // the only flag that might be modified through this call is OPEN_FLAG_APPEND, and
                // it is not supported by the PseudoFile.
                responder.send(ZX_ERR_NOT_SUPPORTED)?;
            }
            fio::FileRequest::GetAttributes { query, responder } => {
                let _ = responder;
                todo!("https://fxbug.dev/77623: query={:?}", query);
            }
            fio::FileRequest::UpdateAttributes { attributes, responder } => {
                let _ = responder;
                todo!("https://fxbug.dev/77623: attributes={:?}", attributes);
            }
            fio::FileRequest::GetFlags { responder } => {
                responder.send(ZX_OK, fio::OpenFlags::NODE_REFERENCE)?;
            }
            fio::FileRequest::SetFlags { flags: _, responder } => {
                responder.send(ZX_ERR_NOT_SUPPORTED)?;
            }
            fio::FileRequest::AdvisoryLock { request: _, responder } => {
                responder.send(&mut Err(ZX_ERR_NOT_SUPPORTED))?;
            }
            fio::FileRequest::ReadDeprecated { count: _, responder } => {
                responder.send(ZX_ERR_ACCESS_DENIED, &[])?;
            }
            fio::FileRequest::Read { count: _, responder } => {
                responder.send(&mut Err(ZX_ERR_ACCESS_DENIED))?;
            }
            fio::FileRequest::ReadAtDeprecated { offset: _, count: _, responder } => {
                responder.send(ZX_ERR_ACCESS_DENIED, &[])?;
            }
            fio::FileRequest::ReadAt { offset: _, count: _, responder } => {
                responder.send(&mut Err(ZX_ERR_ACCESS_DENIED))?;
            }
            fio::FileRequest::WriteDeprecated { data: _, responder } => {
                responder.send(ZX_ERR_ACCESS_DENIED, 0)?;
            }
            fio::FileRequest::Write { data: _, responder } => {
                responder.send(&mut Err(ZX_ERR_ACCESS_DENIED))?;
            }
            fio::FileRequest::WriteAtDeprecated { offset: _, data: _, responder } => {
                responder.send(ZX_ERR_ACCESS_DENIED, 0)?;
            }
            fio::FileRequest::WriteAt { offset: _, data: _, responder } => {
                responder.send(&mut Err(ZX_ERR_ACCESS_DENIED))?;
            }
            fio::FileRequest::SeekDeprecated { offset: _, start: _, responder } => {
                responder.send(ZX_ERR_ACCESS_DENIED, 0)?;
            }
            fio::FileRequest::Seek { origin: _, offset: _, responder } => {
                responder.send(&mut Err(ZX_ERR_ACCESS_DENIED))?;
            }
            fio::FileRequest::TruncateDeprecatedUseResize { length: _, responder } => {
                responder.send(ZX_ERR_ACCESS_DENIED)?;
            }
            fio::FileRequest::Resize { length: _, responder } => {
                responder.send(&mut Err(ZX_ERR_ACCESS_DENIED))?;
            }
            fio::FileRequest::GetBufferDeprecatedUseGetBackingMemory { flags: _, responder } => {
                // There is no backing VMO.
                responder.send(ZX_ERR_NOT_SUPPORTED, None)?;
            }
            fio::FileRequest::GetBackingMemory { flags: _, responder } => {
                // There is no backing VMO.
                responder.send(&mut Err(ZX_ERR_NOT_SUPPORTED))?;
            }
            fio::FileRequest::QueryFilesystem { responder } => {
                responder.send(ZX_ERR_NOT_SUPPORTED, None)?;
            }
        }
        Ok(ConnectionState::Alive)
    }

    fn handle_clone(&mut self, flags: fio::OpenFlags, server_end: ServerEnd<fio::NodeMarker>) {
        let parent_flags = fio::OpenFlags::NODE_REFERENCE;
        let flags = match inherit_rights_for_clone(parent_flags, flags) {
            Ok(updated) => updated,
            Err(status) => {
                send_on_open_with_error(flags, server_end, status);
                return;
            }
        };

        Self::create_connection(self.scope.clone(), flags, 0, server_end);
    }
}
