// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    crate::{
        crypt::Crypt,
        filesystem::{Filesystem, Info, OpenFxFilesystem},
        object_store::volume::root_volume,
        platform::fuchsia::volume::FxVolumeAndRoot,
        serialized_types::LATEST_VERSION,
    },
    anyhow::{Context, Error},
    fidl_fuchsia_fs::{AdminRequest, AdminRequestStream, QueryRequest, QueryRequestStream},
    fidl_fuchsia_io as fio,
    fuchsia_component::server::ServiceFs,
    fuchsia_zircon::{self as zx, AsHandleRef},
    futures::stream::{StreamExt, TryStreamExt},
    futures::TryFutureExt,
    inspect_runtime::service::{TreeServerSendPreference, TreeServerSettings},
    std::{
        convert::TryInto,
        sync::{
            atomic::{self, AtomicBool},
            Arc,
        },
    },
    vfs::{
        directory::entry::DirectoryEntry,
        execution_scope::ExecutionScope,
        inspect::{FsInspect, FsInspectTree, InfoData, UsageData, VolumeData},
        path::Path,
        registry::token_registry,
    },
};

mod device;
mod directory;
mod errors;
pub mod file;
pub mod metrics;
pub mod node;
pub mod pager;
mod remote_crypt;
pub mod vmo_data_buffer;
mod volume;

#[cfg(test)]
mod testing;

// The correct number here is arguably u64::MAX - 1 (because node 0 is reserved). There's a bug
// where inspect test cases fail if we try and use that, possibly because of a signed/unsigned bug.
// See fxbug.dev/87152.  Until that's fixed, we'll have to use i64::MAX.
const TOTAL_NODES: u64 = i64::MAX as u64;

const VFS_TYPE_FXFS: u32 = 0x73667866;

const FXFS_INFO_NAME: &'static str = "fxfs";

// An array used to initialize the FilesystemInfo |name| field. This just spells "fxfs" 0-padded to
// 32 bytes.
const FXFS_INFO_NAME_FIDL: [i8; 32] = [
    0x66, 0x78, 0x66, 0x73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];

enum Services {
    Admin(AdminRequestStream),
    Query(QueryRequestStream),
}

pub use remote_crypt::RemoteCrypt;

pub struct FxfsServer {
    /// Ensure the filesystem is closed when this object is dropped.
    fs: OpenFxFilesystem,

    /// Encapsulates the root volume and the root directory.
    /// TODO(fxbug.dev/89443): Support multiple volumes.
    volume: FxVolumeAndRoot,

    /// Set to true once the associated ExecutionScope associated with the server is shut down.
    closed: AtomicBool,

    /// Unique identifier for this filesystem instance (not preserved across reboots) based on
    /// the kernel object ID to guarantee uniqueness within the system.
    unique_id: zx::Event,
}

impl FxfsServer {
    /// Creates a new FxfsServer by opening or creating |volume_name| in |fs|.
    pub async fn new(
        fs: OpenFxFilesystem,
        volume_name: &str,
        crypt: Option<Arc<dyn Crypt>>,
    ) -> Result<Arc<Self>, Error> {
        let root_volume = root_volume(&fs).await?;
        let unique_id = zx::Event::create().expect("Failed to create event");
        let volume = FxVolumeAndRoot::new(
            root_volume
                .open_or_create_volume(volume_name, crypt)
                .await
                .expect("Open or create volume failed"),
            unique_id.get_koid()?.raw_koid(),
        )
        .await?;
        Ok(Arc::new(Self { fs, volume, closed: AtomicBool::new(false), unique_id }))
    }

    pub async fn run(self: Arc<Self>, outgoing_chan: zx::Channel) -> Result<(), Error> {
        // VFS initialization.
        let registry = token_registry::Simple::new();
        let scope = ExecutionScope::build().token_registry(registry).new();
        let (proxy, server) = fidl::endpoints::create_proxy::<fio::DirectoryMarker>()?;

        self.volume.volume().start_flush_task(volume::DEFAULT_FLUSH_PERIOD);

        self.volume.root().clone().open(
            scope.clone(),
            fio::OpenFlags::RIGHT_READABLE | fio::OpenFlags::RIGHT_WRITABLE,
            0,
            Path::dot(),
            server.into_channel().into(),
        );

        // Since fshost currently exports all filesystem inspect trees under its own diagnostics
        // directory, in order to work properly with Lapis, each filesystem must use a uniquely
        // named root node.

        // The Inspect nodes will remain live until `_fs_inspect_nodes` goes out of scope.
        let self_weak = Arc::downgrade(&self);
        let _fs_inspect_nodes =
            FsInspectTree::new(self_weak, &crate::metrics::FXFS_ROOT_NODE.lock().unwrap());

        // Export the root directory in our outgoing directory.
        let mut fs = ServiceFs::new();
        fs.add_remote("root", proxy);
        fs.add_fidl_service(Services::Admin).add_fidl_service(Services::Query);
        // Serve static Inspect instance from fuchsia_inspect::component to diagnostic directory.
        // We fall back to DeepCopy mode instead of Live mode (the default) if we could not create a
        // child copy of the backing VMO. This helps prevent issues with the reader acquiring a lock
        // while the the filesystem is under load. See fxbug.dev/57330 for details.
        inspect_runtime::serve_with_options(
            fuchsia_inspect::component::inspector(),
            TreeServerSettings {
                send_vmo_preference: TreeServerSendPreference::frozen_or(
                    TreeServerSendPreference::DeepCopy,
                ),
            },
            &mut fs,
        )?;
        fs.serve_connection(outgoing_chan)?;

        // Handle all ServiceFs connections. VFS connections will be spawned as separate tasks.
        const MAX_CONCURRENT: usize = 10_000;
        fs.for_each_concurrent(MAX_CONCURRENT, |request| {
            self.handle_request(request, &scope).unwrap_or_else(|e| log::error!("{}", e))
        })
        .await;

        // At this point all direct connections to ServiceFs will have been closed (and cannot be
        // resurrected), but before we finish, we must wait for all VFS connections to be closed.
        scope.wait().await;

        if !self.closed.load(atomic::Ordering::SeqCst) {
            self.volume.volume().terminate().await;
            self.fs.close().await.unwrap_or_else(|e| log::error!("Failed to shutdown fxfs: {}", e));
        }

        Ok(())
    }

    // Returns true if we should close the connection.
    async fn handle_admin(&self, scope: &ExecutionScope, req: AdminRequest) -> Result<bool, Error> {
        match req {
            AdminRequest::Shutdown { responder } => {
                log::info!("Received shutdown request");
                scope.shutdown();
                if self.closed.swap(true, atomic::Ordering::SeqCst) {
                    return Ok(true);
                }
                self.volume.volume().terminate().await;
                log::info!("Volume terminated");
                self.fs
                    .close()
                    .await
                    .unwrap_or_else(|e| log::error!("Failed to shutdown fxfs: {}", e));
                log::info!("Filesystem instance terminated");
                responder
                    .send()
                    .unwrap_or_else(|e| log::warn!("Failed to send shutdown response: {}", e));
                return Ok(true);
            }
        }
    }

    async fn handle_query(&self, _scope: &ExecutionScope, req: QueryRequest) -> Result<(), Error> {
        unimplemented!("req={:?}", req)
    }

    async fn handle_request(&self, stream: Services, scope: &ExecutionScope) -> Result<(), Error> {
        match stream {
            Services::Admin(mut stream) => {
                while let Some(request) = stream.try_next().await.context("Reading request")? {
                    if self.handle_admin(scope, request).await? {
                        break;
                    }
                }
            }
            Services::Query(mut stream) => {
                while let Some(request) = stream.try_next().await.context("Reading request")? {
                    self.handle_query(scope, request).await?;
                }
            }
        }
        Ok(())
    }
}

impl Info {
    fn to_filesystem_info(self, object_count: u64, fs_id: u64) -> fio::FilesystemInfo {
        fio::FilesystemInfo {
            total_bytes: self.total_bytes,
            used_bytes: self.used_bytes,
            total_nodes: TOTAL_NODES,
            used_nodes: object_count,
            // TODO(fxbug.dev/93770): Support free_shared_pool_bytes.
            free_shared_pool_bytes: 0,
            fs_id,
            block_size: self.block_size.try_into().unwrap(),
            max_filename_size: fio::MAX_FILENAME as u32,
            fs_type: VFS_TYPE_FXFS,
            padding: 0,
            name: FXFS_INFO_NAME_FIDL,
        }
    }
}

impl FsInspect for FxfsServer {
    fn get_info_data(&self) -> InfoData {
        InfoData {
            id: self.unique_id.get_koid().unwrap().raw_koid(),
            fs_type: VFS_TYPE_FXFS.into(),
            name: FXFS_INFO_NAME.into(),
            version_major: LATEST_VERSION.major.into(),
            version_minor: LATEST_VERSION.minor.into(),
            oldest_minor_version: 0, // TODO(fxbug.dev/93770)
            block_size: self.fs.get_info().block_size.into(),
            max_filename_length: fio::MAX_FILENAME,
        }
    }

    fn get_usage_data(&self) -> UsageData {
        let info = self.fs.get_info();
        let object_count = self.volume.volume().store().object_count();
        UsageData {
            total_bytes: info.total_bytes,
            used_bytes: info.used_bytes,
            total_nodes: TOTAL_NODES,
            used_nodes: object_count,
        }
    }

    fn get_volume_data(&self) -> VolumeData {
        // Since we're not using FVM these values should all be set to zero.
        VolumeData {
            size_bytes: 0,
            size_limit_bytes: 0,
            available_space_bytes: 0,
            // TODO(fxbug.dev/93770): Handle out of space events.
            out_of_space_events: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{crypt::InsecureCrypt, filesystem::FxFilesystem, platform::fuchsia::FxfsServer},
        anyhow::Error,
        fidl_fuchsia_fs::AdminMarker,
        fidl_fuchsia_io as fio, fuchsia_async as fasync,
        std::sync::Arc,
        storage_device::{fake_device::FakeDevice, DeviceHolder},
    };

    #[fasync::run(2, test)]
    async fn test_lifecycle() -> Result<(), Error> {
        let device = DeviceHolder::new(FakeDevice::new(16384, 512));
        let filesystem = FxFilesystem::new_empty(device).await?;
        let server = FxfsServer::new(filesystem, "root", Some(Arc::new(InsecureCrypt::new())))
            .await
            .expect("Create server failed");

        let (client_end, server_end) = fidl::endpoints::create_endpoints::<fio::DirectoryMarker>()?;
        let client_proxy = client_end.into_proxy().expect("Create DirectoryProxy failed");
        fasync::Task::spawn(async move {
            let admin_proxy = fuchsia_component::client::connect_to_protocol_at_dir_root::<
                AdminMarker,
            >(&client_proxy)
            .expect("Connect to Admin service failed");
            admin_proxy.shutdown().await.expect("Shutdown failed");
        })
        .detach();

        server.run(server_end.into_channel()).await.expect("Run returned an error");
        Ok(())
    }
}
