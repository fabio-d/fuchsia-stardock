// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/storage/minfs/mount.h"

#include <lib/inspect/service/cpp/service.h>
#include <lib/syslog/cpp/macros.h>

#include <safemath/safe_math.h>

#include "src/lib/storage/vfs/cpp/managed_vfs.h"
#include "src/lib/storage/vfs/cpp/paged_vfs.h"
#include "src/lib/storage/vfs/cpp/pseudo_dir.h"
#include "src/lib/storage/vfs/cpp/trace.h"
#include "src/storage/minfs/minfs_private.h"
#include "src/storage/minfs/service/admin.h"

namespace minfs {

zx::status<CreateBcacheResult> CreateBcache(std::unique_ptr<block_client::BlockDevice> device) {
  fuchsia_hardware_block_BlockInfo info;
  zx_status_t status = device->BlockGetInfo(&info);
  if (status != ZX_OK) {
    FX_LOGS(ERROR) << "Could not access device info: " << status;
    return zx::error(status);
  }

  uint64_t device_size;
  if (!safemath::CheckMul(info.block_size, info.block_count).AssignIfValid(&device_size)) {
    FX_LOGS(ERROR) << "Device slize overflow";
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }
  if (device_size == 0) {
    FX_LOGS(ERROR) << "Invalid device size";
    return zx::error(ZX_ERR_NO_SPACE);
  }

  uint32_t block_count;
  if (!safemath::CheckDiv(device_size, kMinfsBlockSize)
           .Cast<uint32_t>()
           .AssignIfValid(&block_count)) {
    FX_LOGS(ERROR) << "Block count overflow";
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }

  auto bcache_or = minfs::Bcache::Create(std::move(device), block_count);
  if (bcache_or.is_error()) {
    return bcache_or.take_error();
  }

  CreateBcacheResult result{
      .bcache = std::move(bcache_or.value()),
      .is_read_only = static_cast<bool>(info.flags & fuchsia_hardware_block_FLAG_READONLY),
  };
  return zx::ok(std::move(result));
}

zx::status<std::unique_ptr<fs::ManagedVfs>> MountAndServe(const MountOptions& mount_options,
                                                          async_dispatcher_t* dispatcher,
                                                          std::unique_ptr<minfs::Bcache> bcache,
                                                          zx::channel mount_channel,
                                                          fit::closure on_unmount) {
  TRACE_DURATION("minfs", "MountAndServe");

  fbl::RefPtr<VnodeMinfs> data_root;
  auto fs_or = Mount(dispatcher, std::move(bcache), mount_options, &data_root);
  if (fs_or.is_error()) {
    return std::move(fs_or);
  }
  std::unique_ptr<Minfs> fs = std::move(fs_or).value();

  fs->SetUnmountCallback(std::move(on_unmount));

  // At time of writing the Cobalt client has certain requirements around which thread you interact
  // with it on, so we interact with it by posting to the dispatcher.  See fxbug.dev/74396 for more
  // details.
  async::PostTask(dispatcher, [&fs = *fs] { fs.LogMountMetrics(); });

  // Specify to fall back to DeepCopy mode instead of Live mode (the default) on failures to send
  // a Frozen copy of the tree (e.g. if we could not create a child copy of the backing VMO).
  // This helps prevent any issues with querying the inspect tree while the filesystem is under
  // load, since snapshots at the receiving end must be consistent. See fxbug.dev/57330 for
  // details.
  inspect::TreeHandlerSettings settings{.snapshot_behavior =
                                            inspect::TreeServerSendPreference::Frozen(
                                                inspect::TreeServerSendPreference::Type::DeepCopy)};

  auto inspect_tree = fbl::MakeRefCounted<fs::Service>(
      [connector = inspect::MakeTreeHandler(&fs->Inspector(), dispatcher, settings)](
          zx::channel chan) mutable {
        connector(fidl::InterfaceRequest<fuchsia::inspect::Tree>(std::move(chan)));
        return ZX_OK;
      });

  auto outgoing = fbl::MakeRefCounted<fs::PseudoDir>(fs.get());
  outgoing->AddEntry("root", std::move(data_root));

  auto diagnostics_dir = fbl::MakeRefCounted<fs::PseudoDir>(fs.get());
  outgoing->AddEntry("diagnostics", diagnostics_dir);
  diagnostics_dir->AddEntry(fuchsia::inspect::Tree::Name_, inspect_tree);

  outgoing->AddEntry(fidl::DiscoverableProtocolName<fuchsia_fs::Admin>,
                     fbl::MakeRefCounted<AdminService>(fs->dispatcher(), *fs));

  zx_status_t status = fs->ServeDirectory(std::move(outgoing), std::move(mount_channel));
  if (status != ZX_OK) {
    return zx::error(status);
  }
  return zx::ok(std::move(fs));
}

}  // namespace minfs
