// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_BRINGUP_BIN_BOOTSVC_BOOTFS_SERVICE_H_
#define SRC_BRINGUP_BIN_BOOTSVC_BOOTFS_SERVICE_H_

#include <lib/async/dispatcher.h>
#include <lib/zbitl/vmo.h>
#include <lib/zx/resource.h>
#include <lib/zx/vmo.h>

#include <vector>

#include <fbl/ref_counted.h>
#include <fbl/ref_ptr.h>

#include "src/storage/memfs/memfs.h"
#include "src/storage/memfs/vnode.h"
#include "src/storage/memfs/vnode_dir.h"

namespace bootsvc {

class BootfsService : public fbl::RefCounted<BootfsService> {
 public:
  ~BootfsService();

  // Create an empty BootfsService and set up its VFS to use the given async dispatcher.
  static zx_status_t Create(async_dispatcher_t* dispatcher, zx::resource vmex,
                            fbl::RefPtr<BootfsService>* out);

  // Overlays the contents of |bootfs| on top of the existing VFS.
  zx_status_t AddBootfs(zx::vmo bootfs);

  // Creates a connection to the root of the bootfs VFS and returns
  // a channel that can be used to speak the fuchsia.io.Node interface.
  zx_status_t CreateRootConnection(zx::channel* out);

  // Looks up the given path in the bootfs and returns its contents and size. If executable is true,
  // the returned VMO has ZX_RIGHT_EXECUTE (or the open fails if the file cannot be opened
  // executable).
  zx_status_t Open(const char* path, bool executable, zx::vmo* vmo, size_t* size);

  // Publishes all of the VMOs from the startup handles table with the given
  // |type|. |debug_type_name| is used for debug printing.
  void PublishStartupVmos(const std::vector<zx::vmo>& vmos, uint8_t type,
                          const char* debug_type_name);

  // Reads an object directly from the bootfs image. This is a temporary, and will only
  // be used while we still have bootsvc but no longer create a bootfs VFS in it.
  static zx::status<zx::vmo> GetFileFromBootfsVmo(zbitl::MapUnownedVmo unowned_vmo,
                                                  zbitl::MapUnownedVmo unowned_vmo_exec,
                                                  const std::string& path, uint64_t* size);

 private:
  BootfsService(zx::resource vmex_rsrc);

  // Duplicate a handle to the provided VMO and add ZX_RIGHT_EXECUTE.
  zx_status_t DuplicateAsExecutable(const zx::vmo& vmo, zx::vmo* out_vmo);

  // Publishes the given |vmo| range into the bootfs at |path|.  |path| should
  // not begin with a slash and be relative to the root of the bootfs.
  zx_status_t PublishVmo(std::string_view path, zx::vmo vmo, zx_off_t off, size_t len);

  // Same as PublishVmo, but the caller must ensure that |vmo| outlives the
  // bootfs service.
  zx_status_t PublishUnownedVmo(std::string_view path, const zx::vmo& vmo, zx_off_t off,
                                size_t len);

  // owned_vmos contains all VMOs that are claimed by the underlying VFS
  std::vector<zx::vmo> owned_vmos_;

  std::unique_ptr<memfs::Memfs> vfs_;
  // root of the vfs
  fbl::RefPtr<memfs::VnodeDir> root_;
  zx::resource vmex_rsrc_;
};

}  // namespace bootsvc

#endif  // SRC_BRINGUP_BIN_BOOTSVC_BOOTFS_SERVICE_H_
