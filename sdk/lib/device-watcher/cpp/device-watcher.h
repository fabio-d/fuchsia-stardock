// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIB_DEVICE_WATCHER_CPP_DEVICE_WATCHER_H_
#define LIB_DEVICE_WATCHER_CPP_DEVICE_WATCHER_H_

#include <lib/zx/channel.h>

#include <memory>
#include <string_view>

#include <fbl/unique_fd.h>

namespace device_watcher {

// Wait for |file| to appear in |dir|, and open it when it does.
zx_status_t WaitForFile(const fbl::unique_fd& dir, const char* file, fbl::unique_fd* out);

// Waits for the relative |path| starting in |dir| to appear, and opens it.
zx_status_t RecursiveWaitForFile(const fbl::unique_fd& dir, const char* path, fbl::unique_fd* out);

// Waits for the absolute |path| to appear, and opens it.
// NOTE: This only works for paths starting with /dev/,
// otherwise it will return ZX_ERR_NOT_SUPPORTED.
zx_status_t RecursiveWaitForFile(const char* path, fbl::unique_fd* out);

// Waits for the relative |path| starting in |dir| to appear, and opens it in Read only mode.
zx_status_t RecursiveWaitForFileReadOnly(const fbl::unique_fd& dir, const char* path,
                                         fbl::unique_fd* out);

// Waits for the absolute |path| to appear, and opens it as ReadOnly.
// NOTE: This only works for paths starting with /dev/,
// otherwise it will return ZX_ERR_NOT_SUPPORTED.
zx_status_t RecursiveWaitForFileReadOnly(const char* path, fbl::unique_fd* out);

// DirWatcher can be used to detect when a file has been removed from the filesystem.
//
// Example usage:
//
//   std::unique_ptr<DirWatcher> watcher;
//   zx_status_t status = DirWatcher::Create(dir_fd, &watcher);
//   ...
//   // Trigger removal of file here.
//   ...
//   status = watcher->WaitForRemoval(filename, deadline);
class DirWatcher {
 public:
  // |dir_fd| is the directory to watch.
  static zx_status_t Create(fbl::unique_fd dir_fd, std::unique_ptr<DirWatcher>* out_dir_watcher);

  // Users should call Create instead. This is public for make_unique.
  // TODO(https://fxbug.dev/89042): this should be a `fidl::ClientEnd<fuchsia_io::DirectoryWatcher>`
  // once LLCPP is in the SDK.
  explicit DirWatcher(zx::channel client) : client_(std::move(client)) {}

  // Returns ZX_OK if |filename| is removed from the directory before the given timeout elapses.
  // If no filename is specified, this will wait for any file in the directory to be removed.
  zx_status_t WaitForRemoval(std::string_view filename, zx::duration timeout);

 private:
  zx::channel client_;
};

}  // namespace device_watcher

#endif  // LIB_DEVICE_WATCHER_CPP_DEVICE_WATCHER_H_
