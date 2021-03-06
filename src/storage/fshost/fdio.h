// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_STORAGE_FSHOST_FDIO_H_
#define SRC_STORAGE_FSHOST_FDIO_H_

#include <lib/zx/channel.h>
#include <lib/zx/job.h>

#include <memory>

namespace fshost {

// clang-format off

// Flags for specifying what should be in a new process's namespace
// Note that there were previously many more constants here, but this is now only used by fshost
// which only needs to support the following
#define FS_SVC        0x0001
#define FS_DATA       0x0010
#define FS_BLOB_EXEC  0x2000
// Intended to include everything except for:
//   - FS_BLOB_EXEC, which is a RWX blobfs connection and should only be provided to pkgfs
#define FS_ALL        0x9FFF

// clang-format on

class FsProvider {
  // Pure abstract interface describing how to get a clone of a channel to an fs handle.
 public:
  virtual ~FsProvider();

  // Opens a path relative to locally-specified roots.
  //
  // This acts similar to 'open', but avoids utilizing the local process' namespace.
  // Instead, it manually translates hardcoded paths, such as "svc", "dev", etc into
  // their corresponding root connection, where the request is forwarded.
  //
  // This function is implemented by both devmgr and fshost.
  virtual zx::channel CloneFs(const char* path) = 0;
};

class DevmgrLauncher {
 public:
  explicit DevmgrLauncher(FsProvider* fs_provider);
  // If |executable| is invalid, then argv[0] is used as the path to the binary
  // If |loader| is invalid, the default loader service is used.
  zx_status_t LaunchWithLoader(const zx::job& job, const char* name, zx::vmo executable,
                               zx::channel loader, const char* const* argv,
                               const char** initial_envp, int stdiofd,
                               const zx::resource& root_resource, const zx_handle_t* handles,
                               const uint32_t* types, size_t hcount, zx::process* out_proc,
                               uint32_t flags);
  zx_status_t Launch(const zx::job& job, const char* name, const char* const* argv,
                     const char** envp, int stdiofd, const zx::resource& root_resource,
                     const zx_handle_t* handles, const uint32_t* types, size_t hcount,
                     zx::process* proc_out, uint32_t flags);

 private:
  FsProvider* fs_provider_;
};

// Returns the result of splitting |args| into an argument vector.
class ArgumentVector {
 public:
  static ArgumentVector FromCmdline(const char* cmdline);

  // Returns a nullptr-terminated list of arguments.  Only valid for the
  // lifetime of |this|.
  const char* const* argv() const { return argv_; }

 private:
  ArgumentVector() = default;

  static constexpr size_t kMaxArgs = 8;
  const char* argv_[kMaxArgs + 1];
  std::unique_ptr<char[]> raw_bytes_;
};

std::ostream& operator<<(std::ostream& stream, const ArgumentVector& arguments);

// The variable to set on the kernel command line to enable ld.so tracing
// of the processes we launch.
#define LDSO_TRACE_CMDLINE "ldso.trace"
// The env var to set to enable ld.so tracing.
#define LDSO_TRACE_ENV "LD_TRACE=1"

}  // namespace fshost

#endif  // SRC_STORAGE_FSHOST_FDIO_H_
