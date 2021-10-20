// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/storage/f2fs/f2fs.h"

namespace f2fs {

#ifdef __Fuchsia__

constexpr char kFsName[] = "f2fs";

QueryService::QueryService(async_dispatcher_t* dispatcher, F2fs* f2fs)
    : fs::Service([dispatcher, this](fidl::ServerEnd<fuchsia_fs::Query> server_end) {
        return fidl::BindSingleInFlightOnly(dispatcher, std::move(server_end), this);
      }),
      f2fs_(f2fs) {}

void QueryService::GetInfo(GetInfoRequestView request, GetInfoCompleter::Sync& completer) {
  static_assert(sizeof(kFsName) < fuchsia_fs::wire::kMaxFsNameLength, "F2fs name too long");

  fidl::Arena allocator;
  fuchsia_fs::wire::FilesystemInfo filesystem_info(allocator);

  filesystem_info.set_total_bytes(allocator,
                                  f2fs_->GetSuperblockInfo().GetUserBlockCount() * kBlockSize);
  filesystem_info.set_used_bytes(allocator, f2fs_->ValidUserBlocks() * kBlockSize);
  filesystem_info.set_total_nodes(allocator, f2fs_->GetSuperblockInfo().GetTotalNodeCount());
  filesystem_info.set_used_nodes(allocator, f2fs_->ValidInodeCount());

  zx::event fs_id;
  zx_status_t status = f2fs_->GetFsId(&fs_id);
  if (status != ZX_OK) {
    completer.ReplyError(status);
    return;
  }
  filesystem_info.set_fs_id(allocator, std::move(fs_id));

  filesystem_info.set_block_size(allocator, kBlockSize);
  filesystem_info.set_max_node_name_size(allocator, kMaxNameLen);
  filesystem_info.set_fs_type(allocator, fuchsia_fs::wire::FsType::kF2Fs);

  fidl::StringView name(kFsName);
  filesystem_info.set_name(allocator, std::move(name));

  std::string device_path;
  if (auto device_path_or = f2fs_->GetBc().device()->GetDevicePath(); device_path_or.is_error()) {
    completer.ReplyError(device_path_or.error_value());
    return;
  } else {
    device_path = std::move(device_path_or).value();
  }
  filesystem_info.set_device_path(allocator, fidl::StringView::FromExternal(device_path));

  completer.ReplySuccess(std::move(filesystem_info));
}

void QueryService::IsNodeInFilesystem(IsNodeInFilesystemRequestView request,
                                      IsNodeInFilesystemCompleter::Sync& completer) {
  completer.Reply(f2fs_->IsTokenAssociatedWithVnode(std::move(request->token)));
}
#endif  // __Fuchsia__

}  // namespace f2fs
