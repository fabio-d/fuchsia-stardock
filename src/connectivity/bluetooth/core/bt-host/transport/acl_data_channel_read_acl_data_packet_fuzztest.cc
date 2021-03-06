// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "slab_allocators.h"
#include "src/connectivity/bluetooth/core/bt-host/transport/acl_data_channel.h"

namespace bt::hci {

void fuzz(const uint8_t* data, size_t size) {
  // Allocate a buffer for the event. Since we don't know the size beforehand
  // we allocate the largest possible buffer.
  auto packet = ACLDataPacket::New(slab_allocators::kLargeACLDataPayloadSize);
  if (!packet) {
    return;
  }
  zx::channel a;
  zx::channel b;
  zx_status_t status = zx::channel::create(0u, &a, &b);
  if (status != ZX_OK) {
    return;
  }
  a.write(0u, data, size, /*handles=*/nullptr, 0);
  AclDataChannel::ReadAclDataPacketFromChannel(b, packet);
}

}  // namespace bt::hci

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  bt::hci::fuzz(data, size);
  return 0;
}
