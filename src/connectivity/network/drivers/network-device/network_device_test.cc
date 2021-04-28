// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "network_device.h"

#include <lib/fake_ddk/fake_ddk.h>

#include <ddktl/device.h>
#include <gtest/gtest.h>

#include "device/test_util.h"
#include "mac/test_util.h"
#include "src/lib/testing/predicates/status.h"

namespace {
// Enable timeouts only to test things locally, committed code should not use timeouts.
constexpr zx::duration kTestTimeout = zx::duration::infinite();
}  // namespace

namespace network {
namespace testing {

class NetDeviceDriverTest : public ::testing::Test, public fake_ddk::Bind {
 protected:
  using ReleaseOp = void(void*);

  void TearDown() override {
    if (device_created_) {
      RemoveDeviceSync();
    }
  }

  zx_status_t DeviceAdd(zx_driver_t* drv, zx_device_t* parent, device_add_args_t* args,
                        zx_device_t** out) override {
    zx_status_t status = Bind::DeviceAdd(drv, parent, args, out);
    if (status == ZX_OK) {
      release_op_ = args->ops->release;
      device_created_ = true;
    }
    return status;
  }

  void UnbindDeviceSync() {
    if (!unbind_started_) {
      DeviceAsyncRemove(fake_ddk::kFakeDevice);
      EXPECT_OK(sync_completion_wait_deadline(&remove_called_sync_,
                                              zx::deadline_after(kTestTimeout).get()));
    }
  }

  void RemoveDeviceSync() {
    UnbindDeviceSync();
    if (release_op_) {
      release_op_(op_ctx_);
    }
    device_created_ = false;
  }

  zx_status_t CreateDevice(bool with_mac = false) {
    auto proto = device_impl_.proto();
    SetProtocol(ZX_PROTOCOL_NETWORK_DEVICE_IMPL, &proto);
    if (with_mac) {
      device_impl_.port0().SetMac(mac_impl_.proto());
    }

    return NetworkDevice::Create(nullptr, fake_ddk::kFakeParent);
  }

  zx::status<fidl::WireSyncClient<netdev::Device>> ConnectNetDevice() {
    zx::status endpoints = fidl::CreateEndpoints<netdev::Device>();
    if (endpoints.is_error()) {
      return endpoints.take_error();
    }
    auto [client_end, server_end] = std::move(*endpoints);
    fidl::WireResult result =
        fidl::WireCall(fidl::UnownedClientEnd<netdev::DeviceInstance>(zx::unowned(FidlClient())))
            .GetDevice(std::move(server_end));
    if (!result.ok()) {
      return zx::error(result.status());
    }

    return zx::ok(fidl::BindSyncClient(std::move(client_end)));
  }

  zx::status<fidl::WireSyncClient<netdev::MacAddressing>> ConnectMac() {
    zx::status endpoints = fidl::CreateEndpoints<netdev::MacAddressing>();
    if (endpoints.is_error()) {
      return endpoints.take_error();
    }
    auto [client_end, server_end] = std::move(*endpoints);

    fidl::WireResult result =
        fidl::WireCall(fidl::UnownedClientEnd<netdev::DeviceInstance>(zx::unowned(FidlClient())))
            .GetMacAddressing(std::move(server_end));
    if (!result.ok()) {
      return zx::error(result.status());
    }

    return zx::ok(fidl::BindSyncClient(std::move(client_end)));
  }

  bool device_created_ = false;
  FakeMacDeviceImpl mac_impl_;
  FakeNetworkDeviceImpl device_impl_;
  ReleaseOp* release_op_;
};

TEST_F(NetDeviceDriverTest, TestCreateSimple) { ASSERT_OK(CreateDevice()); }

TEST_F(NetDeviceDriverTest, TestOpenSession) {
  ASSERT_OK(CreateDevice());
  TestSession session;
  zx::status connect_result = ConnectNetDevice();
  ASSERT_OK(connect_result.status_value());
  fidl::WireSyncClient<netdev::Device>& netdevice = connect_result.value();
  ASSERT_OK(session.Open(netdevice, "test-session"));
  session.SetPaused(false);
  ASSERT_OK(device_impl_.events().wait_one(kEventStart, zx::deadline_after(kTestTimeout), nullptr));
  UnbindDeviceSync();
  ASSERT_OK(session.WaitClosed(zx::deadline_after(kTestTimeout)));
  // netdevice should also have been closed after device unbind:
  ASSERT_OK(netdevice.channel().wait_one(ZX_CHANNEL_PEER_CLOSED, zx::deadline_after(kTestTimeout),
                                         nullptr));
}

TEST_F(NetDeviceDriverTest, TestWatcherDestruction) {
  // Test that on device removal watcher channels get closed.
  ASSERT_OK(CreateDevice());

  zx::status connect_result = ConnectNetDevice();
  ASSERT_OK(connect_result.status_value());
  fidl::WireSyncClient<netdev::Device>& netdevice = connect_result.value();

  zx::status endpoints = fidl::CreateEndpoints<netdev::StatusWatcher>();
  ASSERT_OK(endpoints.status_value());
  auto [client_end, server_end] = std::move(*endpoints);
  ASSERT_OK(netdevice.GetStatusWatcher(std::move(server_end), 1).status());
  fidl::WireSyncClient watcher = fidl::BindSyncClient(std::move(client_end));
  ASSERT_OK(watcher.WatchStatus().status());
  UnbindDeviceSync();
  ASSERT_OK(watcher.channel().wait_one(ZX_CHANNEL_PEER_CLOSED, zx::deadline_after(kTestTimeout),
                                       nullptr));
  // netdevice should also have been closed after device unbind:
  ASSERT_OK(netdevice.channel().wait_one(ZX_CHANNEL_PEER_CLOSED, zx::deadline_after(kTestTimeout),
                                         nullptr));
}

TEST_F(NetDeviceDriverTest, TestMac) {
  ASSERT_OK(CreateDevice(true));

  zx::status connect_result = ConnectMac();
  ASSERT_OK(connect_result.status_value());
  fidl::WireSyncClient<netdev::MacAddressing>& mac = connect_result.value();

  ASSERT_OK(mac.GetUnicastAddress().status());
  UnbindDeviceSync();
  // mac connection should be closed on device unbind:
  ASSERT_OK(
      mac.channel().wait_one(ZX_CHANNEL_PEER_CLOSED, zx::deadline_after(kTestTimeout), nullptr));
}

TEST_F(NetDeviceDriverTest, TestNoMac) {
  ASSERT_OK(CreateDevice(false));

  zx::status connect_result = ConnectMac();
  ASSERT_OK(connect_result.status_value());
  fidl::WireSyncClient<netdev::MacAddressing>& mac = connect_result.value();

  ASSERT_STATUS(mac.GetUnicastAddress().status(), ZX_ERR_PEER_CLOSED);
}

}  // namespace testing
}  // namespace network
