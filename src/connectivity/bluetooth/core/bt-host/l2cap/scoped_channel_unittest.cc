// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "scoped_channel.h"

#include <gtest/gtest.h>

#include "fake_channel.h"

namespace bt::l2cap::testing {
namespace {

void DoNothing() {}
void NopRxCallback(ByteBufferPtr) {}

}  // namespace

TEST(ScopedChannelTest, Close) {
  auto chan = fbl::AdoptRef(new FakeChannel(1, 1, 1, bt::LinkType::kACL));
  ASSERT_TRUE(chan->Activate(NopRxCallback, DoNothing));
  ASSERT_TRUE(chan->activated());

  {
    ScopedChannel scoped(chan);
    EXPECT_TRUE(chan->activated());
  }

  EXPECT_FALSE(chan->activated());
}

TEST(ScopedChannelTest, Reset) {
  auto chan1 = fbl::AdoptRef(new FakeChannel(1, 1, 1, bt::LinkType::kACL));
  auto chan2 = fbl::AdoptRef(new FakeChannel(1, 1, 1, bt::LinkType::kACL));
  ASSERT_TRUE(chan1->Activate(NopRxCallback, DoNothing));
  ASSERT_TRUE(chan2->Activate(NopRxCallback, DoNothing));
  ASSERT_TRUE(chan1->activated());
  ASSERT_TRUE(chan2->activated());

  ScopedChannel scoped(chan1);
  EXPECT_TRUE(chan1->activated());

  scoped.Reset(chan2);
  EXPECT_FALSE(chan1->activated());
  EXPECT_TRUE(chan2->activated());

  scoped.Reset(nullptr);
  EXPECT_FALSE(chan2->activated());
}

}  // namespace bt::l2cap::testing
