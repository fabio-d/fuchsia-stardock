// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <wlan/mlme/sequence.h>

#include <fbl/type_support.h>
#include <fbl/unique_ptr.h>
#include <lib/zx/time.h>
#include <wlan/common/bitfield.h>
#include <wlan/common/mac_frame.h>
#include <wlan/common/macaddr.h>
#include <zircon/compiler.h>
#include <zircon/types.h>

#include <cstdint>

namespace wlan {

class Packet;

// TODO(hahnr): Remove once frame owns Packet.
template <typename Header, typename Body> class ImmutableFrame {
   public:
    ImmutableFrame(const Header* hdr, const Body* body, size_t body_len)
        : hdr_(hdr), body_(body), body_len_(body_len) {}

    const Header* hdr() const { return hdr_; }
    const Body* body() const { return body_; }
    size_t body_len() const { return body_len_; }

   private:
    const Header* hdr_;
    const Body* body_;
    const size_t body_len_;
};

template <typename Header, typename Body> class Frame {
   public:
    Frame(Header* hdr, Body* body, size_t body_len) : hdr_(hdr), body_(body), body_len_(body_len) {}

    Header* hdr() { return hdr_; }
    Body* body() { return body_; }
    size_t body_len() const { return body_len_; }
    void set_body_len(size_t body_len) { body_len_ = body_len; }

   private:
    Header* hdr_;
    Body* body_;
    size_t body_len_;
};

using Payload = uint8_t;
struct NilHeader {};

// Frame which contains a known header but unknown payload.
template <typename Header> using BaseFrame = Frame<Header, Payload>;
template <typename Header> using ImmutableBaseFrame = ImmutableFrame<Header, Payload>;

template <typename T> using MgmtFrame = Frame<MgmtFrameHeader, T>;
template <typename T> using ImmutableMgmtFrame = ImmutableFrame<MgmtFrameHeader, T>;

template <typename T> using CtrlFrame = BaseFrame<T>;
template <typename T> using ImmutableCtrlFrame = ImmutableBaseFrame<T>;

template <typename T> using DataFrame = Frame<DataFrameHeader, T>;
template <typename T> using ImmutableDataFrame = ImmutableFrame<DataFrameHeader, T>;

// TODO(hahnr): This isn't a great location for these definitions.
using aid_t = size_t;
static constexpr aid_t kGroupAdressedAid = 0;
static constexpr aid_t kMaxBssClients = 2008;
static constexpr aid_t kUnknownAid = kMaxBssClients + 1;

template <typename Body>
MgmtFrame<Body> BuildMgmtFrame(fbl::unique_ptr<Packet>* packet, size_t body_payload_len = 0,
                               bool has_ht_ctrl = false);

zx_status_t FillTxInfo(fbl::unique_ptr<Packet>* packet, const MgmtFrameHeader& hdr);

seq_t NextSeqNo(const MgmtFrameHeader& hdr, Sequence* seq);
seq_t NextSeqNo(const MgmtFrameHeader& hdr, uint8_t aci, Sequence* seq);
seq_t NextSeqNo(const DataFrameHeader& hdr, Sequence* seq);

void SetSeqNo(MgmtFrameHeader* hdr, Sequence* seq);
void SetSeqNo(MgmtFrameHeader* hdr, uint8_t aci, Sequence* seq);
void SetSeqNo(DataFrameHeader* hdr, Sequence* seq);
}  // namespace wlan
