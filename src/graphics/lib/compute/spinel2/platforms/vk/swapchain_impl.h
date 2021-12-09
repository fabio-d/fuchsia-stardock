// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_GRAPHICS_LIB_COMPUTE_SPINEL2_PLATFORMS_VK_SWAPCHAIN_IMPL_H_
#define SRC_GRAPHICS_LIB_COMPUTE_SPINEL2_PLATFORMS_VK_SWAPCHAIN_IMPL_H_

//
//
//

#include "device.h"
#include "swapchain.h"

//
//
//

spinel_result_t
spinel_swapchain_impl_create(struct spinel_device *                 device,
                             spinel_swapchain_create_info_t const * create_info,
                             spinel_swapchain_t *                   swapchain);

//
//
//

#endif  // SRC_GRAPHICS_LIB_COMPUTE_SPINEL2_PLATFORMS_VK_SWAPCHAIN_IMPL_H_
