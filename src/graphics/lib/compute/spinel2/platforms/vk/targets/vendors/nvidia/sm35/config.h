// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_GRAPHICS_LIB_COMPUTE_SPINEL2_PLATFORMS_VK_TARGETS_VENDORS_NVIDIA_SM35_CONFIG_H_
#define SRC_GRAPHICS_LIB_COMPUTE_SPINEL2_PLATFORMS_VK_TARGETS_VENDORS_NVIDIA_SM35_CONFIG_H_

//
// GLSL EXTENSIONS
//
// clang-format off
//
#ifdef VULKAN

#define SPN_EXT_ENABLE_SUBGROUP_UNIFORM                           1

#endif

//
// DEVICE-SPECIFIC
//
#define SPN_DEVICE_NVIDIA_SM50                                    1
#define SPN_DEVICE_SUBGROUP_SIZE_LOG2                             5   // 32
#define SPN_DEVICE_MAX_PUSH_CONSTANTS_SIZE                        256 // bytes
#define SPN_DEVICE_SMEM_PER_SUBGROUP_DWORDS                       512

//
// TILE CONFIGURATION
//
#define SPN_DEVICE_TILE_WIDTH_LOG2                                4
#define SPN_DEVICE_TILE_HEIGHT_LOG2                               4

//
// BLOCK POOL CONFIGURATION
//
// e.g. NVIDIA, AMD, Intel, ARM Bifrost, etc.
//
#define SPN_DEVICE_BLOCK_POOL_BLOCK_DWORDS_LOG2                   7
#define SPN_DEVICE_BLOCK_POOL_SUBBLOCK_DWORDS_LOG2                SPN_DEVICE_TILE_HEIGHT_LOG2

//
// KERNEL: BLOCK POOL INIT
//
#define SPN_DEVICE_BLOCK_POOL_INIT_SUBGROUP_SIZE_LOG2             0
#define SPN_DEVICE_BLOCK_POOL_INIT_WORKGROUP_SIZE                 128
#define SPN_DEVICE_BLOCK_POOL_INIT_BP_IDS_PER_INVOCATION          16

//
// KERNEL: PATHS ALLOC
//
// Note that this workgroup only uses one lane but, depending on the
// target, it might be necessary to launch at least a subgroup.
//
#define SPN_DEVICE_PATHS_ALLOC_SUBGROUP_SIZE_LOG2                 0
#define SPN_DEVICE_PATHS_ALLOC_WORKGROUP_SIZE                     1

//
// KERNEL: PATHS COPY
//
#define SPN_DEVICE_PATHS_COPY_SUBGROUP_SIZE_LOG2                  SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_PATHS_COPY_WORKGROUP_SIZE                      ((1 << SPN_DEVICE_PATHS_COPY_SUBGROUP_SIZE_LOG2) * 1)

//
// KERNEL: FILL SCAN
//
// e.g. NVIDIA, AMD, Intel, ARM Bifrost, etc.
//
#define SPN_DEVICE_FILL_SCAN_SUBGROUP_SIZE_LOG2                   SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_FILL_SCAN_WORKGROUP_SIZE                       ((1 << SPN_DEVICE_FILL_SCAN_SUBGROUP_SIZE_LOG2) * 1)
#define SPN_DEVICE_FILL_SCAN_ROWS                                 4
#define SPN_DEVICE_FILL_SCAN_EXPAND()                             SPN_EXPAND_4()
#define SPN_DEVICE_FILL_SCAN_EXPAND_I_LAST                        3

//
// KERNEL: FILL EXPAND
//
// e.g. NVIDIA, AMD, Intel, ARM Bifrost, etc.
//
#define SPN_DEVICE_FILL_EXPAND_SUBGROUP_SIZE_LOG2                 SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_FILL_EXPAND_WORKGROUP_SIZE                     ((1 << SPN_DEVICE_FILL_EXPAND_SUBGROUP_SIZE_LOG2) * 1)
// enable nvidia partition extensiona
#define SPN_DEVICE_FILL_EXPAND_ENABLE_SUBGROUP_PARTITION_NV       1

//
// KERNEL: FILL DISPATCH
//
#define SPN_DEVICE_FILL_DISPATCH_SUBGROUP_SIZE_LOG2               SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_FILL_DISPATCH_WORKGROUP_SIZE                   ((1 << SPN_DEVICE_FILL_DISPATCH_SUBGROUP_SIZE_LOG2) * 1)

//
// KERNEL: RASTERIZE_[LINES|QUADS|CUBICS|...]pus
//
// e.g. NVIDIA, AMD, Intel, ARM Bifrost, etc.
//
#define SPN_DEVICE_RASTERIZE_SUBGROUP_SIZE_LOG2                   SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_RASTERIZE_WORKGROUP_SIZE                       ((1 << SPN_DEVICE_RASTERIZE_SUBGROUP_SIZE_LOG2) * 1)
// can reduce this to force earlier launches of smaller grids
#define SPN_DEVICE_RASTERIZE_COHORT_SIZE                          (SPN_RASTER_COHORT_METAS_SIZE - 1)
// enable nvidia partition extension
#define SPN_DEVICE_RASTERIZE_ENABLE_SUBGROUP_PARTITION_NV         1

//
// KERNEL: TTRKS SEGMENT
//
#define SPN_DEVICE_TTRKS_SEGMENT_SUBGROUP_SIZE_LOG2               SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_TTRKS_SEGMENT_WORKGROUP_SIZE                   (2 * (1 << SPN_DEVICE_TTRKS_SEGMENT_SUBGROUP_SIZE_LOG2))
#define SPN_DEVICE_TTRKS_SEGMENT_ROWS                             1

//
// KERNEL: TTRKS SEGMENT DISPATCH
//
#define SPN_DEVICE_TTRKS_SEGMENT_DISPATCH_SUBGROUP_SIZE_LOG2      0
#define SPN_DEVICE_TTRKS_SEGMENT_DISPATCH_WORKGROUP_SIZE          1

//
// KERNEL: RASTERS ALLOC
//
#define SPN_DEVICE_RASTERS_ALLOC_SUBGROUP_SIZE_LOG2               SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_RASTERS_ALLOC_WORKGROUP_SIZE                   ((1 << SPN_DEVICE_RASTERS_ALLOC_SUBGROUP_SIZE_LOG2) * 1)

//
// KERNEL: RASTERS PREFIX
//
#define SPN_DEVICE_RASTERS_PREFIX_SUBGROUP_SIZE_LOG2              SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_RASTERS_PREFIX_WORKGROUP_SIZE                  ((1 << SPN_DEVICE_RASTERS_PREFIX_SUBGROUP_SIZE_LOG2) * 1)

//
// KERNEL: PLACE TTPK & TTSK
//
#define SPN_DEVICE_PLACE_SUBGROUP_SIZE_LOG2                       SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_PLACE_WORKGROUP_SIZE                           ((1 << SPN_DEVICE_PLACE_SUBGROUP_SIZE_LOG2) * 1)

//
// KERNEL: TTCKS SEGMENT
//
#define SPN_DEVICE_TTCKS_SEGMENT_SUBGROUP_SIZE_LOG2               SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_TTCKS_SEGMENT_WORKGROUP_SIZE                   ((1 << SPN_DEVICE_TTCKS_SEGMENT_SUBGROUP_SIZE_LOG2) * 1)
#define SPN_DEVICE_TTCKS_SEGMENT_ROWS                             1

//
// KERNEL: TTCKS SEGMENT DISPATCH
//
#define SPN_DEVICE_TTCKS_SEGMENT_DISPATCH_SUBGROUP_SIZE_LOG2      0
#define SPN_DEVICE_TTCKS_SEGMENT_DISPATCH_WORKGROUP_SIZE          1

//
// KERNEL: RENDER
//
#define SPN_DEVICE_RENDER_SUBGROUP_SIZE_LOG2                      SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_RENDER_WORKGROUP_SIZE                          ((1 << SPN_DEVICE_RENDER_SUBGROUP_SIZE_LOG2) * 1)
// config switches
#define SPN_DEVICE_RENDER_LGF_USE_SHUFFLE
#define SPN_DEVICE_RENDER_TTCKS_USE_SHUFFLE
#define SPN_DEVICE_RENDER_STYLING_CMDS_USE_SHUFFLE
#define SPN_DEVICE_RENDER_COVERAGE_USE_SHUFFLE
//
// TODO(allanmac): generate a new target for NVIDIA devices that support fp16
//
#if 1
#define SPN_DEVICE_RENDER_TILE_CHANNEL_IS_FLOAT32                 // CC: 3.0, 3.2, 3.5, 3.7, 5.0, 5.2, 6.1
#else
#define SPN_DEVICE_RENDER_TILE_CHANNEL_IS_FLOAT16                 // CC: 5.3, 6.0, 6.2, 7.x
#endif
// expecting VK_FORMAT_R8G8B8A8_UNORM or equivalent
#define SPN_DEVICE_RENDER_SURFACE_TYPE                            rgba8

//
// KERNEL: RENDER DISPATCH
//
#define SPN_DEVICE_RENDER_DISPATCH_SUBGROUP_SIZE_LOG2             0
#define SPN_DEVICE_RENDER_DISPATCH_WORKGROUP_SIZE                 1

//
// KERNEL: PATHS RECLAIM
//
#define SPN_DEVICE_PATHS_RECLAIM_SUBGROUP_SIZE_LOG2               SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_PATHS_RECLAIM_WORKGROUP_SIZE                   ((1 << SPN_DEVICE_PATHS_RECLAIM_SUBGROUP_SIZE_LOG2) * 1)

//
// KERNEL: RASTERS RECLAIM
//
#define SPN_DEVICE_RASTERS_RECLAIM_SUBGROUP_SIZE_LOG2             SPN_DEVICE_SUBGROUP_SIZE_LOG2
#define SPN_DEVICE_RASTERS_RECLAIM_WORKGROUP_SIZE                 ((1 << SPN_DEVICE_RASTERS_RECLAIM_SUBGROUP_SIZE_LOG2) * 1)

//
// clang-format on
//

#endif  // SRC_GRAPHICS_LIB_COMPUTE_SPINEL2_PLATFORMS_VK_TARGETS_VENDORS_NVIDIA_SM35_CONFIG_H_
