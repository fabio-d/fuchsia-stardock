// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2008-2010, 2015 Travis Geiselbrecht
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <debug.h>
#include <lib/gfx/gfx.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>
#include <zircon/errors.h>
#include <zircon/types.h>

#include <arch/ops.h>
#include <dev/display.h>

#if LK_DEBUGLEVEL > 1
#include <lib/console.h>
#endif

#define LOCAL_TRACE 0

namespace gfx {

/**
 * @brief  Create a new graphics surface object from a display
 */
Surface* CreateSurfaceFromDisplay(display_info* info) {
  Surface* surface = static_cast<Surface*>(calloc(1, sizeof(*surface)));
  if (surface == NULL)
    return NULL;
  if (InitSurfaceFromDisplay(surface, info)) {
    free(surface);
    return NULL;
  }
  return surface;
}

zx_status_t InitSurfaceFromDisplay(Surface* surface, display_info* info) {
  zx_status_t r;
  switch (info->format) {
    case ZX_PIXEL_FORMAT_RGB_565:
    case ZX_PIXEL_FORMAT_RGB_332:
    case ZX_PIXEL_FORMAT_RGB_2220:
    case ZX_PIXEL_FORMAT_ARGB_8888:
    case ZX_PIXEL_FORMAT_RGB_x888:
    case ZX_PIXEL_FORMAT_MONO_8:
      // supported formats
      break;
    default:
      dprintf(CRITICAL, "invalid graphics format %x", info->format);
      return ZX_ERR_INVALID_ARGS;
  }

  uint32_t flags = (info->flags & DISPLAY_FLAG_NEEDS_CACHE_FLUSH) ? GFX_FLAG_FLUSH_CPU_CACHE : 0;
  r = InitSurface(surface, info->framebuffer, info->width, info->height, info->stride, info->format,
                  flags);

  surface->Flush = info->flush;
  return r;
}

/**
 * @brief  Write a test pattern to the default display.
 */
void DrawPattern(void) {
  display_info info;
  if (display_get_info(&info) < 0)
    return;

  Surface* surface = CreateSurfaceFromDisplay(&info);
  DEBUG_ASSERT(surface != nullptr);

  uint x, y;
  for (y = 0; y < surface->height; y++) {
    for (x = 0; x < surface->width; x++) {
      uint scaledx;
      uint scaledy;

      scaledx = x * 256 / surface->width;
      scaledy = y * 256 / surface->height;

      PutPixel(surface, x, y,
               (0xff << 24) | (scaledx * scaledy) << 16 | (scaledx >> 1) << 8 | scaledy >> 1);
    }
  }

  Flush(surface);

  DestroySurface(surface);
}

#if LK_DEBUGLEVEL > 1

static int cmd_gfx(int argc, const cmd_args* argv, uint32_t flags);

STATIC_COMMAND_START
STATIC_COMMAND("gfx", "gfx commands", &cmd_gfx)
STATIC_COMMAND_END(gfx)

static int DrawRgbBars(Surface* surface) {
  uint x, y;

  uint step = surface->height * 100 / 256;
  uint color;

  for (y = 0; y < surface->height; y++) {
    // R
    for (x = 0; x < surface->width / 3; x++) {
      color = y * 100 / step;
      PutPixel(surface, x, y, 0xff << 24 | color << 16);
    }
    // G
    for (; x < 2 * (surface->width / 3); x++) {
      color = y * 100 / step;
      PutPixel(surface, x, y, 0xff << 24 | color << 8);
    }
    // B
    for (; x < surface->width; x++) {
      color = y * 100 / step;
      PutPixel(surface, x, y, 0xff << 24 | color);
    }
  }

  return 0;
}

static int cmd_gfx(int argc, const cmd_args* argv, uint32_t flags) {
  if (argc < 2) {
    printf("not enough arguments:\n");
    printf("%s display_info : output information bout the current display\n", argv[0].str);
    printf("%s rgb_bars   : Fill frame buffer with rgb bars\n", argv[0].str);
    printf("%s test_pattern : Fill frame with test pattern\n", argv[0].str);
    printf("%s fill r g b   : Fill frame buffer with RGB888 value and force update\n", argv[0].str);

    return -1;
  }

  display_info info;
  if (display_get_info(&info) < 0) {
    printf("no display to draw on!\n");
    return -1;
  }

  Surface* surface = CreateSurfaceFromDisplay(&info);
  DEBUG_ASSERT(surface != nullptr);

  if (!strcmp(argv[1].str, "display_info")) {
    printf("display:\n");
    printf("\tframebuffer %p\n", info.framebuffer);
    printf("\twidth %u height %u stride %u\n", info.width, info.height, info.stride);
    printf("\tformat 0x%x\n", info.format);
    printf("\tflags 0x%x\n", info.flags);
  } else if (!strcmp(argv[1].str, "rgb_bars")) {
    DrawRgbBars(surface);
  } else if (!strcmp(argv[1].str, "test_pattern")) {
    DrawPattern();
  } else if (!strcmp(argv[1].str, "fill")) {
    uint x, y;

    uint fillval =
        static_cast<uint>((0xff << 24) | (argv[2].u << 16) | (argv[3].u << 8) | argv[4].u);
    for (y = 0; y < surface->height; y++) {
      for (x = 0; x < surface->width; x++) {
        /* write pixel to frame buffer */
        PutPixel(surface, x, y, fillval);
      }
    }
  }

  Flush(surface);

  DestroySurface(surface);

  return 0;
}

#endif

}  // namespace gfx
