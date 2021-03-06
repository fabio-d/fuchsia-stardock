// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <lib/gfx/surface.h>

#include <map>

#include <fuzzer/FuzzedDataProvider.h>

static const unsigned kMaxDimension = 4096;

static bool IsBlendable(gfx::Surface* a, gfx::Surface* b) {
  if (a->format != b->format) {
    return false;
  }

  switch (a->format) {
    case ZX_PIXEL_FORMAT_ARGB_8888:
      return true;
    case ZX_PIXEL_FORMAT_RGB_x888:
      return true;
    case ZX_PIXEL_FORMAT_MONO_8:
      return true;
    default:
      return false;
  }
}

static gfx::Surface* LookupSurface(FuzzedDataProvider* input,
                                   const std::map<unsigned, gfx::Surface*>* surfaces) {
  auto id = input->ConsumeIntegral<unsigned>();
  auto it = surfaces->find(id);
  if (it == surfaces->end()) {
    return nullptr;
  }
  return it->second;
}

unsigned ReadPixelFormat(FuzzedDataProvider* input) {
  static const unsigned LEGAL_PIXEL_FORMATS[] = {
      ZX_PIXEL_FORMAT_RGB_565,   ZX_PIXEL_FORMAT_RGB_332,  ZX_PIXEL_FORMAT_RGB_2220,
      ZX_PIXEL_FORMAT_ARGB_8888, ZX_PIXEL_FORMAT_RGB_x888, ZX_PIXEL_FORMAT_MONO_8,
      ZX_PIXEL_FORMAT_GRAY_8,    ZX_PIXEL_FORMAT_NV12,     ZX_PIXEL_FORMAT_RGB_888,
  };
  return LEGAL_PIXEL_FORMATS[input->ConsumeIntegralInRange<uint8_t>(
      0, sizeof(LEGAL_PIXEL_FORMATS) / sizeof(*LEGAL_PIXEL_FORMATS) - 1)];
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider input(data, size);
  std::map<unsigned, gfx::Surface*> surfaces;

  while (true) {
    switch (input.ConsumeIntegral<uint8_t>()) {
      default:
      case 0: {
        for (auto [id, surface] : surfaces) {
          gfx::DestroySurface(surface);
        }
        surfaces.clear();
        return 0;
      }

      case 1: {
        auto id = input.ConsumeIntegral<unsigned>();
        if (surfaces.count(id)) {
          break;
        }
        auto width = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
        auto height = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
        auto stride = width + input.ConsumeIntegral<uint8_t>();
        auto pixel_format = ReadPixelFormat(&input);
        auto flags = input.ConsumeIntegral<unsigned>() & (GFX_FLAG_FLUSH_CPU_CACHE);
        if (auto* surface =
                gfx::CreateSurface(nullptr, width, height, stride, pixel_format, flags)) {
          surfaces[id] = surface;
        }
        break;
      }

      case 2: {
        auto id = input.ConsumeIntegral<unsigned>();
        auto it = surfaces.find(id);
        if (it == surfaces.end()) {
          break;
        }
        gfx::DestroySurface(it->second);
        surfaces.erase(it);
        break;
      }

      case 3:
        if (auto* surface = LookupSurface(&input, &surfaces)) {
          gfx::Flush(surface);
        }
        break;

      case 4:
        if (auto* surface = LookupSurface(&input, &surfaces)) {
          auto x = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto y = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto width = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
          auto height = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
          auto x2 = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto y2 = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          gfx::CopyRectangle(surface, x, y, width, height, x2, y2);
        }
        break;

      case 5:
        if (auto* surface = LookupSurface(&input, &surfaces)) {
          auto x = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto y = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto width = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
          auto height = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
          auto color = input.ConsumeIntegral<unsigned>();
          gfx::FillRectangle(surface, x, y, width, height, color);
        }
        break;

      case 6:
        if (auto* surface = LookupSurface(&input, &surfaces)) {
          auto x = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto y = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto color = input.ConsumeIntegral<unsigned>();
          gfx::PutPixel(surface, x, y, color);
        }
        break;

      case 7:
        if (auto* surface = LookupSurface(&input, &surfaces)) {
          auto x = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto y = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto x2 = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto y2 = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
          auto color = input.ConsumeIntegral<unsigned>();
          gfx::DrawLine(surface, x, y, x2, y2, color);
        }
        break;

      case 8:
        if (auto* surface1 = LookupSurface(&input, &surfaces)) {
          if (auto* surface2 = LookupSurface(&input, &surfaces)) {
            if (!IsBlendable(surface1, surface2)) {
              break;
            }
            auto destx = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            auto desty = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            gfx::Blend(surface1, surface2, destx, desty);
          }
        }
        break;

      case 9:
        if (auto* surface1 = LookupSurface(&input, &surfaces)) {
          if (auto* surface2 = LookupSurface(&input, &surfaces)) {
            if (!IsBlendable(surface1, surface2)) {
              break;
            }
            auto srcx = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            auto srcy = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            auto width = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
            auto height = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
            auto destx = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            auto desty = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            gfx::Blend(surface1, surface2, srcx, srcy, width, height, destx, desty);
          }
        }
        break;

      case 10:
        if (auto* surface1 = LookupSurface(&input, &surfaces)) {
          if (auto* surface2 = LookupSurface(&input, &surfaces)) {
            auto srcy = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            auto desty = input.ConsumeIntegralInRange<unsigned>(0, kMaxDimension);
            auto height = input.ConsumeIntegralInRange<unsigned>(1, kMaxDimension);
            gfx::CopyLines(surface1, surface2, srcy, desty, height);
          }
        }
        break;

      case 11:
        if (auto* surface = LookupSurface(&input, &surfaces)) {
          auto color = input.ConsumeIntegral<unsigned>();
          gfx::Clear(surface, color);
        }
        break;
    }
  }
}
