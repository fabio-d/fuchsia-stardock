// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    borrow::Cow,
    cell::{RefCell, RefMut},
    collections::hash_map::Entry,
    mem,
    rc::Rc,
};

use rustc_hash::FxHashMap;
use surpass::{
    self,
    painter::{for_each_row, Channel, Color, LayerProps, Props, Rect},
    rasterizer::Rasterizer,
    LinesBuilder,
};

use crate::{
    buffer::{layout::Layout, Buffer, BufferLayerCache},
    layer::{self, IdSet, SmallBitSet},
};

const LINES_GARBAGE_THRESHOLD: usize = 2;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LayerId(usize);

/// Internal ID use to track line data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CompositionId(u32);

/// Per pixel segment ID used by the renderer to track order and properties.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PixelSegmentId(u32);

#[derive(Debug)]
pub(crate) struct Layer {
    pub(crate) id: LayerId,
    pub(crate) inner: surpass::Layer,
    pub(crate) props: Props,
    pub(crate) is_unchanged: SmallBitSet,
    pub(crate) len: usize,
}

impl Layer {
    #[inline]
    pub(crate) fn new(id: LayerId, order: u32) -> Self {
        Self {
            id,
            inner: surpass::Layer { order: Some(order), is_enabled: true, ..Default::default() },
            props: Default::default(),
            is_unchanged: Default::default(),
            len: Default::default(),
        }
    }

    #[inline]
    pub(crate) fn is_unchanged(&self, cache_id: u8) -> bool {
        self.is_unchanged.contains(&cache_id)
    }

    #[inline]
    pub(crate) fn set_is_unchanged(&mut self, cache_id: u8, is_unchanged: bool) -> bool {
        if is_unchanged {
            self.is_unchanged.insert(cache_id)
        } else {
            self.is_unchanged.remove(cache_id)
        }
    }
}

#[derive(Debug)]
pub struct Composition {
    // Option makes it possible to take the value without paying the cost of
    // initializing a new line buffer.
    builder: RefCell<Option<LinesBuilder>>,
    rasterizer: Rasterizer,
    layers: FxHashMap<CompositionId, Layer>,
    composition_ids: IdSet,
    layer_id_count: usize,
    layer_id_to_composition_id: FxHashMap<LayerId, CompositionId>,
    pixel_segment_id_to_composition_id: FxHashMap<PixelSegmentId, CompositionId>,
    buffers_with_caches: Rc<RefCell<SmallBitSet>>,
}

impl Composition {
    #[inline]
    pub fn new() -> Self {
        Self {
            builder: RefCell::new(Some(LinesBuilder::new())),
            rasterizer: Rasterizer::new(),
            layers: FxHashMap::default(),
            composition_ids: IdSet::new(),
            layer_id_count: 0,
            layer_id_to_composition_id: FxHashMap::default(),
            pixel_segment_id_to_composition_id: FxHashMap::default(),
            buffers_with_caches: Rc::new(RefCell::new(SmallBitSet::default())),
        }
    }

    fn builder_len(&self) -> usize {
        self.builder.borrow().as_ref().unwrap().len()
    }

    pub fn create_layer(&mut self) -> Option<layer::Layer<'_>> {
        // Generate a user-facing layer ID.
        let layer_id = {
            let count = self.layer_id_count;
            LayerId(mem::replace(&mut self.layer_id_count, count + 1))
        };

        // Generate a composition ID used to track line data in LinesBuilder.
        let id = self.composition_ids.acquire();
        // TODO(plabatut): Attempt to remove the duplicated call to `remove_disabled()`.
        if id.is_none() {
            self.remove_disabled();
        }
        let id = id.or_else(|| {
            self.remove_disabled();
            self.composition_ids.acquire()
        })?;
        let composition_id = CompositionId(id);

        assert!(
            self.layer_id_to_composition_id.insert(layer_id, composition_id).is_none(),
            "CompositionId should already have been removed by self.remove_disabled"
        );

        let layer = match self.layers.entry(composition_id) {
            Entry::Vacant(entry) => entry.insert(Layer::new(layer_id, composition_id.0)),
            _ => unreachable!("Layer should already have been removed by self.remove_disabled"),
        };

        Some(layer::Layer { layer, lines_builder: &self.builder })
    }

    #[inline]
    pub fn layer(&mut self, layer_id: LayerId) -> Option<layer::Layer<'_>> {
        // TODO: remove with 2021 edition.
        let layers = &mut self.layers;
        let line_builder = &mut self.builder;
        self.layer_id_to_composition_id
            .get(&layer_id)
            .and_then(move |id| layers.get_mut(id))
            .and_then(move |layer| Some(layer::Layer { layer: layer, lines_builder: line_builder }))
    }

    #[inline]
    pub fn layers(&mut self) -> impl Iterator<Item = layer::Layer<'_>> {
        let builder = &self.builder;
        self.layers.values_mut().map(move |layer| layer::Layer { layer, lines_builder: builder })
    }

    /// Number of active layers.
    fn actual_len(&self) -> usize {
        self.layers.values().filter_map(|layer| layer.inner.is_enabled.then(|| layer.len)).sum()
    }

    #[inline]
    pub fn remove_disabled(&mut self) {
        if self.builder_len() >= self.actual_len() * LINES_GARBAGE_THRESHOLD {
            let layers = &mut self.layers;
            self.builder.get_mut().as_mut().unwrap().retain(move |id| {
                layers
                    .get(&CompositionId(id))
                    .map(|layer| layer.inner.is_enabled)
                    .unwrap_or_default()
            });

            let internal_ids = &mut self.composition_ids;
            self.layers.retain(|&composition_id, layer| {
                if !layer.inner.is_enabled {
                    internal_ids.release(composition_id.0);
                }

                layer.inner.is_enabled
            });

            let layers = &mut self.layers;
            self.layer_id_to_composition_id
                .retain(|_, composition_id| layers.contains_key(composition_id));
        }
    }

    #[inline]
    pub fn create_buffer_layer_cache(&mut self) -> Option<BufferLayerCache> {
        self.buffers_with_caches.borrow_mut().first_empty_slot().map(|id| BufferLayerCache {
            id,
            cache: Default::default(),
            buffers_with_caches: Rc::downgrade(&self.buffers_with_caches),
        })
    }

    pub fn render<L>(
        &mut self,
        buffer: &mut Buffer<'_, '_, L>,
        mut channels: [Channel; 4],
        clear_color: Color,
        crop: Option<Rect>,
    ) where
        L: Layout,
    {
        // If `clear_color` has alpha = 1 we can upgrade the alpha channel to `Channel::One`
        // in order to skip reading the alpha channel.
        if clear_color.a == 1.0 {
            channels = channels.map(|c| match c {
                Channel::Alpha => Channel::One,
                c => c,
            });
        }

        if let Some(buffer_layer_cache) = buffer.layer_cache.as_ref() {
            let tiles_len = buffer.layout.width_in_tiles() * buffer.layout.height_in_tiles();

            if buffer_layer_cache.cache.borrow().1.len() != tiles_len {
                buffer_layer_cache.cache.borrow_mut().1.resize(tiles_len, None);
                buffer_layer_cache.clear();
            }
        }

        self.remove_disabled();

        for (id, layer) in &self.layers {
            if layer.inner.is_enabled {
                self.pixel_segment_id_to_composition_id.insert(
                    PixelSegmentId(layer.inner.order.expect("Layers should always have orders")),
                    *id,
                );
            }
        }

        let layers = &self.layers;
        let pixel_segment_id_to_composition_id = &self.pixel_segment_id_to_composition_id;
        let rasterizer = &mut self.rasterizer;

        struct CompositionContext<'l> {
            layers: &'l FxHashMap<CompositionId, Layer>,
            pixel_segment_id_to_composition_id: &'l FxHashMap<PixelSegmentId, CompositionId>,
            cache_id: Option<u8>,
        }

        impl LayerProps for CompositionContext<'_> {
            #[inline]
            fn get(&self, id: u32) -> Cow<'_, Props> {
                let composition_id = self
                    .pixel_segment_id_to_composition_id
                    .get(&PixelSegmentId(id))
                    .expect("pixel_segment_id_to_composition_id was not populated in Composition::render");
                Cow::Borrowed(
                    self.layers
                        .get(composition_id)
                        .map(|layer| &layer.props)
                        .expect("pixel_segment_id_to_composition_id points to non-existant Layer"),
                )
            }

            #[inline]
            fn is_unchanged(&self, id: u32) -> bool {
                match self.cache_id {
                    None => false,
                    Some(cache_id) => {
                        let composition_id = self
                            .pixel_segment_id_to_composition_id
                            .get(&PixelSegmentId(id))
                            .expect("pixel_segment_id_to_composition_id was not populated in Composition::render");
                        self.layers
                            .get(composition_id)
                            .map(|layer| layer.is_unchanged(cache_id))
                            .expect(
                                "pixel_segment_id_to_composition_id points to non-existant Layer",
                            )
                    }
                }
            }
        }

        let context = CompositionContext {
            layers,
            pixel_segment_id_to_composition_id,
            cache_id: buffer.layer_cache.as_ref().map(|cache| cache.id),
        };

        // `take()` sets the RefCell's content with `Default::default()` which is cheap for Option.
        let builder = self.builder.take().unwrap();
        self.builder.replace({
            let lines = {
                duration!("gfx", "LinesBuilder::build");
                builder.build(|id| layers.get(&CompositionId(id)).map(|layer| layer.inner.clone()))
            };

            {
                duration!("gfx", "Rasterizer::rasterize");
                rasterizer.rasterize(&lines);
            }
            {
                duration!("gfx", "Rasterizer::sort");
                rasterizer.sort();
            }

            let previous_clear_color =
                buffer.layer_cache.as_ref().and_then(|layer_cache| layer_cache.cache.borrow().0);

            let layers_per_tile = buffer.layer_cache.as_ref().map(|layer_cache| {
                RefMut::map(layer_cache.cache.borrow_mut(), |cache| &mut cache.1)
            });

            {
                duration!("gfx", "painter::for_each_row");
                for_each_row(
                    buffer.layout,
                    buffer.buffer,
                    channels,
                    buffer.flusher.as_deref(),
                    previous_clear_color,
                    layers_per_tile,
                    rasterizer.segments(),
                    clear_color,
                    &crop,
                    &context,
                );
            }

            Some(lines.unwrap())
        });

        if let Some(buffer_layer_cache) = &buffer.layer_cache {
            buffer_layer_cache.cache.borrow_mut().0 = Some(clear_color);

            for layer in self.layers.values_mut() {
                layer.set_is_unchanged(buffer_layer_cache.id, layer.inner.is_enabled);
            }
        }
    }
}

impl Default for Composition {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryFrom;

    use surpass::{
        painter::{Color, RGBA},
        Path, TILE_HEIGHT, TILE_WIDTH,
    };

    use crate::{
        buffer::{layout::LinearLayout, BufferBuilder},
        Fill, FillRule, Func, GeomPresTransform, PathBuilder, Point, Style,
    };

    const BLACK_SRGB: [u8; 4] = [0x00, 0x00, 0x00, 0xFF];
    const GRAY_SRGB: [u8; 4] = [0xBB, 0xBB, 0xBB, 0xFF];
    const GRAY_ALPHA_50_SRGB: [u8; 4] = [0xBB, 0xBB, 0xBB, 0x80];
    const WHITE_ALPHA_0_SRGB: [u8; 4] = [0xFF, 0xFF, 0xFF, 0x00];
    const RED_SRGB: [u8; 4] = [0xFF, 0x00, 0x00, 0xFF];
    const GREEN_SRGB: [u8; 4] = [0x00, 0xFF, 0x00, 0xFF];
    const RED_50_GREEN_50_SRGB: [u8; 4] = [0xBB, 0xBB, 0x00, 0xFF];

    const BLACK: Color = Color { r: 0.0, g: 0.0, b: 0.0, a: 1.0 };
    const BLACK_ALPHA_50: Color = Color { r: 0.0, g: 0.0, b: 0.0, a: 0.5 };
    const GRAY: Color = Color { r: 0.5, g: 0.5, b: 0.5, a: 1.0 };
    const WHITE_TRANSPARENT: Color = Color { r: 1.0, g: 1.0, b: 1.0, a: 0.0 };
    const RED: Color = Color { r: 1.0, g: 0.0, b: 0.0, a: 1.0 };
    const GREEN: Color = Color { r: 0.0, g: 1.0, b: 0.0, a: 1.0 };

    fn pixel_path(x: i32, y: i32) -> Path {
        let mut builder = PathBuilder::new();

        builder.move_to(Point::new(x as f32, y as f32));
        builder.line_to(Point::new(x as f32, (y + 1) as f32));
        builder.line_to(Point::new((x + 1) as f32, (y + 1) as f32));
        builder.line_to(Point::new((x + 1) as f32, y as f32));
        builder.line_to(Point::new(x as f32, y as f32));

        builder.build()
    }

    fn solid(color: Color) -> Props {
        Props {
            func: Func::Draw(Style { fill: Fill::Solid(color), ..Default::default() }),
            ..Default::default()
        }
    }

    #[test]
    fn background_color_clear() {
        let mut buffer = [GREEN_SRGB].concat();
        let mut layout = LinearLayout::new(1, 4, 1);

        let mut composition = Composition::new();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            RED,
            None,
        );

        assert_eq!(buffer, [RED_SRGB].concat());
    }

    #[test]
    fn background_color_clear_when_changed() {
        let mut buffer = [GREEN_SRGB].concat();
        let mut layout = LinearLayout::new(1, 4, 1);

        let mut composition = Composition::new();
        let layer_cache = composition.create_buffer_layer_cache().unwrap();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone())
                .build(),
            RGBA,
            RED,
            None,
        );

        assert_eq!(buffer, [RED_SRGB].concat());

        buffer = [GREEN_SRGB].concat();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone())
                .build(),
            RGBA,
            RED,
            None,
        );

        // Skip clearing if the color is the same.
        assert_eq!(buffer, [GREEN_SRGB].concat());

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer, [BLACK_SRGB].concat());
    }

    #[test]
    fn one_pixel() {
        let mut buffer = [GREEN_SRGB; 3].concat();
        let mut layout = LinearLayout::new(3, 3 * 4, 1);

        let mut composition = Composition::new();

        composition.create_layer().unwrap().insert(&pixel_path(1, 0)).set_props(solid(RED));

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [GREEN_SRGB, RED_SRGB, GREEN_SRGB].concat());
    }

    #[test]
    fn two_pixels_same_layer() {
        let mut buffer = [GREEN_SRGB; 3].concat();
        let mut layout = LinearLayout::new(3, 3 * 4, 1);
        let mut composition = Composition::new();

        composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(1, 0))
            .insert(&pixel_path(2, 0))
            .set_props(solid(RED));

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [GREEN_SRGB, RED_SRGB, RED_SRGB].concat());
    }

    #[test]
    fn one_pixel_translated() {
        let mut buffer = [GREEN_SRGB; 3].concat();
        let mut layout = LinearLayout::new(3, 3 * 4, 1);

        let mut composition = Composition::new();

        composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(1, 0))
            .set_props(solid(RED))
            .set_transform(GeomPresTransform::try_from([1.0, 0.0, 0.0, 1.0, 0.5, 0.0]).unwrap());

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [GREEN_SRGB, RED_50_GREEN_50_SRGB, RED_50_GREEN_50_SRGB].concat());
    }

    #[test]
    fn one_pixel_rotated() {
        let mut buffer = [GREEN_SRGB; 3].concat();
        let mut layout = LinearLayout::new(3, 3 * 4, 1);

        let mut composition = Composition::new();
        let angle = -std::f32::consts::PI / 2.0;

        composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(-1, 1))
            .set_props(solid(RED))
            .set_transform(
                GeomPresTransform::try_from([
                    angle.cos(),
                    -angle.sin(),
                    angle.sin(),
                    angle.cos(),
                    0.0,
                    0.0,
                ])
                .unwrap(),
            );

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [GREEN_SRGB, RED_SRGB, GREEN_SRGB].concat());
    }

    #[test]
    fn remove_and_resize() {
        let mut buffer = [GREEN_SRGB; 4].concat();
        let mut composition = Composition::new();

        let layer_id0 = composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(0, 0))
            .set_props(solid(RED))
            .id();

        composition.create_layer().unwrap().insert(&pixel_path(1, 0)).set_props(solid(RED));

        let layer_id2 = composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(2, 0))
            .insert(&pixel_path(3, 0))
            .set_props(solid(RED))
            .id();

        let mut layout = LinearLayout::new(4, 4 * 4, 1);

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [RED_SRGB, RED_SRGB, RED_SRGB, RED_SRGB].concat());
        assert_eq!(composition.builder_len(), 16);
        assert_eq!(composition.actual_len(), 16);

        buffer = [GREEN_SRGB; 4].concat();

        let mut layout = LinearLayout::new(4, 4 * 4, 1);

        composition.layer(layer_id0).unwrap().disable();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [GREEN_SRGB, RED_SRGB, RED_SRGB, RED_SRGB].concat());
        assert_eq!(composition.builder_len(), 16);
        assert_eq!(composition.actual_len(), 12);

        buffer = [GREEN_SRGB; 4].concat();

        let mut layout = LinearLayout::new(4, 4 * 4, 1);

        composition.layer(layer_id2).unwrap().disable();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            GREEN,
            None,
        );

        assert_eq!(buffer, [GREEN_SRGB, RED_SRGB, GREEN_SRGB, GREEN_SRGB].concat());
        assert_eq!(composition.builder_len(), 4);
        assert_eq!(composition.actual_len(), 4);
    }

    #[test]
    fn remove_twice() {
        let mut composition = Composition::new();

        let layer_id = composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(0, 0))
            .set_props(solid(RED))
            .id();
        assert_eq!(composition.actual_len(), 4);

        composition.layer(layer_id).unwrap().disable();

        assert_eq!(composition.actual_len(), 0);

        composition.layer(layer_id).unwrap().disable();

        assert_eq!(composition.actual_len(), 0);
    }

    #[test]
    fn srgb_alpha_blending() {
        let mut buffer = [BLACK_SRGB; 3].concat();
        let mut layout = LinearLayout::new(3, 3 * 4, 1);

        let mut composition = Composition::new();

        composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(0, 0))
            .set_props(solid(BLACK_ALPHA_50));
        composition.create_layer().unwrap().insert(&pixel_path(1, 0)).set_props(solid(GRAY));

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            WHITE_TRANSPARENT,
            None,
        );

        assert_eq!(buffer, [GRAY_ALPHA_50_SRGB, GRAY_SRGB, WHITE_ALPHA_0_SRGB].concat());
    }

    #[test]
    fn render_change_layers_only() {
        let mut buffer = [BLACK_SRGB; 3 * TILE_WIDTH * TILE_HEIGHT].concat();
        let mut layout = LinearLayout::new(3 * TILE_WIDTH, 3 * TILE_WIDTH * 4, TILE_HEIGHT);
        let mut composition = Composition::new();
        let layer_cache = composition.create_buffer_layer_cache();

        composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(0, 0))
            .insert(&pixel_path(TILE_WIDTH as i32, 0))
            .set_props(solid(RED));

        let layer_id = composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(TILE_WIDTH as i32 + 1, 0))
            .insert(&pixel_path(2 * TILE_WIDTH as i32, 0))
            .set_props(solid(GREEN))
            .id();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], RED_SRGB);
        assert_eq!(buffer[TILE_WIDTH * 4..TILE_WIDTH * 4 + 4], RED_SRGB);
        assert_eq!(buffer[(TILE_WIDTH + 1) * 4..(TILE_WIDTH + 1) * 4 + 4], GREEN_SRGB);
        assert_eq!(buffer[2 * TILE_WIDTH * 4..2 * TILE_WIDTH * 4 + 4], GREEN_SRGB);

        let mut buffer = [BLACK_SRGB; 3 * TILE_WIDTH * TILE_HEIGHT].concat();

        composition.layer(layer_id).unwrap().set_props(solid(RED));

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], BLACK_SRGB);
        assert_eq!(buffer[TILE_WIDTH * 4..TILE_WIDTH * 4 + 4], RED_SRGB);
        assert_eq!(buffer[(TILE_WIDTH + 1) * 4..(TILE_WIDTH + 1) * 4 + 4], RED_SRGB);
        assert_eq!(buffer[2 * TILE_WIDTH * 4..2 * TILE_WIDTH * 4 + 4], RED_SRGB);
    }

    #[test]
    fn clear_emptied_tiles() {
        let mut buffer = [BLACK_SRGB; 2 * TILE_WIDTH * TILE_HEIGHT].concat();
        let mut layout = LinearLayout::new(2 * TILE_WIDTH, 2 * TILE_WIDTH * 4, TILE_HEIGHT);
        let mut composition = Composition::new();
        let layer_cache = composition.create_buffer_layer_cache();

        let layer_id = composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(0, 0))
            .set_props(solid(RED))
            .insert(&pixel_path(TILE_WIDTH as i32, 0))
            .id();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], RED_SRGB);

        composition.layer(layer_id).unwrap().set_transform(
            GeomPresTransform::try_from([1.0, 0.0, 0.0, 1.0, TILE_WIDTH as f32, 0.0]).unwrap(),
        );

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], BLACK_SRGB);

        composition.layer(layer_id).unwrap().set_transform(
            GeomPresTransform::try_from([1.0, 0.0, 0.0, 1.0, -(TILE_WIDTH as f32), 0.0]).unwrap(),
        );

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], RED_SRGB);

        composition.layer(layer_id).unwrap().set_transform(
            GeomPresTransform::try_from([1.0, 0.0, 0.0, 1.0, 0.0, TILE_HEIGHT as f32]).unwrap(),
        );

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache.unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], BLACK_SRGB);
    }

    #[test]
    fn separate_layer_caches() {
        let mut buffer = [BLACK_SRGB; TILE_WIDTH * TILE_HEIGHT].concat();
        let mut layout = LinearLayout::new(TILE_WIDTH, TILE_WIDTH * 4, TILE_HEIGHT);
        let mut composition = Composition::new();
        let layer_cache0 = composition.create_buffer_layer_cache();
        let layer_cache1 = composition.create_buffer_layer_cache();

        let layer_id = composition
            .create_layer()
            .unwrap()
            .insert(&pixel_path(0, 0))
            .set_props(solid(RED))
            .id();
        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache0.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], RED_SRGB);

        let mut buffer = [BLACK_SRGB; TILE_WIDTH * TILE_HEIGHT].concat();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache0.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], BLACK_SRGB);

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache1.clone().unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], RED_SRGB);

        composition
            .layer(layer_id)
            .unwrap()
            .set_transform(GeomPresTransform::try_from([1.0, 0.0, 0.0, 1.0, 1.0, 0.0]).unwrap());

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache0.unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], BLACK_SRGB);
        assert_eq!(buffer[4..8], RED_SRGB);

        let mut buffer = [BLACK_SRGB; TILE_WIDTH * TILE_HEIGHT].concat();

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout)
                .layer_cache(layer_cache1.unwrap())
                .build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], BLACK_SRGB);
        assert_eq!(buffer[4..8], RED_SRGB);
    }

    #[test]
    fn even_odd() {
        let mut builder = PathBuilder::new();

        builder.move_to(Point::new(0.0, 0.0));
        builder.line_to(Point::new(0.0, TILE_HEIGHT as f32));
        builder.line_to(Point::new(3.0 * TILE_WIDTH as f32, TILE_HEIGHT as f32));
        builder.line_to(Point::new(3.0 * TILE_WIDTH as f32, 0.0));
        builder.line_to(Point::new(TILE_WIDTH as f32, 0.0));
        builder.line_to(Point::new(TILE_WIDTH as f32, TILE_HEIGHT as f32));
        builder.line_to(Point::new(2.0 * TILE_WIDTH as f32, TILE_HEIGHT as f32));
        builder.line_to(Point::new(2.0 * TILE_WIDTH as f32, 0.0));
        builder.line_to(Point::new(0.0, 0.0));

        let path = builder.build();

        let mut buffer = [BLACK_SRGB; 3 * TILE_WIDTH * TILE_HEIGHT].concat();
        let mut layout = LinearLayout::new(3 * TILE_WIDTH, 3 * TILE_WIDTH * 4, TILE_HEIGHT);

        let mut composition = Composition::new();

        composition.create_layer().unwrap().insert(&path).set_props(Props {
            fill_rule: FillRule::EvenOdd,
            func: Func::Draw(Style { fill: Fill::Solid(RED), ..Default::default() }),
        });

        composition.render(
            &mut BufferBuilder::new(&mut buffer, &mut layout).build(),
            RGBA,
            BLACK,
            None,
        );

        assert_eq!(buffer[0..4], RED_SRGB);
        assert_eq!(buffer[TILE_WIDTH * 4..(TILE_WIDTH * 4 + 4)], BLACK_SRGB);
        assert_eq!(buffer[2 * TILE_WIDTH * 4..2 * TILE_WIDTH * 4 + 4], RED_SRGB);
    }
}
