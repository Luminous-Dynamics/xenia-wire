// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decode-only reimplementation of `xenia_video::hdc`'s wire format
//! (the HDC hybrid tile-delta codec).
//!
//! Mirrors `xenia_video::hdc::HdcPacket`/`TilePatch`/`TileContentType`
//! and `HdcDecoder::decode`'s canvas-patching logic from scratch --
//! same constraint as `handshake.rs`/`session.rs`: this crate ships
//! standalone and can't depend on the `xenia-peer` repo at runtime.
//! Verified byte-identical against the real native encoder+decoder by
//! `tests/hdc_cross_compat.rs` (dev-dependency only).
//!
//! The browser only ever *decodes* (the daemon is always the encoder
//! side), so unlike the native crate this module has no encoder, no
//! `ContinuousHV`, and no change-detection/classification -- only the
//! packet layout and the patch-into-canvas logic, which is all a
//! decoder needs.
//!
//! ## Wire format
//!
//! Bincode-v1 serialization of [`HdcPacketShadow`]. `tag` is `0x01`
//! for a keyframe (every tile) or `0x02` for a delta (changed tiles
//! only). Each [`TilePatchShadow::values`] is `tile_w * tile_h * 3`
//! bytes of RGB (no alpha; decoded output always sets A=255) -- see
//! `xenia_video::hdc`'s module doc for why RGB, not grayscale
//! (M4.2b).

use serde::Deserialize;

/// Shadow of `xenia_video::hdc::TileContentType`. Field order MUST
/// match the upstream crate byte-for-byte -- bincode encodes a
/// fieldless enum's declaration-order variant index as a `u32`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[allow(dead_code)] // variants are never matched on, only deserialized
enum TileContentTypeShadow {
    Static,
    Text,
    Photo,
    Video,
}

/// Shadow of `xenia_video::hdc::TilePatch`. Field order must match
/// the upstream exactly.
#[derive(Debug, Deserialize)]
struct TilePatchShadow {
    index: u16,
    #[allow(dead_code)] // not needed for decode; kept for field-order parity
    surprise: f32,
    values: Vec<u8>,
    #[allow(dead_code)]
    content_type: TileContentTypeShadow,
    tile_w: u16,
    tile_h: u16,
}

/// Shadow of `xenia_video::hdc::HdcPacket`. Field order must match
/// the upstream exactly.
#[derive(Debug, Deserialize)]
struct HdcPacketShadow {
    tag: u8,
    width: u32,
    height: u32,
    tile_cols: u16,
    tile_rows: u16,
    #[allow(dead_code)]
    frame_id: u64,
    pts_ms: u64,
    patches: Vec<TilePatchShadow>,
}

const TILE_SIZE: usize = 64;

/// Decoded-frame result: RGBA pixels + declared dimensions +
/// source-time presentation timestamp.
pub(crate) struct DecodedHdcFrame {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pts_ms: u64,
    pub(crate) rgba: Vec<u8>,
}

/// Per-lane HDC decode state. Holds the full-frame RGBA canvas and
/// patches incoming keyframe/delta packets into it -- mirrors
/// `xenia_video::hdc::HdcDecoder` exactly. One instance lives for the
/// lifetime of a video lane (held inside `WasmLaneSession`), since HDC
/// is delta-coded: a delta packet is meaningless without the
/// keyframe's canvas to patch into.
#[derive(Default)]
pub(crate) struct HdcDecoderState {
    canvas: Vec<u8>,
    width: u32,
    height: u32,
    tile_cols: u16,
    tile_rows: u16,
    primed: bool,
}

impl HdcDecoderState {
    pub(crate) fn decode(&mut self, bytes: &[u8]) -> Result<DecodedHdcFrame, String> {
        let pkt: HdcPacketShadow =
            bincode::deserialize(bytes).map_err(|e| format!("HdcPacket bincode decode: {e}"))?;

        let canvas_len = (pkt.width as usize) * (pkt.height as usize) * 4;
        if pkt.tag == 0x01 {
            if self.canvas.len() != canvas_len {
                self.canvas = vec![0u8; canvas_len];
            } else {
                self.canvas.fill(0);
            }
            self.width = pkt.width;
            self.height = pkt.height;
            self.tile_cols = pkt.tile_cols;
            self.tile_rows = pkt.tile_rows;
            self.primed = true;
        } else if pkt.tag == 0x02 {
            if !self.primed {
                return Err("hdc: delta received before first keyframe".to_string());
            }
            if pkt.width != self.width || pkt.height != self.height {
                return Err(
                    "hdc: delta declared different dimensions than current canvas".to_string(),
                );
            }
        } else {
            return Err(format!("hdc: unknown packet tag {:#x}", pkt.tag));
        }

        for patch in &pkt.patches {
            let idx = patch.index as usize;
            if idx >= (self.tile_cols as usize) * (self.tile_rows as usize) {
                return Err(format!("hdc: tile index {idx} out of range"));
            }
            let row = idx / self.tile_cols as usize;
            let col = idx % self.tile_cols as usize;
            let tile_x = col * TILE_SIZE;
            let tile_y = row * TILE_SIZE;
            let tw = patch.tile_w as usize;
            let th = patch.tile_h as usize;
            if patch.values.len() != tw * th * 3 {
                return Err(format!(
                    "hdc: tile {idx} has {} bytes, declared {tw}×{th}×3",
                    patch.values.len()
                ));
            }
            for dy in 0..th {
                for dx in 0..tw {
                    let src_off = (dy * tw + dx) * 3;
                    let dst_off = ((tile_y + dy) * self.width as usize + (tile_x + dx)) * 4;
                    if dst_off + 3 < self.canvas.len() {
                        self.canvas[dst_off] = patch.values[src_off];
                        self.canvas[dst_off + 1] = patch.values[src_off + 1];
                        self.canvas[dst_off + 2] = patch.values[src_off + 2];
                        self.canvas[dst_off + 3] = 255;
                    }
                }
            }
        }

        Ok(DecodedHdcFrame {
            width: self.width,
            height: self.height,
            pts_ms: pkt.pts_ms,
            rgba: self.canvas.clone(),
        })
    }
}
