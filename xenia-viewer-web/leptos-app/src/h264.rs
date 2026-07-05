// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! WebCodecs H.264 playback, mirroring `www/daemon.js`'s `handleH264Frame`/
//! `drawVideoFrame`. Actual decode happens in the browser's native
//! `VideoDecoder`, not in WASM -- `OpenedLaneFrame::H264` only carries
//! undecoded Annex-B bytes plus the two things the wire format doesn't
//! include that `configure()`/`EncodedVideoChunk` need: a keyframe flag
//! and (on SPS-bearing chunks) a real profile/level-derived codec string.
//!
//! `web-sys`'s WebCodecs bindings (`VideoDecoder`, `EncodedVideoChunk*`,
//! `VideoFrame`) are gated behind `#[cfg(web_sys_unstable_apis)]` --
//! enabled for this crate via `.cargo/config.toml`'s `--cfg=web_sys_unstable_apis`
//! rustflag. `VideoDecoderConfig` has no typed `avc` field (missing from
//! web-sys's dictionary bindings), so it's set via a raw `js_sys::Reflect`
//! property write -- the standard escape hatch for a dictionary field
//! `web-sys` hasn't generated a typed setter for.

use js_sys::{Object, Reflect, Uint8Array};
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    CanvasRenderingContext2d, EncodedVideoChunk, EncodedVideoChunkInit, EncodedVideoChunkType,
    HtmlCanvasElement, VideoDecoder, VideoDecoderConfig, VideoDecoderInit, VideoFrame,
};

use crate::UiState;

fn draw_video_frame(
    ctx: &CanvasRenderingContext2d,
    canvas: &HtmlCanvasElement,
    frame: &VideoFrame,
    ui: UiState,
) {
    let width = frame.display_width();
    let height = frame.display_height();
    if canvas.width() != width {
        canvas.set_width(width);
    }
    if canvas.height() != height {
        canvas.set_height(height);
    }
    // `draw_image_with_video_frame` draws at the frame's natural
    // dimensions starting at (dx, dy) -- matches daemon.js's
    // `ctx.drawImage(videoFrame, 0, 0, w, h)` closely enough since the
    // canvas is already resized to those same dimensions above.
    let _ = ctx.draw_image_with_video_frame(frame, 0.0, 0.0);
    ui.frame_count.update(|n| *n += 1);
    ui.last_frame.set(format!("{width}×{height} (h264)"));
    // VideoFrames hold real GPU/native memory -- MUST be closed promptly
    // or the browser leaks (same requirement as daemon.js's finally block).
    frame.close();
}

/// One WebCodecs decoder instance, lazily configured on the first chunk
/// that carries a real SPS-derived codec string (see `h264.rs` on the
/// native side for why that's usually the very first keyframe).
pub struct H264Player {
    decoder: VideoDecoder,
    configured: bool,
    seen_keyframe: bool,
    // Closures must outlive the VideoDecoder that holds JS-side references
    // to them (as `output`/`error` callbacks) -- dropping these early would
    // invalidate the callbacks mid-session.
    _output_closure: Closure<dyn FnMut(VideoFrame)>,
    _error_closure: Closure<dyn FnMut(JsValue)>,
}

impl H264Player {
    pub fn new(
        ctx: CanvasRenderingContext2d,
        canvas: HtmlCanvasElement,
        ui: UiState,
    ) -> Result<Self, JsValue> {
        let output_closure = Closure::<dyn FnMut(VideoFrame)>::new(move |frame: VideoFrame| {
            draw_video_frame(&ctx, &canvas, &frame, ui);
        });
        let error_closure = Closure::<dyn FnMut(JsValue)>::new(move |e: JsValue| {
            web_sys::console::error_2(&"VideoDecoder error:".into(), &e);
            ui.err.set(format!(
                "VideoDecoder: {}",
                e.as_string().unwrap_or_default()
            ));
        });
        let init = VideoDecoderInit::new(
            error_closure.as_ref().unchecked_ref(),
            output_closure.as_ref().unchecked_ref(),
        );
        let decoder = VideoDecoder::new(&init)?;
        Ok(Self {
            decoder,
            configured: false,
            seen_keyframe: false,
            _output_closure: output_closure,
            _error_closure: error_closure,
        })
    }

    /// Feed one H.264 Annex-B access unit into the decoder. Mirrors
    /// daemon.js's `handleH264Frame` exactly: configure lazily from the
    /// first available codec string, drop deltas until a real keyframe
    /// has been seen (WebCodecs throws on a delta-before-keyframe).
    pub fn handle_frame(
        &mut self,
        is_keyframe: bool,
        codec_string: Option<String>,
        timestamp_ms: u64,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        if !self.configured {
            let Some(codec) = codec_string else {
                // No SPS yet (mid-stream reconnect landed on a delta) --
                // can't configure without a real profile/level.
                return Ok(());
            };
            let config = VideoDecoderConfig::new(&codec);
            let avc = Object::new();
            Reflect::set(
                &avc,
                &JsValue::from_str("format"),
                &JsValue::from_str("annexb"),
            )?;
            Reflect::set(&config, &JsValue::from_str("avc"), &avc)?;
            self.decoder.configure(&config)?;
            self.configured = true;
        }
        if is_keyframe {
            self.seen_keyframe = true;
        } else if !self.seen_keyframe {
            return Ok(());
        }

        let data = Uint8Array::from(bytes);
        let chunk_type = if is_keyframe {
            EncodedVideoChunkType::Key
        } else {
            EncodedVideoChunkType::Delta
        };
        let init = EncodedVideoChunkInit::new_with_u8_array(&data, 0, chunk_type);
        // WebCodecs wants microseconds; the wire carries milliseconds.
        init.set_timestamp_f64(timestamp_ms as f64 * 1000.0);
        let chunk = EncodedVideoChunk::new(&init)?;
        self.decoder.decode(&chunk)
    }
}

impl Drop for H264Player {
    fn drop(&mut self) {
        // Best-effort: a decoder in an already-errored state may reject
        // close(), which is fine to ignore here.
        let _ = self.decoder.close();
    }
}
