// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Proves xenia-viewer-web's from-scratch decode-only HDC reimplementation
// (src/hdc.rs, wired through WasmLaneSession/open_lane_frame_inner)
// decodes byte-identical RGBA to a REAL native xenia_video::hdc
// encoder+decoder pair, across a keyframe and a subsequent delta.
// Dev-dependency only -- xenia-video never ships in the wasm artifact
// (see Cargo.toml comment).

use xenia_peer_core::frame::{PixelFormat, RawFrame};
use xenia_peer_core::LaneSession;
use xenia_video::{EncodeParams, Encoder, PixelFormat as XvPixelFormat};

fn fixture_schedule() -> xenia_handshake::SessionKeySchedule {
    let root_key = [0x44u8; 32];
    let transcript_hash = [0x55u8; 32];
    xenia_handshake::derive_session_key_schedule(&root_key, &transcript_hash)
}

/// A two-tone frame (distinct R/G/B, not grayscale-collapsible) so this
/// test also guards M4.2b's color-fidelity fix, not just the wire
/// framing.
fn two_tone_rgba(w: u32, h: u32) -> Vec<u8> {
    let mut p = vec![0u8; (w * h * 4) as usize];
    for y in 0..h as usize {
        for x in 0..w as usize {
            let i = (y * w as usize + x) * 4;
            if x < w as usize / 2 {
                p[i] = 200; // R
                p[i + 1] = 30;
                p[i + 2] = 30;
            } else {
                p[i] = 30;
                p[i + 1] = 30;
                p[i + 2] = 200; // B
            }
            p[i + 3] = 255;
        }
    }
    p
}

fn hdc_frame(
    frame_id: u64,
    timestamp_ms: u64,
    width: u32,
    height: u32,
    hdc_bytes: Vec<u8>,
) -> RawFrame {
    RawFrame::encoded(
        frame_id,
        timestamp_ms,
        width,
        height,
        PixelFormat::Hdc,
        hdc_bytes,
    )
}

#[test]
fn hdc_keyframe_and_delta_decode_byte_identical_to_native() {
    let schedule = fixture_schedule();

    let mut host = LaneSession::with_fixture([0x66; 8], 0x01);
    host.install_schedule(&schedule);

    let mut browser = xenia_viewer_web::WasmLaneSession::new();
    browser
        .install_schedule(
            &schedule.control,
            &schedule.video,
            &schedule.audio,
            &schedule.telemetry,
        )
        .expect("installSchedule failed");

    let width = 128u32;
    let height = 128u32;
    let mut enc = xenia_video::hdc::HdcEncoder::new(EncodeParams {
        width,
        height,
        pixel_format: XvPixelFormat::Rgba,
        target_fps: 30,
        bitrate_kbps: 1000, // ignored by HDC
    });

    // 1. Keyframe: encode a real two-tone frame natively, seal as a
    //    lane-enveloped video frame, open on the browser side.
    let frame0 = two_tone_rgba(width, height);
    let pkt0 = enc
        .encode(&frame0, 0)
        .expect("native encode (keyframe) failed");
    assert!(pkt0[0].is_keyframe);
    let frame_id0 = host.next_frame_id();
    let sealed0 = host
        .seal_frame(&hdc_frame(
            frame_id0,
            1_000,
            width,
            height,
            pkt0[0].bytes.clone(),
        ))
        .expect("host seal_frame (keyframe) failed");
    let decoded0 = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed0)
        .expect("browser openLaneFrame failed on HDC keyframe");
    match decoded0 {
        xenia_viewer_web::OpenedLaneFrame::Hdc {
            width: w,
            height: h,
            rgba,
            ..
        } => {
            assert_eq!((w, h), (width, height));
            assert_eq!(
                rgba, frame0,
                "keyframe decode must byte-for-byte match the native HdcEncoder's input"
            );
        }
        other => panic!("expected Hdc, got {other:?}"),
    }

    // 2. Delta: change half the frame, encode + seal + open again.
    //    Proves the browser's persistent per-lane canvas correctly
    //    patches only the changed tiles rather than needing a fresh
    //    keyframe every time.
    let mut frame1 = frame0.clone();
    for y in 0..height as usize {
        for x in (width as usize / 2)..width as usize {
            let i = (y * width as usize + x) * 4;
            frame1[i] = 10;
            frame1[i + 1] = 220;
            frame1[i + 2] = 10;
        }
    }
    let pkt1 = enc
        .encode(&frame1, 33)
        .expect("native encode (delta) failed");
    assert!(!pkt1[0].is_keyframe);
    let frame_id1 = host.next_frame_id();
    let sealed1 = host
        .seal_frame(&hdc_frame(
            frame_id1,
            1_033,
            width,
            height,
            pkt1[0].bytes.clone(),
        ))
        .expect("host seal_frame (delta) failed");
    let decoded1 = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed1)
        .expect("browser openLaneFrame failed on HDC delta");
    match decoded1 {
        xenia_viewer_web::OpenedLaneFrame::Hdc {
            width: w,
            height: h,
            rgba,
            ..
        } => {
            assert_eq!((w, h), (width, height));
            assert_eq!(
                rgba, frame1,
                "delta decode must byte-for-byte match the native HdcEncoder's input"
            );
        }
        other => panic!("expected Hdc, got {other:?}"),
    }
}
