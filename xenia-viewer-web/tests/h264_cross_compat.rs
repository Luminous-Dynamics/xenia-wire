// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Proves the h264.rs helpers (is_keyframe_chunk / sps_codec_string --
// exposed here via WasmLaneSession::open_lane_frame_inner, not
// directly, since they're pub(crate)) work correctly against REAL
// Annex-B output from xenia_video::h264::H264Encoder (ffmpeg-next /
// libx264), not just hand-built fixtures. Gated behind the `h264-test`
// feature (see Cargo.toml) since it needs libav dev headers -- run via
// `nix develop` from the xenia-peer workspace:
//
//   nix develop /path/to/xenia-peer --command \
//     cargo test --features h264-test --test h264_cross_compat

use xenia_peer_core::frame::{PixelFormat, RawFrame};
use xenia_peer_core::LaneSession;
use xenia_video::{EncodeParams, Encoder, PixelFormat as XvPixelFormat};

fn fixture_schedule() -> xenia_handshake::SessionKeySchedule {
    let root_key = [0x77u8; 32];
    let transcript_hash = [0x88u8; 32];
    xenia_handshake::derive_session_key_schedule(&root_key, &transcript_hash)
}

fn gradient_rgba(w: u32, h: u32, seed: u8) -> Vec<u8> {
    let mut p = vec![0u8; (w * h * 4) as usize];
    for y in 0..h as usize {
        for x in 0..w as usize {
            let i = (y * w as usize + x) * 4;
            p[i] = (x as u8).wrapping_add(seed);
            p[i + 1] = (y as u8).wrapping_add(seed);
            p[i + 2] = seed.wrapping_mul(3);
            p[i + 3] = 255;
        }
    }
    p
}

fn h264_frame(
    frame_id: u64,
    timestamp_ms: u64,
    width: u32,
    height: u32,
    bytes: Vec<u8>,
) -> RawFrame {
    RawFrame::encoded(
        frame_id,
        timestamp_ms,
        width,
        height,
        PixelFormat::H264,
        bytes,
    )
}

#[test]
fn h264_keyframe_detection_and_codec_string_match_real_encoder_output() {
    let schedule = fixture_schedule();

    let mut host = LaneSession::with_fixture([0x99; 8], 0x01);
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

    let width = 64u32;
    let height = 64u32;
    let mut enc = xenia_video::h264::H264Encoder::new(EncodeParams {
        width,
        height,
        pixel_format: XvPixelFormat::Rgba,
        target_fps: 30,
        bitrate_kbps: 1000,
    })
    .expect("H264Encoder::new failed (libav headers missing? run under nix develop)");

    // First encoded packet from a fresh encoder must be a real IDR
    // keyframe with an inline SPS -- x264's default GOP structure
    // always opens a stream this way.
    let frame0 = gradient_rgba(width, height, 0);
    let packets0 = enc.encode(&frame0, 0).expect("native encode #0 failed");
    assert!(
        !packets0.is_empty(),
        "encoder produced no packets for frame 0"
    );
    let pkt0 = &packets0[0];
    assert!(
        pkt0.is_keyframe,
        "native encoder says packet 0 is a keyframe"
    );

    let frame_id0 = host.next_frame_id();
    let sealed0 = host
        .seal_frame(&h264_frame(frame_id0, 0, width, height, pkt0.bytes.clone()))
        .expect("host seal_frame (keyframe) failed");
    let decoded0 = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed0)
        .expect("browser openLaneFrame failed on H.264 keyframe");
    match decoded0 {
        xenia_viewer_web::OpenedLaneFrame::H264 {
            is_keyframe,
            codec_string,
            bytes,
            ..
        } => {
            assert!(
                is_keyframe,
                "h264.rs must detect the real encoder's first packet as a keyframe (IDR NAL scan)"
            );
            let codec_string = codec_string
                .expect("h264.rs must extract a codec string from the real encoder's inline SPS");
            assert!(
                codec_string.starts_with("avc1."),
                "codec string must be avc1.PPCCLL shaped, got {codec_string}"
            );
            assert_eq!(
                codec_string.len(),
                "avc1.".len() + 6,
                "codec string must be exactly 3 hex-encoded bytes after avc1., got {codec_string}"
            );
            assert_eq!(
                bytes, pkt0.bytes,
                "sealed/opened bytes must round-trip exactly"
            );
        }
        other => panic!("expected H264, got {other:?}"),
    }

    // Encode several more frames with real motion (gradient shifts) so
    // x264 has a real chance to emit a genuine P-frame (non-IDR) before
    // its next scheduled keyframe -- feed them all through and assert
    // at least one comes back correctly classified as a non-keyframe.
    let mut saw_non_keyframe = false;
    for i in 1..20u8 {
        let frame = gradient_rgba(width, height, i.wrapping_mul(7));
        let packets = enc
            .encode(&frame, i as u64 * 33)
            .unwrap_or_else(|e| panic!("native encode #{i} failed: {e:?}"));
        for pkt in packets {
            let frame_id = host.next_frame_id();
            let sealed = host
                .seal_frame(&h264_frame(
                    frame_id,
                    i as u64 * 33,
                    width,
                    height,
                    pkt.bytes.clone(),
                ))
                .expect("host seal_frame (delta) failed");
            let decoded = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed)
                .expect("browser openLaneFrame failed on H.264 delta");
            match decoded {
                xenia_viewer_web::OpenedLaneFrame::H264 { is_keyframe, .. } => {
                    assert_eq!(
                        is_keyframe, pkt.is_keyframe,
                        "h264.rs's IDR scan must agree with the real encoder's own is_keyframe flag"
                    );
                    if !is_keyframe {
                        saw_non_keyframe = true;
                    }
                }
                other => panic!("expected H264, got {other:?}"),
            }
        }
    }
    assert!(
        saw_non_keyframe,
        "expected at least one real non-keyframe (P-frame) packet across 19 more encoded frames"
    );
}
