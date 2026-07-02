// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Proves xenia-viewer-web's from-scratch lane-envelope + rekey
// reimplementation (src/session.rs) decodes byte-identical plaintext
// to a REAL native xenia_peer_core::LaneSession, including across a
// live rekey transition. Dev-dependency only -- xenia-peer-core never
// ships in the wasm artifact (see Cargo.toml comment).
//
// Drives a real native LaneSession (host role, sealing) paired against
// WasmLaneSession (browser role, opening) -- both installed with the
// identical transcript-bound schedule a real handshake would produce.

use xenia_peer_core::frame::{PixelFormat, RawFrame};
use xenia_peer_core::{
    LaneSession, RekeyEpochContextV1, RekeyPolicy, RekeyReason, SessionEpochState,
};
use xenia_viewer_web::{WasmLaneSession, WasmRekeyState};

fn fixture_schedule() -> (xenia_handshake::SessionKeySchedule, [u8; 32]) {
    let root_key = [0x11u8; 32];
    let transcript_hash = [0x22u8; 32];
    (
        xenia_handshake::derive_session_key_schedule(&root_key, &transcript_hash),
        transcript_hash,
    )
}

fn solid_rgba(w: u32, h: u32) -> Vec<u8> {
    (0..(w * h)).flat_map(|_| [10u8, 20, 30, 255]).collect()
}

/// Build a `xenia-video` passthrough-codec payload: 12-byte header
/// (magic 'X', version 1, pix_fmt 0=RGBA, reserved, width LE u32,
/// height LE u32) + raw RGBA body. Matches what a real `--codec
/// passthrough` daemon actually sends (`RawFrame::encoded(..,
/// PixelFormat::Passthrough, ..)`) -- `LaneSession::seal_captured_rgba`
/// produces the *different*, header-less `PixelFormat::Rgba8` shape,
/// which `open_lane_frame_inner`/`decode_passthrough` don't decode.
fn passthrough_frame(
    frame_id: u64,
    timestamp_ms: u64,
    width: u32,
    height: u32,
    rgba: &[u8],
) -> RawFrame {
    let mut bytes = Vec::with_capacity(12 + rgba.len());
    bytes.push(0x58); // 'X'
    bytes.push(0x01); // version
    bytes.push(0x00); // pix_fmt: RGBA
    bytes.push(0x00); // reserved
    bytes.extend_from_slice(&width.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(rgba);
    RawFrame::encoded(
        frame_id,
        timestamp_ms,
        width,
        height,
        PixelFormat::Passthrough,
        bytes,
    )
}

#[test]
fn video_frame_and_rekey_transition_decode_byte_identical_to_native() {
    let (schedule, transcript_hash) = fixture_schedule();

    let mut host = LaneSession::with_fixture([0x33; 8], 0x01);
    host.install_schedule(&schedule);

    let mut browser = WasmLaneSession::new();
    browser
        .install_schedule(
            &schedule.control,
            &schedule.video,
            &schedule.audio,
            &schedule.telemetry,
        )
        .expect("installSchedule failed");

    // 1. Pre-rekey video frame: host seals, browser opens.
    //    (open_lane_frame_inner, not open_lane_frame_js -- the latter
    //    builds a JsValue return object, which panics outside a real
    //    JS host; see OpenedLaneFrame's doc comment.)
    let pixels = solid_rgba(4, 2);
    let frame = passthrough_frame(host.next_frame_id(), 1_000, 4, 2, &pixels);
    let sealed = host.seal_frame(&frame).expect("host seal_frame failed");
    let decoded = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed)
        .expect("browser openLaneFrame failed on pre-rekey video frame");
    match decoded {
        xenia_viewer_web::OpenedLaneFrame::Passthrough {
            width,
            height,
            rgba,
            ..
        } => {
            assert_eq!((width, height), (4, 2));
            assert_eq!(
                rgba, pixels,
                "decoded pixels must byte-for-byte match what the host sealed"
            );
        }
        other => panic!("expected Passthrough, got {other:?}"),
    }

    // 2. Drive a real rekey: host proposes, browser validates + installs
    //    + builds the Ack, host opens the Ack under its own new key.
    let mut epoch_state = SessionEpochState::new(transcript_hash, RekeyPolicy::from_limits(0, 0));
    let context: RekeyEpochContextV1 = epoch_state.next_rekey_context(RekeyReason::Manual);
    let epoch_hash = context.epoch_hash().expect("epoch_hash failed");

    let proposal = xenia_peer_core::RawRekey::Proposal {
        key_epoch: context.key_epoch,
        base_transcript_hash: context.base_transcript_hash,
        previous_epoch_hash: context.previous_epoch_hash,
        reason: context.reason,
        epoch_hash,
    }
    .into_frame(host.next_frame_id(), 0)
    .expect("RawRekey::Proposal into_frame failed");
    let proposal_envelope = host
        .seal_control_frame(&proposal)
        .expect("host seal_control_frame(proposal) failed");

    // Host installs its new epoch keys locally (mirrors
    // apps/xenia-peer/src/main.rs's perform_rekey/perform_rekey_split).
    let host_new_keys = epoch_state
        .derive_and_install(&schedule, &context)
        .expect("host derive_and_install failed");
    host.install_rekey_keys(&host_new_keys);

    // Browser receives + validates the proposal, installs its own new
    // keys, and produces the Ack envelope.
    let mut rekey_state =
        WasmRekeyState::new(&schedule.rekey, &transcript_hash).expect("WasmRekeyState::new failed");
    let ack_envelope = rekey_state
        .handle_proposal(
            &mut browser,
            context.key_epoch,
            &context.base_transcript_hash,
            &context.previous_epoch_hash,
            reason_name(context.reason),
            &epoch_hash,
        )
        .expect("browser handleProposal failed");

    // Host opens the browser's Ack under its (already-installed) new
    // control key -- the real proof the browser sealed it correctly.
    let ack_frame = host
        .open_frame(&ack_envelope)
        .expect("host failed to open browser's rekey Ack");
    match xenia_peer_core::RawRekey::from_frame(&ack_frame).expect("RawRekey::from_frame failed") {
        xenia_peer_core::RawRekey::Ack {
            key_epoch,
            epoch_hash: ack_hash,
        } => {
            assert_eq!(key_epoch, context.key_epoch);
            assert_eq!(ack_hash, epoch_hash);
        }
        other => panic!("expected RawRekey::Ack, got {other:?}"),
    }
    assert_eq!(rekey_state.current_epoch(), context.key_epoch);

    // 3. Post-rekey video frame: host seals under the NEW key, browser
    //    (now holding the new key via handle_proposal) opens it.
    let pixels_2 = solid_rgba(4, 2);
    let frame_2 = passthrough_frame(host.next_frame_id(), 2_000, 4, 2, &pixels_2);
    let sealed_2 = host.seal_frame(&frame_2).expect("host seal_frame failed");
    let decoded_2 = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed_2)
        .expect("browser openLaneFrame failed on post-rekey video frame -- rekey install broken");
    match decoded_2 {
        xenia_viewer_web::OpenedLaneFrame::Passthrough { rgba, .. } => {
            assert_eq!(rgba, pixels_2, "post-rekey pixels must byte-for-byte match");
        }
        other => panic!("expected Passthrough, got {other:?}"),
    }

    // 4. The proposal envelope itself must also open cleanly against a
    //    fresh native viewer LaneSession holding the same pre-rekey
    //    schedule (sanity: our own proposal construction is well-formed,
    //    independent of the browser's handling of it).
    let mut sanity_viewer = LaneSession::with_fixture([0x33; 8], 0x01);
    sanity_viewer.install_schedule(&schedule);
    let opened_proposal = sanity_viewer
        .open_frame(&proposal_envelope)
        .expect("sanity viewer failed to open the proposal envelope");
    match xenia_peer_core::RawRekey::from_frame(&opened_proposal).unwrap() {
        xenia_peer_core::RawRekey::Proposal { key_epoch, .. } => {
            assert_eq!(key_epoch, context.key_epoch);
        }
        other => panic!("expected RawRekey::Proposal, got {other:?}"),
    }
}

fn reason_name(r: RekeyReason) -> &'static str {
    match r {
        RekeyReason::Manual => "manual",
        RekeyReason::FrameCount => "frame_count",
        RekeyReason::ByteCount => "byte_count",
        RekeyReason::Time => "time",
        RekeyReason::TransportChange => "transport_change",
    }
}
