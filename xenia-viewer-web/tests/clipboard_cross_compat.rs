// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Proves xenia-viewer-web's from-scratch OpenedLaneFrame::Clipboard
// decode (src/session.rs) matches a REAL native xenia_peer_core::
// RawClipboard byte-for-byte. Host-to-viewer only -- the forward
// direction rides the lane-envelope control channel, same as
// Capabilities/Rekey; the browser never seals a RawClipboard itself
// (no reverse path wired here, see OpenedLaneFrame::Clipboard's doc
// comment for why).

use xenia_peer_core::frame::ClipboardContent;
use xenia_peer_core::{LaneSession, RawClipboard};
use xenia_viewer_web::{
    ClipboardContent as WasmClipboardContent, OpenedLaneFrame, WasmLaneSession,
};

fn fixture_schedule() -> xenia_handshake::SessionKeySchedule {
    xenia_handshake::derive_session_key_schedule(&[0x44u8; 32], &[0x55u8; 32])
}

#[test]
fn clipboard_text_update_decodes_byte_identical_to_native() {
    let schedule = fixture_schedule();

    let mut host = LaneSession::with_fixture([0x66; 8], 0x02);
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

    let frame_id = host.next_frame_id();
    let clip = RawClipboard {
        sequence: 7,
        timestamp_ms: 12_345,
        content: ClipboardContent::Text("hello from the host clipboard".to_string()),
    }
    .into_frame(frame_id)
    .expect("RawClipboard::into_frame failed");
    let sealed = host.seal_frame(&clip).expect("host seal_frame failed");

    let decoded = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed)
        .expect("browser openLaneFrame failed on clipboard frame");
    match decoded {
        OpenedLaneFrame::Clipboard {
            frame_id: decoded_frame_id,
            sequence,
            content,
            ..
        } => {
            assert_eq!(decoded_frame_id, frame_id);
            assert_eq!(sequence, 7);
            assert_eq!(
                content,
                WasmClipboardContent::Text("hello from the host clipboard".to_string())
            );
        }
        other => panic!("expected Clipboard, got {other:?}"),
    }
}

#[test]
fn clipboard_cleared_update_decodes_byte_identical_to_native() {
    let schedule = fixture_schedule();

    let mut host = LaneSession::with_fixture([0x77; 8], 0x03);
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

    let frame_id = host.next_frame_id();
    let clip = RawClipboard {
        sequence: 1,
        timestamp_ms: 999,
        content: ClipboardContent::Cleared,
    }
    .into_frame(frame_id)
    .expect("RawClipboard::into_frame failed");
    let sealed = host.seal_frame(&clip).expect("host seal_frame failed");

    let decoded = xenia_viewer_web::open_lane_frame_inner(&mut browser, &sealed)
        .expect("browser openLaneFrame failed on clipboard frame");
    match decoded {
        OpenedLaneFrame::Clipboard { content, .. } => {
            assert_eq!(content, WasmClipboardContent::Cleared);
        }
        other => panic!("expected Clipboard, got {other:?}"),
    }
}
