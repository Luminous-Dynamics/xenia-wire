// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: the LZ4 frame path — `open_frame_lz4()`.
//!
//! Two surfaces in one target:
//!   1. Raw `open_frame_lz4()` on arbitrary bytes — exercises the
//!      AEAD-reject and malformed/oversize size-prefix paths (the
//!      decompression-bomb guard) without a valid key.
//!   2. A real `seal_frame_lz4()` -> `open_frame_lz4()` round trip on the
//!      same fuzz bytes as payload — exercises the compress/decompress
//!      happy path and asserts it reconstructs the input exactly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_wire::{open_frame_lz4, seal_frame_lz4, Frame, Session};

fuzz_target!(|data: &[u8]| {
    // Surface 1: arbitrary bytes into the open path (bomb / malformed).
    let mut open_session = Session::with_source_id([0; 8], 0);
    open_session.install_key([0xAB; 32]);
    let _ = open_frame_lz4(data, &mut open_session);

    // Surface 2: honest round trip with the fuzz bytes as payload.
    let mut seal_session = Session::with_source_id([1; 8], 0);
    seal_session.install_key([0xCD; 32]);
    let mut recv_session = Session::with_source_id([1; 8], 0);
    recv_session.install_key([0xCD; 32]);

    let frame = Frame {
        frame_id: 1,
        timestamp_ms: 0,
        payload: data.to_vec(),
    };
    if let Ok(sealed) = seal_frame_lz4(&frame, &mut seal_session) {
        let opened =
            open_frame_lz4(&sealed, &mut recv_session).expect("a frame we just sealed must open");
        assert_eq!(opened.payload, data, "lz4 round trip must preserve payload");
    }
});
