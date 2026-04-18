// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Quick-start example: seal a frame, ship the bytes, open on the other
//! side, then demonstrate replay rejection.
//!
//! Run with: `cargo run --example hello_xenia`

use xenia_wire::{open_frame, seal_frame, Frame, Session};

fn main() {
    // In production, `key` arrives from an ML-KEM-768 handshake. Here we
    // use a shared fixture so both peers can open each other's envelopes.
    let key = [0xAB; 32];

    let mut sender = Session::new();
    let mut receiver = Session::new();
    sender.install_key(key);
    receiver.install_key(key);

    let frame = Frame {
        frame_id: 1,
        timestamp_ms: 1_700_000_000_000,
        payload: b"hello, xenia".to_vec(),
    };

    // Seal on the sender side.
    let sealed = seal_frame(&frame, &mut sender).expect("seal should succeed with a valid key");
    println!(
        "sealed {} plaintext bytes into {} envelope bytes",
        frame.payload.len(),
        sealed.len()
    );

    // Ship `sealed` over whatever transport you like (TCP, WS, QUIC, UDP).
    // Xenia does not open sockets — the wire format is transport-agnostic.

    // Open on the receiver side.
    let opened = open_frame(&sealed, &mut receiver).expect("open should succeed");
    assert_eq!(opened.payload, b"hello, xenia");
    println!("opened: {:?}", String::from_utf8_lossy(&opened.payload));

    // Replaying the same bytes fails — the sliding replay window catches it.
    match open_frame(&sealed, &mut receiver) {
        Err(e) => println!("replay correctly rejected: {e}"),
        Ok(_) => panic!("replay should have been rejected"),
    }
}
