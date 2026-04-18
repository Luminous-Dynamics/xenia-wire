// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Integration tests exercising the public API from outside the crate.

#![cfg(feature = "reference-frame")]

use xenia_wire::{
    open_frame, open_input, seal_frame, seal_input, Frame, Input, Session, WireError,
};

fn paired_sessions(key: [u8; 32]) -> (Session, Session) {
    let mut sender = Session::with_source_id([0x11; 8], 0x42);
    let mut receiver = Session::with_source_id([0x11; 8], 0x42);
    sender.install_key(key);
    receiver.install_key(key);
    (sender, receiver)
}

fn sample_frame() -> Frame {
    Frame {
        frame_id: 42,
        timestamp_ms: 1_700_000_000_000,
        payload: (0..1024u16).map(|i| (i & 0xFF) as u8).collect(),
    }
}

#[test]
fn frame_seal_open_roundtrip() {
    let (mut sender, mut receiver) = paired_sessions([0xAB; 32]);
    let frame = sample_frame();
    let sealed = seal_frame(&frame, &mut sender).unwrap();
    let opened = open_frame(&sealed, &mut receiver).unwrap();
    assert_eq!(opened, frame);
}

#[test]
fn input_seal_open_roundtrip() {
    let (mut sender, mut receiver) = paired_sessions([0xCD; 32]);
    let input = Input {
        sequence: 7,
        timestamp_ms: 1_700_000_000_050,
        payload: b"tap(123,456)".to_vec(),
    };
    let sealed = seal_input(&input, &mut sender).unwrap();
    let opened = open_input(&sealed, &mut receiver).unwrap();
    assert_eq!(opened, input);
}

#[test]
fn replay_rejected_by_sliding_window() {
    let (mut sender, mut receiver) = paired_sessions([0x11; 32]);
    let frame = sample_frame();
    let sealed = seal_frame(&frame, &mut sender).unwrap();

    assert!(open_frame(&sealed, &mut receiver).is_ok());
    // Same envelope again → rejected.
    assert!(matches!(
        open_frame(&sealed, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[test]
fn wrong_key_rejected() {
    let mut sender = Session::with_source_id([0x22; 8], 0x43);
    let mut receiver = Session::with_source_id([0x22; 8], 0x43);
    sender.install_key([0x77; 32]);
    receiver.install_key([0x88; 32]);

    let frame = sample_frame();
    let sealed = seal_frame(&frame, &mut sender).unwrap();
    assert!(matches!(
        open_frame(&sealed, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[test]
fn truncated_envelope_rejected() {
    let (mut sender, mut receiver) = paired_sessions([0x33; 32]);
    let frame = sample_frame();
    let mut sealed = seal_frame(&frame, &mut sender).unwrap();
    sealed.truncate(10);
    assert!(open_frame(&sealed, &mut receiver).is_err());
}

#[test]
fn tampered_ciphertext_rejected() {
    let (mut sender, mut receiver) = paired_sessions([0x44; 32]);
    let frame = sample_frame();
    let mut sealed = seal_frame(&frame, &mut sender).unwrap();
    let mid = sealed.len() / 2;
    sealed[mid] ^= 0xFF; // flip a byte in the ciphertext
    assert!(matches!(
        open_frame(&sealed, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[test]
fn frame_and_input_on_same_session_do_not_collide() {
    // A single session sealing alternating Frame / Input envelopes should
    // produce independent replay windows — same underlying nonce counter,
    // but the payload_type byte separates the streams.
    let (mut sender, mut receiver) = paired_sessions([0x55; 32]);
    let frame = sample_frame();
    let input = Input {
        sequence: 1,
        timestamp_ms: 1,
        payload: b"hi".to_vec(),
    };

    let sealed_frame = seal_frame(&frame, &mut sender).unwrap();
    let sealed_input = seal_input(&input, &mut sender).unwrap();

    assert!(open_frame(&sealed_frame, &mut receiver).is_ok());
    assert!(open_input(&sealed_input, &mut receiver).is_ok());
}

#[test]
fn sequential_stream_accepts_many_frames() {
    let (mut sender, mut receiver) = paired_sessions([0x66; 32]);
    for i in 0..500 {
        let frame = Frame {
            frame_id: i,
            timestamp_ms: i * 10,
            payload: vec![(i & 0xFF) as u8; 64],
        };
        let sealed = seal_frame(&frame, &mut sender).unwrap();
        let opened = open_frame(&sealed, &mut receiver).unwrap();
        assert_eq!(opened.frame_id, i);
    }
}

#[cfg(feature = "lz4")]
#[test]
fn lz4_roundtrip() {
    use xenia_wire::{open_frame_lz4, seal_frame_lz4};

    let (mut sender, mut receiver) = paired_sessions([0x77; 32]);
    let frame = Frame {
        frame_id: 1,
        timestamp_ms: 0,
        payload: vec![0x7Eu8; 8192], // compressible
    };
    let sealed = seal_frame_lz4(&frame, &mut sender).unwrap();
    let opened = open_frame_lz4(&sealed, &mut receiver).unwrap();
    assert_eq!(opened, frame);
}
