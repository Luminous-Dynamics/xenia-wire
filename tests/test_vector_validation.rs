// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Validate that the hex test vectors in `test-vectors/` open correctly
//! against the current crate. Acts as a regression guard: any change to
//! the wire format, nonce layout, or AEAD parameters that would silently
//! break interop will fail here.
//!
//! If this test fails after an intentional wire-format change, regenerate
//! the vectors via `cargo run --example gen_test_vectors --all-features`
//! AND bump the spec version in SPEC.md.

#![cfg(feature = "reference-frame")]

use std::fs;
use std::path::Path;
use xenia_wire::Session;

const FIXED_KEY: [u8; 32] = *b"xenia-wire-test-vector-key-2026!";
const FIXED_SOURCE_ID: [u8; 8] = *b"XENIATST";
const FIXED_EPOCH: u8 = 0x42;

fn read_hex(path: &Path) -> Vec<u8> {
    let s = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut out = Vec::new();
    for line in s.lines() {
        for i in (0..line.len()).step_by(2) {
            out.push(u8::from_str_radix(&line[i..i + 2], 16).unwrap());
        }
    }
    out
}

fn fresh_receiver() -> Session {
    let mut s = Session::with_source_id(FIXED_SOURCE_ID, FIXED_EPOCH);
    s.install_key(FIXED_KEY);
    s
}

fn vectors_dir() -> &'static Path {
    Path::new("test-vectors")
}

#[test]
fn vector_01_hello_frame_opens_to_expected_plaintext() {
    let envelope = read_hex(&vectors_dir().join("01_hello_frame.envelope.hex"));
    let expected = read_hex(&vectors_dir().join("01_hello_frame.input.hex"));
    let mut receiver = fresh_receiver();
    let plaintext = receiver.open(&envelope).expect("vector 01 must open");
    assert_eq!(plaintext, expected);
}

#[test]
fn vector_02_input_pointer_opens_to_expected_plaintext() {
    let envelope = read_hex(&vectors_dir().join("02_input_pointer.envelope.hex"));
    let expected = read_hex(&vectors_dir().join("02_input_pointer.input.hex"));
    let mut receiver = fresh_receiver();
    let plaintext = receiver.open(&envelope).expect("vector 02 must open");
    assert_eq!(plaintext, expected);
}

#[test]
fn vector_03_empty_payload_opens_to_expected_plaintext() {
    let envelope = read_hex(&vectors_dir().join("03_empty_payload.envelope.hex"));
    let expected = read_hex(&vectors_dir().join("03_empty_payload.input.hex"));
    let mut receiver = fresh_receiver();
    let plaintext = receiver.open(&envelope).expect("vector 03 must open");
    assert_eq!(plaintext, expected);
}

#[test]
fn vector_04_long_payload_opens_to_expected_plaintext() {
    let envelope = read_hex(&vectors_dir().join("04_long_payload.envelope.hex"));
    let expected = read_hex(&vectors_dir().join("04_long_payload.input.hex"));
    let mut receiver = fresh_receiver();
    let plaintext = receiver.open(&envelope).expect("vector 04 must open");
    assert_eq!(plaintext, expected);
}

#[test]
fn vector_05_nonce_structure_has_incrementing_sequence() {
    // Parse the concatenated envelope file and verify the sequence bytes.
    let raw = fs::read_to_string(vectors_dir().join("05_nonce_structure.envelopes.hex"))
        .expect("read vector 05");
    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    let mut current = Vec::<u8>::new();
    for line in raw.lines() {
        if line.starts_with("--") {
            if !current.is_empty() {
                envelopes.push(std::mem::take(&mut current));
            }
            continue;
        }
        for i in (0..line.len()).step_by(2) {
            current.push(u8::from_str_radix(&line[i..i + 2], 16).unwrap());
        }
    }
    if !current.is_empty() {
        envelopes.push(current);
    }
    assert_eq!(envelopes.len(), 3, "vector 05 must contain 3 envelopes");

    // Each envelope must open, and the sequence byte at nonce[8] must
    // increment 0 → 1 → 2.
    let mut receiver = fresh_receiver();
    for (i, env) in envelopes.iter().enumerate() {
        assert!(
            receiver.open(env).is_ok(),
            "vector 05 envelope {i} must open"
        );
        // Nonce bytes [8..12] are a little-endian u32 sequence.
        let seq = u32::from_le_bytes(env[8..12].try_into().unwrap());
        assert_eq!(seq, i as u32, "envelope {i} must have seq {i}");
        // Shared prefix bytes must be identical across all three.
        assert_eq!(env[..8], envelopes[0][..8]);
    }
}

#[cfg(feature = "lz4")]
#[test]
fn vector_06_lz4_frame_roundtrips() {
    use xenia_wire::{open_frame_lz4, Frame};
    let envelope = read_hex(&vectors_dir().join("06_lz4_frame.envelope.hex"));
    let mut receiver = fresh_receiver();
    let opened: Frame = open_frame_lz4(&envelope, &mut receiver).expect("vector 06 must open");
    assert_eq!(opened.frame_id, 9);
    assert_eq!(opened.timestamp_ms, 1_700_000_000_500);
    assert_eq!(opened.payload, vec![0x5A; 2048]);
}
