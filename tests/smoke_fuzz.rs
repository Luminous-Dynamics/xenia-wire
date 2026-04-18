// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Smoke fuzzer: verifies `Session::open()` cannot panic on arbitrary
//! input. Runs as a regular `cargo test` — no nightly toolchain, no
//! external fuzzing harness.
//!
//! Scope: this catches the panic / unwrap-on-user-input class of bugs
//! that would otherwise let a network attacker trivially DoS a
//! xenia-wire receiver. It does NOT replace `cargo-fuzz` — the fuzz/
//! directory holds the real coverage-guided harness for deeper campaigns.
//!
//! Target: 100,000 random envelopes per test in ~a few seconds.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use xenia_wire::Session;

/// Deterministic seed so failures reproduce. Bump if you add a new
/// scenario that needs independent randomness.
const SEED: u64 = 0xFACE_FEED_DEAD_BEEF;

fn install_key(session: &mut Session, key: [u8; 32]) {
    session.install_key(key);
}

#[test]
fn open_never_panics_on_random_bytes_without_key() {
    // No key installed: every open should return NoSessionKey or
    // OpenFailed (short-envelope), never panic.
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let mut buf = [0u8; 256];
    let mut session = Session::new();
    for _ in 0..100_000 {
        let len = (rng.next_u32() as usize) % 256;
        rng.fill_bytes(&mut buf[..len]);
        let _ = session.open(&buf[..len]); // must not panic
    }
}

#[test]
fn open_never_panics_on_random_bytes_with_key() {
    // Key installed: AEAD verification will fail on random bytes, but
    // open() must return OpenFailed cleanly without panicking.
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ 0x01);
    let mut buf = [0u8; 1024];
    let mut session = Session::new();
    install_key(&mut session, [0x42; 32]);
    for _ in 0..100_000 {
        let len = (rng.next_u32() as usize) % 1024;
        rng.fill_bytes(&mut buf[..len]);
        let _ = session.open(&buf[..len]);
    }
}

#[test]
fn open_never_panics_on_minimally_valid_structure() {
    // Envelopes that pass the length check but contain random nonce +
    // ciphertext + tag. Stresses the AEAD verify + replay-window path
    // more than unstructured random bytes.
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ 0x02);
    let mut session = Session::new();
    install_key(&mut session, [0xAB; 32]);
    for _ in 0..50_000 {
        let payload_len = (rng.next_u32() as usize) % 512;
        let mut envelope = vec![0u8; 12 + payload_len + 16];
        rng.fill_bytes(&mut envelope);
        let _ = session.open(&envelope);
    }
}

#[cfg(feature = "reference-frame")]
#[test]
fn open_frame_never_panics_on_random_bytes() {
    // Same as above but through the public `open_frame` wrapper so
    // we cover the bincode-deserialize step as well.
    use xenia_wire::open_frame;
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ 0x03);
    let mut session = Session::new();
    install_key(&mut session, [0xCD; 32]);
    let mut buf = [0u8; 512];
    for _ in 0..50_000 {
        let len = (rng.next_u32() as usize) % 512;
        rng.fill_bytes(&mut buf[..len]);
        let _ = open_frame(&buf[..len], &mut session);
    }
}

#[cfg(feature = "reference-frame")]
#[test]
fn seal_then_corrupt_arbitrarily_never_panics_on_open() {
    // Seal a valid envelope, then corrupt a random prefix / suffix /
    // middle slice. All variants must open cleanly (with an error).
    use xenia_wire::{open_frame, seal_frame, Frame};
    let mut rng = ChaCha20Rng::seed_from_u64(SEED ^ 0x04);
    let mut sender = Session::new();
    let mut receiver = Session::new();
    install_key(&mut sender, [0xEF; 32]);
    install_key(&mut receiver, [0xEF; 32]);
    for _ in 0..10_000 {
        let len = (rng.next_u32() as usize) % 256;
        let mut payload = vec![0u8; len];
        rng.fill_bytes(&mut payload);
        let frame = Frame {
            frame_id: rng.next_u64(),
            timestamp_ms: rng.next_u64(),
            payload,
        };
        let mut sealed = seal_frame(&frame, &mut sender).unwrap();
        // Corrupt a random sub-range of the envelope.
        let corrupt_start = (rng.next_u32() as usize) % sealed.len().max(1);
        let corrupt_end =
            corrupt_start + ((rng.next_u32() as usize) % (sealed.len() - corrupt_start).max(1));
        for b in &mut sealed[corrupt_start..corrupt_end] {
            *b ^= rng.next_u32() as u8;
        }
        // Must not panic. Error is expected (AEAD/codec).
        let _ = open_frame(&sealed, &mut receiver);
    }
}
