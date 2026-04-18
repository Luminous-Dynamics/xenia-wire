// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Property-based tests for the core wire invariants.
//!
//! These use `proptest` to generate thousands of randomized inputs. They
//! complement the hand-written integration tests by catching edge cases
//! the author didn't think of — exactly the category of bug cryptographic
//! code is prone to.

#![cfg(feature = "reference-frame")]

use proptest::prelude::*;
use xenia_wire::{open_frame, seal_frame, Frame, ReplayWindow, Session, WireError, WINDOW_BITS};

// ── ReplayWindow properties ───────────────────────────────────────────

proptest! {
    /// Sequential accepts in order must all succeed.
    #[test]
    fn replay_window_sequential_always_accepts(n in 0u64..=200) {
        let mut w = ReplayWindow::new();
        for seq in 0..=n {
            prop_assert!(w.accept(0x1234_5678_9ABC_DEF0, 0x10, 0u8, seq));
        }
    }

    /// Any sequence already accepted is a duplicate the second time.
    #[test]
    fn replay_window_duplicate_always_rejects(seq in 0u64..1_000_000) {
        let mut w = ReplayWindow::new();
        prop_assert!(w.accept(0xDEAD_BEEF, 0x10, 0u8, seq));
        prop_assert!(!w.accept(0xDEAD_BEEF, 0x10, 0u8, seq));
    }

    /// Different (source_id, payload_type) keys are independent — the
    /// same sequence number accepted on one stream says nothing about
    /// whether it was accepted on another.
    #[test]
    fn replay_window_streams_are_independent(
        seq in 0u64..10_000,
        sid1 in any::<u64>(),
        sid2 in any::<u64>(),
        pt1 in any::<u8>(),
        pt2 in any::<u8>(),
    ) {
        prop_assume!((sid1, pt1) != (sid2, pt2));
        let mut w = ReplayWindow::new();
        prop_assert!(w.accept(sid1, pt1, 0u8, seq));
        // Same seq on the OTHER stream is a first-seen on that stream.
        prop_assert!(w.accept(sid2, pt2, 0u8, seq));
        // But each stream rejects its own replay.
        prop_assert!(!w.accept(sid1, pt1, 0u8, seq));
        prop_assert!(!w.accept(sid2, pt2, 0u8, seq));
    }

    /// Advancing the window by > WINDOW_BITS permanently drops the old
    /// sequences — they can no longer be accepted.
    #[test]
    fn replay_window_advance_past_window_rejects_old(
        old_seq in 0u64..100,
        jump in (WINDOW_BITS + 1)..(WINDOW_BITS + 1_000),
    ) {
        let mut w = ReplayWindow::new();
        prop_assert!(w.accept(0x42, 0x10, 0u8, old_seq));
        prop_assert!(w.accept(0x42, 0x10, 0u8, old_seq + jump));
        // old_seq is now more than WINDOW_BITS below highest → too old.
        prop_assert!(!w.accept(0x42, 0x10, 0u8, old_seq));
    }

    /// Out-of-order arrivals within the window are accepted (once) and
    /// rejected on replay.
    #[test]
    fn replay_window_out_of_order_within_window_accepted_once(
        highest in WINDOW_BITS..(WINDOW_BITS + 1_000),
        offset in 1u64..WINDOW_BITS,
    ) {
        let mut w = ReplayWindow::new();
        prop_assert!(w.accept(0x77, 0x10, 0u8, highest));
        let target = highest - offset;
        prop_assert!(w.accept(0x77, 0x10, 0u8, target));
        prop_assert!(!w.accept(0x77, 0x10, 0u8, target));
    }
}

// ── seal/open roundtrip properties ────────────────────────────────────

fn paired_sessions(key: [u8; 32]) -> (Session, Session) {
    let mut sender = Session::with_source_id([0x99; 8], 0x11);
    let mut receiver = Session::with_source_id([0x99; 8], 0x11);
    sender.install_key(key);
    receiver.install_key(key);
    (sender, receiver)
}

proptest! {
    /// Any bytes that bincode will serialize roundtrip through seal/open.
    /// Plaintext length bounded to keep test time reasonable.
    #[test]
    fn seal_open_frame_roundtrip(
        frame_id in any::<u64>(),
        timestamp_ms in any::<u64>(),
        payload in prop::collection::vec(any::<u8>(), 0..4096),
        key in any::<[u8; 32]>(),
    ) {
        let (mut sender, mut receiver) = paired_sessions(key);
        let frame = Frame { frame_id, timestamp_ms, payload };
        let sealed = seal_frame(&frame, &mut sender).expect("seal");
        let opened = open_frame(&sealed, &mut receiver).expect("open");
        prop_assert_eq!(opened.frame_id, frame.frame_id);
        prop_assert_eq!(opened.timestamp_ms, frame.timestamp_ms);
        prop_assert_eq!(opened.payload, frame.payload);
    }

    /// Flipping ANY single byte in the envelope makes open fail.
    /// Covers nonce corruption, ciphertext corruption, and tag corruption
    /// in a single generic property.
    #[test]
    fn single_byte_flip_in_envelope_always_fails(
        payload in prop::collection::vec(any::<u8>(), 1..512),
        key in any::<[u8; 32]>(),
        flip_index_seed in any::<u32>(),
        flip_mask in 1u8..=255,
    ) {
        let (mut sender, mut receiver) = paired_sessions(key);
        let frame = Frame { frame_id: 1, timestamp_ms: 0, payload };
        let mut sealed = seal_frame(&frame, &mut sender).expect("seal");
        let idx = (flip_index_seed as usize) % sealed.len();
        sealed[idx] ^= flip_mask;
        let result = open_frame(&sealed, &mut receiver);
        prop_assert!(
            matches!(result, Err(WireError::OpenFailed) | Err(WireError::Codec(_))),
            "corrupted envelope at byte {} must be rejected, got {:?}",
            idx, result,
        );
    }

    /// Any mismatched session key makes open fail.
    #[test]
    fn mismatched_keys_always_fail_open(
        k_sender in any::<[u8; 32]>(),
        k_receiver in any::<[u8; 32]>(),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(k_sender != k_receiver);
        let mut sender = Session::with_source_id([0xAA; 8], 0x01);
        let mut receiver = Session::with_source_id([0xAA; 8], 0x01);
        sender.install_key(k_sender);
        receiver.install_key(k_receiver);
        let frame = Frame { frame_id: 0, timestamp_ms: 0, payload };
        let sealed = seal_frame(&frame, &mut sender).expect("seal");
        prop_assert!(matches!(
            open_frame(&sealed, &mut receiver),
            Err(WireError::OpenFailed)
        ));
    }

    /// An envelope can only be successfully opened once — second attempt
    /// is rejected by the replay window.
    #[test]
    fn seal_open_second_attempt_is_always_replay_rejected(
        payload in prop::collection::vec(any::<u8>(), 0..512),
        key in any::<[u8; 32]>(),
    ) {
        let (mut sender, mut receiver) = paired_sessions(key);
        let frame = Frame { frame_id: 0, timestamp_ms: 0, payload };
        let sealed = seal_frame(&frame, &mut sender).expect("seal");
        prop_assert!(open_frame(&sealed, &mut receiver).is_ok());
        prop_assert!(matches!(
            open_frame(&sealed, &mut receiver),
            Err(WireError::OpenFailed)
        ));
    }

    /// Sealing N frames in order, then opening them in any permutation
    /// that falls within the replay window, must all succeed. Catches
    /// bugs in the window's out-of-order acceptance logic.
    #[test]
    fn sequential_seals_open_in_any_window_order(
        n in 2usize..=32,
        permutation_seed in any::<u64>(),
        key in any::<[u8; 32]>(),
    ) {
        let (mut sender, mut receiver) = paired_sessions(key);
        // Seal N frames.
        let envelopes: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let frame = Frame {
                    frame_id: i as u64,
                    timestamp_ms: i as u64,
                    payload: vec![(i & 0xFF) as u8; 16],
                };
                seal_frame(&frame, &mut sender).expect("seal")
            })
            .collect();

        // Deterministic shuffle using the seed.
        let mut indices: Vec<usize> = (0..n).collect();
        let mut rng_state = permutation_seed.wrapping_add(1);
        for i in (1..indices.len()).rev() {
            // xorshift for a cheap permutation
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            let j = (rng_state as usize) % (i + 1);
            indices.swap(i, j);
        }

        // Open in the shuffled order — all N must succeed because they're
        // within the 64-slot window.
        prop_assume!(n <= (WINDOW_BITS as usize));
        for i in &indices {
            prop_assert!(
                open_frame(&envelopes[*i], &mut receiver).is_ok(),
                "frame {} should open in shuffled order",
                i
            );
        }
    }
}
