// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression tests for the per-key-epoch replay-state fix
//! (issue #5, SPEC draft-02r1 §5.3).
//!
//! Before the fix, the reference implementation keyed replay state
//! by `(source_id, pld_type)` only. On rekey the sender counter
//! resets to `0`, so a receiver whose `highest` had advanced far
//! under the old key would reject the low-sequence new-key traffic.
//! These tests prove that doesn't happen anymore — and that replay
//! protection during the grace period still works.

#![cfg(feature = "reference-frame")]

use std::time::Duration;

use xenia_wire::{open_frame, seal_frame, Frame, Session, WireError};

fn sample_frame(id: u64) -> Frame {
    Frame {
        frame_id: id,
        timestamp_ms: id.wrapping_mul(10),
        payload: vec![(id & 0xFF) as u8; 64],
    }
}

/// The primary regression: advance `highest` far under the old key,
/// then rekey. The new-key sender starts at seq=0 and the receiver
/// MUST accept all of it — the old key's replay state is no longer
/// on the path.
#[test]
fn rekey_with_high_old_sequence_does_not_false_reject_new_stream() {
    let mut sender = Session::with_source_id([0x11; 8], 0xAA);
    let mut receiver = Session::with_source_id([0x11; 8], 0xAA);
    sender.install_key([0x33; 32]);
    receiver.install_key([0x33; 32]);

    // Seal 1_000 frames under the initial key. Receiver's replay
    // state advances to highest=999 for the FRAME stream under
    // epoch 0.
    for i in 0..1000 {
        let sealed = seal_frame(&sample_frame(i), &mut sender).unwrap();
        assert!(open_frame(&sealed, &mut receiver).is_ok(), "seq {i}");
    }

    // Rekey both sides. Sender resets nonce_counter to 0; epoch
    // advances 0 → 1.
    let new_key = [0x55; 32];
    sender.install_key(new_key);
    receiver.install_key(new_key);

    // Now seal 200 frames under the new key starting at seq=0.
    // Before the fix, all of these would have been rejected by the
    // receiver's stale replay state (highest=999, delta > 64).
    for i in 0..200 {
        let sealed = seal_frame(&sample_frame(i), &mut sender).unwrap();
        let opened = open_frame(&sealed, &mut receiver);
        assert!(
            opened.is_ok(),
            "new-key frame {i} must open after rekey; got {opened:?}",
        );
    }
}

/// Replay under the old key during the grace period is still
/// rejected — the old-epoch replay window remembers its own
/// history.
#[test]
fn replay_under_prev_key_during_grace_is_rejected() {
    let mut sender = Session::with_source_id([0x22; 8], 0xBB);
    let mut receiver = Session::with_source_id([0x22; 8], 0xBB);
    sender.install_key([0x44; 32]);
    receiver.install_key([0x44; 32]);

    // Seal + deliver one envelope under the initial key.
    let sealed_old = seal_frame(&sample_frame(0), &mut sender).unwrap();
    assert!(open_frame(&sealed_old, &mut receiver).is_ok());

    // Sender rekeys but holds onto the old sealed envelope. Receiver
    // rekeys too. During the grace window the receiver still has
    // the old key available, so the old envelope *could* decrypt —
    // but replay protection must still catch it as a duplicate.
    sender.install_key([0x77; 32]);
    receiver.install_key([0x77; 32]);

    // Replay the old envelope. Must reject.
    let replay_result = open_frame(&sealed_old, &mut receiver);
    assert!(
        matches!(replay_result, Err(WireError::OpenFailed)),
        "old-key replay during grace must be rejected; got {replay_result:?}",
    );
}

/// A legitimate in-flight envelope sealed BEFORE rekey but arriving
/// AFTER rekey (e.g. network reorder) still opens correctly under
/// the previous key during the grace window.
#[test]
fn in_flight_old_key_envelope_opens_after_rekey() {
    let mut sender = Session::with_source_id([0x33; 8], 0xCC);
    let mut receiver = Session::with_source_id([0x33; 8], 0xCC);
    sender.install_key([0x88; 32]);
    receiver.install_key([0x88; 32]);

    // Sender seals a frame under the initial key — but we hold it
    // instead of delivering immediately (simulating in-flight).
    let in_flight = seal_frame(&sample_frame(0), &mut sender).unwrap();

    // Rekey both sides. New-key traffic can now start.
    sender.install_key([0x99; 32]);
    receiver.install_key([0x99; 32]);
    let new_key_frame = seal_frame(&sample_frame(1), &mut sender).unwrap();

    // Now deliver both — in-flight old-key first, then new-key.
    // Both must succeed.
    let old = open_frame(&in_flight, &mut receiver);
    let new = open_frame(&new_key_frame, &mut receiver);
    assert!(
        old.is_ok(),
        "in-flight old-key frame must open; got {old:?}"
    );
    assert!(new.is_ok(), "new-key frame must open; got {new:?}");
}

/// After the previous key's grace period expires, its replay window
/// entries are reclaimed on `tick()`. An envelope that could have
/// verified under the old key no longer even AEAD-verifies (key gone),
/// so the old-epoch replay state is pure memory overhead and is
/// correctly dropped.
#[test]
fn tick_reclaims_old_epoch_replay_state_after_grace() {
    let mut sender = Session::with_source_id([0x44; 8], 0xDD);
    let mut receiver =
        Session::with_source_id([0x44; 8], 0xDD).with_rekey_grace(Duration::from_millis(10));
    sender.install_key([0xAA; 32]);
    receiver.install_key([0xAA; 32]);

    // Populate the epoch=0 replay window.
    for i in 0..5 {
        let s = seal_frame(&sample_frame(i), &mut sender).unwrap();
        assert!(open_frame(&s, &mut receiver).is_ok());
    }

    // Rekey.
    let new_key = [0xBB; 32];
    sender.install_key(new_key);
    receiver.install_key(new_key);
    // Receiver still has both epoch=0 and epoch=1 replay state:
    // epoch=0 retains its pre-rekey history, epoch=1 starts empty
    // (the sample_frame(0) we're about to seal creates it).
    let post_rekey = seal_frame(&sample_frame(0), &mut sender).unwrap();
    assert!(open_frame(&post_rekey, &mut receiver).is_ok());

    // Wait past the grace window, then tick.
    std::thread::sleep(Duration::from_millis(20));
    receiver.tick();

    // We can't directly assert that epoch=0 is gone from the private
    // `replay_window` field without exposing it. But we CAN assert
    // the behaviorally-correct outcome: a fresh sealed envelope at
    // seq=0 under the current key (epoch=1) continues to work. This
    // is a smoke that tick() didn't accidentally nuke active state.
    let post_tick = seal_frame(&sample_frame(1), &mut sender).unwrap();
    assert!(open_frame(&post_tick, &mut receiver).is_ok());
}

/// Extended variant of the primary regression at a stress scale:
/// ten rekeys in sequence, each advancing `highest` far under its
/// own epoch, all new-key streams continue to open cleanly.
#[test]
fn ten_rekeys_with_high_sequences_all_succeed() {
    let mut sender = Session::with_source_id([0x55; 8], 0xEE);
    let mut receiver = Session::with_source_id([0x55; 8], 0xEE);
    let mut key = [0x00; 32];
    key[0] = 1;
    sender.install_key(key);
    receiver.install_key(key);

    for rekey in 0..10 {
        // 500 frames per epoch.
        for i in 0..500 {
            let s = seal_frame(&sample_frame(i), &mut sender).unwrap();
            assert!(
                open_frame(&s, &mut receiver).is_ok(),
                "rekey {rekey} seq {i}",
            );
        }
        key[0] = (rekey + 2) as u8; // new key each time
        sender.install_key(key);
        receiver.install_key(key);
    }
}
