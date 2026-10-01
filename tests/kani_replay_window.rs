// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Kani proof harnesses for the production `ReplayWindow` transition kernel.
//!
//! Evidence boundary: these harnesses provide bounded model-safety evidence
//! over the exact production API. They are not an unbounded replay-security
//! theorem, cryptographic proof, compiler proof, or runtime authorization.

// Ordinary cargo test/clippy still parses this Kani-only target; older stable
// toolchains do not know the `kani` cfg name. Kani itself supplies it.
// Keep the allowance scoped to this proof-harness target only.
#![allow(unexpected_cfgs)]
#![cfg(kani)]

use xenia_wire::ReplayWindow;

#[kani::proof]
fn immediate_duplicate_is_rejected() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let seq: u64 = kani::any();

    let mut window = ReplayWindow::new();
    assert!(window.accept(source_id, payload_type, key_epoch, seq));
    assert!(!window.accept(source_id, payload_type, key_epoch, seq));
}

#[kani::proof]
fn unseen_out_of_order_sequence_is_accepted_once() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let high: u64 = kani::any();
    kani::assume(high > 0);
    let previous = high - 1;

    let mut window = ReplayWindow::new();
    assert!(window.accept(source_id, payload_type, key_epoch, high));
    assert!(window.accept(source_id, payload_type, key_epoch, previous));
    assert!(!window.accept(source_id, payload_type, key_epoch, previous));
}

#[kani::proof]
fn sequence_at_window_width_is_stale() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let high: u64 = kani::any();
    kani::assume(high >= 64);
    let stale = high - 64;

    let mut window = ReplayWindow::new();
    assert!(window.accept(source_id, payload_type, key_epoch, high));
    assert!(!window.accept(source_id, payload_type, key_epoch, stale));
}

#[kani::proof]
fn higher_sequence_advances_without_reviving_duplicates() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let seq: u64 = kani::any();
    kani::assume(seq < u64::MAX);
    let next = seq + 1;

    let mut window = ReplayWindow::new();
    assert!(window.accept(source_id, payload_type, key_epoch, seq));
    assert!(window.accept(source_id, payload_type, key_epoch, next));
    assert!(!window.accept(source_id, payload_type, key_epoch, next));
    assert!(!window.accept(source_id, payload_type, key_epoch, seq));
}

#[kani::proof]
fn stream_key_dimensions_are_isolated() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let seq: u64 = kani::any();

    let other_source = source_id.wrapping_add(1);
    let other_payload = payload_type.wrapping_add(1);
    let other_epoch = key_epoch.wrapping_add(1);

    let mut window = ReplayWindow::new();
    assert!(window.accept(source_id, payload_type, key_epoch, seq));
    assert!(window.accept(other_source, payload_type, key_epoch, seq));
    assert!(window.accept(source_id, other_payload, key_epoch, seq));
    assert!(window.accept(source_id, payload_type, other_epoch, seq));
}

#[kani::proof]
fn drop_epoch_is_narrow() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let seq: u64 = kani::any();
    let other_epoch = key_epoch.wrapping_add(1);

    let mut window = ReplayWindow::new();
    assert!(window.accept(source_id, payload_type, key_epoch, seq));
    assert!(window.accept(source_id, payload_type, other_epoch, seq));

    window.drop_epoch(key_epoch);

    // Dropped epoch starts fresh; the other epoch must retain its replay bit.
    assert!(window.accept(source_id, payload_type, key_epoch, seq));
    assert!(!window.accept(source_id, payload_type, other_epoch, seq));
}

#[kani::proof]
fn cross_word_shift_preserves_seen_bit() {
    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let shift: u64 = kani::any();
    kani::assume((65..128).contains(&shift));

    let mut window = ReplayWindow::with_window_bits(128);
    assert!(window.accept(source_id, payload_type, key_epoch, 0));
    assert!(window.accept(source_id, payload_type, key_epoch, shift));

    // seq 0 remains inside the 128-bit window and must still be marked seen,
    // including when the shift crosses the 64-bit word boundary.
    assert!(!window.accept(source_id, payload_type, key_epoch, 0));
}

#[kani::proof]
fn admitted_window_widths_do_not_panic_on_transitions() {
    let words: u32 = kani::any();
    kani::assume((1..=16).contains(&words));
    let bits = words * 64;

    let source_id: u64 = kani::any();
    let payload_type: u8 = kani::any();
    let key_epoch: u32 = kani::any();
    let first: u64 = kani::any();
    let second: u64 = kani::any();
    let third: u64 = kani::any();

    let mut window = ReplayWindow::with_window_bits(bits);
    let _ = window.accept(source_id, payload_type, key_epoch, first);
    let _ = window.accept(source_id, payload_type, key_epoch, second);
    let _ = window.accept(source_id, payload_type, key_epoch, third);
}
