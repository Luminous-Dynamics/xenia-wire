// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Kani proof harnesses for the production `ReplayWindow` transition kernel.
//!
//! Evidence boundary: bounded model-safety over the exact production API.
//! These harnesses are not unbounded replay-security, cryptographic,
//! compiler-correctness, or runtime-authorization proofs.

#![allow(unexpected_cfgs)]
#![cfg(kani)]

use xenia_wire::ReplayWindow;

const SOURCE_ID: u64 = 0x1122_3344_5566_7788;
const PAYLOAD_TYPE: u8 = 0x30;
const KEY_EPOCH: u32 = 7;

#[kani::proof]
fn immediate_duplicate_is_rejected() {
    let seq: u64 = kani::any();
    let mut window = ReplayWindow::new();
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
}

#[kani::proof]
fn unseen_out_of_order_sequence_is_accepted_once() {
    let high: u64 = kani::any();
    kani::assume(high > 0);
    let previous = high - 1;

    let mut window = ReplayWindow::new();
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, high));
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, previous));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, previous));
}

#[kani::proof]
fn sequence_at_window_width_is_stale() {
    let high: u64 = kani::any();
    kani::assume(high >= 64);
    let stale = high - 64;

    let mut window = ReplayWindow::new();
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, high));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, stale));
}

#[kani::proof]
fn higher_sequence_advances_without_reviving_duplicates() {
    let seq: u64 = kani::any();
    kani::assume(seq < u64::MAX);
    let next = seq + 1;

    let mut window = ReplayWindow::new();
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, next));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, next));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
}

#[kani::proof]
fn stream_key_dimensions_are_isolated() {
    let seq: u64 = kani::any();

    let mut window = ReplayWindow::new();
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
    assert!(window.accept(SOURCE_ID.wrapping_add(1), PAYLOAD_TYPE, KEY_EPOCH, seq));
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE.wrapping_add(1), KEY_EPOCH, seq));
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH + 1, seq));
}

#[kani::proof]
fn drop_epoch_is_narrow() {
    let seq: u64 = kani::any();

    let mut window = ReplayWindow::new();
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH + 1, seq));

    window.drop_epoch(KEY_EPOCH);

    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, seq));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH + 1, seq));
}

#[kani::proof]
fn cross_word_shift_preserves_seen_bit() {
    let selector: u8 = kani::any();
    kani::assume(selector < 63);
    let shift = 65u64 + selector as u64;

    let mut window = ReplayWindow::with_window_bits(128);
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, 0));
    assert!(window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, shift));
    assert!(!window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, 0));
}

#[kani::proof]
fn admitted_window_widths_do_not_panic_on_transitions() {
    let selector: u8 = kani::any();
    kani::assume(selector < 4);
    let bits = match selector {
        0 => 64,
        1 => 128,
        2 => 512,
        _ => 1024,
    };

    let first: u64 = kani::any();
    let second: u64 = kani::any();
    let third: u64 = kani::any();

    let mut window = ReplayWindow::with_window_bits(bits);
    let _ = window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, first);
    let _ = window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, second);
    let _ = window.accept(SOURCE_ID, PAYLOAD_TYPE, KEY_EPOCH, third);
}
