// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Kani harnesses for the replay transition kernel.
//!
//! Kept separate from the production kernel so proof-harness evolution does
//! not alter the production subject blob. This module is compiled only under
//! Kani and exercises the crate-private production transition API.

use crate::replay_kernel::{ReplayState, transition};

const WORD_BITS: u32 = u64::BITS;

fn any_window_bits() -> u32 {
    let selector: u8 = kani::any();
    match selector % 5 {
        0 => 64,
        1 => 128,
        2 => 256,
        3 => 512,
        _ => 1024,
    }
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_duplicate_rejected() {
    let mut state = ReplayState::new();
    let seq: u64 = kani::any();
    assert!(transition(&mut state, 64, seq));
    assert!(!transition(&mut state, 64, seq));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_first_sequence_initializes_exactly() {
    let mut state = ReplayState::new();
    let seq: u64 = kani::any();
    assert!(transition(&mut state, 64, seq));
    assert!(state.initialized);
    assert!(state.highest == seq);
    assert!(state.bitmap[0] == 1);
    for i in 1..state.bitmap.len() {
        assert!(state.bitmap[i] == 0);
    }
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_stale_boundary_is_rejected() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 64, 100));
    assert!(!transition(&mut state, 64, 36));
    assert!(transition(&mut state, 64, 37));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_higher_sequence_is_monotonic() {
    let mut state = ReplayState::new();
    let first: u64 = kani::any();
    let next: u64 = kani::any();
    kani::assume(next > first);
    assert!(transition(&mut state, 64, first));
    assert!(transition(&mut state, 64, next));
    assert!(state.highest == next);
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_cross_word_shift_preserves_in_window_history() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 128, 100));
    assert!(transition(&mut state, 128, 99));
    assert!(transition(&mut state, 128, 164)); // exact 65-bit cross-word shift
    assert!(!transition(&mut state, 128, 99)); // old bit moved to offset 65
    assert!(transition(&mut state, 128, 98)); // unseen, still in window
    assert!(!transition(&mut state, 128, 98));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_exact_word_shift_preserves_in_window_history() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 128, 100));
    assert!(transition(&mut state, 128, 99));
    assert!(transition(&mut state, 128, 164)); // exact 64-bit word shift
    assert!(!transition(&mut state, 128, 100)); // old highest moved to offset 64
    assert!(!transition(&mut state, 128, 99)); // old offset 1 moved to offset 65
    assert!(transition(&mut state, 128, 98)); // unseen, still in window
    assert!(!transition(&mut state, 128, 98));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_max_width_multiword_shift_preserves_history() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 1024, 1000));
    assert!(transition(&mut state, 1024, 999));
    assert!(transition(&mut state, 1024, 1513)); // exact 513-bit multiword shift
    assert!(!transition(&mut state, 1024, 1000)); // moved to offset 513
    assert!(!transition(&mut state, 1024, 999)); // moved to offset 514
    assert!(transition(&mut state, 1024, 998)); // unseen, still in window
    assert!(!transition(&mut state, 1024, 998));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_exact_window_jump_resets_history() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 64, 100));
    assert!(transition(&mut state, 64, 99));
    assert!(transition(&mut state, 64, 164)); // exact 64-bit jump resets history
    assert!(transition(&mut state, 64, 163)); // fresh history remains usable
    assert!(!transition(&mut state, 64, 164)); // new highest duplicate rejected
    assert!(!transition(&mut state, 64, 99)); // old history was discarded
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_max_width_near_window_shift_preserves_history_boundary() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 1024, 1000));
    assert!(transition(&mut state, 1024, 999));
    assert!(transition(&mut state, 1024, 2023)); // exact 1023-bit shift
    assert!(!transition(&mut state, 1024, 999)); // old offset 1 moved to offset 1024 and is rejected
    assert!(!transition(&mut state, 1024, 1000)); // old highest moved to offset 1023 and remains in-window
    assert!(transition(&mut state, 1024, 1001)); // unseen, in-window at offset 1022
    assert!(!transition(&mut state, 1024, 1001));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_symbolic_shift_preserves_or_discards_history_exactly() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 1024, 1000));
    assert!(transition(&mut state, 1024, 999)); // mark offset 1

    let delta: u64 = kani::any();
    kani::assume(delta > 0);
    kani::assume(delta < 1024);

    assert!(transition(&mut state, 1024, 1000 + delta));
    assert!(state.highest == 1000 + delta);

    assert!(!transition(&mut state, 1024, 999));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_supported_widths_do_not_panic() {
    let mut state = ReplayState::new();
    let width = any_window_bits();
    let first: u64 = kani::any();
    let second: u64 = kani::any();
    kani::assume(second >= first);
    let _ = transition(&mut state, width, first);
    let _ = transition(&mut state, width, second);
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_supported_width_boundary_is_exact() {
    let width = any_window_bits();
    let base = width as u64 + 1;
    let mut state = ReplayState::new();
    assert!(transition(&mut state, width, base));
    assert!(!transition(&mut state, width, base - width as u64));
    assert!(transition(&mut state, width, base - width as u64 + 1));
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_bitmap_tail_is_zero_for_supported_widths() {
    let width = any_window_bits();
    let words = (width / WORD_BITS) as usize;
    let mut state = ReplayState::new();
    let first: u64 = kani::any();
    let second: u64 = kani::any();
    kani::assume(second >= first);
    let _ = transition(&mut state, width, first);
    let _ = transition(&mut state, width, second);
    for i in words..state.bitmap.len() {
        assert!(state.bitmap[i] == 0);
    }
}

#[kani::proof]
#[kani::unwind(20)]
fn kernel_u64_max_advance_preserves_previous_sequence() {
    let mut state = ReplayState::new();
    assert!(transition(&mut state, 64, u64::MAX - 1));
    assert!(transition(&mut state, 64, u64::MAX));
    assert!(!transition(&mut state, 64, u64::MAX));
    assert!(!transition(&mut state, 64, u64::MAX - 1));
}
