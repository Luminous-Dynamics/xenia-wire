// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Deterministic per-stream replay transition kernel.
//!
//! This module deliberately contains no map routing, hashing, allocation, or
//! dynamic bitmap storage. ReplayWindow owns those concerns; it delegates
//! every production transition to this exact kernel so the formal target is
//! the code that runs in production.

const MAX_BITMAP_WORDS: usize = 16;
const WORD_BITS: u32 = 64;

#[derive(Debug, Clone)]
pub(crate) struct ReplayState {
    pub(crate) highest: u64,
    pub(crate) bitmap: [u64; MAX_BITMAP_WORDS],
    pub(crate) initialized: bool,
}

impl ReplayState {
    pub(crate) fn new() -> Self {
        Self { highest: 0, bitmap: [0; MAX_BITMAP_WORDS], initialized: false }
    }
}

/// Apply one replay-window transition to one already-routed stream.
///
/// The bitmap uses offset-from-highest semantics: bit 0 represents
/// highest, bit 1 represents highest - 1, etc. window_bits is an
/// admitted multiple of 64 between 64 and 1024.
///
/// This is the production transition function used by ReplayWindow::accept.
pub(crate) fn transition(state: &mut ReplayState, window_bits: u32, seq: u64) -> bool {
    debug_assert!((64..=1024).contains(&window_bits) && window_bits % WORD_BITS == 0);
    let words = (window_bits / WORD_BITS) as usize;

    if !state.initialized {
        state.highest = seq;
        state.bitmap = [0; MAX_BITMAP_WORDS];
        state.bitmap[0] = 1;
        state.initialized = true;
        return true;
    }

    if seq > state.highest {
        let shift = seq - state.highest;
        if shift >= window_bits as u64 {
            state.bitmap = [0; MAX_BITMAP_WORDS];
            state.bitmap[0] = 1;
        } else {
            shift_bitmap_left(&mut state.bitmap, words, shift as u32);
            state.bitmap[0] |= 1;
        }
        state.highest = seq;
        true
    } else {
        let offset = state.highest - seq;
        if offset >= window_bits as u64 {
            false
        } else {
            let word_idx = (offset / WORD_BITS as u64) as usize;
            let bit_idx = (offset % WORD_BITS as u64) as u32;
            let mask = 1u64 << bit_idx;
            if state.bitmap[word_idx] & mask != 0 { false } else {
                state.bitmap[word_idx] |= mask;
                true
            }
        }
    }
}

#[inline]
fn shift_bitmap_left(bitmap: &mut [u64; MAX_BITMAP_WORDS], words: usize, shift: u32) {
    debug_assert!(words > 0 && words <= MAX_BITMAP_WORDS);
    debug_assert!((shift as usize) < words * WORD_BITS as usize);
    if shift == 0 { return; }
    let word_shift = (shift / WORD_BITS) as usize;
    let bit_shift = shift % WORD_BITS;
    if bit_shift == 0 {
        for i in (0..words).rev() {
            bitmap[i] = if i >= word_shift { bitmap[i - word_shift] } else { 0 };
        }
    } else {
        let inv = WORD_BITS - bit_shift;
        for i in (0..words).rev() {
            let hi = if i >= word_shift { bitmap[i - word_shift] << bit_shift } else { 0 };
            let lo = if i > word_shift { bitmap[i - word_shift - 1] >> inv } else { 0 };
            bitmap[i] = hi | lo;
        }
    }
    for i in 0..MAX_BITMAP_WORDS { if i >= words { bitmap[i] = 0; } }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn any_window_bits() -> u32 {
        let selector: u8 = kani::any();
        match selector % 5 { 0 => 64, 1 => 128, 2 => 256, 3 => 512, _ => 1024 }
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
        for i in 1..MAX_BITMAP_WORDS { assert!(state.bitmap[i] == 0); }
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
        assert!(transition(&mut state, 128, 98));  // unseen, still in window
        assert!(!transition(&mut state, 128, 98));
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
        for i in words..MAX_BITMAP_WORDS {
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
}
