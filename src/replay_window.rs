// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Replay-protection sliding window for AEAD-sealed streams.
//!
//! ## Why
//!
//! ChaCha20-Poly1305 + monotonic nonce prevents *encryption* reuse (the
//! sender will never produce two ciphertexts with the same nonce under the
//! same key), but it does NOT prevent a network attacker from capturing a
//! sealed envelope and replaying it later — the receiver will accept it
//! because AEAD verification still succeeds against the original key.
//!
//! For idempotent payloads (screen updates) replay is mostly cosmetic. For
//! reverse-path input messages, replay is a real security hole: a
//! captured `tap (504, 1122)` could be re-fired to re-execute the action.
//!
//! ## Design
//!
//! Sliding window over received sequence numbers, keyed by `(source_id,
//! payload_type)`. Window size is [`WINDOW_BITS`] bits — the receiver tracks
//! the highest sequence number seen so far plus a [`WINDOW_BITS`]-bit bitmap
//! of the most recent sequences. A sequence is accepted iff:
//!
//! 1. It is strictly higher than the highest-seen-so-far (advance the
//!    window), OR
//! 2. It falls within the bitmap range AND the corresponding bit is unset
//!    (mark the bit, accept the message).
//!
//! Sequences that are too old (more than [`WINDOW_BITS`] below the highest
//! seen) are rejected outright. Duplicates within the bitmap range are
//! rejected.
//!
//! ## Wraparound
//!
//! u64 sequence space is effectively unbounded — at 30 frames/sec this
//! wraps in ~19 billion years. The implementation does not handle
//! wraparound specifically because real session lifetime (governed by key
//! rotation) is many orders of magnitude shorter.
//!
//! ## Multi-stream isolation
//!
//! Different `(source_id, payload_type)` tuples have independent windows.
//! This is required because the forward-path frame stream and reverse-path
//! input stream share a session key but maintain independent sequence
//! counters via [`crate::Session::next_nonce`]. Replay protection is per
//! tuple, not per session.
//!
//! ## Key epoch scoping (SPEC draft-02r1 §5.3)
//!
//! Windows are additionally scoped by a `key_epoch` byte that
//! increments each time a new session key is installed. This matters
//! because [`crate::Session::install_key`] resets the nonce counter
//! to `0` on rekey — without per-epoch scoping, a counter-reset
//! sender would produce low sequences that the receiver would
//! reject against a still-high `highest` from the previous key.
//!
//! During the rekey grace period two per-epoch windows are live
//! simultaneously for the same `(source_id, payload_type)` stream
//! — one per key — and each envelope is routed to the window
//! matching the key that verified its AEAD tag. When the previous
//! key expires, [`ReplayWindow::drop_epoch`] removes that epoch's
//! entries to bound memory.

use std::collections::HashMap;

/// Default replay window width in bits.
///
/// 64 bits is the standard IPsec/DTLS replay window width. See SPEC §5.1.
/// Configurable per-session via [`crate::SessionBuilder::with_replay_window_bits`]
/// (draft-02r2 / alpha.5+) up to [`MAX_WINDOW_BITS`].
pub const DEFAULT_WINDOW_BITS: u32 = 64;

/// Maximum supported replay window width in bits.
///
/// 1024 bits = 128 bytes of bitmap per stream. Suitable for high-jitter
/// transports where ~64-packet reordering is realistic. The upper bound
/// is chosen to keep per-stream memory bounded; callers with unusual
/// requirements can bump this constant, but the default / SPEC-specified
/// maximum is 1024.
pub const MAX_WINDOW_BITS: u32 = 1024;

/// Legacy alias for [`DEFAULT_WINDOW_BITS`]. Kept for backwards-
/// compatible public API; new code should use `DEFAULT_WINDOW_BITS`.
pub const WINDOW_BITS: u64 = DEFAULT_WINDOW_BITS as u64;

/// Per-stream replay state: highest sequence seen + bitmap of the most
/// recent `window_bits` sequences. The bitmap is stored as a vector of
/// u64 words, length = `window_bits / 64`.
#[derive(Debug, Clone)]
struct StreamWindow {
    /// Highest sequence number seen so far. The bitmap tracks
    /// `[highest - window_bits + 1, highest]`. Bit position 0 = highest,
    /// bit position `window_bits-1` = oldest.
    highest: u64,
    /// Bitmap of received sequences. `bitmap[w]` covers bits
    /// `[64*w .. 64*(w+1))` in offset-from-highest space. Bit 0 of
    /// `bitmap[0]` is always set once the window is initialized
    /// (corresponds to `highest`).
    bitmap: Vec<u64>,
    /// Whether this window has seen any sequence yet.
    initialized: bool,
}

impl StreamWindow {
    fn new(bitmap_words: usize) -> Self {
        Self {
            highest: 0,
            bitmap: vec![0u64; bitmap_words],
            initialized: false,
        }
    }
}

/// Sliding-window replay protection for multiple independent streams.
///
/// Streams are keyed by `(source_id, payload_type, key_epoch)` — see
/// module-level docs on why the key epoch matters across rekey. Use
/// [`Self::accept`] to atomically check-and-mark a sequence as received.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    streams: HashMap<(u64, u8, u8), StreamWindow>,
    window_bits: u32,
    bitmap_words: usize,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Create an empty replay window with the default 64-bit width.
    pub fn new() -> Self {
        Self::with_window_bits(DEFAULT_WINDOW_BITS)
    }

    /// Create an empty replay window with a caller-chosen width.
    ///
    /// `bits` MUST be a multiple of 64, at least 64, at most
    /// [`MAX_WINDOW_BITS`] (1024). Panics otherwise.
    pub fn with_window_bits(bits: u32) -> Self {
        assert!(
            (DEFAULT_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&bits)
                && bits % DEFAULT_WINDOW_BITS == 0,
            "replay window bits must be a multiple of 64 between 64 and 1024; got {bits}",
        );
        Self {
            streams: HashMap::new(),
            window_bits: bits,
            bitmap_words: (bits / DEFAULT_WINDOW_BITS) as usize,
        }
    }

    /// Current window width in bits.
    pub fn window_bits(&self) -> u32 {
        self.window_bits
    }

    /// Reset all tracked streams. Primarily useful for tests and for
    /// session teardown. Rekey-driven cleanup is narrower — use
    /// [`Self::drop_epoch`] to forget only the old key's windows while
    /// preserving the current one.
    pub fn clear(&mut self) {
        self.streams.clear();
    }

    /// Atomically check whether `seq` is acceptable for the given
    /// `(source_id, payload_type, key_epoch)` tuple, and mark it as
    /// received if so.
    ///
    /// Returns `true` if the message should be processed (sequence is new
    /// and within the window), `false` if it should be dropped (duplicate
    /// or too old).
    ///
    /// `source_id` is the 6-byte random identifier from the AEAD nonce
    /// interpreted as little-endian u64. `payload_type` is the nonce
    /// byte 6. `key_epoch` is a receiver-local counter that advances on
    /// every `install_key` call — the caller MUST pass the epoch of the
    /// key that verified the AEAD tag, not (for example) the current
    /// epoch if the previous key is what actually opened the envelope.
    pub fn accept(&mut self, source_id: u64, payload_type: u8, key_epoch: u8, seq: u64) -> bool {
        let window_bits_u64 = self.window_bits as u64;
        let bitmap_words = self.bitmap_words;
        let win = self
            .streams
            .entry((source_id, payload_type, key_epoch))
            .or_insert_with(|| StreamWindow::new(bitmap_words));

        if !win.initialized {
            // First sequence for this stream: accept and initialize.
            win.highest = seq;
            win.bitmap.fill(0);
            win.bitmap[0] = 1; // bit 0 (offset 0 = highest) = "seq seen"
            win.initialized = true;
            return true;
        }

        if seq > win.highest {
            // New high sequence: shift the bitmap left by (seq - highest)
            // bits. Bits shifted past the window edge are discarded.
            let shift = seq - win.highest;
            if shift >= window_bits_u64 {
                // Jumped entirely past the old bitmap. Clear + seed.
                win.bitmap.fill(0);
                win.bitmap[0] = 1;
            } else {
                shift_bitmap_left(&mut win.bitmap, shift as u32);
                // Seed bit 0 (the new highest) AFTER shifting.
                win.bitmap[0] |= 1;
            }
            win.highest = seq;
            true
        } else {
            // seq <= highest: check if it falls within the window and is
            // unseen.
            let offset = win.highest - seq;
            if offset >= window_bits_u64 {
                // Too old.
                false
            } else {
                let word_idx = (offset / DEFAULT_WINDOW_BITS as u64) as usize;
                let bit_idx = (offset % DEFAULT_WINDOW_BITS as u64) as u32;
                let mask = 1u64 << bit_idx;
                if win.bitmap[word_idx] & mask != 0 {
                    false
                } else {
                    win.bitmap[word_idx] |= mask;
                    true
                }
            }
        }
    }

    /// Drop all stream state associated with a specific `key_epoch`.
    /// Called by [`crate::Session::tick`] when the previous-key grace
    /// period ends — at that point the old key's envelopes can no longer
    /// verify anyway, so the old window is pure memory overhead and
    /// should be reclaimed. Safe to call for an epoch that has no
    /// entries (no-op).
    pub fn drop_epoch(&mut self, key_epoch: u8) {
        self.streams.retain(|(_, _, epoch), _| *epoch != key_epoch);
    }

    /// Number of distinct streams currently tracked. Mostly for tests and
    /// observability; not part of the protection guarantee.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

/// Shift a multi-word bitmap left by `shift` bits, filling low bits
/// with zeros. `bitmap[0]` is the LOW word (covers bit offsets 0..64).
/// `bitmap[N]` is higher. A left shift moves bits toward higher offsets
/// — equivalent to `u64::<<` semantics extended across words.
///
/// Precondition: `shift < bitmap.len() * 64`. The caller (`accept`)
/// handles the shift-past-end case by clearing the bitmap instead.
///
/// Runs in O(N) where N is the number of words. For the default
/// 1-word (64-bit) case this degenerates to a single `u64 << shift`.
#[inline]
fn shift_bitmap_left(bitmap: &mut [u64], shift: u32) {
    debug_assert!(
        (shift as usize) < bitmap.len() * 64,
        "shift {} out of range for {}-word bitmap",
        shift,
        bitmap.len()
    );
    if bitmap.is_empty() || shift == 0 {
        return;
    }
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let len = bitmap.len();

    if bit_shift == 0 {
        // Pure word shift — move whole words, zero the low ones.
        for i in (0..len).rev() {
            bitmap[i] = if i >= word_shift {
                bitmap[i - word_shift]
            } else {
                0
            };
        }
        return;
    }

    // General case: each output word gets a contribution from the
    // high part of one source word (<< bit_shift) OR'd with the
    // low part of the next-lower source word (>> (64 - bit_shift)).
    // Iterate from high to low so we don't clobber sources.
    let inv_bit_shift = 64 - bit_shift;
    for i in (0..len).rev() {
        let hi_src = if i >= word_shift {
            bitmap[i - word_shift] << bit_shift
        } else {
            0
        };
        let lo_src = if i > word_shift {
            bitmap[i - word_shift - 1] >> inv_bit_shift
        } else {
            0
        };
        bitmap[i] = hi_src | lo_src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: u64 = 0xDEAD_BEEF_CAFE_BABE;
    const EPOCH: u8 = 0; // most single-epoch tests use epoch 0

    fn accept_default(w: &mut ReplayWindow, pld: u8, seq: u64) -> bool {
        w.accept(SRC, pld, EPOCH, seq)
    }

    #[test]
    fn first_sequence_accepted() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 0));
    }

    #[test]
    fn sequential_sequences_accepted() {
        let mut w = ReplayWindow::new();
        for seq in 0..100 {
            assert!(accept_default(&mut w, 0x10, seq), "seq {seq} should accept");
        }
    }

    #[test]
    fn duplicate_at_highest_rejected() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 5));
        assert!(
            !accept_default(&mut w, 0x10, 5),
            "duplicate at highest should reject"
        );
    }

    #[test]
    fn duplicate_within_window_rejected() {
        let mut w = ReplayWindow::new();
        for seq in 0..=5 {
            assert!(accept_default(&mut w, 0x10, seq));
        }
        assert!(!accept_default(&mut w, 0x10, 2));
        assert!(accept_default(&mut w, 0x10, 6));
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 10));
        assert!(accept_default(&mut w, 0x10, 7));
        assert!(!accept_default(&mut w, 0x10, 7));
        assert!(accept_default(&mut w, 0x10, 8));
    }

    #[test]
    fn too_old_sequence_rejected() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 100));
        assert!(!accept_default(&mut w, 0x10, 35));
        assert!(!accept_default(&mut w, 0x10, 36));
        assert!(accept_default(&mut w, 0x10, 37));
    }

    #[test]
    fn future_arrival_shifts_window_correctly() {
        let mut w = ReplayWindow::new();
        for seq in 0..=5 {
            assert!(accept_default(&mut w, 0x10, seq));
        }
        assert!(accept_default(&mut w, 0x10, 1000));
        for seq in 0..=5 {
            assert!(
                !accept_default(&mut w, 0x10, seq),
                "old seq {seq} after jump should reject"
            );
        }
        assert!(accept_default(&mut w, 0x10, 999));
        assert!(accept_default(&mut w, 0x10, 950));
        assert!(!accept_default(&mut w, 0x10, 936));
    }

    #[test]
    fn independent_streams_dont_interfere() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 5));
        assert!(accept_default(&mut w, 0x11, 5));
        assert!(!accept_default(&mut w, 0x10, 5));
        assert!(!accept_default(&mut w, 0x11, 5));
        assert_eq!(w.stream_count(), 2);
    }

    #[test]
    fn different_source_ids_dont_interfere() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0xAAAA_AAAA_AAAA_AAAA, 0x10, EPOCH, 100));
        assert!(w.accept(0xBBBB_BBBB_BBBB_BBBB, 0x10, EPOCH, 100));
        assert!(!w.accept(0xAAAA_AAAA_AAAA_AAAA, 0x10, EPOCH, 100));
        assert_eq!(w.stream_count(), 2);
    }

    #[test]
    fn window_edge_exactly_window_bits_below_rejected() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 100));
        assert!(!accept_default(&mut w, 0x10, 36));
        assert!(accept_default(&mut w, 0x10, 37));
    }

    #[test]
    fn clear_resets_all_streams() {
        let mut w = ReplayWindow::new();
        assert!(accept_default(&mut w, 0x10, 5));
        assert!(accept_default(&mut w, 0x11, 7));
        assert_eq!(w.stream_count(), 2);
        w.clear();
        assert_eq!(w.stream_count(), 0);
        assert!(accept_default(&mut w, 0x10, 5));
        assert!(accept_default(&mut w, 0x11, 7));
    }

    // ─── Per-key-epoch tests (SPEC §5.3) ───────────────────────────────

    #[test]
    fn independent_epochs_dont_interfere_even_with_same_stream() {
        // This is the bug-fix regression test. Before the epoch split,
        // the second accept for epoch=1 at seq=0 would be rejected
        // because highest=1000 from epoch=0 was stored in a window
        // keyed only by (source_id, pld_type).
        let mut w = ReplayWindow::new();
        for seq in 0..=1000 {
            assert!(w.accept(SRC, 0x10, 0, seq));
        }
        // Rekey: new epoch starts fresh at seq=0.
        assert!(
            w.accept(SRC, 0x10, 1, 0),
            "new-epoch seq=0 must be accepted despite old-epoch highest=1000"
        );
        assert!(w.accept(SRC, 0x10, 1, 1));
        assert!(w.accept(SRC, 0x10, 1, 2));
    }

    #[test]
    fn drop_epoch_removes_only_that_epoch() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(SRC, 0x10, 0, 5));
        assert!(w.accept(SRC, 0x10, 1, 5));
        assert!(w.accept(SRC, 0x11, 0, 5));
        assert_eq!(w.stream_count(), 3);

        w.drop_epoch(0);
        assert_eq!(w.stream_count(), 1); // only (SRC, 0x10, 1) left

        // Re-accepting on the dropped epoch is fine — fresh state.
        assert!(w.accept(SRC, 0x10, 0, 5));
        // But the un-dropped epoch still sees its old state.
        assert!(!w.accept(SRC, 0x10, 1, 5));
    }

    #[test]
    fn drop_epoch_with_no_entries_is_noop() {
        let mut w = ReplayWindow::new();
        w.drop_epoch(42); // no-op, must not panic
        assert_eq!(w.stream_count(), 0);
    }
}
