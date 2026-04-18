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

/// Width of the bitmap tracking recent sequence numbers, in bits.
///
/// 64 bits is the standard IPsec/DTLS replay window width and is large
/// enough to absorb realistic out-of-order delivery on a WebSocket or
/// unreliable UDP stream while being cheap to update (single u64 shift +
/// OR).
pub const WINDOW_BITS: u64 = 64;

/// Per-stream replay state: highest sequence seen + bitmap of the most
/// recent [`WINDOW_BITS`] sequences.
#[derive(Debug, Clone, Default)]
struct StreamWindow {
    /// Highest sequence number seen so far. The bitmap tracks
    /// `[highest - WINDOW_BITS + 1, highest]`. Bit position 0 = highest,
    /// bit position `WINDOW_BITS-1` = oldest.
    highest: u64,
    /// 64-bit bitmap of received sequences. Bit `i` corresponds to sequence
    /// `highest - i`. Bit 0 (LSB) is always set if `highest` was seen
    /// (which it always is once the window is initialized).
    bitmap: u64,
    /// Whether this window has seen any sequence yet.
    initialized: bool,
}

/// Sliding-window replay protection for multiple independent streams.
///
/// Streams are keyed by `(source_id, payload_type, key_epoch)` — see
/// module-level docs on why the key epoch matters across rekey. Use
/// [`Self::accept`] to atomically check-and-mark a sequence as received.
#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    streams: HashMap<(u64, u8, u8), StreamWindow>,
}

impl ReplayWindow {
    /// Create an empty replay window with no tracked streams.
    pub fn new() -> Self {
        Self::default()
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
        let win = self
            .streams
            .entry((source_id, payload_type, key_epoch))
            .or_default();

        if !win.initialized {
            // First sequence for this stream: accept and initialize.
            win.highest = seq;
            win.bitmap = 1; // bit 0 = "seq seen"
            win.initialized = true;
            return true;
        }

        if seq > win.highest {
            // New high sequence: shift the bitmap.
            let shift = seq - win.highest;
            if shift >= WINDOW_BITS {
                // Window jumped entirely past the old bitmap.
                win.bitmap = 1;
            } else {
                // Shift left and set bit 0 for the new highest.
                win.bitmap = (win.bitmap << shift) | 1;
            }
            win.highest = seq;
            true
        } else {
            // seq <= highest: check if it falls within the window and is unseen.
            let offset = win.highest - seq;
            if offset >= WINDOW_BITS {
                // Too old.
                false
            } else {
                let mask = 1u64 << offset;
                if win.bitmap & mask != 0 {
                    // Already seen.
                    false
                } else {
                    // In window, unseen → accept and mark.
                    win.bitmap |= mask;
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
