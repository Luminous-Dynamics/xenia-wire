// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Session state: keys, nonce construction, replay protection.
//!
//! A [`Session`] holds the minimum state required to seal and open AEAD
//! envelopes for a single logical stream:
//!
//! - the current 32-byte ChaCha20-Poly1305 key,
//! - an optional previous key with a grace period so in-flight envelopes
//!   sealed under the old key still verify after rekey,
//! - a per-session random 8-byte `source_id` and 1-byte `epoch` that
//!   domain-separate this session's nonces from any other session sharing
//!   (by accident or compromise) the same key material,
//! - a monotonic 64-bit `nonce_counter` that advances on every seal,
//! - a [`crate::ReplayWindow`] that rejects duplicates and too-old sequences
//!   on the receive path.
//!
//! Not in this crate's scope:
//!
//! - **Handshake**: session keys arrive from an outer layer (ML-KEM-768 in
//!   production deployments; a shared fixture in tests).
//! - **Transport**: sealed envelope bytes are handed to the caller; the
//!   caller ships them over TCP / WebSocket / QUIC / UDP / IPFS / bytes
//!   on a napkin.
//! - **Session lifecycle**: connecting, authenticating, closing — all
//!   application concerns. `Session` has no state machine; `install_key`
//!   is idempotent and `seal` / `open` simply fail when no key is present.

use std::time::Duration;

// `std::time::Instant` panics on `wasm32-unknown-unknown` because there is no
// default time source. `web-time` provides a drop-in replacement that delegates
// to `performance.now()` via wasm-bindgen. On native targets it re-exports
// `std::time::Instant`, so the API surface is identical.
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

use zeroize::Zeroizing;

use crate::replay_window::ReplayWindow;
use crate::WireError;

#[cfg(feature = "consent")]
use crate::consent::ConsentEvent;

/// Default grace period for the previous session key after a rekey.
///
/// In-flight envelopes sealed under the old key continue to verify for
/// this window after the new key is installed, then fall back to failing
/// [`Session::open`]. 5 seconds accommodates a ~30 fps frame stream with
/// generous RTT headroom; callers with slower streams should widen via
/// [`Session::with_rekey_grace`].
pub const DEFAULT_REKEY_GRACE: Duration = Duration::from_secs(5);

/// Session state for a single logical stream.
///
/// See the module-level docs for what `Session` owns and what it
/// deliberately does not. Use [`Session::new`] to construct with random
/// `source_id` + `epoch`, then [`Session::install_key`] before the first
/// seal or open.
pub struct Session {
    /// Current session key (wrapped in `Zeroizing` so drop wipes it).
    session_key: Option<Zeroizing<[u8; 32]>>,
    /// Previous session key, still valid during the rekey grace period.
    prev_session_key: Option<Zeroizing<[u8; 32]>>,
    /// When the current key was installed (for observability + rotation
    /// policy decisions by higher layers).
    key_established_at: Option<Instant>,
    /// When the previous key stops being accepted for opens.
    prev_key_expires_at: Option<Instant>,
    /// Monotonic AEAD nonce counter.
    nonce_counter: u64,
    /// Per-session random 8-byte source identifier. 6 bytes land in the
    /// nonce; the remaining 2 are available for higher-layer routing if
    /// needed (not currently used by the wire).
    source_id: [u8; 8],
    /// Per-session random epoch byte. Further domain-separates nonces
    /// across sessions that happen to share the same key + source_id.
    epoch: u8,
    /// Sliding-window replay protection on the open path.
    replay_window: ReplayWindow,
    /// How long the previous key remains valid after rekey.
    rekey_grace: Duration,
    /// Epoch of the current session key (SPEC draft-02r1 §5.3).
    /// Increments (wrapping) on each `install_key`. Purely internal;
    /// not transmitted on the wire. Used to key per-epoch replay-window
    /// state so a counter reset at rekey doesn't clash with lingering
    /// high-water marks from the previous key.
    current_key_epoch: u8,
    /// Epoch of the previous session key during the rekey grace
    /// window. `Some` iff `prev_session_key` is `Some`.
    prev_key_epoch: Option<u8>,
    /// Consent ceremony state (draft-02 §12). Only enforced when the
    /// `consent` feature is compiled in.
    #[cfg(feature = "consent")]
    consent_state: crate::consent::ConsentState,
}

impl Session {
    /// Construct a session with random `source_id` + `epoch` and no key yet.
    ///
    /// Call [`Self::install_key`] before the first seal or open.
    pub fn new() -> Self {
        Self::with_source_id(rand::random(), rand::random())
    }

    /// Construct a session with caller-supplied `source_id` + `epoch`.
    ///
    /// Primarily useful for test fixtures and deterministic replay. The
    /// caller MUST ensure no two live sessions share the same
    /// `(source_id, epoch, key)` tuple — nonce reuse under ChaCha20-Poly1305
    /// catastrophically breaks confidentiality.
    pub fn with_source_id(source_id: [u8; 8], epoch: u8) -> Self {
        Self {
            session_key: None,
            prev_session_key: None,
            key_established_at: None,
            prev_key_expires_at: None,
            nonce_counter: 0,
            source_id,
            epoch,
            replay_window: ReplayWindow::new(),
            rekey_grace: DEFAULT_REKEY_GRACE,
            current_key_epoch: 0,
            prev_key_epoch: None,
            #[cfg(feature = "consent")]
            consent_state: crate::consent::ConsentState::Pending,
        }
    }

    /// Override the default rekey grace period. Must be called before the
    /// first rekey.
    pub fn with_rekey_grace(mut self, grace: Duration) -> Self {
        self.rekey_grace = grace;
        self
    }

    /// Install a 32-byte session key.
    ///
    /// First call installs the initial key. Subsequent calls perform a
    /// rekey: the previous key is moved to `prev_session_key` with a
    /// grace-period expiry of the configured `rekey_grace`; the new key becomes
    /// current; the nonce counter resets to zero.
    ///
    /// The replay window is NOT cleared on rekey, but it IS scoped by
    /// key epoch (SPEC §5.3 / draft-02r1) — the incoming new-key
    /// stream starts a fresh per-epoch window rather than fighting
    /// the old key's high-water mark. When the previous key expires
    /// in [`Self::tick`], its per-epoch replay state is dropped.
    pub fn install_key(&mut self, key: [u8; 32]) {
        if self.session_key.is_some() {
            self.prev_session_key = self.session_key.take();
            self.prev_key_expires_at = Some(Instant::now() + self.rekey_grace);
            self.prev_key_epoch = Some(self.current_key_epoch);
            self.current_key_epoch = self.current_key_epoch.wrapping_add(1);
        }
        self.session_key = Some(Zeroizing::new(key));
        self.key_established_at = Some(Instant::now());
        self.nonce_counter = 0;
    }

    /// Return `true` if the session has a current key.
    pub fn has_key(&self) -> bool {
        self.session_key.is_some()
    }

    /// Advance session state that depends on wall-clock time.
    ///
    /// Call periodically (e.g. once per tick, or lazily before seal/open)
    /// to expire the previous key once the grace period has elapsed.
    pub fn tick(&mut self) {
        if let Some(expires) = self.prev_key_expires_at {
            if Instant::now() > expires {
                self.prev_session_key = None;
                self.prev_key_expires_at = None;
                // Drop replay state for the old epoch — its envelopes
                // can no longer AEAD-verify, so the window is pure
                // memory overhead now.
                if let Some(old_epoch) = self.prev_key_epoch.take() {
                    self.replay_window.drop_epoch(old_epoch);
                }
            }
        }
    }

    /// Allocate the next AEAD nonce sequence number.
    ///
    /// Uses `wrapping_add` to avoid a debug-build panic on overflow; the
    /// low 32 bits embedded in the nonce wrap in ~4.5 years of continuous
    /// operation at 30 fps. Real session lifetime is governed by rekey
    /// cadence, so wraparound is not a practical concern.
    pub fn next_nonce(&mut self) -> u64 {
        let n = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        n
    }

    /// Current AEAD nonce counter, for observability.
    pub fn nonce_counter(&self) -> u64 {
        self.nonce_counter
    }

    /// Per-session source identifier.
    pub fn source_id(&self) -> &[u8; 8] {
        &self.source_id
    }

    /// Per-session epoch byte.
    pub fn epoch(&self) -> u8 {
        self.epoch
    }

    /// Time the current key was installed, if any.
    pub fn key_established_at(&self) -> Option<Instant> {
        self.key_established_at
    }

    /// Current consent ceremony state (SPEC draft-02 §12).
    ///
    /// Only available when the `consent` feature is enabled.
    #[cfg(feature = "consent")]
    pub fn consent_state(&self) -> crate::consent::ConsentState {
        self.consent_state
    }

    /// Drive the consent state machine from an observed consent message.
    ///
    /// Callers invoke this AFTER successfully opening a consent envelope
    /// (`PAYLOAD_TYPE_CONSENT_REQUEST` / `_RESPONSE` / `_REVOCATION`)
    /// and verifying the signature. The session does not validate
    /// signatures itself — that's an application-level policy decision
    /// (which pubkeys are trusted, which expiry windows are acceptable,
    /// etc.).
    ///
    /// Transitions (see [`crate::consent::ConsentState`]):
    ///
    /// - `Pending` + `Request` → `Requested`
    /// - `Requested` + `Response{approved=true}` → `Approved`
    /// - `Requested` + `Response{approved=false}` → `Denied`
    /// - `Approved` + `Revocation` → `Revoked`
    /// - Any other combination is a no-op (the caller's state machine
    ///   is out of sync; rejecting here would leak sub-case detail).
    ///
    /// Returns the new state for observability.
    #[cfg(feature = "consent")]
    pub fn observe_consent(&mut self, event: ConsentEvent) -> crate::consent::ConsentState {
        use crate::consent::ConsentState;
        self.consent_state = match (self.consent_state, event) {
            (ConsentState::Pending, ConsentEvent::Request) => ConsentState::Requested,
            (ConsentState::Requested, ConsentEvent::ResponseApproved) => ConsentState::Approved,
            (ConsentState::Requested, ConsentEvent::ResponseDenied) => ConsentState::Denied,
            (ConsentState::Approved, ConsentEvent::Revocation) => ConsentState::Revoked,
            (state, _) => state,
        };
        self.consent_state
    }

    /// Gate predicate: is the session allowed to seal/open a `FRAME`
    /// payload right now?
    ///
    /// Enforcement is opt-in:
    ///
    /// - `Pending` (initial state, no ceremony observed): **allowed**.
    ///   A caller who never starts a consent ceremony gets draft-01
    ///   behavior — the `consent` feature is a capability, not a
    ///   mandate. This preserves compatibility for application-level
    ///   consent models that don't use Xenia's built-in ceremony.
    /// - `Requested` (ceremony in progress, awaiting response):
    ///   blocked. Once you commit to the ceremony, you finish it.
    /// - `Approved`: allowed.
    /// - `Denied` / `Revoked`: blocked.
    #[cfg(feature = "consent")]
    #[inline]
    fn can_seal_frame(&self) -> Result<(), WireError> {
        use crate::consent::ConsentState;
        match self.consent_state {
            ConsentState::Pending | ConsentState::Approved => Ok(()),
            ConsentState::Revoked => Err(WireError::ConsentRevoked),
            ConsentState::Requested | ConsentState::Denied => Err(WireError::NoConsent),
        }
    }

    /// Seal a binary plaintext under the current session key using
    /// ChaCha20-Poly1305.
    ///
    /// Wire format: `[ nonce (12 bytes) | ciphertext | poly1305 tag (16 bytes) ]`.
    ///
    /// Nonce layout: `source_id[0..6] | payload_type | epoch | sequence[0..4]`
    /// — little-endian on the sequence portion.
    ///
    /// Returns [`WireError::NoSessionKey`] if no key is installed, or
    /// [`WireError::SealFailed`] if the underlying AEAD implementation
    /// rejects the input (should not happen with a valid 32-byte key).
    pub fn seal(&mut self, plaintext: &[u8], payload_type: u8) -> Result<Vec<u8>, WireError> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        // Consent gate — only when the consent feature is compiled in.
        // Applies only to the reference application payload types (FRAME,
        // INPUT, FRAME_LZ4); consent-ceremony payloads (0x20..=0x22) and
        // application-range payloads (0x30..=0xFF) flow ungated.
        #[cfg(feature = "consent")]
        if matches!(
            payload_type,
            crate::payload_types::PAYLOAD_TYPE_FRAME
                | crate::payload_types::PAYLOAD_TYPE_INPUT
                | crate::payload_types::PAYLOAD_TYPE_FRAME_LZ4
        ) {
            self.can_seal_frame()?;
        }

        let key = self.session_key.as_ref().ok_or(WireError::NoSessionKey)?;
        let key_bytes: [u8; 32] = **key;

        // The nonce embeds only the low 32 bits of the counter. Once the
        // counter reaches 2^32, the next seal would wrap to sequence 0
        // under the same key — catastrophic AEAD failure (nonce reuse
        // reveals the keystream XOR of the two plaintexts). Refuse rather
        // than wrap. Caller must rekey via install_key() before sealing
        // more. See SPEC.md §3.1.
        if self.nonce_counter >= (1u64 << 32) {
            return Err(WireError::SequenceExhausted);
        }

        let seq = (self.next_nonce() & 0xFFFF_FFFF) as u32;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..6].copy_from_slice(&self.source_id[..6]);
        nonce_bytes[6] = payload_type;
        nonce_bytes[7] = self.epoch;
        nonce_bytes[8..12].copy_from_slice(&seq.to_le_bytes());

        let cipher = ChaCha20Poly1305::new((&key_bytes).into());
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| WireError::SealFailed)?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a sealed envelope and return the plaintext.
    ///
    /// Performs three checks in order:
    ///
    /// 1. **Length**: envelope must be at least 28 bytes (12 nonce + 16 tag).
    /// 2. **AEAD verify**: ChaCha20-Poly1305 decrypt against the current
    ///    session key, falling back to the previous key during the rekey
    ///    grace period.
    /// 3. **Replay window**: the sequence embedded in nonce bytes 8..12
    ///    (little-endian u32) must be either strictly higher than any
    ///    previously accepted sequence for the same `(source_id,
    ///    payload_type)` stream, OR within the 64-message sliding window
    ///    AND not previously seen.
    ///
    /// Returns [`WireError::OpenFailed`] on any failure. Mutates `self`
    /// to advance the replay window on success.
    ///
    /// The payload type embedded in the nonce is used for replay-window
    /// keying only — the caller is responsible for dispatching the returned
    /// plaintext to the correct deserializer.
    pub fn open(&mut self, envelope: &[u8]) -> Result<Vec<u8>, WireError> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        if envelope.len() < 12 + 16 {
            return Err(WireError::OpenFailed);
        }
        let (nonce_bytes, ciphertext) = envelope.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // AEAD verify: current key, then prev_session_key fallback.
        // Track which key verified so the replay-window check below can
        // use the correct key_epoch (SPEC §5.3 / draft-02r1).
        let (plaintext, verified_epoch) = if let Some(key) = self.session_key.as_ref() {
            let key_bytes: [u8; 32] = **key;
            let cipher = ChaCha20Poly1305::new((&key_bytes).into());
            if let Ok(pt) = cipher.decrypt(nonce, ciphertext) {
                (Some(pt), Some(self.current_key_epoch))
            } else if let (Some(prev), Some(prev_epoch)) =
                (self.prev_session_key.as_ref(), self.prev_key_epoch)
            {
                let prev_bytes: [u8; 32] = **prev;
                let cipher = ChaCha20Poly1305::new((&prev_bytes).into());
                match cipher.decrypt(nonce, ciphertext) {
                    Ok(pt) => (Some(pt), Some(prev_epoch)),
                    Err(_) => (None, None),
                }
            } else {
                (None, None)
            }
        } else if let (Some(prev), Some(prev_epoch)) =
            (self.prev_session_key.as_ref(), self.prev_key_epoch)
        {
            let prev_bytes: [u8; 32] = **prev;
            let cipher = ChaCha20Poly1305::new((&prev_bytes).into());
            match cipher.decrypt(nonce, ciphertext) {
                Ok(pt) => (Some(pt), Some(prev_epoch)),
                Err(_) => (None, None),
            }
        } else {
            return Err(WireError::NoSessionKey);
        };

        let plaintext = plaintext.ok_or(WireError::OpenFailed)?;
        // If AEAD succeeded we MUST have an epoch; debug-assert to catch
        // any refactor that breaks the invariant.
        let verified_epoch =
            verified_epoch.expect("AEAD succeeded so a key verified; epoch must be set");

        // Replay window check — scoped to the epoch of the key that
        // verified (NOT the current epoch; an old envelope that
        // verified under prev_key is checked against the prev-epoch
        // window, not the current-epoch window).
        let mut source_id_u64 = 0u64;
        for (i, b) in nonce_bytes[..6].iter().enumerate() {
            source_id_u64 |= (*b as u64) << (i * 8);
        }
        let payload_type = nonce_bytes[6];
        let seq = u32::from_le_bytes([
            nonce_bytes[8],
            nonce_bytes[9],
            nonce_bytes[10],
            nonce_bytes[11],
        ]) as u64;

        if !self
            .replay_window
            .accept(source_id_u64, payload_type, verified_epoch, seq)
        {
            return Err(WireError::OpenFailed);
        }

        // Consent gate on the open path — symmetric with seal. Only
        // application-reference payload types are gated. The caller may
        // still drive state transitions via `observe_consent` after
        // opening consent-ceremony envelopes (0x20..=0x22).
        #[cfg(feature = "consent")]
        if matches!(
            payload_type,
            crate::payload_types::PAYLOAD_TYPE_FRAME
                | crate::payload_types::PAYLOAD_TYPE_INPUT
                | crate::payload_types::PAYLOAD_TYPE_FRAME_LZ4
        ) {
            self.can_seal_frame()?;
        }

        Ok(plaintext)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_has_no_key() {
        let s = Session::new();
        assert!(!s.has_key());
    }

    #[test]
    fn install_key_sets_has_key() {
        let mut s = Session::new();
        s.install_key([0x11; 32]);
        assert!(s.has_key());
        assert_eq!(s.nonce_counter(), 0);
    }

    #[test]
    fn seal_fails_without_key() {
        let mut s = Session::new();
        assert!(matches!(s.seal(b"hi", 0x10), Err(WireError::NoSessionKey)));
    }

    #[test]
    fn open_fails_without_key() {
        let mut s = Session::new();
        let envelope = [0u8; 40];
        assert!(matches!(s.open(&envelope), Err(WireError::NoSessionKey)));
    }

    #[test]
    fn open_short_envelope_fails() {
        let mut s = Session::new();
        s.install_key([0u8; 32]);
        assert!(matches!(s.open(&[0u8; 10]), Err(WireError::OpenFailed)));
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut sender = Session::with_source_id([1; 8], 0xAA);
        let mut receiver = Session::with_source_id([1; 8], 0xAA);
        sender.install_key([0x33; 32]);
        receiver.install_key([0x33; 32]);

        let sealed = sender.seal(b"hello xenia", 0x10).unwrap();
        let opened = receiver.open(&sealed).unwrap();
        assert_eq!(opened, b"hello xenia");
    }

    #[test]
    fn nonce_counter_monotonic() {
        let mut s = Session::new();
        assert_eq!(s.next_nonce(), 0);
        assert_eq!(s.next_nonce(), 1);
        assert_eq!(s.next_nonce(), 2);
    }

    #[test]
    fn nonce_counter_wraps_without_panic() {
        // `next_nonce` uses wrapping_add internally; the guard against
        // catastrophic nonce reuse lives in `seal` (see
        // `seal_refuses_at_sequence_exhaustion` below), not here.
        let mut s = Session::new();
        s.nonce_counter = u64::MAX;
        assert_eq!(s.next_nonce(), u64::MAX);
        assert_eq!(s.next_nonce(), 0);
    }

    #[test]
    fn seal_refuses_at_sequence_exhaustion() {
        // After 2^32 successful seals, the low-32-bit sequence embedded in
        // the AEAD nonce would wrap to 0 on the next seal — catastrophic
        // nonce reuse under the same key. `seal` must refuse instead.
        let mut s = Session::with_source_id([0; 8], 0);
        s.install_key([0x77; 32]);
        // Seed the counter at the boundary. The 2^32-th seal completed
        // with seq = 2^32 - 1; the next seal would wrap.
        s.nonce_counter = 1u64 << 32;
        assert!(matches!(
            s.seal(b"must-refuse", 0x10),
            Err(WireError::SequenceExhausted)
        ));
    }

    #[test]
    fn seal_allows_last_valid_sequence_before_exhaustion() {
        // The 2^32 - 1 value (u32::MAX) is a legitimate sequence — it's
        // the final seal before the boundary kicks in. Verify it succeeds.
        let mut s = Session::with_source_id([0; 8], 0);
        s.install_key([0x77; 32]);
        s.nonce_counter = (1u64 << 32) - 1; // = u32::MAX as u64
        let sealed = s.seal(b"last-valid", 0x10).expect("seal at boundary - 1");
        assert_eq!(sealed.len(), 12 + 10 + 16); // nonce + plaintext + tag
                                                // Counter is now at the boundary — next seal must refuse.
        assert!(matches!(
            s.seal(b"over-the-edge", 0x10),
            Err(WireError::SequenceExhausted)
        ));
    }

    #[test]
    fn rekey_resets_sequence_after_exhaustion() {
        // The caller's only escape from `SequenceExhausted` is to rekey.
        // Verify that install_key resets the counter so seals resume.
        let mut s = Session::with_source_id([0; 8], 0);
        s.install_key([0x77; 32]);
        s.nonce_counter = 1u64 << 32;
        assert!(s.seal(b"blocked", 0x10).is_err());
        // Rekey.
        s.install_key([0x88; 32]);
        // Counter reset to 0, sealing works again.
        assert!(s.seal(b"unblocked", 0x10).is_ok());
    }

    #[test]
    fn rekey_preserves_old_envelopes_during_grace() {
        let mut sender = Session::with_source_id([2; 8], 0xBB);
        let mut receiver = Session::with_source_id([2; 8], 0xBB);
        sender.install_key([0x44; 32]);
        receiver.install_key([0x44; 32]);

        // Seal under old key.
        let sealed_old = sender.seal(b"first", 0x10).unwrap();

        // Rekey on receiver only (simulating a rotation where sealed_old is
        // already in flight when the new key lands).
        receiver.install_key([0x55; 32]);

        // Old envelope still opens during the grace period.
        let opened = receiver.open(&sealed_old).unwrap();
        assert_eq!(opened, b"first");
    }

    #[test]
    fn replay_rejected() {
        let mut sender = Session::with_source_id([3; 8], 0xCC);
        let mut receiver = Session::with_source_id([3; 8], 0xCC);
        sender.install_key([0x66; 32]);
        receiver.install_key([0x66; 32]);

        let sealed = sender.seal(b"once", 0x10).unwrap();
        assert!(receiver.open(&sealed).is_ok());
        assert!(matches!(receiver.open(&sealed), Err(WireError::OpenFailed)));
    }

    #[test]
    fn wrong_key_fails() {
        let mut sender = Session::with_source_id([4; 8], 0xDD);
        let mut receiver = Session::with_source_id([4; 8], 0xDD);
        sender.install_key([0x77; 32]);
        receiver.install_key([0x88; 32]);

        let sealed = sender.seal(b"secret", 0x10).unwrap();
        assert!(matches!(receiver.open(&sealed), Err(WireError::OpenFailed)));
    }

    #[test]
    fn independent_payload_types_do_not_collide() {
        let mut sender = Session::with_source_id([5; 8], 0xEE);
        let mut receiver = Session::with_source_id([5; 8], 0xEE);
        sender.install_key([0x99; 32]);
        receiver.install_key([0x99; 32]);

        // Same sequence on two different payload types: both accepted.
        let a = sender.seal(b"frame-0", 0x10).unwrap();
        let b = sender.seal(b"input-0", 0x11).unwrap();
        assert!(receiver.open(&a).is_ok());
        assert!(receiver.open(&b).is_ok());
    }

    #[test]
    fn tick_expires_prev_key_after_grace() {
        let mut sender = Session::with_source_id([6; 8], 0xFF);
        let mut receiver =
            Session::with_source_id([6; 8], 0xFF).with_rekey_grace(Duration::from_millis(1));
        sender.install_key([0xAA; 32]);
        receiver.install_key([0xAA; 32]);

        let sealed_old = sender.seal(b"old", 0x10).unwrap();

        // Rekey receiver with ~1ms grace.
        receiver.install_key([0xBB; 32]);
        std::thread::sleep(Duration::from_millis(5));
        receiver.tick();

        // Old envelope no longer opens.
        assert!(receiver.open(&sealed_old).is_err());
    }
}
