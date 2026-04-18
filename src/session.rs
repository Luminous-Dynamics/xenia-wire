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
    /// Consent ceremony state (draft-03 §12). Only enforced when the
    /// `consent` feature is compiled in.
    #[cfg(feature = "consent")]
    consent_state: crate::consent::ConsentState,
    /// The `request_id` of the active ceremony, if any. Set when a
    /// `Request` event transitions the session to `Requested`; bumped
    /// on replacement / new-ceremony-after-terminal-state. `None`
    /// while state is `LegacyBypass` or `AwaitingRequest`.
    /// Used by `observe_consent` to distinguish stale responses,
    /// contradictory responses, and legitimate replacements.
    #[cfg(feature = "consent")]
    active_request_id: Option<u64>,
    /// The last observed `approved` decision for `active_request_id`,
    /// if any. `Some(true)` in `Approved`; `Some(false)` in `Denied`;
    /// `None` otherwise. Enables detection of contradictory responses
    /// (SPEC draft-03 §12.6 / `ConsentViolation::ContradictoryResponse`).
    #[cfg(feature = "consent")]
    last_response_approved: Option<bool>,
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
            consent_state: crate::consent::ConsentState::LegacyBypass,
            #[cfg(feature = "consent")]
            active_request_id: None,
            #[cfg(feature = "consent")]
            last_response_approved: None,
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

    /// Current consent ceremony state (SPEC draft-03 §12).
    ///
    /// Only available when the `consent` feature is enabled.
    #[cfg(feature = "consent")]
    pub fn consent_state(&self) -> crate::consent::ConsentState {
        self.consent_state
    }

    /// Derive the 32-byte session fingerprint for a given `request_id`
    /// (SPEC draft-03 §12.3.1).
    ///
    /// The fingerprint is HKDF-SHA-256 over the current session key:
    ///
    /// ```text
    /// salt   = b"xenia-session-fingerprint-v1"
    /// ikm    = current session_key   (32 bytes)
    /// info   = source_id || epoch || request_id.to_be_bytes()
    ///          (8 + 1 + 8 = 17 bytes)
    /// output = 32 bytes
    /// ```
    ///
    /// Both peers derive the same fingerprint from their own copy of
    /// the session key. Each peer embeds the derived fingerprint in
    /// every signed consent message body; receivers re-derive locally
    /// and compare. A signed consent message whose fingerprint does
    /// not match the receiver's derivation has been replayed from a
    /// different session and MUST be rejected.
    ///
    /// Returns [`WireError::NoSessionKey`] if no key is installed.
    /// Callers SHOULD derive the fingerprint immediately before
    /// signing / verifying and not cache it across rekeys — the
    /// fingerprint changes with the session key.
    #[cfg(feature = "consent")]
    pub fn session_fingerprint(&self, request_id: u64) -> Result<[u8; 32], WireError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let key = self.session_key.as_ref().ok_or(WireError::NoSessionKey)?;
        let ikm: [u8; 32] = **key;

        let mut info = [0u8; 8 + 1 + 8];
        info[..8].copy_from_slice(&self.source_id);
        info[8] = self.epoch;
        info[9..17].copy_from_slice(&request_id.to_be_bytes());

        let hk = Hkdf::<Sha256>::new(Some(b"xenia-session-fingerprint-v1"), &ikm);
        let mut out = [0u8; 32];
        hk.expand(&info, &mut out)
            .expect("HKDF-SHA-256 expand of 32 bytes cannot fail");
        Ok(out)
    }

    /// Sign a [`ConsentRequestCore`] after injecting the session
    /// fingerprint derived from this session's state and the core's
    /// `request_id` (SPEC draft-03 §12.3 / §12.3.1).
    ///
    /// The caller constructs a `ConsentRequestCore` with any
    /// `session_fingerprint` value (the helper overwrites it). On the
    /// send path this is the recommended entry point; it removes the
    /// possibility of a caller forgetting to derive-and-inject.
    #[cfg(feature = "consent")]
    pub fn sign_consent_request(
        &self,
        mut core: crate::consent::ConsentRequestCore,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<crate::consent::ConsentRequest, WireError> {
        core.session_fingerprint = self.session_fingerprint(core.request_id)?;
        Ok(crate::consent::ConsentRequest::sign(core, signing_key))
    }

    /// Sign a [`ConsentResponseCore`] after injecting the session
    /// fingerprint for the core's `request_id`. See
    /// [`Self::sign_consent_request`].
    #[cfg(feature = "consent")]
    pub fn sign_consent_response(
        &self,
        mut core: crate::consent::ConsentResponseCore,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<crate::consent::ConsentResponse, WireError> {
        core.session_fingerprint = self.session_fingerprint(core.request_id)?;
        Ok(crate::consent::ConsentResponse::sign(core, signing_key))
    }

    /// Sign a [`ConsentRevocationCore`] after injecting the session
    /// fingerprint for the core's `request_id`. See
    /// [`Self::sign_consent_request`].
    #[cfg(feature = "consent")]
    pub fn sign_consent_revocation(
        &self,
        mut core: crate::consent::ConsentRevocationCore,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<crate::consent::ConsentRevocation, WireError> {
        core.session_fingerprint = self.session_fingerprint(core.request_id)?;
        Ok(crate::consent::ConsentRevocation::sign(core, signing_key))
    }

    /// Verify a [`ConsentRequest`] against this session's fingerprint
    /// AND the requester's public key (SPEC draft-03 §12.3.1).
    ///
    /// Returns `true` iff:
    ///
    /// 1. The Ed25519 signature is valid,
    /// 2. The embedded public key matches `expected_pubkey` (if provided),
    ///    and
    /// 3. The embedded `session_fingerprint` equals the fingerprint
    ///    this session derives locally for the same `request_id`.
    ///
    /// Returns `false` (never a `WireError`) on any mismatch — per SPEC
    /// §11 the caller should react to verification failure the same way
    /// for all sub-cases.
    #[cfg(feature = "consent")]
    pub fn verify_consent_request(
        &self,
        req: &crate::consent::ConsentRequest,
        expected_pubkey: Option<&[u8; 32]>,
    ) -> bool {
        if !req.verify(expected_pubkey) {
            return false;
        }
        match self.session_fingerprint(req.core.request_id) {
            Ok(fp) => ct_eq_32(&fp, &req.core.session_fingerprint),
            Err(_) => false,
        }
    }

    /// Verify a [`ConsentResponse`] against this session's fingerprint
    /// AND the responder's public key. See
    /// [`Self::verify_consent_request`].
    #[cfg(feature = "consent")]
    pub fn verify_consent_response(
        &self,
        resp: &crate::consent::ConsentResponse,
        expected_pubkey: Option<&[u8; 32]>,
    ) -> bool {
        if !resp.verify(expected_pubkey) {
            return false;
        }
        match self.session_fingerprint(resp.core.request_id) {
            Ok(fp) => ct_eq_32(&fp, &resp.core.session_fingerprint),
            Err(_) => false,
        }
    }

    /// Verify a [`ConsentRevocation`] against this session's fingerprint
    /// AND the revoker's public key. See
    /// [`Self::verify_consent_request`].
    #[cfg(feature = "consent")]
    pub fn verify_consent_revocation(
        &self,
        rev: &crate::consent::ConsentRevocation,
        expected_pubkey: Option<&[u8; 32]>,
    ) -> bool {
        if !rev.verify(expected_pubkey) {
            return false;
        }
        match self.session_fingerprint(rev.core.request_id) {
            Ok(fp) => ct_eq_32(&fp, &rev.core.session_fingerprint),
            Err(_) => false,
        }
    }

    /// Drive the consent state machine from an observed consent message.
    ///
    /// Callers invoke this AFTER successfully opening a consent envelope
    /// (`PAYLOAD_TYPE_CONSENT_REQUEST` / `_RESPONSE` / `_REVOCATION`)
    /// and verifying the signature AND the session fingerprint. The
    /// session does not validate signatures or fingerprints itself —
    /// that's an application policy decision (which pubkeys to trust,
    /// which expiry windows to accept). Use
    /// [`Self::verify_consent_request`] (and siblings) for the
    /// standard verification path.
    ///
    /// # Transition table (SPEC draft-03 §12.6)
    ///
    /// `LegacyBypass` is **sticky** — every event is a no-op, state
    /// stays `LegacyBypass`. The caller opts into ceremony mode at
    /// construction via [`SessionBuilder::require_consent`]; a session
    /// in LegacyBypass never emits or honors consent events.
    ///
    /// For the remaining states, `id` refers to `event.request_id()`
    /// and `active` refers to the session's `active_request_id`.
    ///
    /// | Current          | Event                    | Next state / action                                    |
    /// |------------------|--------------------------|--------------------------------------------------------|
    /// | `AwaitingRequest`| `Request{id}`            | → `Requested`, `active_id = id`                        |
    /// | `AwaitingRequest`| `Response{*, id}`        | → **`StaleResponseForUnknownRequest`**                 |
    /// | `AwaitingRequest`| `Revocation{id}`         | → **`RevocationBeforeApproval`**                       |
    /// | `Requested`      | `Request{id}`, id > active | → `Requested`, `active_id = id` (replacement)        |
    /// | `Requested`      | `Request{id}`, id ≤ active | no-op (stale)                                        |
    /// | `Requested`      | `ResponseApproved{id==active}` | → `Approved`, record `last_response=true`         |
    /// | `Requested`      | `ResponseDenied{id==active}`   | → `Denied`, record `last_response=false`          |
    /// | `Requested`      | `Response{id≠active}`    | → **`StaleResponseForUnknownRequest`**                 |
    /// | `Requested`      | `Revocation{id}`         | → **`RevocationBeforeApproval`**                       |
    /// | `Approved`       | `Request{id}`, id > active | → `Requested`, reset tracking (new ceremony)         |
    /// | `Approved`       | `ResponseApproved{id==active}` | no-op (idempotent)                                |
    /// | `Approved`       | `ResponseDenied{id==active}` | → **`ContradictoryResponse{prior=true, new=false}`** |
    /// | `Approved`       | `Response{id≠active}`    | → **`StaleResponseForUnknownRequest`**                 |
    /// | `Approved`       | `Revocation{id==active}` | → `Revoked`                                            |
    /// | `Approved`       | `Revocation{id≠active}`  | no-op (stale revocation)                               |
    /// | `Denied`         | `Request{id}`, id > active | → `Requested`, reset tracking (new ceremony)         |
    /// | `Denied`         | `ResponseDenied{id==active}` | no-op (idempotent)                                 |
    /// | `Denied`         | `ResponseApproved{id==active}` | → **`ContradictoryResponse{prior=false, new=true}`** |
    /// | `Denied`         | `Revocation{id}`         | no-op (nothing to revoke)                              |
    /// | `Revoked`        | `Request{id}`, id > active | → `Requested`, reset tracking (fresh ceremony)       |
    /// | `Revoked`        | *                        | no-op                                                  |
    ///
    /// Bold entries return `Err(ConsentViolation)`; the state is NOT
    /// mutated on violation (the caller is expected to tear down).
    ///
    /// # Returns
    ///
    /// - `Ok(state)` on any legal transition or benign no-op.
    /// - `Err(ConsentViolation)` when the peer emitted an event that
    ///   cannot follow the current state. The session state is left
    ///   untouched. The caller SHOULD terminate the session.
    #[cfg(feature = "consent")]
    pub fn observe_consent(
        &mut self,
        event: ConsentEvent,
    ) -> Result<crate::consent::ConsentState, crate::consent::ConsentViolation> {
        use crate::consent::{ConsentState, ConsentViolation};

        // LegacyBypass is sticky — all events are no-ops.
        if self.consent_state == ConsentState::LegacyBypass {
            return Ok(self.consent_state);
        }

        let event_id = event.request_id();

        match (self.consent_state, event) {
            // ─── AwaitingRequest ───────────────────────────────────
            (ConsentState::AwaitingRequest, ConsentEvent::Request { request_id }) => {
                self.consent_state = ConsentState::Requested;
                self.active_request_id = Some(request_id);
                self.last_response_approved = None;
            }
            (ConsentState::AwaitingRequest, ConsentEvent::ResponseApproved { .. })
            | (ConsentState::AwaitingRequest, ConsentEvent::ResponseDenied { .. }) => {
                return Err(ConsentViolation::StaleResponseForUnknownRequest {
                    request_id: event_id,
                });
            }
            (ConsentState::AwaitingRequest, ConsentEvent::Revocation { .. }) => {
                return Err(ConsentViolation::RevocationBeforeApproval {
                    request_id: event_id,
                });
            }

            // ─── Requested ─────────────────────────────────────────
            (ConsentState::Requested, ConsentEvent::Request { request_id }) => {
                match self.active_request_id {
                    Some(active) if request_id > active => {
                        self.active_request_id = Some(request_id);
                        self.last_response_approved = None;
                    }
                    _ => { /* stale / equal — drop */ }
                }
            }
            (ConsentState::Requested, ConsentEvent::ResponseApproved { request_id }) => {
                if self.active_request_id != Some(request_id) {
                    return Err(ConsentViolation::StaleResponseForUnknownRequest {
                        request_id,
                    });
                }
                self.consent_state = ConsentState::Approved;
                self.last_response_approved = Some(true);
            }
            (ConsentState::Requested, ConsentEvent::ResponseDenied { request_id }) => {
                if self.active_request_id != Some(request_id) {
                    return Err(ConsentViolation::StaleResponseForUnknownRequest {
                        request_id,
                    });
                }
                self.consent_state = ConsentState::Denied;
                self.last_response_approved = Some(false);
            }
            (ConsentState::Requested, ConsentEvent::Revocation { .. }) => {
                return Err(ConsentViolation::RevocationBeforeApproval {
                    request_id: event_id,
                });
            }

            // ─── Approved ──────────────────────────────────────────
            (ConsentState::Approved, ConsentEvent::Request { request_id }) => {
                match self.active_request_id {
                    Some(active) if request_id > active => {
                        // New ceremony starting after approval.
                        self.consent_state = ConsentState::Requested;
                        self.active_request_id = Some(request_id);
                        self.last_response_approved = None;
                    }
                    _ => { /* stale — drop */ }
                }
            }
            (ConsentState::Approved, ConsentEvent::ResponseApproved { request_id }) => {
                match self.active_request_id {
                    Some(active) if active == request_id => { /* idempotent */ }
                    _ => {
                        return Err(ConsentViolation::StaleResponseForUnknownRequest {
                            request_id,
                        });
                    }
                }
            }
            (ConsentState::Approved, ConsentEvent::ResponseDenied { request_id }) => {
                if self.active_request_id == Some(request_id) {
                    return Err(ConsentViolation::ContradictoryResponse {
                        request_id,
                        prior_approved: true,
                        new_approved: false,
                    });
                }
                return Err(ConsentViolation::StaleResponseForUnknownRequest { request_id });
            }
            (ConsentState::Approved, ConsentEvent::Revocation { request_id }) => {
                if self.active_request_id == Some(request_id) {
                    self.consent_state = ConsentState::Revoked;
                }
                // Stale revocation (different request_id) is a no-op.
            }

            // ─── Denied ────────────────────────────────────────────
            (ConsentState::Denied, ConsentEvent::Request { request_id }) => {
                match self.active_request_id {
                    Some(active) if request_id > active => {
                        self.consent_state = ConsentState::Requested;
                        self.active_request_id = Some(request_id);
                        self.last_response_approved = None;
                    }
                    _ => { /* stale — drop */ }
                }
            }
            (ConsentState::Denied, ConsentEvent::ResponseDenied { request_id }) => {
                match self.active_request_id {
                    Some(active) if active == request_id => { /* idempotent */ }
                    _ => {
                        return Err(ConsentViolation::StaleResponseForUnknownRequest {
                            request_id,
                        });
                    }
                }
            }
            (ConsentState::Denied, ConsentEvent::ResponseApproved { request_id }) => {
                if self.active_request_id == Some(request_id) {
                    return Err(ConsentViolation::ContradictoryResponse {
                        request_id,
                        prior_approved: false,
                        new_approved: true,
                    });
                }
                return Err(ConsentViolation::StaleResponseForUnknownRequest { request_id });
            }
            (ConsentState::Denied, ConsentEvent::Revocation { .. }) => {
                // Nothing to revoke; no-op.
            }

            // ─── Revoked ───────────────────────────────────────────
            (ConsentState::Revoked, ConsentEvent::Request { request_id }) => {
                match self.active_request_id {
                    Some(active) if request_id > active => {
                        self.consent_state = ConsentState::Requested;
                        self.active_request_id = Some(request_id);
                        self.last_response_approved = None;
                    }
                    _ => { /* stale — drop */ }
                }
            }
            (ConsentState::Revoked, _) => { /* no-op */ }

            // ─── LegacyBypass handled up top ───────────────────────
            (ConsentState::LegacyBypass, _) => unreachable!(),
        }

        Ok(self.consent_state)
    }

    /// Gate predicate: is the session allowed to seal/open a `FRAME`
    /// payload right now?
    ///
    /// See SPEC §12.7 for the normative rule. Summary:
    ///
    /// - `LegacyBypass` (default — consent system not in use):
    ///   **allowed**. Preserves draft-02 behavior for callers with
    ///   an out-of-band consent mechanism.
    /// - `AwaitingRequest` (opt-in via
    ///   [`SessionBuilder::require_consent`]): **blocked** until a
    ///   ceremony completes. `NoConsent` error.
    /// - `Requested` (ceremony in progress, awaiting response):
    ///   blocked. `NoConsent` error.
    /// - `Approved`: **allowed**.
    /// - `Denied`: blocked. `NoConsent` error.
    /// - `Revoked`: blocked. `ConsentRevoked` error.
    #[cfg(feature = "consent")]
    #[inline]
    fn can_seal_frame(&self) -> Result<(), WireError> {
        use crate::consent::ConsentState;
        match self.consent_state {
            ConsentState::LegacyBypass | ConsentState::Approved => Ok(()),
            ConsentState::Revoked => Err(WireError::ConsentRevoked),
            ConsentState::AwaitingRequest
            | ConsentState::Requested
            | ConsentState::Denied => Err(WireError::NoConsent),
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

// ─── SessionBuilder (added in draft-02r2) ─────────────────────────────
//
// The builder pattern exists to let callers opt into behaviors that
// would otherwise require either (a) new `Session::with_*` constructors
// (API churn) or (b) post-construction mutators (awkward order-of-
// operations). The builder is additive: existing `Session::new`,
// `Session::with_source_id`, and `Session::with_rekey_grace` remain
// unchanged.

/// Opt-in configuration for a fresh [`Session`]. Constructed via
/// [`Session::builder`]; finalized via [`SessionBuilder::build`].
///
/// Defaults reproduce [`Session::new`]: random `source_id` + `epoch`,
/// [`DEFAULT_REKEY_GRACE`] grace, 64-slot replay window, and
/// `consent_required = false` (→ [`crate::consent::ConsentState::LegacyBypass`]
/// when the `consent` feature is on).
pub struct SessionBuilder {
    source_id: Option<[u8; 8]>,
    epoch: Option<u8>,
    rekey_grace: Duration,
    #[cfg(feature = "consent")]
    consent_required: bool,
    replay_window_bits: u32,
}

impl SessionBuilder {
    /// Create a builder with default values.
    pub fn new() -> Self {
        Self {
            source_id: None,
            epoch: None,
            rekey_grace: DEFAULT_REKEY_GRACE,
            #[cfg(feature = "consent")]
            consent_required: false,
            replay_window_bits: 64,
        }
    }

    /// Pin the `source_id` + `epoch` for deterministic test fixtures.
    /// Normal callers SHOULD omit this and let the builder randomize.
    pub fn with_source_id(mut self, source_id: [u8; 8], epoch: u8) -> Self {
        self.source_id = Some(source_id);
        self.epoch = Some(epoch);
        self
    }

    /// Override the previous-key grace duration. See
    /// [`DEFAULT_REKEY_GRACE`].
    pub fn with_rekey_grace(mut self, grace: Duration) -> Self {
        self.rekey_grace = grace;
        self
    }

    /// Require the consent ceremony to complete before application
    /// `FRAME` / `INPUT` / `FRAME_LZ4` payloads are accepted.
    ///
    /// - `require = false` (default): initial state is `LegacyBypass`;
    ///   consent is handled out-of-band by the application.
    /// - `require = true`: initial state is `AwaitingRequest`;
    ///   application payloads are blocked until a `ConsentRequest` +
    ///   approving `ConsentResponse` transition the session to
    ///   `Approved`.
    ///
    /// Only available with the `consent` feature.
    #[cfg(feature = "consent")]
    pub fn require_consent(mut self, require: bool) -> Self {
        self.consent_required = require;
        self
    }

    /// Override the per-stream replay window size in bits.
    /// Must be a multiple of 64; valid values are 64 (default),
    /// 128, 256, 512, 1024.
    ///
    /// Memory cost per `(source_id, pld_type, key_epoch)` stream is
    /// `bits / 8` bytes of bitmap plus a small constant. 1024-slot
    /// windows cost 128 bytes per stream.
    ///
    /// Panics at `build()` time if the value is out of range.
    pub fn with_replay_window_bits(mut self, bits: u32) -> Self {
        self.replay_window_bits = bits;
        self
    }

    /// Finalize the builder and construct a [`Session`].
    ///
    /// Panics if `replay_window_bits` is invalid (not a multiple of 64,
    /// less than 64, or more than 1024).
    pub fn build(self) -> Session {
        let source_id = self.source_id.unwrap_or_else(rand::random);
        let epoch = self.epoch.unwrap_or_else(rand::random);
        let replay_window = ReplayWindow::with_window_bits(self.replay_window_bits);

        Session {
            session_key: None,
            prev_session_key: None,
            key_established_at: None,
            prev_key_expires_at: None,
            nonce_counter: 0,
            source_id,
            epoch,
            replay_window,
            rekey_grace: self.rekey_grace,
            current_key_epoch: 0,
            prev_key_epoch: None,
            #[cfg(feature = "consent")]
            consent_state: if self.consent_required {
                crate::consent::ConsentState::AwaitingRequest
            } else {
                crate::consent::ConsentState::LegacyBypass
            },
            #[cfg(feature = "consent")]
            active_request_id: None,
            #[cfg(feature = "consent")]
            last_response_approved: None,
        }
    }
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// Start a [`SessionBuilder`] for opt-in configuration. Use this
    /// when you want `require_consent()`, a non-default replay window
    /// size, or deterministic fixture `source_id` / `epoch` without
    /// stacking multiple post-construction mutators.
    ///
    /// Added in draft-02r2.
    pub fn builder() -> SessionBuilder {
        SessionBuilder::new()
    }
}

/// Constant-time equality for two 32-byte arrays.
///
/// Avoids a data-dependent early-return in the fingerprint compare path.
/// Kept inline here rather than reaching for `subtle` — one byte of
/// dependency surface for a loop we can read in three lines.
#[cfg(feature = "consent")]
#[inline]
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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
