// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Consent ceremony for Xenia sessions (SPEC draft-03 §12).
//!
//! Before any application payload flows on a session, the technician's
//! side sends a [`ConsentRequest`] — a signed, time-limited, scoped
//! description of what access is being asked for. The end-user's side
//! returns a [`ConsentResponse`] that either approves or denies; only
//! after a valid approval does the session accept `FRAME` payloads.
//! Either side may send a [`ConsentRevocation`] at any time to
//! asymmetrically terminate the session; subsequent application frames
//! return [`crate::WireError::ConsentRevoked`].
//!
//! ## Wire-level integration
//!
//! The three consent payload types are:
//!
//! - `0x20` [`PAYLOAD_TYPE_CONSENT_REQUEST`][crate::PAYLOAD_TYPE_CONSENT_REQUEST]
//! - `0x21` [`PAYLOAD_TYPE_CONSENT_RESPONSE`][crate::PAYLOAD_TYPE_CONSENT_RESPONSE]
//! - `0x22` [`PAYLOAD_TYPE_CONSENT_REVOCATION`][crate::PAYLOAD_TYPE_CONSENT_REVOCATION]
//!
//! They seal through the same [`Session::seal`][crate::Session::seal]
//! path as everything else; what distinguishes them is the session-level
//! state machine in [`crate::Session::observe_consent`] that tracks
//! whether the ceremony has completed.
//!
//! ## Signing
//!
//! Each consent message carries a device-key Ed25519 signature. The
//! signing is over a canonical byte representation of the message
//! fields — NOT over the sealed envelope. A receiver that wants to
//! verify the consent independently of the AEAD channel (for example,
//! to log the consent in an external audit system) can do so using
//! only the plaintext + the peer's public key.
//!
//! ## Session binding (draft-03)
//!
//! Every signed consent body carries a 32-byte `session_fingerprint`
//! derived via HKDF-SHA-256 from the current AEAD session key with
//! `info = source_id || epoch || request_id_be` (see
//! [`Session::session_fingerprint`][crate::Session::session_fingerprint]).
//! The fingerprint cryptographically binds the consent message to the
//! specific session AND ceremony in which it was signed, preventing
//! replay of a signed `ConsentResponse` across sessions or across
//! request_ids with the same participants.
//!
//! Both peers derive the same fingerprint from their own copy of the
//! key; receivers reject signatures whose embedded fingerprint does
//! not match local derivation. Use
//! [`Session::sign_consent_request`][crate::Session::sign_consent_request]
//! (and siblings) on the send path, and
//! [`Session::verify_consent_request`][crate::Session::verify_consent_request]
//! on the receive path to avoid manual fingerprint handling.
//!
//! ## Forward-compatibility
//!
//! [`ConsentRequestCore::causal_binding`] is reserved for a future
//! Ricardian-contract extension (ticket-state-bound authority). In
//! draft-03 it MUST be `None`; the wire slot is reserved so that
//! v1.1-aware receivers can honor it without breaking v1 peers.
//!
//! ## Threat model
//!
//! The consent ceremony assumes:
//!
//! - Each peer holds an Ed25519 signing key on their device. The
//!   binding of a device key to a human identity is out of scope here
//!   (that's the MSP attestation chain in SPEC draft-03 §12.5).
//! - The session's AEAD key has already been established via the outer
//!   handshake. The consent messages flow INSIDE the sealed channel —
//!   the signature adds a second layer of authentication specifically
//!   for third-party-verifiable consent records, and the
//!   `session_fingerprint` binds each record to a specific session.
//! - `valid_until` uses the Unix epoch in seconds. Clock skew between
//!   peers matters for this field; callers SHOULD grant a small grace
//!   window (the reference implementation accepts +/- 30 s).

#![cfg(feature = "consent")]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Sealable, WireError};

/// Length in bytes of an Ed25519 signature. Exposed as a constant so
/// alternate-language implementations can size buffers without depending
/// on the Rust `ed25519-dalek` crate.
pub const SIGNATURE_LEN: usize = 64;

/// Length in bytes of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Scope of access being requested.
///
/// The scope is advisory — the wire does not enforce what the technician
/// actually sends. An application-level check against the active
/// [`ConsentRequest`] is the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConsentScope {
    /// View the screen only. Input forwarding SHOULD be ignored.
    ScreenOnly = 0,
    /// View the screen and send input events (mouse, keyboard, touch).
    ScreenAndInput = 1,
    /// Screen + input + file transfer.
    ScreenInputFiles = 2,
    /// Full interactive session: screen + input + files + shell.
    Interactive = 3,
}

/// Reserved for a future Ricardian-contract extension that binds the
/// consent to external causal state (e.g., "authority valid while
/// ticket #1234 is In-Progress"). Always `None` in draft-02.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalPredicate {
    /// Human-readable description of the binding condition.
    pub description: String,
    /// Implementation-defined machine-readable predicate. Opaque to
    /// `xenia-wire`; evaluated by higher layers.
    pub opaque: Vec<u8>,
}

/// Canonical on-the-wire form of a consent request before signing.
///
/// The signature in [`ConsentRequest`] is computed over
/// `bincode::serialize(&ConsentRequestCore { ... })`. Canonical encoding
/// is bincode v1 with default little-endian fixint, matching the other
/// payloads in this crate.
///
/// **Field order is load-bearing** — the bincode serialization is the
/// signed payload, so reordering fields breaks signature verification
/// across implementations. The draft-03 canonical order is:
/// `request_id`, `requester_pubkey`, `session_fingerprint`,
/// `valid_until`, `scope`, `reason`, `causal_binding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRequestCore {
    /// Monotonic request identifier chosen by the requester. Used by the
    /// responder to correlate `ConsentResponse.request_id`.
    pub request_id: u64,
    /// Technician's device public key (raw 32-byte Ed25519).
    pub requester_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Session binding (draft-03): HKDF-SHA-256 of the session key,
    /// derived by the requester at sign time. See
    /// [`Session::session_fingerprint`][crate::Session::session_fingerprint].
    /// Prevents replay of this signed request in a different session.
    #[serde(with = "BigArray")]
    pub session_fingerprint: [u8; 32],
    /// Unix epoch seconds after which the request expires. Callers SHOULD
    /// grant ±30 s clock skew.
    pub valid_until: u64,
    /// Scope of access requested.
    pub scope: ConsentScope,
    /// Free-text justification (ticket reference, reason).
    pub reason: String,
    /// Reserved for v1.1 Ricardian binding. MUST be `None` in draft-03.
    pub causal_binding: Option<CausalPredicate>,
}

/// Request for session consent. Sealed with
/// [`crate::PAYLOAD_TYPE_CONSENT_REQUEST`] (0x20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRequest {
    /// Request body.
    pub core: ConsentRequestCore,
    /// Ed25519 signature over `bincode::serialize(&core)` by
    /// `core.requester_pubkey`.
    #[serde(with = "BigArray")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl ConsentRequest {
    /// Construct and sign a consent request.
    pub fn sign(core: ConsentRequestCore, signing_key: &SigningKey) -> Self {
        let bytes = bincode::serialize(&core).expect("consent core serializes");
        let signature = signing_key.sign(&bytes);
        Self {
            core,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the signature against the embedded public key.
    ///
    /// Returns `true` if the signature is valid AND the embedded public
    /// key matches the caller-supplied `expected_pubkey`. A caller who
    /// accepts any public key can pass `None`.
    ///
    /// Does NOT check `valid_until` — expiry is a policy decision for
    /// the caller, not a wire property.
    pub fn verify(&self, expected_pubkey: Option<&[u8; PUBLIC_KEY_LEN]>) -> bool {
        if let Some(exp) = expected_pubkey {
            if exp != &self.core.requester_pubkey {
                return false;
            }
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.core.requester_pubkey) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let bytes = match bincode::serialize(&self.core) {
            Ok(b) => b,
            Err(_) => return false,
        };
        pk.verify(&bytes, &sig).is_ok()
    }
}

impl Sealable for ConsentRequest {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// End-user's response to a consent request. Carries an approval or
/// denial plus a signature. Sealed with
/// [`crate::PAYLOAD_TYPE_CONSENT_RESPONSE`] (0x21).
///
/// **Canonical field order (draft-03):** `request_id`,
/// `responder_pubkey`, `session_fingerprint`, `approved`, `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentResponseCore {
    /// Matches `ConsentRequestCore::request_id` to correlate.
    pub request_id: u64,
    /// End-user's device public key (raw 32-byte Ed25519).
    pub responder_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Session binding (draft-03). Same derivation as on
    /// [`ConsentRequestCore::session_fingerprint`]. Prevents replay
    /// of this signed response in a different session or across
    /// different `request_id`s.
    #[serde(with = "BigArray")]
    pub session_fingerprint: [u8; 32],
    /// Whether the consent is approved.
    pub approved: bool,
    /// Optional free-text denial reason (empty when approved).
    pub reason: String,
}

/// Response to a consent request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentResponse {
    /// Response body.
    pub core: ConsentResponseCore,
    /// Ed25519 signature over `bincode::serialize(&core)` by
    /// `core.responder_pubkey`.
    #[serde(with = "BigArray")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl ConsentResponse {
    /// Construct and sign a consent response.
    pub fn sign(core: ConsentResponseCore, signing_key: &SigningKey) -> Self {
        let bytes = bincode::serialize(&core).expect("consent response core serializes");
        let signature = signing_key.sign(&bytes);
        Self {
            core,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the signature against the embedded public key, optionally
    /// requiring the embedded public key to match `expected_pubkey`.
    pub fn verify(&self, expected_pubkey: Option<&[u8; PUBLIC_KEY_LEN]>) -> bool {
        if let Some(exp) = expected_pubkey {
            if exp != &self.core.responder_pubkey {
                return false;
            }
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.core.responder_pubkey) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let bytes = match bincode::serialize(&self.core) {
            Ok(b) => b,
            Err(_) => return false,
        };
        pk.verify(&bytes, &sig).is_ok()
    }
}

impl Sealable for ConsentResponse {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// Asymmetric session termination. Either peer may send this at any time
/// after a successful consent; subsequent `FRAME` payloads on the session
/// return [`crate::WireError::ConsentRevoked`]. Sealed with
/// [`crate::PAYLOAD_TYPE_CONSENT_REVOCATION`] (0x22).
///
/// **Canonical field order (draft-03):** `request_id`, `revoker_pubkey`,
/// `session_fingerprint`, `issued_at`, `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRevocationCore {
    /// References the `request_id` being revoked.
    pub request_id: u64,
    /// Public key of the revoker (either party may revoke).
    pub revoker_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Session binding (draft-03). Same derivation as on
    /// [`ConsentRequestCore::session_fingerprint`].
    #[serde(with = "BigArray")]
    pub session_fingerprint: [u8; 32],
    /// Unix epoch seconds at which the revocation was issued.
    pub issued_at: u64,
    /// Free-text reason (displayed to the counterparty).
    pub reason: String,
}

/// Asymmetric session revocation message. Wraps a signed revocation
/// body; sealed with [`crate::PAYLOAD_TYPE_CONSENT_REVOCATION`] (0x22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRevocation {
    /// Revocation body.
    pub core: ConsentRevocationCore,
    /// Ed25519 signature over `bincode::serialize(&core)` by
    /// `core.revoker_pubkey`.
    #[serde(with = "BigArray")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl ConsentRevocation {
    /// Construct and sign a consent revocation.
    pub fn sign(core: ConsentRevocationCore, signing_key: &SigningKey) -> Self {
        let bytes = bincode::serialize(&core).expect("consent revocation core serializes");
        let signature = signing_key.sign(&bytes);
        Self {
            core,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the signature against the embedded public key.
    pub fn verify(&self, expected_pubkey: Option<&[u8; PUBLIC_KEY_LEN]>) -> bool {
        if let Some(exp) = expected_pubkey {
            if exp != &self.core.revoker_pubkey {
                return false;
            }
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.core.revoker_pubkey) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let bytes = match bincode::serialize(&self.core) {
            Ok(b) => b,
            Err(_) => return false,
        };
        pk.verify(&bytes, &sig).is_ok()
    }
}

impl Sealable for ConsentRevocation {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// Session-level consent state machine (draft-02r2).
///
/// Two start states disambiguate the pre-draft-02r2 `Pending` variant:
///
/// - [`Session::new`](crate::Session::new) →
///   [`ConsentState::LegacyBypass`] (sticky; FRAME flows out-of-band).
/// - [`SessionBuilder::require_consent(true)`](crate::SessionBuilder::require_consent)
///   → [`ConsentState::AwaitingRequest`] (FRAME blocked until ceremony
///   completes).
///
/// ```text
///                      (any event)
/// LegacyBypass ◀──────────────────────── LegacyBypass   (sticky)
///
///                       ConsentRequest opened
/// AwaitingRequest ─────────────────────────▶ Requested
///                                            │
///                                            │ ConsentResponse{approved=true}
///                                            ▼
///                                         Approved ────┐
///                                            │         │ ConsentRevocation
///                                            │         ▼
///                                            │      Revoked   (terminal)
///                                            │
///                                            │ ConsentResponse{approved=false}
///                                            ▼
///                                          Denied    (terminal)
/// ```
///
/// `Session::observe_consent` drives these transitions. Application
/// `FRAME` payloads are accepted in `LegacyBypass` and `Approved`; any
/// other state blocks the seal / open path. See [`crate::Session::seal`]
/// and [`crate::Session::open`] for the enforcement points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// Consent system not in use for this session. Application
    /// payloads flow unimpeded. Default for [`crate::Session::new`];
    /// preserves the draft-02 "Pending allows traffic" behavior.
    /// Use this when consent is handled out-of-band (e.g. via an
    /// MSP pre-authorization mechanism above the wire).
    ///
    /// Added in draft-02r2.
    LegacyBypass,
    /// Consent system IS in use; no `ConsentRequest` observed yet.
    /// Application `FRAME` / `INPUT` / `FRAME_LZ4` payloads are
    /// blocked until a ceremony completes. Opt in via
    /// [`crate::SessionBuilder::require_consent`].
    ///
    /// Added in draft-02r2 to disambiguate the dual meaning of
    /// the pre-draft-02r2 `Pending` state. See SPEC §12.7.
    AwaitingRequest,
    /// A `ConsentRequest` was sent / received but not yet answered.
    Requested,
    /// Consent was approved by the responder. FRAME payloads flow.
    Approved,
    /// The responder denied the request. Terminal for this ceremony.
    Denied,
    /// A revocation was received after approval. Terminal for this
    /// ceremony.
    Revoked,
}

/// Observed consent-ceremony events that drive [`crate::Session`]'s
/// state machine. The caller constructs one of these AFTER verifying
/// the underlying signed message, and passes it to
/// [`crate::Session::observe_consent`].
///
/// Every event carries the `request_id` of the consent message it
/// describes (SPEC draft-03 §12.6). The session's transition table
/// uses `request_id` to distinguish legitimate ceremony progression
/// (e.g., a fresh `Request` with a higher id starting a new ceremony
/// after a terminal state) from protocol violations (e.g., a
/// `Denied` contradicting a prior `Approved` for the *same* id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentEvent {
    /// A `ConsentRequest` was observed (either sent or received).
    Request {
        /// `ConsentRequestCore::request_id` of the observed request.
        request_id: u64,
    },
    /// A `ConsentResponse` with `approved = true` was observed.
    ResponseApproved {
        /// `ConsentResponseCore::request_id` of the observed response.
        request_id: u64,
    },
    /// A `ConsentResponse` with `approved = false` was observed.
    ResponseDenied {
        /// `ConsentResponseCore::request_id` of the observed response.
        request_id: u64,
    },
    /// A `ConsentRevocation` was observed.
    Revocation {
        /// `ConsentRevocationCore::request_id` of the observed revocation.
        request_id: u64,
    },
}

impl ConsentEvent {
    /// Returns the `request_id` carried by this event.
    pub fn request_id(&self) -> u64 {
        match self {
            ConsentEvent::Request { request_id }
            | ConsentEvent::ResponseApproved { request_id }
            | ConsentEvent::ResponseDenied { request_id }
            | ConsentEvent::Revocation { request_id } => *request_id,
        }
    }
}

/// A consent-state-machine transition that is a protocol violation
/// (SPEC draft-03 §12.6). Returned in the `Err` arm of
/// [`crate::Session::observe_consent`] and wrapped by
/// [`crate::WireError::ConsentProtocolViolation`].
///
/// The wire layer returns these values without side effects on the
/// session state — once a violation is raised, the caller's contract
/// is to terminate the session. The wire cannot tear down the
/// underlying transport; that's the application's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConsentViolation {
    /// A `Revocation` was observed while the session state is
    /// `AwaitingRequest` or `Requested` — i.e., the peer is trying
    /// to revoke consent that was never approved. A correct peer in
    /// that situation would either do nothing (no consent to revoke)
    /// or emit a `ResponseDenied`.
    #[error("revocation observed before any approval (request_id={request_id})")]
    RevocationBeforeApproval {
        /// `request_id` carried by the offending `Revocation` event.
        request_id: u64,
    },
    /// A `Response` was observed whose `approved` field contradicts a
    /// prior `Response` for the same `request_id` — e.g. a
    /// `ResponseDenied` after a `ResponseApproved`, or vice-versa.
    ///
    /// SPEC §12.6 REQUIRES rejecting this rather than accepting
    /// "later wins." The correct UX primitive for "the user changed
    /// their mind after approving" is a fresh [`ConsentRevocation`],
    /// which has its own signature, timestamp, and wire type.
    #[error(
        "contradictory response for request_id={request_id}: prior approved={prior_approved}, new approved={new_approved}"
    )]
    ContradictoryResponse {
        /// `request_id` of both responses (they share it by
        /// definition of "contradictory").
        request_id: u64,
        /// The `approved` field recorded first for this `request_id`.
        prior_approved: bool,
        /// The `approved` field on the contradictory response.
        new_approved: bool,
    },
    /// A `Response` was observed for a `request_id` that was never
    /// `Requested` on this session. A correct peer would have
    /// observed the `Request` first.
    #[error("response for unknown request_id={request_id} (no prior Request)")]
    StaleResponseForUnknownRequest {
        /// `request_id` of the orphan response.
        request_id: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_key_pair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_bytes();
        (sk, pk_bytes)
    }

    // A placeholder fingerprint for unit-level sign/verify tests that
    // don't drive a full Session. Real callers derive this from
    // `Session::session_fingerprint`.
    const TEST_FP: [u8; 32] = [0xAA; 32];

    #[test]
    fn consent_request_signs_and_verifies() {
        let (sk, pk) = test_key_pair();
        let core = ConsentRequestCore {
            request_id: 42,
            requester_pubkey: pk,
            session_fingerprint: TEST_FP,
            valid_until: 1_700_000_000,
            scope: ConsentScope::ScreenAndInput,
            reason: "ticket #1234 password reset".to_string(),
            causal_binding: None,
        };
        let req = ConsentRequest::sign(core, &sk);
        assert!(req.verify(None));
        assert!(req.verify(Some(&pk)));
    }

    #[test]
    fn consent_request_rejects_wrong_pubkey() {
        let (sk, _) = test_key_pair();
        let (_, other_pk) = test_key_pair();
        let core = ConsentRequestCore {
            request_id: 1,
            requester_pubkey: sk.verifying_key().to_bytes(),
            session_fingerprint: TEST_FP,
            valid_until: 1,
            scope: ConsentScope::ScreenOnly,
            reason: "".into(),
            causal_binding: None,
        };
        let req = ConsentRequest::sign(core, &sk);
        assert!(!req.verify(Some(&other_pk)));
    }

    #[test]
    fn consent_request_rejects_tampered_body() {
        let (sk, pk) = test_key_pair();
        let core = ConsentRequestCore {
            request_id: 1,
            requester_pubkey: pk,
            session_fingerprint: TEST_FP,
            valid_until: 100,
            scope: ConsentScope::ScreenOnly,
            reason: "original".into(),
            causal_binding: None,
        };
        let mut req = ConsentRequest::sign(core, &sk);
        req.core.reason = "tampered".into();
        assert!(!req.verify(None));
    }

    #[test]
    fn consent_request_rejects_tampered_fingerprint() {
        // A fingerprint byte-flip after signing must invalidate the
        // signature — session-binding is load-bearing at the
        // signed-body level.
        let (sk, pk) = test_key_pair();
        let core = ConsentRequestCore {
            request_id: 1,
            requester_pubkey: pk,
            session_fingerprint: TEST_FP,
            valid_until: 100,
            scope: ConsentScope::ScreenOnly,
            reason: "".into(),
            causal_binding: None,
        };
        let mut req = ConsentRequest::sign(core, &sk);
        req.core.session_fingerprint[0] ^= 0x01;
        assert!(!req.verify(None));
    }

    #[test]
    fn consent_response_signs_and_verifies() {
        let (sk, pk) = test_key_pair();
        let core = ConsentResponseCore {
            request_id: 42,
            responder_pubkey: pk,
            session_fingerprint: TEST_FP,
            approved: true,
            reason: "".into(),
        };
        let resp = ConsentResponse::sign(core, &sk);
        assert!(resp.verify(Some(&pk)));
    }

    #[test]
    fn consent_revocation_signs_and_verifies() {
        let (sk, pk) = test_key_pair();
        let core = ConsentRevocationCore {
            request_id: 42,
            revoker_pubkey: pk,
            session_fingerprint: TEST_FP,
            issued_at: 1_700_000_500,
            reason: "session complete".into(),
        };
        let rev = ConsentRevocation::sign(core, &sk);
        assert!(rev.verify(Some(&pk)));
    }

    #[test]
    fn consent_messages_are_sealable() {
        let (sk, pk) = test_key_pair();
        let req = ConsentRequest::sign(
            ConsentRequestCore {
                request_id: 1,
                requester_pubkey: pk,
                session_fingerprint: TEST_FP,
                valid_until: 1,
                scope: ConsentScope::ScreenOnly,
                reason: "".into(),
                causal_binding: None,
            },
            &sk,
        );
        let bytes = req.to_bin().unwrap();
        let decoded = ConsentRequest::from_bin(&bytes).unwrap();
        assert_eq!(decoded, req);
    }
}
