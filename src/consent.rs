// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Consent ceremony for Xenia sessions (SPEC draft-02 §12).
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
//! ## Forward-compatibility
//!
//! [`ConsentRequestCore::causal_binding`] is reserved for a future
//! Ricardian-contract extension (ticket-state-bound authority). In
//! draft-02 it MUST be `None`; the wire slot is reserved so that
//! v1.1-aware receivers can honor it without breaking v1 peers.
//!
//! ## Threat model
//!
//! The consent ceremony assumes:
//!
//! - Each peer holds an Ed25519 signing key on their device. The
//!   binding of a device key to a human identity is out of scope here
//!   (that's the MSP attestation chain in SPEC draft-02 §12.5).
//! - The session's AEAD key has already been established via the outer
//!   handshake. The consent messages flow INSIDE the sealed channel —
//!   the signature adds a second layer of authentication specifically
//!   for non-repudiation.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRequestCore {
    /// Monotonic request identifier chosen by the requester. Used by the
    /// responder to correlate `ConsentResponse.request_id`.
    pub request_id: u64,
    /// Technician's device public key (raw 32-byte Ed25519).
    pub requester_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Unix epoch seconds after which the request expires. Callers SHOULD
    /// grant ±30 s clock skew.
    pub valid_until: u64,
    /// Scope of access requested.
    pub scope: ConsentScope,
    /// Free-text justification (ticket reference, reason).
    pub reason: String,
    /// Reserved for v1.1 Ricardian binding. MUST be `None` in draft-02.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentResponseCore {
    /// Matches `ConsentRequestCore::request_id` to correlate.
    pub request_id: u64,
    /// End-user's device public key (raw 32-byte Ed25519).
    pub responder_pubkey: [u8; PUBLIC_KEY_LEN],
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRevocationCore {
    /// References the `request_id` being revoked.
    pub request_id: u64,
    /// Public key of the revoker (either party may revoke).
    pub revoker_pubkey: [u8; PUBLIC_KEY_LEN],
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

/// Session-level consent state machine.
///
/// Transitions:
///
/// ```text
///           ConsentRequest sealed
/// Pending  ────────────────────────▶  Requested
///                                     │
///                                     │ ConsentResponse{approved=true} opened
///                                     ▼
///                                  Approved ────┐
///                                     │         │ ConsentRevocation opened
///                                     │         ▼
///                                     │      Revoked
///                                     │
///                                     │ ConsentResponse{approved=false} opened
///                                     ▼
///                                   Denied
/// ```
///
/// `Session::observe_consent` drives these transitions. Application
/// `FRAME` payloads are accepted only in the `Approved` state — see
/// [`crate::Session::seal`] and [`crate::Session::open`] for the
/// enforcement points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// No request has been observed on this session yet.
    Pending,
    /// A `ConsentRequest` was sent / received but not yet answered.
    Requested,
    /// Consent was approved by the responder. FRAME payloads flow.
    Approved,
    /// The responder denied the request. Terminal state.
    Denied,
    /// A revocation was received after approval. Terminal state.
    Revoked,
}

/// Observed consent-ceremony events that drive [`crate::Session`]'s
/// state machine. The caller constructs one of these AFTER verifying
/// the underlying signed message, and passes it to
/// [`crate::Session::observe_consent`].
///
/// Keeping the event type a lightweight enum — rather than passing the
/// full `ConsentRequest`/etc. struct — lets the session stay
/// storage-agnostic (no need to hold message bodies) and makes
/// application-level verification policy the explicit caller
/// responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentEvent {
    /// A `ConsentRequest` was observed (either sent or received).
    Request,
    /// A `ConsentResponse` with `approved = true` was observed.
    ResponseApproved,
    /// A `ConsentResponse` with `approved = false` was observed.
    ResponseDenied,
    /// A `ConsentRevocation` was observed.
    Revocation,
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

    #[test]
    fn consent_request_signs_and_verifies() {
        let (sk, pk) = test_key_pair();
        let core = ConsentRequestCore {
            request_id: 42,
            requester_pubkey: pk,
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
    fn consent_response_signs_and_verifies() {
        let (sk, pk) = test_key_pair();
        let core = ConsentResponseCore {
            request_id: 42,
            responder_pubkey: pk,
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
