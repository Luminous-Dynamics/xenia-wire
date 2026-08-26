// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Experimental typed authority profile carried by consent `causal_binding`.
//!
//! This module is deliberately opt-in behind the `causal-authority` feature.
//! It does not change the envelope, consent-request, consent-response, or
//! revocation wire layouts. Instead, it gives the already-reserved
//! [`crate::consent::CausalPredicate::opaque`] field a domain-separated,
//! canonical profile for binding a signed Xenia consent ceremony to one exact
//! external action subject.
//!
//! A verifier must validate the signed request *and* signed approval together.
//! A ledger `Approval` event or human-readable scope string alone is not an
//! external-action authorization.

#![cfg(feature = "causal-authority")]

use serde::{Deserialize, Serialize};

use crate::WireError;
use crate::consent::{
    CausalPredicate, ConsentRequest, ConsentResponse, ConsentRevocation, PUBLIC_KEY_LEN,
};

/// Human-readable profile identifier carried in `CausalPredicate::description`.
pub const EXTERNAL_ACTION_AUTHORITY_PROFILE: &str = "xenia.external-action-authority.v1";

/// Domain separator that prefixes the canonical opaque payload.
///
/// The terminating NUL prevents concatenation ambiguity if future profile names
/// share this prefix.
pub const EXTERNAL_ACTION_AUTHORITY_MAGIC: &[u8] = b"xenia.external-action-authority.v1\0";

/// Reuse policy attached to an external action authorization.
///
/// Xenia wire can cryptographically bind this policy but cannot itself persist
/// cross-session consumption state. A caller accepting [`SingleUse`](Self::SingleUse)
/// MUST durably record consumption keyed by `subject_id` before or atomically with
/// the consequential action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityUsePolicy {
    /// The authority may authorize at most one consequential action.
    SingleUse,
    /// The authority may be reused only within the same Xenia consent session,
    /// until expiry or revocation, for the exact bound subject.
    SessionBoundReusable,
}

/// Canonical semantic payload for one externally authorized action.
///
/// This struct is serialized with bincode v1, prefixed by
/// [`EXTERNAL_ACTION_AUTHORITY_MAGIC`], and stored in
/// [`CausalPredicate::opaque`]. The whole `CausalPredicate` is then covered by
/// the existing `ConsentRequestCore` signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionAuthorityV1 {
    /// Stable caller-defined subject identifier, normally an intent UUID encoded
    /// as 16 bytes. It must not be all zeroes.
    pub subject_id: [u8; 16],
    /// Exact target identifier understood by the consuming application.
    pub target: String,
    /// Exact capability being delegated, e.g. `nixos.rebuild`.
    pub capability: String,
    /// Digest of the canonical action representation.
    pub action_digest: [u8; 32],
    /// Digest of the canonical action parameters.
    pub parameters_digest: [u8; 32],
    /// Exact maximum application-defined scope. Consumers must compare it using
    /// their canonical scope semantics and must never silently broaden it.
    pub max_scope: String,
    /// Absolute Unix-epoch expiry in milliseconds.
    pub expires_at_ms: u64,
    /// Whether the bound authority is single-use or session-bound reusable.
    pub use_policy: AuthorityUsePolicy,
}

impl ExternalActionAuthorityV1 {
    /// Encode this authority as the reserved Xenia causal predicate.
    pub fn to_causal_predicate(&self) -> Result<CausalPredicate, WireError> {
        self.validate_shape()
            .map_err(|e| WireError::Codec(format!("external authority: {e}")))?;

        let encoded = bincode::serialize(self).map_err(WireError::encode)?;
        let mut opaque = Vec::with_capacity(EXTERNAL_ACTION_AUTHORITY_MAGIC.len() + encoded.len());
        opaque.extend_from_slice(EXTERNAL_ACTION_AUTHORITY_MAGIC);
        opaque.extend_from_slice(&encoded);

        Ok(CausalPredicate {
            description: EXTERNAL_ACTION_AUTHORITY_PROFILE.to_owned(),
            opaque,
        })
    }

    /// Decode and validate a causal predicate carrying this exact profile.
    ///
    /// Unknown profiles fail closed. The payload is re-serialized and compared
    /// byte-for-byte to reject non-canonical encodings or trailing data.
    pub fn from_causal_predicate(
        predicate: &CausalPredicate,
    ) -> Result<Self, ExternalAuthorityError> {
        if predicate.description != EXTERNAL_ACTION_AUTHORITY_PROFILE {
            return Err(ExternalAuthorityError::UnsupportedProfile);
        }

        let payload = predicate
            .opaque
            .strip_prefix(EXTERNAL_ACTION_AUTHORITY_MAGIC)
            .ok_or(ExternalAuthorityError::UnsupportedProfile)?;

        let decoded: Self =
            bincode::deserialize(payload).map_err(|_| ExternalAuthorityError::MalformedBinding)?;
        let canonical =
            bincode::serialize(&decoded).map_err(|_| ExternalAuthorityError::MalformedBinding)?;
        if canonical.as_slice() != payload {
            return Err(ExternalAuthorityError::MalformedBinding);
        }
        decoded.validate_shape()?;
        Ok(decoded)
    }

    fn validate_shape(&self) -> Result<(), ExternalAuthorityError> {
        if self.subject_id.iter().all(|byte| *byte == 0) {
            return Err(ExternalAuthorityError::ZeroSubjectId);
        }
        if self.target.trim().is_empty() {
            return Err(ExternalAuthorityError::EmptyTarget);
        }
        if self.capability.trim().is_empty() {
            return Err(ExternalAuthorityError::EmptyCapability);
        }
        if self.max_scope.trim().is_empty() {
            return Err(ExternalAuthorityError::EmptyScope);
        }
        if self.expires_at_ms == 0 {
            return Err(ExternalAuthorityError::InvalidExpiry);
        }
        Ok(())
    }
}

/// Result of verifying a complete Xenia approval ceremony carrying an exact
/// external action authority profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExternalActionAuthority {
    /// The exact machine-readable subject covered by the signed request.
    pub authority: ExternalActionAuthorityV1,
    /// Xenia consent request identifier.
    pub request_id: u64,
    /// Signed requester device key.
    pub requester_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Signed responder device key that approved the request.
    pub responder_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Session fingerprint shared by request and response.
    pub session_fingerprint: [u8; 32],
    /// Consent request expiry in Unix seconds.
    pub consent_valid_until: u64,
}

/// Semantic failures returned by external-action authority verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExternalAuthorityError {
    /// The consent request signature/key binding did not verify.
    #[error("invalid consent request signature or requester key")]
    InvalidRequestSignature,
    /// The consent response signature/key binding did not verify.
    #[error("invalid consent response signature or responder key")]
    InvalidResponseSignature,
    /// Request and response refer to different request identifiers.
    #[error("consent response refers to a different request")]
    RequestIdMismatch,
    /// The signed request is not bound to the expected live session fingerprint.
    #[error("consent request session fingerprint mismatch")]
    RequestFingerprintMismatch,
    /// The signed response is not bound to the expected live session fingerprint.
    #[error("consent response session fingerprint mismatch")]
    ResponseFingerprintMismatch,
    /// The responder explicitly denied the request.
    #[error("consent request was denied")]
    Denied,
    /// No causal authority profile was present on the signed request.
    #[error("signed consent request has no causal authority binding")]
    MissingCausalBinding,
    /// The causal profile is unknown or has the wrong domain separator.
    #[error("unsupported causal authority profile")]
    UnsupportedProfile,
    /// The causal profile bytes are malformed or non-canonical.
    #[error("malformed causal authority binding")]
    MalformedBinding,
    /// The external subject identifier is all zeroes.
    #[error("external authority subject id must be non-zero")]
    ZeroSubjectId,
    /// The target is empty.
    #[error("external authority target is empty")]
    EmptyTarget,
    /// The capability is empty.
    #[error("external authority capability is empty")]
    EmptyCapability,
    /// The application scope is empty.
    #[error("external authority scope is empty")]
    EmptyScope,
    /// The external authority has an invalid zero expiry.
    #[error("external authority expiry is invalid")]
    InvalidExpiry,
    /// The signed consent request has expired.
    #[error("signed consent request has expired")]
    RequestExpired,
    /// The exact external authority has expired.
    #[error("external action authority has expired")]
    AuthorityExpired,
    /// The external authority claims to survive longer than the consent request.
    #[error("external authority outlives signed consent request")]
    AuthorityOutlivesRequest,
    /// A matching revocation has an invalid signer, signature, or timestamp.
    #[error("invalid matching consent revocation")]
    InvalidRevocation,
    /// A valid matching revocation terminates the authority.
    #[error("external action authority has been revoked")]
    Revoked,
}

/// Verify one exact external-action authorization carried by a signed Xenia
/// request/approval pair, including any matching revocations supplied by the
/// caller.
///
/// `expected_session_fingerprint` must come from the trusted live-session or
/// transcript-verification path; merely checking that the two embedded
/// fingerprints equal each other is not sufficient replay protection.
///
/// The caller is responsible for supplying all relevant revocations from its
/// canonical evidence source. For [`AuthorityUsePolicy::SingleUse`], the caller
/// must additionally enforce durable one-time consumption of `subject_id`.
#[allow(clippy::too_many_arguments)]
pub fn verify_approved_external_action_authority(
    request: &ConsentRequest,
    response: &ConsentResponse,
    revocations: &[ConsentRevocation],
    expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
    expected_responder_pubkey: &[u8; PUBLIC_KEY_LEN],
    expected_session_fingerprint: &[u8; 32],
    now_ms: u64,
) -> Result<VerifiedExternalActionAuthority, ExternalAuthorityError> {
    if !request.verify(Some(expected_requester_pubkey)) {
        return Err(ExternalAuthorityError::InvalidRequestSignature);
    }
    if !response.verify(Some(expected_responder_pubkey)) {
        return Err(ExternalAuthorityError::InvalidResponseSignature);
    }
    if request.core.request_id != response.core.request_id {
        return Err(ExternalAuthorityError::RequestIdMismatch);
    }
    if &request.core.session_fingerprint != expected_session_fingerprint {
        return Err(ExternalAuthorityError::RequestFingerprintMismatch);
    }
    if &response.core.session_fingerprint != expected_session_fingerprint {
        return Err(ExternalAuthorityError::ResponseFingerprintMismatch);
    }
    if !response.core.approved {
        return Err(ExternalAuthorityError::Denied);
    }

    let request_expiry_ms = request.core.valid_until.saturating_mul(1_000);
    if now_ms >= request_expiry_ms {
        return Err(ExternalAuthorityError::RequestExpired);
    }

    let predicate = request
        .core
        .causal_binding
        .as_ref()
        .ok_or(ExternalAuthorityError::MissingCausalBinding)?;
    let authority = ExternalActionAuthorityV1::from_causal_predicate(predicate)?;

    if authority.expires_at_ms > request_expiry_ms {
        return Err(ExternalAuthorityError::AuthorityOutlivesRequest);
    }
    if now_ms >= authority.expires_at_ms {
        return Err(ExternalAuthorityError::AuthorityExpired);
    }

    for revocation in revocations {
        if revocation.core.request_id != request.core.request_id
            || &revocation.core.session_fingerprint != expected_session_fingerprint
        {
            continue;
        }

        let revoker = &revocation.core.revoker_pubkey;
        let known_party = revoker == expected_requester_pubkey || revoker == expected_responder_pubkey;
        if !known_party || !revocation.verify(Some(revoker)) {
            return Err(ExternalAuthorityError::InvalidRevocation);
        }

        let issued_at_ms = revocation.core.issued_at.saturating_mul(1_000);
        if issued_at_ms > now_ms {
            return Err(ExternalAuthorityError::InvalidRevocation);
        }
        return Err(ExternalAuthorityError::Revoked);
    }

    Ok(VerifiedExternalActionAuthority {
        authority,
        request_id: request.core.request_id,
        requester_pubkey: request.core.requester_pubkey,
        responder_pubkey: response.core.responder_pubkey,
        session_fingerprint: request.core.session_fingerprint,
        consent_valid_until: request.core.valid_until,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::{
        ConsentRequestCore, ConsentResponseCore, ConsentRevocationCore, ConsentScope,
    };
    use ed25519_dalek::SigningKey;

    const FP: [u8; 32] = [0xA5; 32];

    fn requester() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn responder() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn authority(expires_at_ms: u64) -> ExternalActionAuthorityV1 {
        ExternalActionAuthorityV1 {
            subject_id: [0x33; 16],
            target: "host:workstation-17".into(),
            capability: "nixos.rebuild".into(),
            action_digest: [0x44; 32],
            parameters_digest: [0x55; 32],
            max_scope: "host:workstation-17".into(),
            expires_at_ms,
            use_policy: AuthorityUsePolicy::SingleUse,
        }
    }

    fn request(binding: ExternalActionAuthorityV1) -> ConsentRequest {
        let sk = requester();
        ConsentRequest::sign(
            ConsentRequestCore {
                request_id: 7,
                requester_pubkey: sk.verifying_key().to_bytes(),
                session_fingerprint: FP,
                valid_until: 20,
                scope: ConsentScope::Interactive,
                reason: "approved recovery".into(),
                causal_binding: Some(binding.to_causal_predicate().unwrap()),
            },
            &sk,
        )
    }

    fn response(approved: bool, request_id: u64) -> ConsentResponse {
        let sk = responder();
        ConsentResponse::sign(
            ConsentResponseCore {
                request_id,
                responder_pubkey: sk.verifying_key().to_bytes(),
                session_fingerprint: FP,
                approved,
                reason: String::new(),
            },
            &sk,
        )
    }

    fn verify(
        request: &ConsentRequest,
        response: &ConsentResponse,
        revocations: &[ConsentRevocation],
        now_ms: u64,
    ) -> Result<VerifiedExternalActionAuthority, ExternalAuthorityError> {
        verify_approved_external_action_authority(
            request,
            response,
            revocations,
            &requester().verifying_key().to_bytes(),
            &responder().verifying_key().to_bytes(),
            &FP,
            now_ms,
        )
    }

    #[test]
    fn profile_round_trips_canonically() {
        let expected = authority(15_000);
        let predicate = expected.to_causal_predicate().unwrap();
        assert_eq!(predicate.description, EXTERNAL_ACTION_AUTHORITY_PROFILE);
        assert!(predicate.opaque.starts_with(EXTERNAL_ACTION_AUTHORITY_MAGIC));
        assert_eq!(
            ExternalActionAuthorityV1::from_causal_predicate(&predicate).unwrap(),
            expected
        );
    }

    #[test]
    fn exact_signed_request_and_approval_verify() {
        let req = request(authority(15_000));
        let resp = response(true, 7);
        let verified = verify(&req, &resp, &[], 10_000).unwrap();
        assert_eq!(verified.authority.capability, "nixos.rebuild");
        assert_eq!(verified.authority.action_digest, [0x44; 32]);
        assert_eq!(verified.authority.parameters_digest, [0x55; 32]);
    }

    #[test]
    fn tampering_bound_action_invalidates_request_signature() {
        let mut req = request(authority(15_000));
        let mut decoded = ExternalActionAuthorityV1::from_causal_predicate(
            req.core.causal_binding.as_ref().unwrap(),
        )
        .unwrap();
        decoded.action_digest = [0x99; 32];
        req.core.causal_binding = Some(decoded.to_causal_predicate().unwrap());
        let resp = response(true, 7);
        assert_eq!(
            verify(&req, &resp, &[], 10_000),
            Err(ExternalAuthorityError::InvalidRequestSignature)
        );
    }

    #[test]
    fn response_for_other_request_is_rejected() {
        let req = request(authority(15_000));
        let resp = response(true, 8);
        assert_eq!(
            verify(&req, &resp, &[], 10_000),
            Err(ExternalAuthorityError::RequestIdMismatch)
        );
    }

    #[test]
    fn denial_is_not_authority() {
        let req = request(authority(15_000));
        let resp = response(false, 7);
        assert_eq!(
            verify(&req, &resp, &[], 10_000),
            Err(ExternalAuthorityError::Denied)
        );
    }

    #[test]
    fn authority_cannot_outlive_request() {
        let req = request(authority(20_001));
        let resp = response(true, 7);
        assert_eq!(
            verify(&req, &resp, &[], 10_000),
            Err(ExternalAuthorityError::AuthorityOutlivesRequest)
        );
    }

    #[test]
    fn authority_expiry_is_enforced() {
        let req = request(authority(12_000));
        let resp = response(true, 7);
        assert_eq!(
            verify(&req, &resp, &[], 12_000),
            Err(ExternalAuthorityError::AuthorityExpired)
        );
    }

    #[test]
    fn unknown_profile_fails_closed() {
        let mut req = request(authority(15_000));
        let sk = requester();
        req.core.causal_binding = Some(CausalPredicate {
            description: "unknown.profile.v9".into(),
            opaque: b"anything".to_vec(),
        });
        req = ConsentRequest::sign(req.core, &sk);
        let resp = response(true, 7);
        assert_eq!(
            verify(&req, &resp, &[], 10_000),
            Err(ExternalAuthorityError::UnsupportedProfile)
        );
    }

    #[test]
    fn matching_valid_revocation_terminates_authority() {
        let req = request(authority(15_000));
        let resp = response(true, 7);
        let sk = responder();
        let revocation = ConsentRevocation::sign(
            ConsentRevocationCore {
                request_id: 7,
                revoker_pubkey: sk.verifying_key().to_bytes(),
                session_fingerprint: FP,
                issued_at: 11,
                reason: "operator cancelled".into(),
            },
            &sk,
        );
        assert_eq!(
            verify(&req, &resp, &[revocation], 12_000),
            Err(ExternalAuthorityError::Revoked)
        );
    }

    #[test]
    fn wrong_session_fingerprint_is_rejected() {
        let req = request(authority(15_000));
        let resp = response(true, 7);
        assert_eq!(
            verify_approved_external_action_authority(
                &req,
                &resp,
                &[],
                &requester().verifying_key().to_bytes(),
                &responder().verifying_key().to_bytes(),
                &[0xCC; 32],
                10_000,
            ),
            Err(ExternalAuthorityError::RequestFingerprintMismatch)
        );
    }
}
