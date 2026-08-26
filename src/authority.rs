// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Experimental typed authority profile carried by consent `causal_binding`.
//!
//! Exact external authority needs a stronger approval primitive than the
//! draft-03 `ConsentResponse`: that response signs a request id + session
//! fingerprint, but not the exact request body. This module therefore adds an
//! opt-in bound response whose signature commits to a domain-separated digest
//! of the complete signed [`ConsentRequest`].
//!
//! The extension is deliberately experimental and feature-gated. It does not
//! redefine draft-03 consent semantics.

#![cfg(feature = "causal-authority")]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};

use crate::consent::{
    CausalPredicate, ConsentRequest, ConsentRevocation, ConsentScope, PUBLIC_KEY_LEN,
    SIGNATURE_LEN,
};
use crate::{Sealable, Session, WireError};

/// Human-readable profile identifier carried in `CausalPredicate::description`.
pub const EXTERNAL_ACTION_AUTHORITY_PROFILE: &str = "xenia.external-action-authority.v1";

/// Domain separator prefixing the canonical authority payload.
pub const EXTERNAL_ACTION_AUTHORITY_MAGIC: &[u8] = b"xenia.external-action-authority.v1\0";

/// Domain separator for the digest of the complete signed consent request.
pub const AUTHORITY_REQUEST_DIGEST_DOMAIN: &[u8] = b"xenia.causal-authority.request-digest.v1\0";

/// Domain separator for the durable approval-instance identifier.
pub const AUTHORITY_INSTANCE_ID_DOMAIN: &[u8] = b"xenia.causal-authority.instance-id.v1\0";

/// Maximum size of each application-defined canonical identifier.
pub const MAX_AUTHORITY_IDENTIFIER_BYTES: usize = 1024;

/// Maximum complete `CausalPredicate::opaque` size accepted by this profile.
pub const MAX_CAUSAL_AUTHORITY_OPAQUE_BYTES: usize = 8 * 1024;

/// Maximum human-readable response reason size.
pub const MAX_AUTHORITY_RESPONSE_REASON_BYTES: usize = 4096;

/// Maximum human-readable request reason accepted by the authority verifier.
pub const MAX_AUTHORITY_REQUEST_REASON_BYTES: usize = 4096;

/// Maximum serialized bound-response size accepted by `Sealable::from_bin`.
pub const MAX_CAUSAL_AUTHORITY_RESPONSE_BYTES: usize = 16 * 1024;

/// Clock-skew tolerance for signed response/revocation issue times.
pub const AUTHORITY_CLOCK_SKEW_MS: u64 = 30_000;

/// Reuse policy attached to an external action authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityUsePolicy {
    /// The approval may authorize at most one consequential action.
    ///
    /// Xenia binds this requirement but cannot persist consumption. Consumers
    /// must atomically/durably consume `VerifiedExternalActionAuthority::authority_id`.
    SingleUse,
    /// Reuse is permitted only for the exact bound subject in the same Xenia
    /// session until expiry or revocation.
    SessionBoundReusable,
}

/// Canonical semantic payload for one externally authorized action.
///
/// `target`, `capability`, and `max_scope` are canonical application bytes, not
/// human-readable strings. This avoids Unicode/case/normalization ambiguity
/// between independent verifiers. Human-readable explanation belongs in the
/// enclosing signed consent request/response `reason` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionAuthorityV1 {
    /// Stable caller-defined subject identifier, typically an immutable intent
    /// UUID encoded as 16 bytes. Must not be all zeroes.
    pub subject_id: [u8; 16],
    /// Exact canonical target identifier bytes.
    pub target: Vec<u8>,
    /// Exact canonical capability identifier bytes.
    pub capability: Vec<u8>,
    /// Digest of the canonical action representation.
    pub action_digest: [u8; 32],
    /// Digest of the canonical action parameters. Hash an explicit empty
    /// canonical parameter representation rather than using all zeroes.
    pub parameters_digest: [u8; 32],
    /// Exact canonical maximum-scope identifier bytes.
    pub max_scope: Vec<u8>,
    /// Absolute Unix-epoch expiry in milliseconds.
    pub expires_at_ms: u64,
    /// Whether this approval is single-use or session-bound reusable.
    pub use_policy: AuthorityUsePolicy,
}

impl ExternalActionAuthorityV1 {
    /// Encode this authority as the reserved Xenia causal predicate.
    pub fn to_causal_predicate(&self) -> Result<CausalPredicate, ExternalAuthorityError> {
        self.validate_shape()?;
        let encoded = bincode::serialize(self).map_err(|_| ExternalAuthorityError::Encoding)?;
        let total_len = EXTERNAL_ACTION_AUTHORITY_MAGIC
            .len()
            .saturating_add(encoded.len());
        if total_len > MAX_CAUSAL_AUTHORITY_OPAQUE_BYTES {
            return Err(ExternalAuthorityError::BindingTooLarge);
        }

        let mut opaque = Vec::with_capacity(total_len);
        opaque.extend_from_slice(EXTERNAL_ACTION_AUTHORITY_MAGIC);
        opaque.extend_from_slice(&encoded);
        Ok(CausalPredicate {
            description: EXTERNAL_ACTION_AUTHORITY_PROFILE.to_owned(),
            opaque,
        })
    }

    /// Decode and validate a causal predicate carrying this exact profile.
    ///
    /// Unknown profiles fail closed. Re-serialization must exactly reproduce the
    /// payload, which rejects trailing/non-canonical encodings.
    pub fn from_causal_predicate(
        predicate: &CausalPredicate,
    ) -> Result<Self, ExternalAuthorityError> {
        if predicate.description != EXTERNAL_ACTION_AUTHORITY_PROFILE {
            return Err(ExternalAuthorityError::UnsupportedProfile);
        }
        if predicate.opaque.len() > MAX_CAUSAL_AUTHORITY_OPAQUE_BYTES {
            return Err(ExternalAuthorityError::BindingTooLarge);
        }

        let payload = predicate
            .opaque
            .strip_prefix(EXTERNAL_ACTION_AUTHORITY_MAGIC)
            .ok_or(ExternalAuthorityError::UnsupportedProfile)?;
        let decoded: Self =
            bincode::deserialize(payload).map_err(|_| ExternalAuthorityError::MalformedBinding)?;
        let canonical =
            bincode::serialize(&decoded).map_err(|_| ExternalAuthorityError::Encoding)?;
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
        validate_identifier(&self.target, IdentifierKind::Target)?;
        validate_identifier(&self.capability, IdentifierKind::Capability)?;
        validate_identifier(&self.max_scope, IdentifierKind::Scope)?;
        if self.action_digest.iter().all(|byte| *byte == 0) {
            return Err(ExternalAuthorityError::ZeroActionDigest);
        }
        if self.parameters_digest.iter().all(|byte| *byte == 0) {
            return Err(ExternalAuthorityError::ZeroParametersDigest);
        }
        if self.expires_at_ms == 0 {
            return Err(ExternalAuthorityError::InvalidExpiry);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IdentifierKind {
    Target,
    Capability,
    Scope,
}

fn validate_identifier(bytes: &[u8], kind: IdentifierKind) -> Result<(), ExternalAuthorityError> {
    if bytes.is_empty() {
        return Err(match kind {
            IdentifierKind::Target => ExternalAuthorityError::EmptyTarget,
            IdentifierKind::Capability => ExternalAuthorityError::EmptyCapability,
            IdentifierKind::Scope => ExternalAuthorityError::EmptyScope,
        });
    }
    if bytes.len() > MAX_AUTHORITY_IDENTIFIER_BYTES {
        return Err(match kind {
            IdentifierKind::Target => ExternalAuthorityError::TargetTooLong,
            IdentifierKind::Capability => ExternalAuthorityError::CapabilityTooLong,
            IdentifierKind::Scope => ExternalAuthorityError::ScopeTooLong,
        });
    }
    Ok(())
}

/// Signed responder statement for exact external authority.
///
/// Unlike draft-03 `ConsentResponseCore`, this body commits to
/// `request_digest`, which hashes the complete signed `ConsentRequest`.
/// Canonical field order is load-bearing:
/// `request_id`, `request_digest`, `responder_pubkey`, `session_fingerprint`,
/// `approved`, `issued_at_ms`, `reason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalAuthorityResponseCore {
    /// Consent request identifier.
    pub request_id: u64,
    /// Domain-separated SHA-256 digest of the complete signed request.
    pub request_digest: [u8; 32],
    /// Responder device public key.
    pub responder_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Session fingerprint copied from the exact request being approved.
    pub session_fingerprint: [u8; 32],
    /// Approval/denial decision.
    pub approved: bool,
    /// Unix-epoch issue time in milliseconds.
    pub issued_at_ms: u64,
    /// Human-readable reason. It is signed but not machine authorization.
    pub reason: String,
}

/// Signed response that approves or denies one exact signed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalAuthorityResponse {
    /// Signed response body.
    pub core: CausalAuthorityResponseCore,
    /// Ed25519 signature over `bincode::serialize(&core)`.
    #[serde(with = "BigArray")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl CausalAuthorityResponse {
    /// Sign an explicitly constructed core.
    pub fn sign(core: CausalAuthorityResponseCore, signing_key: &SigningKey) -> Self {
        let bytes = bincode::serialize(&core).expect("causal authority response core serializes");
        let signature = signing_key.sign(&bytes);
        Self {
            core,
            signature: signature.to_bytes(),
        }
    }

    /// Build and sign a response bound to the exact signed request bytes.
    pub fn sign_for_request(
        request: &ConsentRequest,
        approved: bool,
        issued_at_ms: u64,
        reason: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<Self, ExternalAuthorityError> {
        if issued_at_ms == 0 {
            return Err(ExternalAuthorityError::InvalidResponseIssueTime);
        }
        let reason = reason.into();
        if reason.as_bytes().len() > MAX_AUTHORITY_RESPONSE_REASON_BYTES {
            return Err(ExternalAuthorityError::ResponseReasonTooLong);
        }
        Ok(Self::sign(
            CausalAuthorityResponseCore {
                request_id: request.core.request_id,
                request_digest: authority_request_digest(request)?,
                responder_pubkey: signing_key.verifying_key().to_bytes(),
                session_fingerprint: request.core.session_fingerprint,
                approved,
                issued_at_ms,
                reason,
            },
            signing_key,
        ))
    }

    /// Verify the response signature and optional expected responder key.
    pub fn verify(&self, expected_pubkey: Option<&[u8; PUBLIC_KEY_LEN]>) -> bool {
        if self.core.issued_at_ms == 0
            || self.core.reason.as_bytes().len() > MAX_AUTHORITY_RESPONSE_REASON_BYTES
        {
            return false;
        }
        if expected_pubkey.is_some_and(|expected| expected != &self.core.responder_pubkey) {
            return false;
        }
        let Ok(pk) = VerifyingKey::from_bytes(&self.core.responder_pubkey) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let Ok(bytes) = bincode::serialize(&self.core) else {
            return false;
        };
        pk.verify(&bytes, &signature).is_ok()
    }
}

impl Sealable for CausalAuthorityResponse {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }

    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_CAUSAL_AUTHORITY_RESPONSE_BYTES {
            return Err(WireError::Codec("decode: causal authority response too large".into()));
        }
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// Seal an exact-authority response under the reserved `0x24` payload type.
pub fn seal_causal_authority_response(
    response: &CausalAuthorityResponse,
    session: &mut Session,
) -> Result<Vec<u8>, WireError> {
    crate::seal(
        response,
        session,
        crate::payload_types::PAYLOAD_TYPE_CAUSAL_AUTHORITY_RESPONSE,
    )
}

/// Open an exact-authority response, failing closed on payload-type mismatch.
///
/// The explicit type check prevents a different stream's bincode-compatible
/// plaintext from being interpreted as an authority approval.
pub fn open_causal_authority_response(
    bytes: &[u8],
    session: &mut Session,
) -> Result<CausalAuthorityResponse, WireError> {
    if crate::envelope_payload_type(bytes)
        != Some(crate::payload_types::PAYLOAD_TYPE_CAUSAL_AUTHORITY_RESPONSE)
    {
        return Err(WireError::OpenFailed);
    }
    crate::open(bytes, session)
}

/// Compute the digest a responder signs when approving an exact request.
///
/// The complete signed `ConsentRequest` is hashed, not only its core. This binds
/// the approval to the exact requester-authenticated object and remains robust
/// if a future requester signature algorithm becomes non-deterministic.
pub fn authority_request_digest(
    request: &ConsentRequest,
) -> Result<[u8; 32], ExternalAuthorityError> {
    let bytes = bincode::serialize(request).map_err(|_| ExternalAuthorityError::Encoding)?;
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_REQUEST_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// Derive a stable identifier for one exact responder approval instance.
///
/// Consumers enforcing `SingleUse` should durably/atomically consume this id,
/// not merely the caller-defined `subject_id`.
pub fn authority_instance_id(response: &CausalAuthorityResponse) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_INSTANCE_ID_DOMAIN);
    hasher.update(response.core.request_digest);
    hasher.update(response.core.responder_pubkey);
    hasher.update(response.signature);
    hasher.finalize().into()
}

/// Result of verifying a complete exact-authority ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExternalActionAuthority {
    /// Exact machine-readable subject carried by the signed request.
    pub authority: ExternalActionAuthorityV1,
    /// Stable id for durable single-use consumption.
    pub authority_id: [u8; 32],
    /// Digest of the exact signed request approved by the responder.
    pub request_digest: [u8; 32],
    /// Xenia consent request identifier.
    pub request_id: u64,
    /// Signed requester device key.
    pub requester_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Signed responder device key.
    pub responder_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Trusted session fingerprint shared by request and response.
    pub session_fingerprint: [u8; 32],
    /// Session-level consent scope contained in the exact approved request.
    pub consent_scope: ConsentScope,
    /// Consent request expiry in Unix seconds.
    pub consent_valid_until: u64,
    /// Bound response issue time in Unix milliseconds.
    pub approved_at_ms: u64,
}

/// Semantic failures returned by exact external-authority verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExternalAuthorityError {
    /// Serialization failed while constructing canonical bytes.
    #[error("external authority canonical encoding failed")]
    Encoding,
    /// Signed request signature/key binding is invalid.
    #[error("invalid consent request signature or requester key")]
    InvalidRequestSignature,
    /// Bound response signature/key binding is invalid.
    #[error("invalid causal authority response signature or responder key")]
    InvalidResponseSignature,
    /// Request and response carry different request ids.
    #[error("causal authority response refers to a different request id")]
    RequestIdMismatch,
    /// Response does not approve the exact signed request bytes supplied.
    #[error("causal authority response request digest mismatch")]
    RequestDigestMismatch,
    /// Request is not bound to the expected live session fingerprint.
    #[error("consent request session fingerprint mismatch")]
    RequestFingerprintMismatch,
    /// Response is not bound to the expected live session fingerprint.
    #[error("causal authority response session fingerprint mismatch")]
    ResponseFingerprintMismatch,
    /// Responder explicitly denied the request.
    #[error("external action authority was denied")]
    Denied,
    /// Signed request reason exceeds the profile's authority limit.
    #[error("consent request reason is too long for causal authority")]
    RequestReasonTooLong,
    /// Signed response reason exceeds the profile's authority limit.
    #[error("causal authority response reason is too long")]
    ResponseReasonTooLong,
    /// Bound response issue time is zero/invalid.
    #[error("causal authority response issue time is invalid")]
    InvalidResponseIssueTime,
    /// Bound response issue time is implausibly in the future.
    #[error("causal authority response issue time is in the future")]
    ResponseFromFuture,
    /// Bound response was issued after the enclosing request expired.
    #[error("causal authority response was issued after consent expiry")]
    ResponseAfterRequestExpiry,
    /// Bound response was issued after the exact action authority expired.
    #[error("causal authority response was issued after action-authority expiry")]
    ResponseAfterAuthorityExpiry,
    /// No causal authority profile exists on the signed request.
    #[error("signed consent request has no causal authority binding")]
    MissingCausalBinding,
    /// Causal profile id/domain is unknown.
    #[error("unsupported causal authority profile")]
    UnsupportedProfile,
    /// Causal profile bytes are malformed/non-canonical.
    #[error("malformed causal authority binding")]
    MalformedBinding,
    /// Causal profile exceeds the profile size bound.
    #[error("causal authority binding is too large")]
    BindingTooLarge,
    /// Subject id is all zeroes.
    #[error("external authority subject id must be non-zero")]
    ZeroSubjectId,
    /// Target identifier is empty.
    #[error("external authority target is empty")]
    EmptyTarget,
    /// Target identifier exceeds the profile bound.
    #[error("external authority target is too long")]
    TargetTooLong,
    /// Capability identifier is empty.
    #[error("external authority capability is empty")]
    EmptyCapability,
    /// Capability identifier exceeds the profile bound.
    #[error("external authority capability is too long")]
    CapabilityTooLong,
    /// Scope identifier is empty.
    #[error("external authority scope is empty")]
    EmptyScope,
    /// Scope identifier exceeds the profile bound.
    #[error("external authority scope is too long")]
    ScopeTooLong,
    /// Action digest uses the reserved all-zero sentinel.
    #[error("external authority action digest must be non-zero")]
    ZeroActionDigest,
    /// Parameter digest uses the reserved all-zero sentinel.
    #[error("external authority parameters digest must be non-zero")]
    ZeroParametersDigest,
    /// Authority expiry is zero.
    #[error("external authority expiry is invalid")]
    InvalidExpiry,
    /// Signed request is expired at verification time.
    #[error("signed consent request has expired")]
    RequestExpired,
    /// Exact action authority is expired at verification time.
    #[error("external action authority has expired")]
    AuthorityExpired,
    /// Action authority claims to outlive the signed consent request.
    #[error("external authority outlives signed consent request")]
    AuthorityOutlivesRequest,
    /// A matching revocation has an invalid signer/signature/time.
    #[error("invalid matching consent revocation")]
    InvalidRevocation,
    /// A valid matching revocation terminates the authority.
    #[error("external action authority has been revoked")]
    Revoked,
}

/// Verify one exact external-action authorization.
///
/// This verifier intentionally does not accept a draft-03 `ConsentResponse`.
/// Exact authority requires [`CausalAuthorityResponse`], whose responder
/// signature commits to the complete signed request digest.
///
/// `expected_session_fingerprint` must come from a trusted live-session or
/// transcript-verification path. The caller must supply the complete relevant
/// revocation view from its canonical evidence source.
#[allow(clippy::too_many_arguments)]
pub fn verify_approved_external_action_authority(
    request: &ConsentRequest,
    response: &CausalAuthorityResponse,
    revocations: &[ConsentRevocation],
    expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
    expected_responder_pubkey: &[u8; PUBLIC_KEY_LEN],
    expected_session_fingerprint: &[u8; 32],
    now_ms: u64,
) -> Result<VerifiedExternalActionAuthority, ExternalAuthorityError> {
    if !request.verify(Some(expected_requester_pubkey)) {
        return Err(ExternalAuthorityError::InvalidRequestSignature);
    }
    if request.core.reason.as_bytes().len() > MAX_AUTHORITY_REQUEST_REASON_BYTES {
        return Err(ExternalAuthorityError::RequestReasonTooLong);
    }
    if &request.core.session_fingerprint != expected_session_fingerprint {
        return Err(ExternalAuthorityError::RequestFingerprintMismatch);
    }

    if !response.verify(Some(expected_responder_pubkey)) {
        return Err(ExternalAuthorityError::InvalidResponseSignature);
    }
    if request.core.request_id != response.core.request_id {
        return Err(ExternalAuthorityError::RequestIdMismatch);
    }
    if &response.core.session_fingerprint != expected_session_fingerprint {
        return Err(ExternalAuthorityError::ResponseFingerprintMismatch);
    }
    let request_digest = authority_request_digest(request)?;
    if response.core.request_digest != request_digest {
        return Err(ExternalAuthorityError::RequestDigestMismatch);
    }

    if response.core.issued_at_ms == 0 {
        return Err(ExternalAuthorityError::InvalidResponseIssueTime);
    }
    let future_limit = now_ms.saturating_add(AUTHORITY_CLOCK_SKEW_MS);
    if response.core.issued_at_ms > future_limit {
        return Err(ExternalAuthorityError::ResponseFromFuture);
    }

    let request_expiry_ms = request.core.valid_until.saturating_mul(1_000);
    if response.core.issued_at_ms >= request_expiry_ms {
        return Err(ExternalAuthorityError::ResponseAfterRequestExpiry);
    }
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
    if response.core.issued_at_ms >= authority.expires_at_ms {
        return Err(ExternalAuthorityError::ResponseAfterAuthorityExpiry);
    }
    if now_ms >= authority.expires_at_ms {
        return Err(ExternalAuthorityError::AuthorityExpired);
    }
    if !response.core.approved {
        return Err(ExternalAuthorityError::Denied);
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
        if issued_at_ms > future_limit {
            return Err(ExternalAuthorityError::InvalidRevocation);
        }
        return Err(ExternalAuthorityError::Revoked);
    }

    Ok(VerifiedExternalActionAuthority {
        authority,
        authority_id: authority_instance_id(response),
        request_digest,
        request_id: request.core.request_id,
        requester_pubkey: request.core.requester_pubkey,
        responder_pubkey: response.core.responder_pubkey,
        session_fingerprint: request.core.session_fingerprint,
        consent_scope: request.core.scope.clone(),
        consent_valid_until: request.core.valid_until,
        approved_at_ms: response.core.issued_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::{ConsentRequestCore, ConsentRevocationCore};

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
            target: b"host:workstation-17".to_vec(),
            capability: b"nixos.rebuild".to_vec(),
            action_digest: [0x44; 32],
            parameters_digest: [0x55; 32],
            max_scope: b"host:workstation-17".to_vec(),
            expires_at_ms,
            use_policy: AuthorityUsePolicy::SingleUse,
        }
    }

    fn request(binding: ExternalActionAuthorityV1) -> ConsentRequest {
        request_with_id(binding, 7)
    }

    fn request_with_id(binding: ExternalActionAuthorityV1, request_id: u64) -> ConsentRequest {
        let sk = requester();
        ConsentRequest::sign(
            ConsentRequestCore {
                request_id,
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

    fn response(request: &ConsentRequest, approved: bool) -> CausalAuthorityResponse {
        CausalAuthorityResponse::sign_for_request(
            request,
            approved,
            10_000,
            "operator decision",
            &responder(),
        )
        .unwrap()
    }

    fn verify(
        request: &ConsentRequest,
        response: &CausalAuthorityResponse,
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
    fn exact_bound_request_and_approval_verify() {
        let req = request(authority(15_000));
        let resp = response(&req, true);
        let verified = verify(&req, &resp, &[], 11_000).unwrap();
        assert_eq!(verified.authority.capability, b"nixos.rebuild".to_vec());
        assert_eq!(verified.request_digest, authority_request_digest(&req).unwrap());
        assert_eq!(verified.authority_id, authority_instance_id(&resp));
    }

    #[test]
    fn two_valid_same_id_requests_cannot_share_one_approval() {
        let req_a = request(authority(15_000));
        let mut alternate = authority(15_000);
        alternate.action_digest = [0x99; 32];
        let req_b = request(alternate);
        assert!(req_a.verify(Some(&requester().verifying_key().to_bytes())));
        assert!(req_b.verify(Some(&requester().verifying_key().to_bytes())));
        assert_eq!(req_a.core.request_id, req_b.core.request_id);
        assert_eq!(req_a.core.session_fingerprint, req_b.core.session_fingerprint);

        let approval_for_a = response(&req_a, true);
        assert_eq!(
            verify(&req_b, &approval_for_a, &[], 11_000),
            Err(ExternalAuthorityError::RequestDigestMismatch)
        );
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
        let resp = response(&request(authority(15_000)), true);
        assert_eq!(
            verify(&req, &resp, &[], 11_000),
            Err(ExternalAuthorityError::InvalidRequestSignature)
        );
    }

    #[test]
    fn response_for_other_request_id_is_rejected() {
        let req = request(authority(15_000));
        let other = request_with_id(authority(15_000), 8);
        let resp = response(&other, true);
        assert_eq!(
            verify(&req, &resp, &[], 11_000),
            Err(ExternalAuthorityError::RequestIdMismatch)
        );
    }

    #[test]
    fn denial_is_not_authority() {
        let req = request(authority(15_000));
        let resp = response(&req, false);
        assert_eq!(
            verify(&req, &resp, &[], 11_000),
            Err(ExternalAuthorityError::Denied)
        );
    }

    #[test]
    fn authority_cannot_outlive_request() {
        let req = request(authority(20_001));
        let resp = response(&req, true);
        assert_eq!(
            verify(&req, &resp, &[], 11_000),
            Err(ExternalAuthorityError::AuthorityOutlivesRequest)
        );
    }

    #[test]
    fn response_after_authority_expiry_is_rejected() {
        let req = request(authority(9_999));
        let resp = CausalAuthorityResponse::sign_for_request(
            &req,
            true,
            10_000,
            "late approval",
            &responder(),
        )
        .unwrap();
        assert_eq!(
            verify(&req, &resp, &[], 10_001),
            Err(ExternalAuthorityError::ResponseAfterAuthorityExpiry)
        );
    }

    #[test]
    fn zero_issue_time_is_rejected_at_construction() {
        let req = request(authority(15_000));
        assert_eq!(
            CausalAuthorityResponse::sign_for_request(
                &req,
                true,
                0,
                "invalid",
                &responder(),
            ),
            Err(ExternalAuthorityError::InvalidResponseIssueTime)
        );
    }

    #[test]
    fn future_response_is_rejected() {
        let req = request(authority(15_000));
        let resp = CausalAuthorityResponse::sign_for_request(
            &req,
            true,
            50_001,
            "future approval",
            &responder(),
        )
        .unwrap();
        assert_eq!(
            verify(&req, &resp, &[], 20_000),
            Err(ExternalAuthorityError::ResponseFromFuture)
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
        let resp = response(&req, true);
        assert_eq!(
            verify(&req, &resp, &[], 11_000),
            Err(ExternalAuthorityError::UnsupportedProfile)
        );
    }

    #[test]
    fn oversized_identifier_fails_closed() {
        let mut oversized = authority(15_000);
        oversized.target = vec![0x41; MAX_AUTHORITY_IDENTIFIER_BYTES + 1];
        assert_eq!(
            oversized.to_causal_predicate(),
            Err(ExternalAuthorityError::TargetTooLong)
        );
    }

    #[test]
    fn matching_valid_revocation_terminates_authority() {
        let req = request(authority(15_000));
        let resp = response(&req, true);
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
        let resp = response(&req, true);
        assert_eq!(
            verify_approved_external_action_authority(
                &req,
                &resp,
                &[],
                &requester().verifying_key().to_bytes(),
                &responder().verifying_key().to_bytes(),
                &[0xCC; 32],
                11_000,
            ),
            Err(ExternalAuthorityError::RequestFingerprintMismatch)
        );
    }

    #[test]
    fn bound_response_is_sealable() {
        let req = request(authority(15_000));
        let resp = response(&req, true);
        let bytes = resp.to_bin().unwrap();
        let decoded = CausalAuthorityResponse::from_bin(&bytes).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn bound_response_wire_roundtrip_and_type_check() {
        let req = request(authority(15_000));
        let resp = response(&req, true);
        let mut sender = Session::with_source_id([0x71; 8], 0x31);
        let mut receiver = Session::with_source_id([0x71; 8], 0x31);
        sender.install_key([0x42; 32]);
        receiver.install_key([0x42; 32]);

        let envelope = seal_causal_authority_response(&resp, &mut sender).unwrap();
        assert_eq!(
            crate::envelope_payload_type(&envelope),
            Some(crate::payload_types::PAYLOAD_TYPE_CAUSAL_AUTHORITY_RESPONSE)
        );
        let opened = open_causal_authority_response(&envelope, &mut receiver).unwrap();
        assert_eq!(opened, resp);
    }

    #[test]
    fn authority_open_rejects_wrong_payload_type_before_decode() {
        let req = request(authority(15_000));
        let resp = response(&req, true);
        let mut sender = Session::with_source_id([0x72; 8], 0x32);
        let mut receiver = Session::with_source_id([0x72; 8], 0x32);
        sender.install_key([0x43; 32]);
        receiver.install_key([0x43; 32]);

        let envelope = crate::seal(&resp, &mut sender, 0x30).unwrap();
        assert!(matches!(
            open_causal_authority_response(&envelope, &mut receiver),
            Err(WireError::OpenFailed)
        ));
    }

    #[test]
    fn approval_instance_id_changes_with_signed_decision() {
        let req = request(authority(15_000));
        let first = CausalAuthorityResponse::sign_for_request(
            &req,
            true,
            10_000,
            "first",
            &responder(),
        )
        .unwrap();
        let second = CausalAuthorityResponse::sign_for_request(
            &req,
            true,
            10_001,
            "second",
            &responder(),
        )
        .unwrap();
        assert_ne!(authority_instance_id(&first), authority_instance_id(&second));
    }
}
