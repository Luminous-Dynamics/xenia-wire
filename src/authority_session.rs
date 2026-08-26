// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Rekey-aware safe-path helpers for exact external authority.
//!
//! The low-level authority verifier accepts an expected session fingerprint so
//! offline/transcript verifiers can supply independently authenticated context.
//! Live Xenia applications should normally use this module instead: it asks the
//! [`crate::Session`] to authenticate the request against the current session key
//! or any still-valid previous key in the rekey grace window, then delegates to
//! the exact request-bound authority verifier.
//!
//! This prevents an application from accidentally treating the fingerprint
//! embedded in an untrusted request as trusted context merely because request
//! and response agree with each other.

#![cfg(feature = "causal-authority")]

use ed25519_dalek::SigningKey;

use crate::Session;
use crate::authority::{
    CausalAuthorityResponse, ExternalAuthorityError, VerifiedExternalActionAuthority,
    verify_approved_external_action_authority,
};
use crate::consent::{ConsentRequest, ConsentRevocation, PUBLIC_KEY_LEN};

/// Failures specific to binding exact authority to a live Xenia session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthoritySessionError {
    /// The signed request is not authentic for the expected requester in this
    /// session's current or still-valid previous key epoch.
    #[error("causal authority request is not authenticated for this Xenia session")]
    RequestNotBoundToSession,
    /// Exact-authority semantic or cryptographic verification failed.
    #[error(transparent)]
    Authority(#[from] ExternalAuthorityError),
}

/// Sign a bound authority response only after authenticating the request against
/// this live Xenia session.
///
/// `Session::verify_consent_request` probes both the current session key and all
/// still-valid previous keys in the rekey grace window. A request signed moments
/// before a rekey can therefore still be approved safely after the rekey, while a
/// request from an unrelated session fails closed.
#[allow(clippy::too_many_arguments)]
pub fn sign_causal_authority_response_for_session(
    session: &Session,
    request: &ConsentRequest,
    expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
    approved: bool,
    issued_at_ms: u64,
    reason: impl Into<String>,
    responder_signing_key: &SigningKey,
) -> Result<CausalAuthorityResponse, AuthoritySessionError> {
    if !session.verify_consent_request(request, Some(expected_requester_pubkey)) {
        return Err(AuthoritySessionError::RequestNotBoundToSession);
    }

    Ok(CausalAuthorityResponse::sign_for_request(
        request,
        approved,
        issued_at_ms,
        reason,
        responder_signing_key,
    )?)
}

/// Verify exact external authority against a live Xenia session.
///
/// This is the recommended online verification path. The session first proves
/// that the request fingerprint belongs to its current or rekey-grace key
/// material. Only after that proof succeeds is the request's embedded
/// fingerprint promoted to the `expected_session_fingerprint` supplied to the
/// lower-level exact verifier.
///
/// Offline evidence systems that independently authenticate a transcript may use
/// `authority::verify_approved_external_action_authority` directly instead.
#[allow(clippy::too_many_arguments)]
pub fn verify_approved_external_action_authority_for_session(
    session: &Session,
    request: &ConsentRequest,
    response: &CausalAuthorityResponse,
    revocations: &[ConsentRevocation],
    expected_requester_pubkey: &[u8; PUBLIC_KEY_LEN],
    expected_responder_pubkey: &[u8; PUBLIC_KEY_LEN],
    now_ms: u64,
) -> Result<VerifiedExternalActionAuthority, AuthoritySessionError> {
    if !session.verify_consent_request(request, Some(expected_requester_pubkey)) {
        return Err(AuthoritySessionError::RequestNotBoundToSession);
    }

    Ok(verify_approved_external_action_authority(
        request,
        response,
        revocations,
        expected_requester_pubkey,
        expected_responder_pubkey,
        &request.core.session_fingerprint,
        now_ms,
    )?)
}
