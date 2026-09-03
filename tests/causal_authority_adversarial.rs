#![cfg(feature = "causal-authority")]

use ed25519_dalek::SigningKey;
use xenia_wire::authority::{
    AuthorityUsePolicy, CausalAuthorityResponse, EXTERNAL_ACTION_AUTHORITY_PROFILE,
    ExternalActionAuthorityV1, ExternalAuthorityError, MAX_AUTHORITY_IDENTIFIER_BYTES,
    MAX_CAUSAL_AUTHORITY_OPAQUE_BYTES, verify_approved_external_action_authority,
};
use xenia_wire::consent::{CausalPredicate, ConsentRequest, ConsentRequestCore, ConsentScope};

const FP: [u8; 32] = [0xA7; 32];

fn requester() -> SigningKey {
    SigningKey::from_bytes(&[0x31; 32])
}

fn responder() -> SigningKey {
    SigningKey::from_bytes(&[0x32; 32])
}

fn other() -> SigningKey {
    SigningKey::from_bytes(&[0x33; 32])
}

fn authority() -> ExternalActionAuthorityV1 {
    ExternalActionAuthorityV1 {
        subject_id: [0x41; 16],
        target: b"target:canonical".to_vec(),
        capability: b"capability:transition".to_vec(),
        action_digest: [0x42; 32],
        parameters_digest: [0x43; 32],
        max_scope: b"scope:canonical".to_vec(),
        expires_at_ms: 50_000,
        use_policy: AuthorityUsePolicy::SingleUse,
    }
}

fn request_with_predicate(predicate: CausalPredicate) -> ConsentRequest {
    let key = requester();
    ConsentRequest::sign(
        ConsentRequestCore {
            request_id: 19,
            requester_pubkey: key.verifying_key().to_bytes(),
            session_fingerprint: FP,
            valid_until: 60,
            scope: ConsentScope::Interactive,
            reason: "adversarial fixture".into(),
            causal_binding: Some(predicate),
        },
        &key,
    )
}

fn request() -> ConsentRequest {
    request_with_predicate(authority().to_causal_predicate().unwrap())
}

fn response(request: &ConsentRequest) -> CausalAuthorityResponse {
    CausalAuthorityResponse::sign_for_request(request, true, 10_000, "approved", &responder())
        .unwrap()
}

fn verify(
    request: &ConsentRequest,
    response: &CausalAuthorityResponse,
    expected_requester: &[u8; 32],
    expected_responder: &[u8; 32],
) -> Result<xenia_wire::authority::VerifiedExternalActionAuthority, ExternalAuthorityError> {
    verify_approved_external_action_authority(
        request,
        response,
        &[],
        expected_requester,
        expected_responder,
        &FP,
        11_000,
    )
}

#[test]
fn requester_key_substitution_is_rejected() {
    let req = request();
    let resp = response(&req);
    assert_eq!(
        verify(
            &req,
            &resp,
            &other().verifying_key().to_bytes(),
            &responder().verifying_key().to_bytes(),
        ),
        Err(ExternalAuthorityError::InvalidRequestSignature)
    );
}

#[test]
fn responder_key_substitution_is_rejected() {
    let req = request();
    let resp = response(&req);
    assert_eq!(
        verify(
            &req,
            &resp,
            &requester().verifying_key().to_bytes(),
            &other().verifying_key().to_bytes(),
        ),
        Err(ExternalAuthorityError::InvalidResponseSignature)
    );
}

#[test]
fn response_signature_substitution_is_rejected() {
    let req = request();
    let mut resp = response(&req);
    resp.signature[0] ^= 0x80;
    assert_eq!(
        verify(
            &req,
            &resp,
            &requester().verifying_key().to_bytes(),
            &responder().verifying_key().to_bytes(),
        ),
        Err(ExternalAuthorityError::InvalidResponseSignature)
    );
}

#[test]
fn truncated_canonical_binding_is_rejected() {
    let mut predicate = authority().to_causal_predicate().unwrap();
    predicate.opaque.pop();
    let req = request_with_predicate(predicate);
    let resp = response(&req);
    assert_eq!(
        verify(
            &req,
            &resp,
            &requester().verifying_key().to_bytes(),
            &responder().verifying_key().to_bytes(),
        ),
        Err(ExternalAuthorityError::MalformedBinding)
    );
}

#[test]
fn trailing_noncanonical_binding_bytes_are_rejected() {
    let mut predicate = authority().to_causal_predicate().unwrap();
    predicate.opaque.push(0x00);
    let req = request_with_predicate(predicate);
    let resp = response(&req);
    assert_eq!(
        verify(
            &req,
            &resp,
            &requester().verifying_key().to_bytes(),
            &responder().verifying_key().to_bytes(),
        ),
        Err(ExternalAuthorityError::MalformedBinding)
    );
}

#[test]
fn exact_identifier_boundary_is_accepted() {
    let mut bound = authority();
    bound.target = vec![0x54; MAX_AUTHORITY_IDENTIFIER_BYTES];
    bound.capability = vec![0x43; MAX_AUTHORITY_IDENTIFIER_BYTES];
    bound.max_scope = vec![0x53; MAX_AUTHORITY_IDENTIFIER_BYTES];
    let predicate = bound.to_causal_predicate().unwrap();
    let req = request_with_predicate(predicate);
    let resp = response(&req);
    let verified = verify(
        &req,
        &resp,
        &requester().verifying_key().to_bytes(),
        &responder().verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(
        verified.authority.target.len(),
        MAX_AUTHORITY_IDENTIFIER_BYTES
    );
}

#[test]
fn oversized_opaque_binding_fails_before_decode() {
    let predicate = CausalPredicate {
        description: EXTERNAL_ACTION_AUTHORITY_PROFILE.into(),
        opaque: vec![0xAA; MAX_CAUSAL_AUTHORITY_OPAQUE_BYTES + 1],
    };
    let req = request_with_predicate(predicate);
    let resp = response(&req);
    assert_eq!(
        verify(
            &req,
            &resp,
            &requester().verifying_key().to_bytes(),
            &responder().verifying_key().to_bytes(),
        ),
        Err(ExternalAuthorityError::BindingTooLarge)
    );
}
