#![cfg(feature = "causal-authority")]

use ed25519_dalek::SigningKey;
use xenia_wire::Session;
use xenia_wire::authority::{AuthorityUsePolicy, ExternalActionAuthorityV1};
use xenia_wire::authority_session::{
    AuthoritySessionError, sign_causal_authority_response_for_session,
    verify_approved_external_action_authority_for_session,
};
use xenia_wire::consent::{ConsentRequestCore, ConsentScope};

fn requester() -> SigningKey {
    SigningKey::from_bytes(&[0x61; 32])
}

fn responder() -> SigningKey {
    SigningKey::from_bytes(&[0x62; 32])
}

fn authority() -> ExternalActionAuthorityV1 {
    ExternalActionAuthorityV1 {
        subject_id: [0x63; 16],
        target: b"host:rekey-fixture".to_vec(),
        capability: b"system.transition".to_vec(),
        action_digest: [0x64; 32],
        parameters_digest: [0x65; 32],
        max_scope: b"host:rekey-fixture".to_vec(),
        expires_at_ms: 50_000,
        use_policy: AuthorityUsePolicy::SingleUse,
    }
}

fn unsigned_core(requester_key: &SigningKey) -> ConsentRequestCore {
    ConsentRequestCore {
        request_id: 41,
        requester_pubkey: requester_key.verifying_key().to_bytes(),
        session_fingerprint: [0; 32], // overwritten by Session helper
        valid_until: 60,
        scope: ConsentScope::Interactive,
        reason: "rekey-safe exact authority".into(),
        causal_binding: Some(authority().to_causal_predicate().unwrap()),
    }
}

#[test]
fn request_from_previous_key_epoch_can_be_approved_during_rekey_grace() {
    let requester = requester();
    let responder = responder();
    let mut session = Session::with_source_id([0x71; 8], 0x42);
    session.install_key([0x81; 32]);

    let request = session
        .sign_consent_request(unsigned_core(&requester), &requester)
        .unwrap();
    let old_fingerprint = request.core.session_fingerprint;

    // Rekey after request creation. The old key remains available to Xenia's
    // fingerprint verifier during the configured grace interval.
    session.install_key([0x82; 32]);
    assert_ne!(
        session.session_fingerprint(request.core.request_id).unwrap(),
        old_fingerprint
    );
    assert!(session.verify_consent_request(
        &request,
        Some(&requester.verifying_key().to_bytes())
    ));

    let response = sign_causal_authority_response_for_session(
        &session,
        &request,
        &requester.verifying_key().to_bytes(),
        true,
        10_000,
        "approved after rekey",
        &responder,
    )
    .unwrap();

    let verified = verify_approved_external_action_authority_for_session(
        &session,
        &request,
        &response,
        &[],
        &requester.verifying_key().to_bytes(),
        &responder.verifying_key().to_bytes(),
        11_000,
    )
    .unwrap();

    assert_eq!(verified.session_fingerprint, old_fingerprint);
    assert_eq!(verified.authority.action_digest, [0x64; 32]);
}

#[test]
fn unrelated_session_cannot_sign_or_verify_the_request() {
    let requester = requester();
    let responder = responder();

    let mut origin = Session::with_source_id([0x72; 8], 0x43);
    origin.install_key([0x83; 32]);
    let request = origin
        .sign_consent_request(unsigned_core(&requester), &requester)
        .unwrap();

    let mut unrelated = Session::with_source_id([0x73; 8], 0x44);
    unrelated.install_key([0x84; 32]);

    assert!(matches!(
        sign_causal_authority_response_for_session(
            &unrelated,
            &request,
            &requester.verifying_key().to_bytes(),
            true,
            10_000,
            "must fail",
            &responder,
        ),
        Err(AuthoritySessionError::RequestNotBoundToSession)
    ));

    let response = sign_causal_authority_response_for_session(
        &origin,
        &request,
        &requester.verifying_key().to_bytes(),
        true,
        10_000,
        "origin approves",
        &responder,
    )
    .unwrap();

    assert!(matches!(
        verify_approved_external_action_authority_for_session(
            &unrelated,
            &request,
            &response,
            &[],
            &requester.verifying_key().to_bytes(),
            &responder.verifying_key().to_bytes(),
            11_000,
        ),
        Err(AuthoritySessionError::RequestNotBoundToSession)
    ));
}
