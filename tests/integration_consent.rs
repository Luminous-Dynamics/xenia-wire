// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! End-to-end consent ceremony integration tests.
//!
//! Exercises the full flow: two peers exchange `ConsentRequest` +
//! `ConsentResponse` + optional `ConsentRevocation` over a sealed
//! channel, each side drives its own `ConsentState` machine, and
//! `FRAME` payloads flow iff the ceremony completed successfully.

#![cfg(all(feature = "consent", feature = "reference-frame"))]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use xenia_wire::consent::{
    ConsentEvent, ConsentRequest, ConsentRequestCore, ConsentResponse, ConsentResponseCore,
    ConsentRevocation, ConsentRevocationCore, ConsentScope, ConsentState,
};
use xenia_wire::{
    open_consent_request, open_consent_response, open_frame, seal_consent_request,
    seal_consent_response, seal_consent_revocation, seal_frame, Frame, Session, WireError,
};

fn paired_sessions(key: [u8; 32]) -> (Session, Session) {
    let mut sender = Session::with_source_id([0x77; 8], 0xAB);
    let mut receiver = Session::with_source_id([0x77; 8], 0xAB);
    sender.install_key(key);
    receiver.install_key(key);
    (sender, receiver)
}

fn new_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn make_request(sk: &SigningKey) -> ConsentRequest {
    ConsentRequest::sign(
        ConsentRequestCore {
            request_id: 1,
            requester_pubkey: sk.verifying_key().to_bytes(),
            valid_until: 1_700_000_000,
            scope: ConsentScope::ScreenAndInput,
            reason: "ticket #1234".into(),
            causal_binding: None,
        },
        sk,
    )
}

fn make_response(
    sk: &SigningKey,
    request_id: u64,
    approved: bool,
    reason: &str,
) -> ConsentResponse {
    ConsentResponse::sign(
        ConsentResponseCore {
            request_id,
            responder_pubkey: sk.verifying_key().to_bytes(),
            approved,
            reason: reason.to_string(),
        },
        sk,
    )
}

fn make_revocation(sk: &SigningKey, request_id: u64) -> ConsentRevocation {
    ConsentRevocation::sign(
        ConsentRevocationCore {
            request_id,
            revoker_pubkey: sk.verifying_key().to_bytes(),
            issued_at: 1_700_000_500,
            reason: "session complete".into(),
        },
        sk,
    )
}

fn sample_frame() -> Frame {
    Frame {
        frame_id: 1,
        timestamp_ms: 1_700_000_000_100,
        payload: b"in-session".to_vec(),
    }
}

#[test]
fn full_consent_ceremony_allows_frame_flow() {
    let (mut tech, mut user) = paired_sessions([0x11; 32]);
    let tech_sk = new_signing_key();
    let user_sk = new_signing_key();

    // 1. Tech seals a ConsentRequest, then records that it sent one.
    let request = make_request(&tech_sk);
    let sealed_req = seal_consent_request(&request, &mut tech).unwrap();
    tech.observe_consent(ConsentEvent::Request);
    assert_eq!(tech.consent_state(), ConsentState::Requested);

    // 2. User opens the request, verifies the signature, THEN drives
    //    its state machine. Observe-after-open is the natural order on
    //    the receive side.
    let received_req: ConsentRequest = open_consent_request(&sealed_req, &mut user).unwrap();
    assert!(received_req.verify(None));
    user.observe_consent(ConsentEvent::Request);
    assert_eq!(user.consent_state(), ConsentState::Requested);

    // 3. User seals an approving response, records it.
    let response = make_response(&user_sk, received_req.core.request_id, true, "");
    let sealed_resp = seal_consent_response(&response, &mut user).unwrap();
    user.observe_consent(ConsentEvent::ResponseApproved);
    assert_eq!(user.consent_state(), ConsentState::Approved);

    // 4. Tech opens the response, verifies, THEN observes.
    let received_resp: ConsentResponse = open_consent_response(&sealed_resp, &mut tech).unwrap();
    assert!(received_resp.verify(None));
    assert!(received_resp.core.approved);
    tech.observe_consent(ConsentEvent::ResponseApproved);
    assert_eq!(tech.consent_state(), ConsentState::Approved);

    // 5. Application FRAME now flows.
    let frame = sample_frame();
    let sealed_frame = seal_frame(&frame, &mut tech).unwrap();
    let opened_frame = open_frame(&sealed_frame, &mut user).unwrap();
    assert_eq!(opened_frame.payload, frame.payload);
}

#[test]
fn requested_state_blocks_frame_until_response() {
    let (mut tech, _user) = paired_sessions([0x22; 32]);
    tech.observe_consent(ConsentEvent::Request);
    assert_eq!(tech.consent_state(), ConsentState::Requested);

    // In Requested state, FRAME seal is blocked.
    let frame = sample_frame();
    let err = seal_frame(&frame, &mut tech);
    assert!(
        matches!(err, Err(WireError::NoConsent)),
        "Requested state should block FRAME, got {err:?}"
    );
}

#[test]
fn denied_response_blocks_frame() {
    let (mut tech, mut user) = paired_sessions([0x33; 32]);
    let tech_sk = new_signing_key();
    let user_sk = new_signing_key();

    let req = make_request(&tech_sk);
    seal_consent_request(&req, &mut tech).unwrap();
    tech.observe_consent(ConsentEvent::Request);

    // User denies.
    let resp = make_response(&user_sk, 1, false, "nope");
    let sealed = seal_consent_response(&resp, &mut user).unwrap();
    let received: ConsentResponse = open_consent_response(&sealed, &mut tech).unwrap();
    assert!(!received.core.approved);
    tech.observe_consent(ConsentEvent::ResponseDenied);
    assert_eq!(tech.consent_state(), ConsentState::Denied);

    // FRAME refused after denial.
    assert!(matches!(
        seal_frame(&sample_frame(), &mut tech),
        Err(WireError::NoConsent)
    ));
}

#[test]
fn revocation_terminates_session_and_blocks_subsequent_frames() {
    let (mut tech, mut user) = paired_sessions([0x44; 32]);
    let tech_sk = new_signing_key();
    let user_sk = new_signing_key();

    // Bring both peers to Approved.
    let req = make_request(&tech_sk);
    seal_consent_request(&req, &mut tech).unwrap();
    tech.observe_consent(ConsentEvent::Request);
    user.observe_consent(ConsentEvent::Request);

    let resp = make_response(&user_sk, 1, true, "");
    seal_consent_response(&resp, &mut user).unwrap();
    tech.observe_consent(ConsentEvent::ResponseApproved);
    user.observe_consent(ConsentEvent::ResponseApproved);

    // One frame flows successfully.
    let sealed = seal_frame(&sample_frame(), &mut tech).unwrap();
    let _: Frame = open_frame(&sealed, &mut user).unwrap();

    // User revokes via the dedicated wrapper.
    let rev = make_revocation(&user_sk, 1);
    let sealed_rev = seal_consent_revocation(&rev, &mut user).unwrap();
    user.observe_consent(ConsentEvent::Revocation);
    assert_eq!(user.consent_state(), ConsentState::Revoked);

    let received_rev: ConsentRevocation =
        xenia_wire::open_consent_revocation(&sealed_rev, &mut tech).unwrap();
    assert!(received_rev.verify(None));
    tech.observe_consent(ConsentEvent::Revocation);
    assert_eq!(tech.consent_state(), ConsentState::Revoked);

    // FRAME refused on both sides after revocation.
    assert!(matches!(
        seal_frame(&sample_frame(), &mut tech),
        Err(WireError::ConsentRevoked)
    ));
    assert!(matches!(
        seal_frame(&sample_frame(), &mut user),
        Err(WireError::ConsentRevoked)
    ));
}

#[test]
fn unsolicited_events_are_no_ops() {
    // ResponseApproved without a preceding Request does nothing.
    let mut s = Session::new();
    assert_eq!(s.consent_state(), ConsentState::Pending);
    s.observe_consent(ConsentEvent::ResponseApproved);
    assert_eq!(s.consent_state(), ConsentState::Pending);
    // FRAME still allowed (we never started a ceremony).
    s.install_key([0x55; 32]);
    assert!(seal_frame(&sample_frame(), &mut s).is_ok());
}

#[test]
fn revocation_only_after_approved() {
    // Revocation from Pending is a no-op — the ceremony never approved.
    let mut s = Session::new();
    s.observe_consent(ConsentEvent::Revocation);
    assert_eq!(s.consent_state(), ConsentState::Pending);
}

#[test]
fn tampered_consent_message_fails_verification() {
    let tech_sk = new_signing_key();
    let mut req = make_request(&tech_sk);
    // Tamper with the request body after signing.
    req.core.reason = "sneaky".into();
    assert!(!req.verify(None));
}
