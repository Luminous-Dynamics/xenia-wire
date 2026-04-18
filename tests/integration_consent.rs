// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! End-to-end consent ceremony integration tests (SPEC draft-03).
//!
//! Exercises the full flow: two peers exchange `ConsentRequest` +
//! `ConsentResponse` + optional `ConsentRevocation` over a sealed
//! channel, each side drives its own `ConsentState` machine, and
//! `FRAME` payloads flow iff the ceremony completed successfully.
//!
//! draft-03 changes surfaced here:
//! - Every signed consent body carries a mandatory
//!   `session_fingerprint` derived via HKDF-SHA-256. We use the
//!   `Session::sign_consent_*` and `verify_consent_*` helpers to
//!   drive it automatically.
//! - `ConsentEvent` variants carry a `request_id`; `observe_consent`
//!   returns `Result<ConsentState, ConsentViolation>`.

#![cfg(all(feature = "consent", feature = "reference-frame"))]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use xenia_wire::consent::{
    ConsentEvent, ConsentRequest, ConsentRequestCore, ConsentResponse, ConsentResponseCore,
    ConsentRevocation, ConsentRevocationCore, ConsentScope, ConsentState, ConsentViolation,
};
use xenia_wire::{
    open_consent_request, open_consent_response, open_frame, seal_consent_request,
    seal_consent_response, seal_consent_revocation, seal_frame, Frame, Session, WireError,
};

const REQUEST_ID: u64 = 1;

fn paired_sessions(key: [u8; 32]) -> (Session, Session) {
    // Opt into ceremony mode on both sides.
    let mut sender = Session::builder()
        .with_source_id([0x77; 8], 0xAB)
        .require_consent(true)
        .build();
    let mut receiver = Session::builder()
        .with_source_id([0x77; 8], 0xAB)
        .require_consent(true)
        .build();
    sender.install_key(key);
    receiver.install_key(key);
    (sender, receiver)
}

fn new_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn make_request(session: &Session, sk: &SigningKey, request_id: u64) -> ConsentRequest {
    session
        .sign_consent_request(
            ConsentRequestCore {
                request_id,
                requester_pubkey: sk.verifying_key().to_bytes(),
                session_fingerprint: [0; 32],
                valid_until: 1_700_000_000,
                scope: ConsentScope::ScreenAndInput,
                reason: "ticket #1234".into(),
                causal_binding: None,
            },
            sk,
        )
        .expect("sign consent request")
}

fn make_response(
    session: &Session,
    sk: &SigningKey,
    request_id: u64,
    approved: bool,
    reason: &str,
) -> ConsentResponse {
    session
        .sign_consent_response(
            ConsentResponseCore {
                request_id,
                responder_pubkey: sk.verifying_key().to_bytes(),
                session_fingerprint: [0; 32],
                approved,
                reason: reason.to_string(),
            },
            sk,
        )
        .expect("sign consent response")
}

fn make_revocation(session: &Session, sk: &SigningKey, request_id: u64) -> ConsentRevocation {
    session
        .sign_consent_revocation(
            ConsentRevocationCore {
                request_id,
                revoker_pubkey: sk.verifying_key().to_bytes(),
                session_fingerprint: [0; 32],
                issued_at: 1_700_000_500,
                reason: "session complete".into(),
            },
            sk,
        )
        .expect("sign consent revocation")
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
    let request = make_request(&tech, &tech_sk, REQUEST_ID);
    let sealed_req = seal_consent_request(&request, &mut tech).unwrap();
    tech.observe_consent(ConsentEvent::Request {
        request_id: REQUEST_ID,
    })
    .expect("tech observes its own request");
    assert_eq!(tech.consent_state(), ConsentState::Requested);

    // 2. User opens the request, verifies with session-bound check, THEN
    //    drives its state machine.
    let received_req: ConsentRequest = open_consent_request(&sealed_req, &mut user).unwrap();
    assert!(
        user.verify_consent_request(&received_req, None),
        "session-bound verify must succeed on the counterpart"
    );
    user.observe_consent(ConsentEvent::Request {
        request_id: received_req.core.request_id,
    })
    .expect("user observes request");
    assert_eq!(user.consent_state(), ConsentState::Requested);

    // 3. User seals an approving response.
    let response = make_response(&user, &user_sk, received_req.core.request_id, true, "");
    let sealed_resp = seal_consent_response(&response, &mut user).unwrap();
    user.observe_consent(ConsentEvent::ResponseApproved {
        request_id: received_req.core.request_id,
    })
    .expect("user observes its own response");
    assert_eq!(user.consent_state(), ConsentState::Approved);

    // 4. Tech opens the response, session-bound verifies, THEN observes.
    let received_resp: ConsentResponse = open_consent_response(&sealed_resp, &mut tech).unwrap();
    assert!(tech.verify_consent_response(&received_resp, None));
    assert!(received_resp.core.approved);
    tech.observe_consent(ConsentEvent::ResponseApproved {
        request_id: received_resp.core.request_id,
    })
    .expect("tech observes response");
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
    tech.observe_consent(ConsentEvent::Request {
        request_id: REQUEST_ID,
    })
    .expect("observe request");
    assert_eq!(tech.consent_state(), ConsentState::Requested);

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

    let req = make_request(&tech, &tech_sk, REQUEST_ID);
    seal_consent_request(&req, &mut tech).unwrap();
    tech.observe_consent(ConsentEvent::Request {
        request_id: REQUEST_ID,
    })
    .unwrap();

    // User denies.
    let resp = make_response(&user, &user_sk, REQUEST_ID, false, "nope");
    let sealed = seal_consent_response(&resp, &mut user).unwrap();
    let received: ConsentResponse = open_consent_response(&sealed, &mut tech).unwrap();
    assert!(!received.core.approved);
    tech.observe_consent(ConsentEvent::ResponseDenied {
        request_id: REQUEST_ID,
    })
    .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Denied);

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
    let req = make_request(&tech, &tech_sk, REQUEST_ID);
    seal_consent_request(&req, &mut tech).unwrap();
    tech.observe_consent(ConsentEvent::Request {
        request_id: REQUEST_ID,
    })
    .unwrap();
    user.observe_consent(ConsentEvent::Request {
        request_id: REQUEST_ID,
    })
    .unwrap();

    let resp = make_response(&user, &user_sk, REQUEST_ID, true, "");
    seal_consent_response(&resp, &mut user).unwrap();
    tech.observe_consent(ConsentEvent::ResponseApproved {
        request_id: REQUEST_ID,
    })
    .unwrap();
    user.observe_consent(ConsentEvent::ResponseApproved {
        request_id: REQUEST_ID,
    })
    .unwrap();

    // One frame flows successfully.
    let sealed = seal_frame(&sample_frame(), &mut tech).unwrap();
    let _: Frame = open_frame(&sealed, &mut user).unwrap();

    // User revokes via the dedicated wrapper.
    let rev = make_revocation(&user, &user_sk, REQUEST_ID);
    let sealed_rev = seal_consent_revocation(&rev, &mut user).unwrap();
    user.observe_consent(ConsentEvent::Revocation {
        request_id: REQUEST_ID,
    })
    .unwrap();
    assert_eq!(user.consent_state(), ConsentState::Revoked);

    let received_rev: ConsentRevocation =
        xenia_wire::open_consent_revocation(&sealed_rev, &mut tech).unwrap();
    assert!(tech.verify_consent_revocation(&received_rev, None));
    tech.observe_consent(ConsentEvent::Revocation {
        request_id: REQUEST_ID,
    })
    .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Revoked);

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
fn unsolicited_events_in_legacy_bypass_are_no_ops() {
    let mut s = Session::new();
    assert_eq!(s.consent_state(), ConsentState::LegacyBypass);
    let _ = s
        .observe_consent(ConsentEvent::ResponseApproved { request_id: 1 })
        .expect("legacy bypass no-op");
    assert_eq!(s.consent_state(), ConsentState::LegacyBypass);
    s.install_key([0x55; 32]);
    assert!(seal_frame(&sample_frame(), &mut s).is_ok());
}

#[test]
fn legacy_bypass_is_sticky_on_request() {
    // Session::new defaults to LegacyBypass; a Request event does NOT
    // auto-promote (avoids state-hijacking by unsolicited packets).
    let mut s = Session::new();
    s.install_key([0xAA; 32]);
    let _ = s.observe_consent(ConsentEvent::Request { request_id: 99 });
    assert_eq!(s.consent_state(), ConsentState::LegacyBypass);
}

#[test]
fn revocation_before_approval_is_protocol_violation() {
    // SPEC draft-03 §12.6: Revocation observed from AwaitingRequest
    // or Requested is a hard error. The state is NOT mutated.
    let (mut tech, _user) = paired_sessions([0x66; 32]);
    let before = tech.consent_state();
    let err = tech
        .observe_consent(ConsentEvent::Revocation { request_id: 5 })
        .expect_err("revocation from AwaitingRequest must error");
    assert!(matches!(
        err,
        ConsentViolation::RevocationBeforeApproval { request_id: 5 }
    ));
    assert_eq!(tech.consent_state(), before);

    // Same rule from Requested.
    tech.observe_consent(ConsentEvent::Request { request_id: 6 })
        .unwrap();
    let err = tech
        .observe_consent(ConsentEvent::Revocation { request_id: 6 })
        .expect_err("revocation from Requested must error");
    assert!(matches!(
        err,
        ConsentViolation::RevocationBeforeApproval { request_id: 6 }
    ));
    assert_eq!(tech.consent_state(), ConsentState::Requested);
}

#[test]
fn contradictory_response_after_approved_is_protocol_violation() {
    // Approved + ResponseDenied for the same request_id → hard error.
    // The correct way to change your mind is ConsentRevocation.
    let (mut tech, _) = paired_sessions([0x77; 32]);
    tech.observe_consent(ConsentEvent::Request { request_id: 3 })
        .unwrap();
    tech.observe_consent(ConsentEvent::ResponseApproved { request_id: 3 })
        .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Approved);

    let err = tech
        .observe_consent(ConsentEvent::ResponseDenied { request_id: 3 })
        .expect_err("contradictory response must error");
    assert!(matches!(
        err,
        ConsentViolation::ContradictoryResponse {
            request_id: 3,
            prior_approved: true,
            new_approved: false
        }
    ));
    assert_eq!(tech.consent_state(), ConsentState::Approved);
}

#[test]
fn contradictory_response_after_denied_is_protocol_violation() {
    let (mut tech, _) = paired_sessions([0x88; 32]);
    tech.observe_consent(ConsentEvent::Request { request_id: 4 })
        .unwrap();
    tech.observe_consent(ConsentEvent::ResponseDenied { request_id: 4 })
        .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Denied);

    let err = tech
        .observe_consent(ConsentEvent::ResponseApproved { request_id: 4 })
        .expect_err("contradictory response must error");
    assert!(matches!(
        err,
        ConsentViolation::ContradictoryResponse {
            request_id: 4,
            prior_approved: false,
            new_approved: true
        }
    ));
    assert_eq!(tech.consent_state(), ConsentState::Denied);
}

#[test]
fn response_for_unknown_request_id_is_protocol_violation() {
    let (mut tech, _) = paired_sessions([0x99; 32]);
    // AwaitingRequest state: any Response is a stale orphan.
    let err = tech
        .observe_consent(ConsentEvent::ResponseApproved { request_id: 77 })
        .expect_err("stale response from AwaitingRequest must error");
    assert!(matches!(
        err,
        ConsentViolation::StaleResponseForUnknownRequest { request_id: 77 }
    ));
}

#[test]
fn higher_request_id_after_terminal_starts_fresh_ceremony() {
    // Denied + Request{higher id} → Requested.
    let (mut tech, _) = paired_sessions([0xAB; 32]);
    tech.observe_consent(ConsentEvent::Request { request_id: 10 })
        .unwrap();
    tech.observe_consent(ConsentEvent::ResponseDenied { request_id: 10 })
        .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Denied);

    tech.observe_consent(ConsentEvent::Request { request_id: 11 })
        .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Requested);

    // Now a Response on the NEW id closes the cycle.
    tech.observe_consent(ConsentEvent::ResponseApproved { request_id: 11 })
        .unwrap();
    assert_eq!(tech.consent_state(), ConsentState::Approved);
}

#[test]
fn verify_probes_prev_key_during_rekey_grace() {
    // A consent message signed under the OLD key must still verify
    // on the receiver during the rekey grace window, even though the
    // receiver has already installed the new key. The fingerprint on
    // the message was derived from the old key; the receiver probes
    // both epochs and matches against prev_session_key.

    let original_key = [0x42; 32];
    let mut sender = Session::builder()
        .with_source_id([0x88; 8], 0x01)
        .require_consent(true)
        .build();
    let mut receiver = Session::builder()
        .with_source_id([0x88; 8], 0x01)
        .require_consent(true)
        .build();
    sender.install_key(original_key);
    receiver.install_key(original_key);

    // Sender signs a ConsentRequest under the original key.
    let tech_sk = new_signing_key();
    let request = make_request(&sender, &tech_sk, REQUEST_ID);
    // Sanity: sender's own verify passes.
    assert!(sender.verify_consent_request(&request, None));

    // Receiver rekeys BEFORE observing the request (in-flight seal).
    // Now receiver's current_key is different from the key that
    // derived the fingerprint in `request`.
    receiver.install_key([0x99; 32]);

    // Without the prev-key probe, this would fail. With it, verify
    // still succeeds because prev_session_key still has the original.
    assert!(
        receiver.verify_consent_request(&request, None),
        "in-flight consent signed under prev key must verify during grace"
    );

    // After tick() elapses the grace window, prev key is dropped and
    // the same message must no longer verify.
    let mut receiver2 = Session::builder()
        .with_source_id([0x88; 8], 0x01)
        .require_consent(true)
        .with_rekey_grace(std::time::Duration::from_millis(1))
        .build();
    receiver2.install_key(original_key);
    receiver2.install_key([0x99; 32]);
    std::thread::sleep(std::time::Duration::from_millis(5));
    receiver2.tick();
    assert!(
        !receiver2.verify_consent_request(&request, None),
        "after grace expires, prev-key fingerprint MUST no longer verify"
    );
}

#[test]
fn session_fingerprint_mismatch_fails_verify() {
    // A ConsentRequest signed under one session's fingerprint must NOT
    // verify against a different session's fingerprint, even with the
    // same AEAD key — the fingerprint binds request_id + source_id +
    // epoch, all of which distinguish sessions.
    let mut session_a = Session::builder()
        .with_source_id([0x00; 8], 0x01)
        .require_consent(true)
        .build();
    session_a.install_key([0xCC; 32]);

    let mut session_b = Session::builder()
        .with_source_id([0xFF; 8], 0x02) // different source_id/epoch
        .require_consent(true)
        .build();
    session_b.install_key([0xCC; 32]);

    let sk = new_signing_key();
    let request = make_request(&session_a, &sk, REQUEST_ID);

    // session_a signed it → session_a verifies.
    assert!(session_a.verify_consent_request(&request, None));
    // session_b has a different fingerprint → must reject.
    assert!(
        !session_b.verify_consent_request(&request, None),
        "cross-session replay must fail fingerprint check"
    );
}

#[test]
fn tampered_consent_message_fails_verification() {
    let (tech, _) = paired_sessions([0xBB; 32]);
    let tech_sk = new_signing_key();
    let mut req = make_request(&tech, &tech_sk, REQUEST_ID);
    req.core.reason = "sneaky".into();
    assert!(!req.verify(None));
    assert!(!tech.verify_consent_request(&req, None));
}
