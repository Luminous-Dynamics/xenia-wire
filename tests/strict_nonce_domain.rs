// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "reference-frame")]

use xenia_wire::{
    Frame, NonceDomain, PAYLOAD_TYPE_FRAME, Session, WireError, envelope_nonce_domain, open_frame,
    open_from_nonce_domain, seal_frame,
};

const KEY: [u8; 32] = [0xA9; 32];
const EXPECTED_SOURCE_ID: [u8; 8] = [0x11; 8];
const UNEXPECTED_SOURCE_ID: [u8; 8] = [0x22; 8];
const EPOCH: u8 = 0x42;

fn frame() -> Frame {
    Frame {
        frame_id: 7,
        timestamp_ms: 1_700_000_000_777,
        payload: b"strict nonce domain".to_vec(),
    }
}

fn expected_domain() -> NonceDomain {
    NonceDomain::from_source_id(EXPECTED_SOURCE_ID, PAYLOAD_TYPE_FRAME, EPOCH)
}

#[test]
fn exact_expected_nonce_domain_opens_normally() {
    let mut sender = Session::with_source_id(EXPECTED_SOURCE_ID, EPOCH);
    let mut receiver = Session::with_source_id([0x99; 8], 0x99);
    sender.install_key(KEY);
    receiver.install_key(KEY);

    let sealed = seal_frame(&frame(), &mut sender).unwrap();
    assert_eq!(envelope_nonce_domain(&sealed), Some(expected_domain()));

    let opened: Frame = open_from_nonce_domain(&sealed, &mut receiver, expected_domain()).unwrap();
    assert_eq!(opened, frame());
}

#[test]
fn domain_mismatch_fails_before_replay_state_is_consumed() {
    let mut sender = Session::with_source_id(UNEXPECTED_SOURCE_ID, EPOCH);
    let mut receiver = Session::with_source_id([0x99; 8], 0x99);
    sender.install_key(KEY);
    receiver.install_key(KEY);

    let sealed = seal_frame(&frame(), &mut sender).unwrap();

    let wrong_source = expected_domain();
    assert!(matches!(
        open_from_nonce_domain::<Frame>(&sealed, &mut receiver, wrong_source),
        Err(WireError::OpenFailed)
    ));

    let wrong_payload = NonceDomain::from_source_id(
        UNEXPECTED_SOURCE_ID,
        PAYLOAD_TYPE_FRAME.wrapping_add(1),
        EPOCH,
    );
    assert!(matches!(
        open_from_nonce_domain::<Frame>(&sealed, &mut receiver, wrong_payload),
        Err(WireError::OpenFailed)
    ));

    let wrong_epoch = NonceDomain::from_source_id(
        UNEXPECTED_SOURCE_ID,
        PAYLOAD_TYPE_FRAME,
        EPOCH.wrapping_add(1),
    );
    assert!(matches!(
        open_from_nonce_domain::<Frame>(&sealed, &mut receiver, wrong_epoch),
        Err(WireError::OpenFailed)
    ));

    // All strict-domain failures happened before Session::open, so none may
    // consume the envelope's replay slot. The existing permissive API can still
    // authenticate/open these exact bytes once afterward.
    let opened = open_frame(&sealed, &mut receiver).unwrap();
    assert_eq!(opened, frame());
}

#[test]
fn partial_or_short_nonce_has_no_domain_and_fails_closed() {
    let mut receiver = Session::with_source_id([0x99; 8], 0x99);
    receiver.install_key(KEY);

    for malformed in [&[0u8; 7][..], &[0u8; 8][..], &[0u8; 11][..]] {
        assert_eq!(envelope_nonce_domain(malformed), None);
        assert!(matches!(
            open_from_nonce_domain::<Frame>(malformed, &mut receiver, expected_domain()),
            Err(WireError::OpenFailed)
        ));
    }
}

#[test]
fn source_id_constructor_uses_only_authenticated_prefix() {
    let a = NonceDomain::from_source_id([1, 2, 3, 4, 5, 6, 7, 8], PAYLOAD_TYPE_FRAME, EPOCH);
    let b = NonceDomain::from_source_id([1, 2, 3, 4, 5, 6, 0xAA, 0xBB], PAYLOAD_TYPE_FRAME, EPOCH);

    assert_eq!(a, b);
    assert_eq!(a.source_prefix, [1, 2, 3, 4, 5, 6]);
}
