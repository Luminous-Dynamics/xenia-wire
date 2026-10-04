// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression for xenia-wire #35.
//!
//! Evidence-only PR #36 proves the pre-fix behavior reuses sequence-zero
//! nonce bytes after reinstalling the byte-identical key. This successor
//! requires duplicate installation to preserve sender nonce monotonicity and
//! receiver replay state while keeping ordinary interoperability.

use xenia_wire::Session;

const SOURCE_ID: [u8; 8] = *b"xwdup001";
const SESSION_EPOCH: u8 = 0x52;
const PAYLOAD_TYPE: u8 = 0x30;
const NONCE_LEN: usize = 12;

fn nonce(envelope: &[u8]) -> &[u8] {
    assert!(
        envelope.len() >= NONCE_LEN,
        "sealed envelope must contain a nonce"
    );
    &envelope[..NONCE_LEN]
}

#[test]
fn reinstalling_current_key_preserves_nonce_monotonicity_replay_and_interoperability() {
    let key = [0xA5; 32];
    let mut sender = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);
    let mut receiver = Session::with_source_id(SOURCE_ID, SESSION_EPOCH);

    sender.install_key(key);
    receiver.install_key(key);

    let first = sender
        .seal(b"first plaintext", PAYLOAD_TYPE)
        .expect("seal first envelope");
    assert_eq!(sender.nonce_counter(), 1);
    assert_eq!(
        receiver.open(&first).expect("open first envelope"),
        b"first plaintext"
    );

    sender.install_key(key);
    receiver.install_key(key);

    assert_eq!(
        sender.nonce_counter(),
        1,
        "duplicate install must not reset sender nonce state"
    );
    assert!(
        receiver.open(&first).is_err(),
        "duplicate install must not create a fresh replay epoch that accepts an already-opened envelope"
    );

    let second = sender
        .seal(b"second, different plaintext", PAYLOAD_TYPE)
        .expect("seal second envelope after duplicate install");

    assert_ne!(
        nonce(&first),
        nonce(&second),
        "duplicate install must not recreate a (key, nonce) pair"
    );
    assert_eq!(
        &nonce(&first)[..8],
        &nonce(&second)[..8],
        "same source/payload/static epoch remain unchanged"
    );
    assert_eq!(&nonce(&first)[8..12], &[0, 0, 0, 0]);
    assert_eq!(&nonce(&second)[8..12], &[1, 0, 0, 0]);

    assert_eq!(
        receiver
            .open(&second)
            .expect("receiver opens monotonic post-duplicate envelope"),
        b"second, different plaintext"
    );
}
