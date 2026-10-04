// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Security characterization for xenia-wire #35.
//!
//! This test intentionally captures the current unsafe behavior so a repair can
//! prove it changed the exact invariant. It MUST be flipped from equality to
//! inequality / monotonic continuation before the remediation is mergeable.

use xenia_wire::Session;

const SOURCE_ID: [u8; 8] = *b"xwdup001";
const SESSION_EPOCH: u8 = 0x52;
const PAYLOAD_TYPE: u8 = 0x30;
const NONCE_LEN: usize = 12;

fn nonce(envelope: &[u8]) -> &[u8] {
    assert!(envelope.len() >= NONCE_LEN, "sealed envelope must contain a nonce");
    &envelope[..NONCE_LEN]
}

#[test]
fn reinstalling_current_key_reuses_sequence_zero_nonce_today() {
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

    // Characterization, NOT desired behavior: reinstalling the byte-identical
    // key is treated as a rekey and resets the sender counter to zero. Mirror
    // the same duplicate installation on the receiver to demonstrate that its
    // internal replay-key epoch also advances, allowing the cryptographically
    // reused nonce to be accepted as a fresh envelope.
    sender.install_key(key);
    receiver.install_key(key);
    assert_eq!(
        sender.nonce_counter(),
        0,
        "current implementation resets the nonce counter on duplicate install"
    );

    let second = sender
        .seal(b"second, different plaintext", PAYLOAD_TYPE)
        .expect("seal second envelope after duplicate install");

    assert_eq!(
        nonce(&first),
        nonce(&second),
        "current implementation should reproduce the same-key nonce reuse tracked in #35"
    );
    assert_eq!(
        receiver
            .open(&second)
            .expect("receiver currently accepts reused nonce after mirrored duplicate install"),
        b"second, different plaintext"
    );
}
