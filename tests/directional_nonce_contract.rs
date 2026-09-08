// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression evidence for SPEC_DRAFT03_ERRATA.md E-03-001.
//!
//! These tests intentionally demonstrate a caller-level unsafe construction:
//! two independent sealing roles with the same key, source domain, epoch, and
//! payload type both start at sequence zero and therefore produce the same AEAD
//! nonce. The second test proves the current non-breaking mitigation: distinct
//! sender source prefixes make the nonce domains disjoint.

use xenia_wire::{PAYLOAD_TYPE_APPLICATION_MIN, Session};

const SHARED_KEY: [u8; 32] = [0xA5; 32];
const SESSION_EPOCH: u8 = 0x42;
const SHARED_SOURCE: [u8; 8] = *b"same-dir";
const HOST_SOURCE: [u8; 8] = *b"host-tx1";
const PEER_SOURCE: [u8; 8] = *b"peer-tx1";

fn nonce(envelope: &[u8]) -> &[u8] {
    &envelope[..12]
}

#[test]
fn shared_key_and_sender_domain_can_reuse_nonce_across_roles() {
    let mut host = Session::with_source_id(SHARED_SOURCE, SESSION_EPOCH);
    let mut peer = Session::with_source_id(SHARED_SOURCE, SESSION_EPOCH);

    host.install_key(SHARED_KEY);
    peer.install_key(SHARED_KEY);

    let host_envelope = host
        .seal(b"host control message", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();
    let peer_envelope = peer
        .seal(b"peer control message", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();

    // Both independent senders started at sequence 0. With the same key,
    // source prefix, epoch, and payload type, the full 96-bit AEAD nonce is
    // identical even though the plaintexts differ. This is exactly the
    // construction E-03-001 forbids.
    assert_eq!(nonce(&host_envelope), nonce(&peer_envelope));
    assert_ne!(&host_envelope[12..], &peer_envelope[12..]);
}

#[test]
fn distinct_sender_source_prefixes_separate_bidirectional_nonce_spaces() {
    // Only the first six source bytes enter the nonce, so the test requires
    // separation there rather than merely in the trailing two stored bytes.
    assert_ne!(&HOST_SOURCE[..6], &PEER_SOURCE[..6]);

    let mut host = Session::with_source_id(HOST_SOURCE, SESSION_EPOCH);
    let mut peer = Session::with_source_id(PEER_SOURCE, SESSION_EPOCH);
    host.install_key(SHARED_KEY);
    peer.install_key(SHARED_KEY);

    let host_envelope = host
        .seal(b"host control message", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();
    let peer_envelope = peer
        .seal(b"peer control message", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();

    assert_ne!(nonce(&host_envelope), nonce(&peer_envelope));
    assert_eq!(&nonce(&host_envelope)[..6], &HOST_SOURCE[..6]);
    assert_eq!(&nonce(&peer_envelope)[..6], &PEER_SOURCE[..6]);
}

#[test]
fn directional_separation_survives_genuine_rekey_counter_reset() {
    let mut host = Session::with_source_id(HOST_SOURCE, SESSION_EPOCH);
    let mut peer = Session::with_source_id(PEER_SOURCE, SESSION_EPOCH);
    host.install_key([0x11; 32]);
    peer.install_key([0x11; 32]);

    // Consume different amounts of the old-key sequence spaces, then rotate to
    // the same genuinely different new key. Genuine rekey resets each local
    // sender counter to zero; duplicate current-key installation does not.
    host.seal(b"old host 0", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();
    host.seal(b"old host 1", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();
    peer.seal(b"old peer 0", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();

    host.install_key(SHARED_KEY);
    peer.install_key(SHARED_KEY);

    let host_new = host
        .seal(b"new host sequence zero", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();
    let peer_new = peer
        .seal(b"new peer sequence zero", PAYLOAD_TYPE_APPLICATION_MIN)
        .unwrap();

    assert_eq!(&nonce(&host_new)[8..12], &[0, 0, 0, 0]);
    assert_eq!(&nonce(&peer_new)[8..12], &[0, 0, 0, 0]);
    assert_ne!(nonce(&host_new), nonce(&peer_new));
}
