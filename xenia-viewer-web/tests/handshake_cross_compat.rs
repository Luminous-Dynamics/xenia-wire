// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Proves xenia-viewer-web's from-scratch WASM handshake reimplementation
// (src/handshake.rs) derives byte-identical session keys to the real
// native host implementation (xenia-peer-core::handshake +
// xenia-handshake). Dev-dependency only -- never compiled into the
// shipped wasm artifact (see Cargo.toml comment).
//
// Drives a REAL native host-side handshake
// (perform_host_handshake_with_transcript_and_context) against a mock
// Transport whose recv_envelope() computes the viewer's response inline
// by calling WasmHandshake::begin() on the just-sent HostHello -- so the
// native code path runs entirely unmodified, exactly as it would against
// a real xenia-peer daemon.

use std::cell::RefCell;

use xenia_peer_core::transport::{Transport, TransportError};
use xenia_viewer_web::WasmHandshake;

struct MockTransport {
    sent: Vec<Vec<u8>>,
    viewer: RefCell<WasmHandshake>,
}

impl Transport for MockTransport {
    async fn send_envelope(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.sent.push(bytes.to_vec());
        Ok(())
    }

    async fn recv_envelope(&mut self) -> Result<Vec<u8>, TransportError> {
        // Only ever called once, immediately after HostHello is sent.
        let hello_bytes = self.sent.last().expect("HostHello must be sent first");
        let response = self
            .viewer
            .borrow_mut()
            .begin_inner(hello_bytes)
            .expect("WasmHandshake::begin failed");
        Ok(response)
    }
}

#[tokio::test]
async fn wasm_viewer_handshake_matches_native_host() {
    let mut host_mgr = xenia_handshake::HandshakeManager::new();
    let mut transport = MockTransport {
        sent: Vec::new(),
        viewer: RefCell::new(WasmHandshake::new()),
    };

    let outcome = xenia_peer_core::handshake::perform_host_handshake_with_transcript_and_context(
        &mut transport,
        &mut host_mgr,
        "viewer-1",
        None,
    )
    .await
    .expect("native host handshake failed");

    // transport.sent[0] = HostHello, transport.sent[1] = HostFinalize.
    assert_eq!(transport.sent.len(), 2, "expected exactly hello + finalize");
    let finalize_bytes = &transport.sent[1];

    let viewer_key = transport
        .viewer
        .borrow_mut()
        .finish_inner(finalize_bytes)
        .expect("WasmHandshake::finish failed");

    assert_eq!(
        viewer_key.as_slice(),
        &outcome.session_key[..],
        "viewer-derived session key must byte-for-byte match the host's"
    );
}

#[tokio::test]
async fn wasm_viewer_handshake_matches_native_host_with_negotiated_context() {
    let mut host_mgr = xenia_handshake::HandshakeManager::new();
    let mut transport = MockTransport {
        sent: Vec::new(),
        viewer: RefCell::new(WasmHandshake::new()),
    };

    let negotiated_context_hash = Some([0x42u8; 32]);
    let outcome = xenia_peer_core::handshake::perform_host_handshake_with_transcript_and_context(
        &mut transport,
        &mut host_mgr,
        "viewer-2",
        negotiated_context_hash,
    )
    .await
    .expect("native host handshake failed");

    let finalize_bytes = &transport.sent[1];
    let viewer_key = transport
        .viewer
        .borrow_mut()
        .finish_inner(finalize_bytes)
        .expect("WasmHandshake::finish failed");

    assert_eq!(viewer_key.as_slice(), &outcome.session_key[..]);
}

#[tokio::test]
async fn wasm_viewer_handshake_rejects_tampered_finalize() {
    let mut host_mgr = xenia_handshake::HandshakeManager::new();
    let mut transport = MockTransport {
        sent: Vec::new(),
        viewer: RefCell::new(WasmHandshake::new()),
    };

    xenia_peer_core::handshake::perform_host_handshake_with_transcript_and_context(
        &mut transport,
        &mut host_mgr,
        "viewer-3",
        None,
    )
    .await
    .expect("native host handshake failed");

    let mut tampered_finalize = transport.sent[1].clone();
    let last = tampered_finalize.len() - 1;
    tampered_finalize[last] ^= 0xFF;

    let result = transport.viewer.borrow_mut().finish_inner(&tampered_finalize);
    assert!(
        result.is_err(),
        "viewer must reject a tampered HostFinalize signature"
    );
}
