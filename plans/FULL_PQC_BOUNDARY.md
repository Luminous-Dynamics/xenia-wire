# Full-PQC Boundary

Status: claim-control note for `xenia-wire`.

`xenia-wire` is an AEAD-sealed byte-level protocol. It does not perform peer
authentication or key establishment. Therefore it should not claim to be
"entirely PQC" by itself.

## Current responsibility

`xenia-wire` provides:

- ChaCha20-Poly1305 envelope sealing;
- replay-window enforcement;
- epoch/key-rotation mechanics;
- optional LZ4-before-AEAD compression;
- consent payload formats and Ed25519 consent signatures behind the `consent` feature.

Session keys are caller-provided. A caller may derive those keys from ML-KEM,
hybrid PQ/T TLS, a fixture, or something unsafe. The wire crate cannot prove the
origin of those keys.

## Safe claim

> `xenia-wire` is an AEAD-sealed remote-session wire protocol designed to carry
> session keys derived by an ML-KEM-capable handshake layer.

## Unsafe claim

Do not say that this crate alone is full-PQC, entirely post-quantum, or a PQC
handshake. Full post-quantum posture requires the outer layer to provide PQ key
establishment and PQ authentication/signatures.

## Adjacent real-backend note

A real ML-DSA evidence-verification backend may live in `xenia-peer` /
`xenia-ledger` behind an explicit feature and verifier path. That does not change
this crate's boundary. `xenia-wire` still verifies frame encoding, AEAD opening,
replay protection, and consent-state transitions only. It must not claim to be
PQC-safe by itself; it can only say that it can carry keys and authenticated
session state produced by an outer PQ-capable layer.

## Migration dependency

A final PQ Xenia profile requires:

1. ML-KEM session-key establishment in the handshake layer;
2. ML-DSA/SLH-DSA transcript authentication in the handshake layer;
3. ML-DSA/SLH-DSA consent and ledger signatures in the application layer;
4. algorithm labels in session evidence exports;
5. downgrade tests that reject classical-only authentication when final PQ mode is required.
