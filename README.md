# xenia-wire

[![Crates.io](https://img.shields.io/crates/v/xenia-wire.svg)](https://crates.io/crates/xenia-wire)
[![Docs.rs](https://docs.rs/xenia-wire/badge.svg)](https://docs.rs/xenia-wire)
[![CI](https://github.com/Luminous-Dynamics/xenia-wire/actions/workflows/ci.yml/badge.svg)](https://github.com/Luminous-Dynamics/xenia-wire/actions/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0_OR_MIT-blue.svg)](#license)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)

PQC-sealed binary wire protocol for remote-control streams.

```text
  ╔═══════════════════════════════════════════════════════════╗
  ║  PRE-ALPHA — DO NOT USE IN PRODUCTION                     ║
  ║                                                           ║
  ║  The wire format is not yet frozen. Breaking changes will ║
  ║  land between 0.1.x releases. The handshake layer ships   ║
  ║  a placeholder key-establishment path; real ML-KEM-768    ║
  ║  integration is deferred (see SPEC.md §Handshake).        ║
  ║                                                           ║
  ║  This crate is an early research artifact. It will be     ║
  ║  ready for production use at 0.2.0 or later, after the    ║
  ║  specification is reviewed and the test-vector suite is   ║
  ║  cross-validated against an independent implementation.   ║
  ╚═══════════════════════════════════════════════════════════╝
```

---

**Xenia** (ξενία) — the ancient Greek covenant between guest and host. A
technician is a *guest* in a client's machine; the client extends bounded
hospitality; the protocol codifies the terms cryptographically.

## What it is

`xenia-wire` is the *byte-level* layer of the Xenia protocol: take a
sequence of application payloads, seal each one into a bounded envelope,
protect against replay and tampering, rotate keys without dropping
in-flight messages. It has no opinion about transport (TCP, WebSocket,
QUIC, UDP all fit), no opinion about framing policy (that's the
caller's), and no opinion about handshake. Those live at higher layers.

### What you get

- **ChaCha20-Poly1305 AEAD** with per-session random `source_id` + `epoch` and
  monotonic sequence in the nonce — domain-separated per payload type so the
  same key can seal multiple concurrent streams without nonce collision.
- **64-slot sliding replay window** keyed by `(source_id, payload_type)`,
  matching IPsec/DTLS replay-protection semantics.
- **Previous-key grace period** — rekey without dropping in-flight frames.
- **Optional LZ4-before-seal** compression (behind the `lz4` feature) — the
  only safe place to compress AEAD-sealed streams.
- **Generic `Sealable` trait** — bring your own frame type, or use the
  reference `Frame` / `Input` types for quick prototyping.
- **Zeroize-on-drop** key material.

### What it is *not*

- Not a transport. Your caller ships the sealed bytes; `xenia-wire` doesn't
  open sockets.
- Not a TLS replacement — no certificate chain, no ALPN, no hostname binding.
- Not a handshake. Session keys arrive from somewhere else (ML-KEM-768 in the
  real deployment; your unit tests' `[0xAB; 32]` fixture in development).
- Not a general AEAD library — `xenia-wire` fixes a specific nonce layout
  suited to replay-protected streams.

## Install

Because `0.2.0-alpha.2` is a pre-release, add it with the `@` form —
`cargo add --version ...` rejects pre-release specifiers:

```console
$ cargo add 'xenia-wire@0.2.0-alpha.2'
```

Once a stable `0.2.0` ships, `cargo add xenia-wire` will just work.
Earlier `0.1.x` alphas are still on crates.io but are wire-incompatible
at the signed-consent-body layer (see SPEC Appendix B for the draft
matrix); new integrations should start on `0.2.x`.

## Quick start

```rust
use xenia_wire::{Session, seal_frame, open_frame, Frame};

// Both sides install the same 32-byte key (in production, this comes
// from an ML-KEM-768 handshake; here we use a shared fixture).
let key = [0xAB; 32];
let mut sender = Session::new();
let mut receiver = Session::new();
sender.install_key(key);
receiver.install_key(key);

// Seal a frame on the sender side.
let frame = Frame {
    frame_id: 1,
    timestamp_ms: 1_700_000_000_000,
    payload: b"hello, xenia".to_vec(),
};
let sealed: Vec<u8> = seal_frame(&frame, &mut sender)
    .expect("seal succeeds with a valid key");

// Ship `sealed` over any transport you like (TCP, WS, QUIC, UDP).

// Receiver opens the envelope.
let opened: Frame = open_frame(&sealed, &mut receiver)
    .expect("open succeeds, replay window advances");

assert_eq!(opened.payload, b"hello, xenia");

// Replaying the same bytes fails — replay window catches it.
assert!(open_frame(&sealed, &mut receiver).is_err());
```

Run it:

```console
$ cargo run --example hello_xenia
```

## Features

| Feature          | Default | What it does                                          |
|------------------|---------|-------------------------------------------------------|
| `reference-frame`| yes     | Ships `Frame` + `Input` reference types implementing `Sealable`. Drop it if you're only using custom payload types. |
| `lz4`            | no      | Adds `seal_frame_lz4` / `open_frame_lz4` for LZ4-before-AEAD compression. Measured 2.12× on live Pixel 8 Pro captures. |

## Custom payloads

Implement `Sealable` for your own type:

```rust
use xenia_wire::{Sealable, WireError};

#[derive(serde::Serialize, serde::Deserialize)]
struct MyPayload { data: Vec<u8> }

impl Sealable for MyPayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}
```

Then call `seal` / `open` generically:

```rust
use xenia_wire::{seal, open, Session};

let mut session = Session::new();
session.install_key([0; 32]);

let payload = MyPayload { data: vec![1, 2, 3] };
let sealed = seal(&payload, &mut session, 0x30)?;
# Ok::<(), xenia_wire::WireError>(())
```

Payload type bytes `0x00..=0x0F` and `0x10..=0x2F` are reserved; see
`payload_types.rs`. Use `0x30..=0xFF` for your application.

## Empirical provenance

The wire format is extracted from a production research stack (Holon-Soma,
part of the Symthaea consciousness runtime). Empirical measurements on
real hardware:

- **JSON baseline → bincode seal**: 3.27–3.52× bandwidth reduction (Pixel
  8 Pro, Phase I.A).
- **LZ4-before-seal**: 2.12× additional reduction overall, 2.20× on
  steady-state Delta frames (Pixel 8 Pro, Phase II.A, 2026-04-17).
- **Head-of-line blocking comparison (WS vs QUIC)**: WS tail latency
  inflates 4.7× at 1% packet loss; QUIC stays ≤ 2× (Phase I.C, loopback
  netem harness). Transport-layer result — `xenia-wire` doesn't care
  which transport you pick.

Full methodology is written up in the forthcoming Xenia protocol paper.

## Paper

[`papers/xenia-paper.md`](papers/xenia-paper.md) — the academic
exposition of the protocol, with design rationale, empirical
evaluation (bandwidth, HoL-blocking, LZ4 measurements), and a
design-space comparison against commercial and open-source
alternatives. **Pre-alpha draft**, actively soliciting
cryptographer and MSP-practitioner review. The paper is the
exposition; [`SPEC.md`](SPEC.md) is the normative reference.

## Specification

Reading [`SPEC.md`](SPEC.md) (**draft-03**, current) should be sufficient to
write an interoperable implementation in any language. Reading the
source of this crate should NOT be necessary. If you find gaps in
the spec, please file an issue — the spec is the normative reference,
not the Rust source.

- [`SPEC.md`](SPEC.md) — full wire-format specification, 11 sections
  + 3 appendices covering nonce layout, replay window semantics,
  key lifecycle, LZ4-before-AEAD rule, error taxonomy, and security
  properties.
- [`CHANGELOG.md`](CHANGELOG.md) — version history.
- [`test-vectors/`](test-vectors/README.md) — 6 deterministic hex
  fixtures for cross-implementation validation. An implementation in
  Go, Swift, Python, or any other language can reproduce every
  envelope byte from the published fixtures.

## License

Licensed under either of:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms
or conditions.

## Related

- [Luminous Dynamics](https://luminousdynamics.io) — the research
  organization publishing this crate.
- [Holon-Soma roadmap](https://github.com/Luminous-Dynamics/symthaea)
  (private) — the upstream research roadmap from which this crate
  extracts the wire format.
