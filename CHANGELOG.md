# Changelog

All notable changes to `xenia-wire` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] — 2026-04-18

Initial pre-alpha extraction from the Holon-Soma wire in the Symthaea
research stack. **Not production-ready**: the wire format is not yet
frozen, the handshake is a placeholder, and the specification document
is still to come (Week 2). Published early to enable design feedback.

### Added

- `Session` — minimal AEAD session state: current key, previous key with
  grace period for rekey, per-session random `source_id` + `epoch`,
  monotonic nonce counter, and a 64-slot sliding replay window.
- `ReplayWindow` — sliding-window replay protection keyed by `(source_id,
  payload_type)`. Matches IPsec/DTLS semantics. Accepts out-of-order
  delivery within the window; rejects duplicates and too-old sequences.
- `Sealable` trait — generic bincode-based serialization hook so users
  can bring their own frame types.
- `seal` / `open` — generic functions for any `Sealable` payload.
- `seal_frame` / `open_frame` / `seal_input` / `open_input` —
  convenience wrappers for the reference `Frame` + `Input` types
  (behind the `reference-frame` feature, on by default).
- `seal_frame_lz4` / `open_frame_lz4` — LZ4-before-AEAD compression
  path (behind the `lz4` feature). Measured 2.12× reduction overall,
  2.20× on steady-state Delta frames (Pixel 8 Pro, Phase II.A).
- Payload-type registry in `payload_types.rs`:
  - `0x10` `FRAME` — primary outbound payload.
  - `0x11` `INPUT` — reverse-path (client-to-server) input events.
  - `0x12` `FRAME_LZ4` — LZ4-compressed frame.
  - `0x13..=0x1F` reserved.
  - `0x20..=0x2F` reserved for Week-5 spec differentiators (consent,
    replay recording, attestation — not yet implemented).
- `WireError` taxonomy via `thiserror`: `Codec`, `NoSessionKey`,
  `SealFailed`, `OpenFailed`.
- Zeroize-on-drop for session keys.
- `hello_xenia` example demonstrating seal/open roundtrip.
- Integration tests covering seal/open roundtrip, replay rejection,
  wrong-key rejection, and truncation resistance.
- Criterion bench for seal/open throughput.

### Known limitations

- Handshake layer is out of scope for this crate. Callers supply a
  32-byte session key directly via `Session::install_key`. Real
  ML-KEM-768 handshake integration will be a separate crate.
- Wire format may change incompatibly before `0.1.0` stable.
- `SPEC.md` is not yet published (target: Week 2).
- Test-vector suite is not yet populated (target: Week 2).

[Unreleased]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/Luminous-Dynamics/xenia-wire/releases/tag/v0.1.0-alpha.1
