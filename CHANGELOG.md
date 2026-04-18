# Changelog

All notable changes to `xenia-wire` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.2] — 2026-04-18

### Security

- **Sequence-wraparound guard** — `Session::seal` now returns the new
  `WireError::SequenceExhausted` when the nonce counter reaches `2^32`,
  rather than silently wrapping to `0` under the same key. Silent wrap
  would cause catastrophic nonce reuse under ChaCha20-Poly1305.
  Callers who disabled or failed to trigger rekey previously ran a
  latent time-bomb (~4.5 years at 30 fps, ~40 hours at 30 kHz); now
  they get an actionable error forcing a rekey. Wire format unchanged.
  Users of `0.1.0-alpha.1` SHOULD upgrade.

### Added

- `SPEC.md` draft-01 — full wire-format specification in 11 sections
  (wire format, nonce, payload-type registry, replay window, key
  lifecycle, LZ4-before-AEAD, handshake placeholder, error taxonomy,
  security properties, non-goals) + 3 appendices. Normative reference
  for cross-language implementations.
- `test-vectors/` — 6 deterministic hex fixtures with human-readable
  documentation. Every envelope byte is reproducible from the fixed
  fixture parameters. `examples/gen_test_vectors.rs` regenerates them
  deterministically.
- `papers/xenia-paper.md` — draft academic paper corresponding to
  `0.1.0-alpha.2` + SPEC draft-01. 8 sections (~4,800 words):
  abstract, introduction, related work, wire protocol recap +
  rationale, empirical evaluation (bandwidth, HoL blocking,
  LZ4-before-AEAD), design-space discussion, future work, call
  for review. Pre-alpha — active review solicitation.
- `papers/refs.bib` — BibTeX references (RFC 4303, RFC 9000,
  RFC 9147, FIPS 203, Noise, Signal, RustCrypto, LZ4, scrcpy,
  and comparison systems).
- `papers/README.md` — conversion instructions for submission
  (pandoc-based markdown → LaTeX → PDF pipeline).
- `tests/test_vector_validation.rs` — regression guard: 6 tests
  that open each fixture and compare against the published
  plaintext.
- `tests/smoke_fuzz.rs` — stable-toolchain smoke fuzzer. 310,000
  random envelopes through `Session::open()` in ~0.3s.
- `fuzz/` — `cargo-fuzz` scaffold (nightly-only) with three
  targets: `fuzz_open`, `fuzz_open_frame`, `fuzz_replay_window`.
- `tests/proptest_wire.rs` — 10 property tests (~2,560 effective
  runs by proptest defaults).
- `SECURITY.md` — responsible-disclosure policy for a pre-alpha
  crypto crate.
- `CONTRIBUTING.md` — dual-license clause, dev workflow,
  property-test expectation for wire-format changes.

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

[Unreleased]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Luminous-Dynamics/xenia-wire/releases/tag/v0.1.0-alpha.1
