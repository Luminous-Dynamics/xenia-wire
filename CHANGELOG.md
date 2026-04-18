# Changelog

All notable changes to `xenia-wire` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.2] — 2026-04-18

Tracks **SPEC draft-03**. No wire-format change from 0.2.0-alpha.1;
receiver-side hardening + developer-experience additions. All
draft-03 peers on any mix of 0.2.0-alpha.1 / alpha.2 continue to
interoperate at the wire level.

### Added

- **Rekey-aware fingerprint verification**
  ([SPEC §12.3.1 rekey interaction]) — `Session::verify_consent_request`,
  `_response`, and `_revocation` now transparently probe BOTH the
  current and the previous session keys when comparing a consent
  message's embedded `session_fingerprint`. A consent message
  signed moments before a rekey — AEAD-verified under the previous
  key during the rekey grace window — now also passes the
  fingerprint check. Previously, such in-flight messages would
  false-reject because the verifier derived the local fingerprint
  only from the current key, while the sender had derived from
  the (now-previous) key.
  - Internal helper `Session::session_fingerprint_from_key(request_id,
    key)` factored out of the public `session_fingerprint`.
  - Internal probe `verify_fingerprint_either_epoch` tries current
    then previous; returns `false` iff neither matches.
  - Regression test:
    `integration_consent::verify_probes_prev_key_during_rekey_grace`.

- **Interop test vectors 10 / 11 / 12** for the three
  `ConsentViolation` variants. Event-sequence line-oriented
  fixtures (new format; grammar documented in
  `test-vectors/10_revocation_before_approval.txt`) exercise
  `RevocationBeforeApproval`, `ContradictoryResponse`, and
  `StaleResponseForUnknownRequest` under adversarial ordering.
  Ref-impl runner in `tests/violation_vectors.rs`; alternate-
  language implementations can write a parallel runner from the
  vector format alone. Format separates doc prose from the
  machine-parseable script via an explicit `---BEGIN---` marker.

- **`cargo-fuzz` target `fuzz_observe_consent`** — coverage-guided
  fuzzer for the consent state machine. Feeds arbitrary
  `Vec<ConsentEvent>` (via `arbitrary::Arbitrary`) into a
  ceremony-mode session and asserts four invariants on every
  step: no panic, state always a valid variant, seal-gate matches
  state per SPEC §12.7, and violations never mutate state.
  Enable via `cargo +nightly fuzz run fuzz_observe_consent`. The
  existing `fuzz_replay_window` target was also updated to the
  post-alpha.4 four-argument `ReplayWindow::accept` signature.

- **`MIGRATION.md`** — a dedicated migration guide with
  before/after Rust snippets + TypeScript sketches for every
  API break between published versions. Primary content: the
  0.1.x → 0.2.0-alpha.1 break. Paired with the per-release
  `CHANGELOG` entries.

- **SPEC §12.8 timing-channel requirement** — added a
  load-bearing assumption paragraph specifying that the
  consent-verification pipeline (bincode deserialization,
  Ed25519 verify, fingerprint compare) MUST NOT branch on
  secret-dependent bytes. The reference implementation ships a
  constant-time compare (`ct_eq_32`); alternate-language
  implementers are on the hook for auditing their bincode +
  Ed25519 equivalents. Also enumerates the caveat that
  fixed-size bincode v1 structs are best-effort constant-time
  but not guaranteed — implementations that cannot assert the
  property SHOULD fall back to comparing the re-serialized
  bytes against the wire slice before invoking Ed25519 verify.

### Changed

- Test vector manifest in SPEC Appendix A + `test-vectors/README.md`
  gained rows 10/11/12 for the new event-sequence fixtures.

### Not changed

- Wire format (envelope + signed canonical bodies) unchanged.
- No API break.
- `consent` feature dependency set unchanged.

## [0.2.0-alpha.1] — 2026-04-18

Tracks **SPEC draft-03**. **Breaking wire change at the signed-
consent-body layer.** The envelope layout (SPEC §1–§11) is unchanged;
FRAME / INPUT / FRAME_LZ4 traffic remains interoperable with any
0.1.x peer. The breaking change is the canonical bytes of the three
signed consent bodies — a 0.1.x peer cannot verify a 0.2.x consent
signature (and vice-versa).

Closes the remaining two open-issue items from the round-2 review:

### Added

- **Mandatory session fingerprint on signed consent bodies**
  ([SPEC §12.3.1]; closes
  [#1](https://github.com/Luminous-Dynamics/xenia-wire/issues/1)) —
  every `ConsentRequestCore`, `ConsentResponseCore`, and
  `ConsentRevocationCore` now carries a 32-byte
  `session_fingerprint`. Derived locally per peer:
  ```
  fingerprint = HKDF-SHA-256(
    salt = b"xenia-session-fingerprint-v1",
    ikm  = current session_key,
    info = source_id || epoch || request_id_be,
    L    = 32,
  )
  ```
  Both peers derive the same value from their own copy of the key.
  On verify, receivers re-derive locally and compare in constant time;
  a mismatch fails verification the same as a bad signature. This
  closes the "loose session binding" replay-across-sessions gap that
  draft-02r1 documented as a known limitation.
  - `Session::session_fingerprint(request_id)` — new public method.
  - `Session::sign_consent_request` / `_response` / `_revocation`
    — convenience methods that derive the fingerprint AND sign.
  - `Session::verify_consent_request` / `_response` / `_revocation`
    — convenience methods that check signature + fingerprint +
    optional pubkey match.
  - Test vectors 07/08/09 regenerated (shared fingerprint
    `5b94fb75…d7d4` — same session + same `request_id=7`).
  - Pure Rust, constant-time 32-byte compare (no new runtime deps
    beyond `hkdf` + `sha2`).

- **Normative consent state-machine transition table + violation
  detection** ([SPEC §12.6.1]; closes
  [#3](https://github.com/Luminous-Dynamics/xenia-wire/issues/3)) —
  the consent state machine is now fully normative: every (state,
  event, `request_id`) tuple maps to a specific next state or a
  specific protocol violation. Three violation variants surface as
  `WireError::ConsentProtocolViolation(ConsentViolation)`:
  - `RevocationBeforeApproval` — a `ConsentRevocation` observed
    while state is `AwaitingRequest` or `Requested` (revoking
    something that was never approved). The peer's state machine
    is broken or compromised.
  - `ContradictoryResponse{prior_approved, new_approved}` — a
    `ConsentResponse` whose `approved` contradicts a prior response
    for the same `request_id`. Rejected rather than accepted as
    "later wins"; the correct wire-level primitive for mind-changes
    is a fresh `ConsentRevocation` (SPEC §12.6.2 records the UI
    guidance explicitly).
  - `StaleResponseForUnknownRequest` — a `ConsentResponse` whose
    `request_id` was never `Requested`.
  - The wire does NOT tear down the transport on violation. The
    caller receives the error and decides. On a violation the
    session state is NOT mutated.

- **`ConsentEvent` carries `request_id`** — each variant is now a
  struct-shape:
  ```rust
  pub enum ConsentEvent {
      Request { request_id: u64 },
      ResponseApproved { request_id: u64 },
      ResponseDenied { request_id: u64 },
      Revocation { request_id: u64 },
  }
  ```
  Enables the request_id-sensitive transition rules above.

- **`ConsentViolation` enum** (in `xenia_wire::consent`) with the
  three variants described above. `thiserror::Error` so it formats
  cleanly in logs.

- **`WireError::ConsentProtocolViolation(ConsentViolation)`** — new
  variant surfaced by `Session::observe_consent`.

### Changed

- **`Session::observe_consent` signature**: now returns
  `Result<ConsentState, ConsentViolation>`. Legal transitions and
  benign no-ops return `Ok(state)`; protocol violations return
  `Err(violation)` with state unmutated. Callers MUST handle the
  `Result`.

- **`ConsentState`** no longer has a `Pending` variant (removed in
  0.1.0-alpha.5's rename to `LegacyBypass` / `AwaitingRequest`).
  0.2.0 retains those names.

- **SPEC draft-03**: §1.4, §1.4.1, §12.3, §12.3.1 (new, mandatory
  fingerprint), §12.3.2 (renumbered canonical encoding), §12.6
  (normative table), §12.6.2 (new UI-guidance subsection), §12.7
  (updated). Appendix B draft-03 row.

- Dependencies added: `hkdf = "0.12"`, `sha2 = "0.10"` (both under
  the `consent` feature). No new runtime dependencies when `consent`
  is off.

- `xenia-viewer-web` updated to use `Session::sign_consent_*` helpers;
  the consent walkthrough demo continues to work end-to-end.

### Migration

**Updating from 0.1.0-alpha.5 → 0.2.0-alpha.1:**

1. Existing `Session::new` / `Session::builder` callers — no change.
   `Session::new` still defaults to `LegacyBypass`; the sticky rule
   still holds.
2. Code that constructs `ConsentRequestCore` / `ConsentResponseCore`
   / `ConsentRevocationCore` gains a new field
   `session_fingerprint: [u8; 32]`. Set it to `[0; 32]` and sign via
   `Session::sign_consent_request` (etc.) — the helper overwrites
   the placeholder with the HKDF-derived value before signing. Or:
   derive manually via `Session::session_fingerprint(request_id)`
   and plug the result in before calling `ConsentRequest::sign`.
3. Every `ConsentEvent::*` pattern match gains a `{ request_id }`
   struct binding. The event's request_id can be pulled from the
   corresponding consent message you just opened.
4. Every `session.observe_consent(...)` call returns a `Result` now.
   Handle violations — the most common pattern is to propagate them
   up as session-teardown signals.
5. Cross-implementation interop: draft-03 consent bodies will not
   verify against 0.1.x peers and vice-versa. Bump both sides.

### Plan status

- `#1 session_binding field` — **closed** in this release (mandatory).
- `#3 duplicate/conflict transition table` — **closed** in this release.
- All four originally-tracked design items are now closed.

## [0.1.0-alpha.5] — 2026-04-18

Tracks **SPEC draft-02r2**. No wire-format change from alpha.4 /
draft-02r1 — both additions are receiver-local. Two interoperating
peers on any mix of alpha.3 / alpha.4 / alpha.5 continue to open
each other's envelopes (default configuration).

### Added

- **Split `Pending` consent state** ([SPEC §12.6 / §12.7];
  [plan #2](plans/OPEN_ISSUES_PLAN.md)) — `ConsentState::Pending`
  is replaced by two variants that disambiguate its dual meaning:
  - `ConsentState::LegacyBypass` — consent handled out-of-band;
    FRAME / INPUT / FRAME_LZ4 payloads flow unimpeded. This is
    the default for `Session::new` / `Session::with_source_id`,
    so existing call sites retain draft-02r1 behavior with no
    code changes.
  - `ConsentState::AwaitingRequest` — ceremony mode; FRAME is
    blocked until a full `Request` → `Response{approved=true}`
    cycle transitions the session to `Approved`. Opt in via
    `Session::builder().require_consent(true).build()`.
- **`SessionBuilder`** — a new builder type for opt-in session
  configuration (`require_consent`, `with_source_id`,
  `with_rekey_grace`, `with_replay_window_bits`). Construct via
  `Session::builder()`; finalize via `.build()`.
- **Configurable replay window size**
  ([SPEC §5.1]; [plan #4](plans/OPEN_ISSUES_PLAN.md)) — the
  per-stream replay window is now parameterized in bits.
  Valid values: 64, 128, 256, 512, 1024 (must be a multiple
  of 64). Default remains 64. Wider windows tolerate heavier
  transport reordering at a cost of `W / 8` bytes of bitmap
  per `(source_id, payload_type, key_epoch)` stream.
  - `ReplayWindow::with_window_bits(bits: u32)` — new constructor.
  - `SessionBuilder::with_replay_window_bits(bits: u32)` — session-
    level override.
  - `DEFAULT_WINDOW_BITS` (= 64) and `MAX_WINDOW_BITS` (= 1024)
    constants exported at the crate root. `WINDOW_BITS` retained
    as a back-compat alias for `DEFAULT_WINDOW_BITS`.

### Changed

- `Session::new` default state (under the `consent` feature) is
  now `LegacyBypass` instead of `Pending`. Behavior is unchanged
  — both states allow FRAME to flow. Callers that relied on
  observing `Pending` in telemetry should switch to `LegacyBypass`
  (there is no combined `PendingOrLegacy` helper by design; the
  intent difference was the whole point of the split).
- `ReplayWindow::new()` remains; it constructs a default 64-slot
  window, so existing callers are unaffected.
- `ReplayWindow.bitmap` is now `Vec<u64>` internally instead of a
  single `u64`. Not part of the public API.
- SPEC draft-02r2: §5.1 generalized to `W` bits; §12.6 / §12.7
  redrawn around the six-variant state machine; Appendix B adds
  a draft-02r2 row.
- Consent-ceremony walkthrough in `xenia-viewer-web` updated: the
  WASM fixture now opens in ceremony mode (`AwaitingRequest`) so
  the interactive demo exercises the full state machine.

### Deprecated

- None. `ConsentState::Pending` never shipped outside the
  draft-02 → draft-02r1 docs as a public enum variant (the Rust
  enum was `Pending` in alpha.3 and alpha.4). Callers migrating
  from alpha.4:
  - Pattern matches on `ConsentState::Pending` → rename to
    `ConsentState::LegacyBypass` (unchanged behavior) OR
    `ConsentState::AwaitingRequest` (ceremony mode, opt in via
    `SessionBuilder::require_consent`).
  - Exhaustive matches on `ConsentState` gain two new arms
    (`LegacyBypass` and `AwaitingRequest`). `#[deny(unused)]`
    callers will see a clippy nag until both are handled.

### Plan status

- `#2 Split Pending` — **closed** in this release.
- `#4 Configurable replay window size` — **closed** in this release.
- `#1 session_binding field` and `#3 duplicate/conflict transition
  table` remain deferred to `0.2.0-alpha.1` / draft-03 (both are
  breaking wire or semantics changes).

## [0.1.0-alpha.4] — 2026-04-18

### Security / Correctness

- **Per-key-epoch replay state**
  ([#5](https://github.com/Luminous-Dynamics/xenia-wire/issues/5)) —
  the replay window is now keyed by `(source_id, payload_type,
  key_epoch)` instead of `(source_id, payload_type)`. This closes a
  latent bug where the sender's nonce-counter reset on rekey (SPEC
  §3 / §6.4) would collide with the receiver's accumulated `highest`
  from the old key: a freshly-rekeyed stream at `seq=0` would be
  rejected against an `highest=1000` from the previous key, causing
  silent data loss for up to `highest - WINDOW_BITS + 1` envelopes
  post-rekey.
  - `Session::install_key` now advances an internal `key_epoch` on
    each rekey (wrapping `u8`).
  - `Session::open` tracks which key verified the AEAD tag and
    passes that key's epoch to `ReplayWindow::accept`.
  - `Session::tick` reclaims old-epoch replay state when the
    previous key's grace period expires.
  - `ReplayWindow::accept` signature changed from
    `accept(key: (u64, u8), seq: u64)` to
    `accept(source_id: u64, payload_type: u8, key_epoch: u8, seq: u64)`.
    `ReplayWindow` is not part of the recommended public surface;
    users of `Session::seal` / `Session::open` are unaffected.
  - New `ReplayWindow::drop_epoch(u8)` helper for explicit cleanup.

### Added

- `tests/integration_rekey_replay.rs` — 5 regression tests covering
  the primary bug scenario (high old-key sequence + rekey does not
  false-reject), replay during grace still rejects, in-flight
  old-key envelopes still open during grace, `tick()` reclaims
  old-epoch state, and a 10-rekey stress scenario.
- 3 new `ReplayWindow` unit tests for per-epoch semantics.

### Changed

- SPEC.md §5.3 impl-gap caveat **removed** — the reference
  implementation now matches the draft-02r1 spec.
- `replay_window.rs` module docs updated with the per-epoch scoping
  story (SPEC §5.3).

### Fixed

- The latent silent-data-loss-on-rekey bug described above. No
  production deployment known to be affected (pre-alpha crate), but
  any 0.1.0-alpha.3 user running sustained streams through a rekey
  SHOULD upgrade.

## [0.1.0-alpha.3] — 2026-04-18

### Added

- **API polish for the consent ceremony.** New dedicated wrappers
  `seal_consent_request` / `open_consent_request` /
  `seal_consent_response` / `open_consent_response` /
  `seal_consent_revocation` / `open_consent_revocation`. Callers no
  longer need to import `PAYLOAD_TYPE_CONSENT_*` constants to use
  the generic `seal`/`open` path. Mirrors the `seal_frame` /
  `seal_input` surface for a consistent API shape.
- **Test vectors 08 and 09** — `consent_response` and
  `consent_revocation` with deterministic Ed25519 seeds. Vectors 08
  + 09 share a signing identity (modelling an end-user who first
  approves then later revokes). An alternate-language implementer
  can now validate all three consent message types, not just the
  request.
- **Property tests for the consent state machine**
  (`tests/proptest_consent.rs`): 5 properties × ~256 proptest cases
  each, asserting state-validity, Denied/Revoked terminality,
  FRAME-seal-gate ≡ state, and no-return-to-Pending.
- **SPEC §12.3 canonical-encoding requirement**: signatures MUST be
  verified using bincode v1 with default configuration
  (little-endian, fixint, no size limit). Bincode v2's varint
  encoding is explicitly NOT compatible. This was load-bearing but
  undocumented in draft-02's original text; future drafts may
  define a version-tagged encoding.

### Fixed

- Integration test `full_consent_ceremony_allows_frame_flow` now
  observes consent events AFTER opening each message (the natural
  order on the receive side), not before. Purely cosmetic — the
  state machine accepts out-of-order events — but the test now
  reads the way real callers would structure their handlers.

### Changed

- **Week 4: wasm32 compatibility + browser demo.**
  - `xenia-wire` now compiles cleanly on `wasm32-unknown-unknown`
    across all three feature combinations (no default, default, all).
    `getrandom`'s `"js"` feature and `web-time::Instant` resolve the
    wasm32 std-time / entropy gaps. New CI job guards this.
  - New `xenia-viewer-web/` subcrate — a minimal wasm-bindgen demo
    that runs seal/open roundtrip entirely in the browser. Not
    published to crates.io; hosted as a static site after `wasm-pack
    build`. Preserves `xenia-wire`'s dep hygiene — the main crate
    pulls no wasm-bindgen deps.

- **Week 5: consent ceremony (SPEC draft-02 §12).**
  - New `consent` feature adds the `consent` module with
    `ConsentRequest` / `ConsentResponse` / `ConsentRevocation`
    signed by Ed25519 via `ed25519-dalek`.
  - Session-level state machine (`ConsentState`: Pending →
    Requested → Approved → Revoked, plus Denied as a terminal).
    `Session::observe_consent(ConsentEvent)` drives transitions;
    caller verifies signatures.
  - `FRAME` / `INPUT` / `FRAME_LZ4` seals/opens are gated on
    consent state. Pending state (no ceremony observed) allows
    application frames — opt-in enforcement, preserves draft-01
    behavior for callers with external consent models.
  - New `WireError::NoConsent` and `WireError::ConsentRevoked`
    variants.
  - Reserved payload types `0x20` / `0x21` / `0x22` are now
    assigned by draft-02. `0x23` (AttestedAction) remains reserved.
  - New test-vector `07_consent_request` exercising the full
    Ed25519 sign → bincode → seal pipeline with a deterministic
    fixture seed.
  - 7 new integration tests covering the full ceremony,
    denial, revocation race, unsolicited events, and tampered
    messages.

- **SPEC.md draft-02** — adds §12 Consent Ceremony. No breaking
  changes to §1–§11. Draft version bumped in Appendix B.

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

[Unreleased]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.4...HEAD
[0.1.0-alpha.4]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/Luminous-Dynamics/xenia-wire/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Luminous-Dynamics/xenia-wire/releases/tag/v0.1.0-alpha.1
