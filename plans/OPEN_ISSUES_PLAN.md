# Open-issues plan (post-alpha.4) — CLOSED

**Status**: Phase A + Phase B both **SHIPPED**; all four round-2 review issues resolved. This document is retained as the design-decision provenance for the shipped work; nothing in it is still pending execution. Further hardening ([`0.2.0-alpha.2`](https://github.com/Luminous-Dynamics/xenia-wire/releases/tag/v0.2.0-alpha.2)) is captured in the CHANGELOG, not here.
**Scope**: all 4 GitHub issues left open after `xenia-wire 0.1.0-alpha.4`.
**Last updated**: 2026-04-18 — Phase B closeout.

This document collapsed issues #1–#4 into an executable plan. Each issue
got a concrete design (API shape, state transitions, file list, test
plan). The four were batched into two releases by wire-format compatibility:

| Release | Wire change? | Issues | Status |
|---------|--------------|--------|--------|
| **`0.1.0-alpha.5`** (SPEC draft-02r2) | No | [#2](https://github.com/Luminous-Dynamics/xenia-wire/issues/2) split `Pending`, [#4](https://github.com/Luminous-Dynamics/xenia-wire/issues/4) configurable replay window | ✅ **shipped 2026-04-18** |
| **`0.2.0-alpha.1`** (SPEC draft-03) | Yes (breaking) | [#1](https://github.com/Luminous-Dynamics/xenia-wire/issues/1) `session_binding`, [#3](https://github.com/Luminous-Dynamics/xenia-wire/issues/3) duplicate/conflict transition table | ✅ **shipped 2026-04-18** |
| **`0.2.0-alpha.2`** (draft-03 hardening) | No | Rekey-aware verify; timing-channel assumption; violation vectors; fuzz target; MIGRATION.md | ✅ **shipped 2026-04-18** |

The batching matters: draft-03 breaks the canonical bytes of signed
`ConsentRequestCore`, so anyone consuming consent test vectors or
verifying signatures across implementations has to re-sync. Bundling the
breaking changes into one version minimizes integration pain.

---

## Issue #2 — Split `Pending` into richer states

### Problem

`ConsentState::Pending` overloads two operationally different meanings:
"consent system not in use" (legacy bypass) vs "consent expected but no
request yet" (awaiting request). Callers can't express the second intent.

### Design

Six-variant enum; `LegacyBypass` is the new default and matches
draft-02 `Pending`-allows-traffic behavior:

```rust
pub enum ConsentState {
    /// Consent system not in use. Application traffic allowed.
    /// Default for Session::new().
    LegacyBypass,
    /// Consent system in use; no ConsentRequest observed yet.
    /// Application traffic BLOCKED until ceremony starts.
    /// Opt-in via builder.
    AwaitingRequest,
    Requested,
    Approved,
    Denied,
    Revoked,
}
```

Builder API:

```rust
impl Session {
    pub fn builder() -> SessionBuilder { ... }
}

pub struct SessionBuilder { ... }

impl SessionBuilder {
    pub fn require_consent(mut self, require: bool) -> Self;
    pub fn with_source_id(mut self, id: [u8; 8], epoch: u8) -> Self;
    pub fn with_rekey_grace(mut self, grace: Duration) -> Self;
    pub fn with_replay_window_bits(mut self, bits: u32) -> Self; // from #4
    pub fn build(self) -> Session;
}
```

Keep existing `Session::new()`, `Session::with_source_id()`,
`Session::with_rekey_grace()` for backward compatibility — they build to
`LegacyBypass`. The builder is additive.

### Transitions

| From | Request | ResponseApproved | ResponseDenied | Revocation |
|------|---------|------------------|----------------|------------|
| `LegacyBypass` | LegacyBypass (no-op) | LegacyBypass | LegacyBypass | LegacyBypass |
| `AwaitingRequest` | Requested | AwaitingRequest | AwaitingRequest | AwaitingRequest |
| `Requested` | (see issue #3) | Approved | Denied | (see issue #3) |
| `Approved` | (no-op) | Approved (idempotent) | (see issue #3) | Revoked |
| `Denied` | terminal | terminal | terminal | terminal |
| `Revoked` | terminal | terminal | terminal | terminal |

The `can_seal_frame` predicate:

- `LegacyBypass` → **Ok**
- `Approved` → **Ok**
- `Requested` | `AwaitingRequest` | `Denied` → `NoConsent`
- `Revoked` → `ConsentRevoked`

### Files touched

- `src/consent.rs` — enum + doc
- `src/session.rs` — default `LegacyBypass`, new `SessionBuilder`, updated transitions
- `src/lib.rs` — export `SessionBuilder`
- `tests/integration_consent.rs` — add 4 new tests
- `tests/proptest_consent.rs` — update transitions
- `SPEC.md` §12.6, §12.7 — state diagram + gating rules
- `CHANGELOG.md`

### New tests

- `legacy_bypass_allows_frame_without_ceremony` — regression of draft-02 behavior.
- `awaiting_request_blocks_frame` — new behavior.
- `builder_require_consent_true_starts_in_awaiting_request`.
- `legacy_bypass_ignores_unsolicited_request` — no auto-promotion.

### Effort

~2–4 hours.

---

## Issue #4 — Configurable replay window size

### Problem

Hardcoded `WINDOW_BITS = 64`. High-frequency/high-jitter streams benefit
from 256 or 1024.

### Design

Keep default 64 for backward compatibility; parameterize to multiples of
64 up to 1024:

```rust
pub struct ReplayWindow {
    streams: HashMap<(u64, u8, u8), StreamWindow>,
    window_bits: u32,          // must be multiple of 64, ≥64, ≤1024
    bitmap_words: usize,       // window_bits / 64
}

struct StreamWindow {
    highest: u64,
    bitmap: Vec<u64>,          // len == bitmap_words
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self { Self::with_window_bits(64) }
    pub fn with_window_bits(bits: u32) -> Self {
        assert!(bits >= 64 && bits <= 1024 && bits % 64 == 0);
        // ...
    }
}
```

Session builder exposes it:

```rust
pub fn with_replay_window_bits(mut self, bits: u32) -> Self;
```

### Multi-word shift logic (the tricky part)

```rust
/// Shift `bitmap` left by `shift` bits, filling LSB with 0.
fn shift_left_bitmap(bitmap: &mut [u64], shift: u32) {
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let len = bitmap.len();
    if word_shift >= len {
        bitmap.fill(0);
        return;
    }
    // Iterate from high word to low, moving bits up.
    for i in (0..len).rev() {
        let src_hi = if i >= word_shift { bitmap[i - word_shift] } else { 0 };
        let src_lo = if bit_shift > 0 && i > word_shift {
            bitmap[i - word_shift - 1] >> (64 - bit_shift)
        } else { 0 };
        bitmap[i] = (src_hi << bit_shift) | src_lo;
    }
}
```

Accept logic: replace `u64 << shift` with `shift_left_bitmap()`; replace
`bitmap & mask` with `bitmap[offset / 64] & (1 << (offset % 64))`.

### Files touched

- `src/replay_window.rs` — bitmap generalization + shift helper
- `src/session.rs` — builder option, passes through
- `tests/integration_rekey_replay.rs` — add a config-override test
- New unit tests: `bitmap_shift_across_word_boundary`, `large_window_at_256_slots`, `max_window_at_1024_slots`, `accept_at_boundary_in_multiword`
- `tests/proptest_wire.rs` — add `window_bits` parameter to existing props
- `SPEC.md` §5.1 — note configurability and memory cost
- `CHANGELOG.md`

### Performance

Per-stream memory for 1024-slot window: 128 bytes bitmap + 8 bytes
highest + 1 byte initialized ≈ 137 bytes. For 1000 streams: ~137 KB.
Negligible. The 64-slot fast-path stays a single `u64` shift + mask.

### Effort

~1 focused day. The bit-twiddling is where bugs hide; needs thorough
proptest coverage of boundary cases.

---

## Issue #1 — Session binding on ConsentRequestCore

### Problem

Consent signatures cover `bincode(core)` only. Consent signed in session
A is a valid artifact in session B with the same participants. Loose
binding.

### Design

Add an optional 32-byte field to `ConsentRequestCore`:

```rust
pub struct ConsentRequestCore {
    pub request_id: u64,
    pub requester_pubkey: [u8; 32],
    pub valid_until: u64,
    pub scope: ConsentScope,
    pub reason: String,
    pub causal_binding: Option<CausalPredicate>,
    /// NEW in draft-03: 32-byte session fingerprint.
    /// When Some, the receiver MUST verify the fingerprint matches
    /// their own session's fingerprint. Mismatch → ConsentSessionMismatch.
    pub session_fingerprint: Option<[u8; 32]>,
}
```

### Fingerprint derivation

```rust
use hkdf::Hkdf;
use sha2::Sha256;

fn derive_session_fingerprint(session_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut out = [0u8; 32];
    hk.expand(b"xenia-consent-binding-v1", &mut out)
        .expect("HKDF output size is within SHA-256 limits");
    out
}
```

### The rekey question

Option **A** (chosen): bind to the **initial** session key, not the
current one. Stash `initial_session_fingerprint` on first `install_key`;
don't change it on subsequent rekeys.

Rationale: a consent signed mid-session should remain valid across a
rekey in the same session. Tying to the *current* key would invalidate
prior consent on every rekey — wrong semantics for what
"session-binding" means.

Consequence: "session" = "span from first `install_key` to session
drop"; rekeys don't partition the binding.

### API

```rust
impl Session {
    /// Return the 32-byte session fingerprint for use in
    /// ConsentRequestCore::session_fingerprint. Returns None until the
    /// first `install_key` call.
    pub fn session_fingerprint(&self) -> Option<[u8; 32]>;
}
```

Caller constructs `ConsentRequest` with `session_fingerprint:
session.session_fingerprint()`.

On `open_consent_request`, after Ed25519 verification:

```rust
if let Some(expected) = request.core.session_fingerprint {
    let local = session.session_fingerprint()
        .ok_or(WireError::NoSessionKey)?;
    if expected != local {
        return Err(WireError::ConsentSessionMismatch);
    }
}
```

### Files touched

- `Cargo.toml` — add `hkdf = "0.12"` (or pin whichever `sha2` version matches `ed25519-dalek`'s existing tree)
- `src/consent.rs` — field addition + `derive_session_fingerprint`
- `src/session.rs` — `initial_session_fingerprint: Option<[u8; 32]>` field, `session_fingerprint()` accessor, populated on first `install_key`
- `src/error.rs` — new `ConsentSessionMismatch` variant
- `src/wire.rs` — `open_consent_request` gains the binding check
- `tests/integration_consent.rs` — binding pass + binding mismatch tests
- `examples/gen_test_vectors.rs` — new vectors 10/11/12 for draft-03 bound consent
- `tests/test_vector_validation.rs` — validate new vectors
- `SPEC.md` §12.3 — ConsentRequestCore schema update + verification contract
- `SPEC.md` §12.8 — remove "LOOSE binding" disclaimer, replace with normative text
- `SPEC.md` Appendix B — draft-03 row
- `CHANGELOG.md`

### New tests

- `consent_with_session_fingerprint_verifies_in_same_session`
- `consent_with_session_fingerprint_rejected_across_different_sessions` — the actual point
- `consent_without_session_fingerprint_still_works` (`None` case)
- `consent_fingerprint_survives_rekey_within_same_session`
- `session_fingerprint_is_none_before_install_key`

### Test vectors

Keep existing `07`/`08`/`09` as draft-02 vectors (unchanged). Add new
`10_consent_request_bound`, `11_consent_response_to_bound`, and
`12_consent_revocation_bound` with the same fixture key + a known
session_fingerprint derived from it. This lets cross-implementation
validators test both draft-02 (unbound) and draft-03 (bound) paths.

### Effort

~1 focused day including spec + vectors.

---

## Issue #3 — Duplicate/conflict transition table

### Problem

Draft-02r1 specified first-pass rules but left 5 ambiguities:
- What counts as a "ceremony"?
- Revocation before Response for same request_id?
- Concurrent revocations from both parties?
- Is `request_id` uniqueness enforced at wire or app level?
- What if a Response arrives for an old request_id after a new request is in flight?

### Design: explicit formal transition table

A "ceremony" is the lifecycle of one `request_id`. Each new higher
`request_id` starts a new ceremony. `request_id` MUST be
strictly-monotonic-increasing per-session on the requester side. On the
responder side, receipt of a lower-than-seen `request_id` is a protocol
violation.

The observer state carries a `current_request_id: Option<u64>` alongside
the state variant. Events become:

```rust
pub enum ConsentEvent {
    Request { request_id: u64 },
    ResponseApproved { request_id: u64 },
    ResponseDenied { request_id: u64 },
    Revocation { request_id: u64 },
}
```

Full transition table (current_request_id tracked; "match" = event id
equals current_request_id; "newer" = event id > current_request_id;
"stale" = event id < current_request_id):

| From | Event | New state | Notes |
|------|-------|-----------|-------|
| LegacyBypass | any | LegacyBypass | consent system not in use |
| AwaitingRequest | Request(id) | Requested(id) | start ceremony |
| AwaitingRequest | Response/Revocation | AwaitingRequest | no-op (unsolicited) |
| Requested(cur) | Request(newer) | Requested(newer) | supersede; prior ceremony abandoned |
| Requested(cur) | Request(match or stale) | Requested(cur) | duplicate/stale: no-op |
| Requested(cur) | ResponseApproved(match) | Approved(cur) | |
| Requested(cur) | ResponseApproved(newer/stale) | Requested(cur) | orphan: drop |
| Requested(cur) | ResponseDenied(match) | Denied(cur) | |
| Requested(cur) | ResponseDenied(newer/stale) | Requested(cur) | orphan: drop |
| Requested(cur) | Revocation(any) | Requested(cur) | **ERROR** (revoke before approve) |
| Approved(cur) | Request(newer) | Requested(newer) | new ceremony on top of old |
| Approved(cur) | Response(match) | Approved(cur) | idempotent duplicate |
| Approved(cur) | ResponseDenied(match) | Approved(cur) | **ERROR** (contradictory) |
| Approved(cur) | Revocation(match) | Revoked(cur) | end of ceremony |
| Approved(cur) | Revocation(stale/newer) | Approved(cur) | orphan: drop |
| Denied / Revoked | any | unchanged | terminal |

### Error returns

Two new or repurposed `WireError` variants (new in draft-03):

- `ConsentProtocolViolation` — contradictory or out-of-order events
  that indicate the peer is misbehaving. Session SHOULD be torn down.
- `ConsentStaleEvent` — event for a stale/unknown `request_id`. Drop
  the event; keep the session alive.

`observe_consent` returns `Result<ConsentState, WireError>` (changed
from current infallible signature).

### Files touched

- `src/consent.rs` — ConsentEvent variants with request_id, transition function
- `src/session.rs` — `observe_consent` signature change; internal `current_request_id: Option<u64>`
- `src/error.rs` — new variants
- `tests/integration_consent.rs` — add tests for each of the ~20 transition cells
- `tests/proptest_consent.rs` — random event sequences; assert invariants (monotonic request_ids, no state-from-terminal transitions, etc.)
- `SPEC.md` §12.6 — replace state-machine diagram with the full table
- `CHANGELOG.md`
- Potentially `examples/gen_test_vectors.rs` if we add a "ceremony with duplicate events" vector

### New tests

~20 cells × 1 test each ≈ 20 tests for transitions. Plus ~5
invariant-style property tests. Big but mechanical.

### Effort

~1.5–2 focused days. Most of the time is the transition-table design
(and writing out each test case); code + impl is ~half of that.

---

## Release sequencing

### `0.1.0-alpha.5` (draft-02r2)

**Contents**: #2 + #4.

**Wire compat**: no change. All draft-02 / draft-02r1 envelopes and
signatures open and verify identically.

**Migration**: zero. Existing callers upgrade in place. Callers who
want to opt into consent enforcement use the new
`Session::builder().require_consent(true).build()`; everyone else
stays in `LegacyBypass`. Callers who want a larger replay window use
`.with_replay_window_bits(256)`.

**Target effort**: 1.5 days.

### `0.2.0-alpha.1` (draft-03)

**Contents**: #1 + #3.

**Wire compat**: breaking for consent signed bytes. The serialized
`ConsentRequestCore` gains a new field (`session_fingerprint`), which
changes the canonical bincode v1 bytes → prior signatures fail to
verify under draft-03.

**Migration**: consent-using callers MUST regenerate any persistently-
stored consent artifacts. No migration for FRAME/INPUT traffic. Any
test vectors outside the repo need regeneration.

**Why major bump**: changing from `0.1.x` to `0.2.x` is the right
semver signal — library users might have stored signed consents that
no longer verify. A point-bump (`alpha.4` → `alpha.5`) would
understate the break.

**Target effort**: 2–3 days.

---

## Risks + open design decisions

### Risks

- **#4's multi-word bitmap**: boundary bugs. Proptest is the defense.
- **#3's 20 transition cells**: discovery of more ambiguity during
  implementation. Budget an extra half-day for "I didn't think of
  that."
- **#1's initial-key binding**: interacts weirdly with sessions that
  call `install_key` multiple times at startup (e.g. test fixtures).
  The "initial" is whichever key lands first; callers who rely on a
  specific key must sequence their setup accordingly.
- **draft-03 breaks old vectors**: the reviewer was explicit that
  bincode-v1-as-canonical is technical debt. draft-03 is a reasonable
  place to ALSO fix that, but doing both at once compounds risk.
  Recommendation: defer canonical-encoding re-design to a separate
  draft-04 bump; keep draft-03 focused on session_binding + consent
  semantics.

### Open decisions still on the user

1. **#2**: Should observing an unsolicited Request in `LegacyBypass`
   auto-promote to `Requested`, or stay in `LegacyBypass` (current
   proposal: stay)? Staying is simpler; auto-promotion matches what a
   security-conscious deployment might want.
2. **#3**: Is "revocation before response for same request_id" a hard
   protocol error (tear down session) or a drop-and-continue? Current
   proposal: hard error, because it implies peer misbehavior.
3. **#3**: Is "contradictory response" (Denied after Approved) a hard
   error or does the LATER decision win? Current proposal: hard error.
   Alternative: later-wins, matches real-world "I changed my mind."
4. **#1**: Should `session_fingerprint` be MANDATORY in draft-03 or
   remain `Option<_>`? Current proposal: `Option<_>` — old code paths
   that don't need the binding stay working. Making it mandatory
   forces the pattern, at the cost of a bigger migration.
5. **Release**: Should the `0.2.0` bump happen when #1+#3 land, or
   wait for a handshake spec so `0.2.0` is a coherent "post-handshake"
   milestone? Current proposal: bump when #1+#3 land.

---

## Execution order (if proceeding)

Phase A — alpha.5:
1. Implement #2 (consent.rs enum, session.rs builder, transitions). 2 hrs.
2. Write + pass #2 tests. 1 hr.
3. Implement #4 (replay_window.rs bitmap generalization). 4 hrs.
4. Write + pass #4 tests. 2 hrs.
5. Spec updates (§5.1, §12.6, §12.7). 1 hr.
6. Publish alpha.5. 30 min.

Phase B — alpha.6 / 0.2.0-alpha.1:
1. Design-review the #3 transition table (document first). 2 hrs.
2. Implement #1 (session_fingerprint derivation + field). 3 hrs.
3. Write + pass #1 tests. 2 hrs.
4. Implement #3 (ConsentEvent restructure + transitions). 3 hrs.
5. Write + pass #3 tests (~25 cases). 3 hrs.
6. Regenerate test vectors for draft-03 (keep draft-02 vectors
   alongside). 1 hr.
7. Spec updates (§12 overhaul, Appendix B draft-03 row). 2 hrs.
8. Publish. 30 min.

**Total**: ~3.5 focused days if everything goes smoothly. Budget 5 days
for real-world slippage.

---

## Not in scope of this plan

- Handshake specification (Track 2.5 in the broader Luminous Dynamics
  roadmap). When that lands, a draft-04 revision can switch
  `session_fingerprint`'s derivation source from AEAD-session-key to
  handshake-output hash.
- Full bincode-v1 canonical-encoding replacement. Known technical
  debt; deferred to a dedicated draft.
- Wire-level attestation chain (`0x23` `AttestedAction`). Separate
  design.

---

*Plan draft 1 — 2026-04-18 — open to iteration before execution.*
